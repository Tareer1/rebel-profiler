"""Loopback recording proxy (Phase 13): observe the operator's OWN traffic.

The capability gap this closes: authenticated-attack-surface discovery needs
to see which endpoints a real session actually touches. Existing crawlers
only follow links; the operator's browser hits the API endpoints the crawler
never guesses.

Design laws honored exactly:

  * **Loopback only, fixed.** The proxy binds 127.0.0.1 — the operator's
    own machine. It records requests the OPERATOR makes to an application
    they own (their lab, their device). It is never a network-position
    tool: no ARP/DNS manipulation is possible here by construction.
  * **Record, never rewrite.** Requests are observed, hashed and stored —
    never modified, never replayed, never intercepted for TLS (https CONNECT
    tunnels are recorded as opaque tunnel events with byte counts only).
  * **Bounded.** max_transactions caps the session; every transaction is
    registered as hash-chained evidence as it happens.
  * **The proxy is a foreground service, not an argv action** (the
    no-fake-adapter law): ``rp proxy <case>`` starts it; the case-scoped
    evidence ledger stores what was seen; the parser turns transactions
    into ``proxy_transaction`` claims (method + path only — body bytes are
    hashed into the evidence blob, never stored verbatim).
"""

from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..core.errors import UsageError
from .claims import ClaimLedger
from .injection import scan_injection

MAX_BODY_BYTES = 512_000
DEFAULT_PORT = 18080


class _RecordingHandler(BaseHTTPRequestHandler):
    """Records one transaction, forwards nothing, rewrites nothing.

    The handler is deliberately a dead end: the client's request is logged
    and answered with 502 so the operator points their browser at the REAL
    app, using this proxy purely as a tap. A transparent in-line forwarder
    would make the tool a network-position device — out of scope by design.
    """

    # wired by serve_traffic_proxy()
    case_id: str = ""
    ledger = None
    evidence = None
    max_transactions: int = 200
    state: dict = {}

    protocol_version = "HTTP/1.1"

    def _record(self) -> None:
        if self.state["count"] >= self.max_transactions:
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, MAX_BODY_BYTES)) if length else b""
        host = self.headers.get("Host") or "unknown"
        txn = {
            "seq": self.state["count"] + 1,
            "method": self.command,
            "host": host[:120],
            "path": self.path[:400],
            "request_bytes": len(body),
            "request_sha256": hashlib.sha256(body).hexdigest() if body else "",
            "headers": {k[:60].lower(): v[:120]
                        for k, v in self.headers.items()
                        if k.lower() not in {"cookie", "authorization"}
                        },  # credentials never enter the ledger
        }
        self.state["count"] += 1
        blob = json.dumps(txn, indent=2, sort_keys=True).encode()
        rec = self.evidence.register(
            self.case_id, kind="proxy_transaction", data=blob,
            source="scan.proxy",
            note=f"{self.command} {host}{self.path[:120]}",
            meta={"seq": txn["seq"], "method": txn["method"]},
        )
        self.state["transactions"].append(txn)
        # claim: method + path on the host subject — enough for surface work
        subject = f"http://{host}"
        try:
            claim = self.ledger.add(
                self.case_id, subject=subject, kind="proxy_transaction",
                value=f"{self.command} {self.path[:200]}",
                source="scan.proxy", method="traffic-proxy",
                evidence_id=rec.id,
            )
            self.state["claims"].append(claim.id)
        except Exception:  # noqa: BLE001 - ledger refusal must not kill the proxy
            pass
        injection = scan_injection(f"{host}\n{self.path}")
        self.state["injection_findings"].extend(f.as_dict() for f in injection)

    def do_GET(self):  # noqa: N802
        self._record()
        self._dead_end()

    def do_POST(self):  # noqa: N802
        self._record()
        self._dead_end()

    def do_PUT(self):  # noqa: N802
        self._record()
        self._dead_end()

    def do_DELETE(self):  # noqa: N802
        self._record()
        self._dead_end()

    def do_PATCH(self):  # noqa: N802
        self._record()
        self._dead_end()

    def do_HEAD(self):  # noqa: N802
        self._record()
        self.send_response(502)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_CONNECT(self):  # noqa: N802
        # https tunnels: record the SNI/authority as an opaque tunnel event —
        # no TLS interception, ever.
        if self.state["count"] >= self.max_transactions:
            return
        self.state["count"] += 1
        txn = {"seq": self.state["count"], "method": "CONNECT",
               "host": self.path[:120], "tunnel": True}
        blob = json.dumps(txn, sort_keys=True).encode()
        rec = self.evidence.register(
            self.case_id, kind="proxy_tunnel", data=blob, source="scan.proxy",
            note=f"CONNECT tunnel (opaque): {self.path[:120]}",
            meta={"seq": txn["seq"]},
        )
        self.state["transactions"].append(txn)
        try:
            claim = self.ledger.add(
                self.case_id, subject=self.path[:200], kind="proxy_tunnel",
                value="opaque https tunnel (not intercepted)",
                source="scan.proxy", method="traffic-proxy",
                evidence_id=rec.id,
            )
            self.state["claims"].append(claim.id)
        except Exception:  # noqa: BLE001
            pass
        self.send_response(502)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _dead_end(self) -> None:
        # 502 + Connection: close: the proxy is a tap, not a forwarder, and
        # closing keeps clients from hanging on a keep-alive dead end.
        self.send_response(502)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()

    def log_message(self, format, *args):  # noqa: A002 - silence stderr noise
        return


def serve_traffic_proxy(case_id: str, *, ledger: ClaimLedger, evidence,
                        listen_port: int = DEFAULT_PORT,
                        max_transactions: int = 200) -> dict:
    """Start the loopback recording proxy; returns control immediately.

    The server thread is a daemon: it dies with the process. Callers stop it
    by stopping the CLI process or via the returned handle's ``shutdown``.
    """
    if not (listen_port == 0 or 1024 <= listen_port <= 65535):
        raise UsageError(
            f"Port out of range: {listen_port}",
            reason="The recording proxy binds unprivileged ports only "
                   "(0 = pick an ephemeral port, for tests).",
            action="Pick a port in 1024..65535.",
        )

    state = {"count": 0, "transactions": [], "claims": [],
             "injection_findings": []}

    class _Wired(_RecordingHandler):
        pass

    _Wired.case_id = case_id
    _Wired.ledger = ledger
    _Wired.evidence = evidence
    _Wired.max_transactions = max_transactions
    _Wired.state = state

    server = ThreadingHTTPServer(("127.0.0.1", listen_port), _Wired)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return {
        "bind": "127.0.0.1",
        "port": listen_port,
        "max_transactions": max_transactions,
        "state": state,
        "server": server,
        "thread": thread,
        "note": ("point your browser at http://127.0.0.1:<port> with the real "
                 "app behind it — transactions are recorded to the case "
                 "ledger; the proxy never forwards or rewrites"),
    }
