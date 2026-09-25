#!/usr/bin/env python3
"""Rebel Profiler — local GUI proxy (stdlib-only).

Serves the static GUI (frontend/index.html) and exposes a small, read-only
API for it. Everything binds 127.0.0.1 only. No third-party dependencies.

  GET  /                    → the GUI (frontend/index.html)
  GET  /healthz             → proxy liveness + backend reachability
  GET  /api/state           → proxied GET /state      (read-only gateway)
  GET  /api/events          → proxied GET /events     (read-only gateway)
  POST /api/cli             → whitelisted `rebel-profiler … -o json*` commands
  GET  /api/hermes/stream?goal=…&case=…&tier=…
                            → SSE stream of one hermes run (honest raw lines)

Run:
  python3 frontend/proxy.py [--port 8898] \
      [--api-port 8899] [--api-token SECRET] [--rp /path/to/rebel-profiler]

The gateway itself is started separately (see CHEATSHEET §4a):
  rebel-profiler serve <case-id> --port 8899 --token SECRET
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PROXY_VERSION = 1
HTTP_TIMEOUT = 5
CLI_TIMEOUT = 120

# ---------------------------------------------------------------------------
# CLI whitelist — the only write surface the GUI has, and every entry is a
# command that already gates itself through the broker's six gates. Each
# template lists fixed tokens (kept verbatim) and slot placeholders:
#   {case} → validated case id   {target} → single CLI token (no spaces)
#   {text}, {text2}, … → numbered free-text slots (params.text / params.text2)
#   {int} → digits only
# ---------------------------------------------------------------------------
CLI_WHITELIST = {
    "case_list":       ["case", "list"],
    "case_show":       ["case", "show", "{case}"],
    "case_create":     ["case", "create", "{text}", "{text2}"],
    "scope_add":       ["case", "scope", "add", "{case}", "{target}"],
    "scope_add_excl":  ["case", "scope", "add", "{case}", "{target}", "--exclude"],
    "case_activate":   ["case", "activate", "{case}"],
    "adapters":        ["adapters"],
    "claims":          ["intel", "claims", "{case}"],
    "report":          ["report", "{case}"],
    "surface_map":     ["surface", "map", "{case}"],
    "audit_verify":    ["audit", "verify", "{case}"],
    "dork_search":     ["intel", "collect", "{case}", "dork-search", "{target}",
                        "-p", "engine", "{text}", "-p", "dork", "{text2}", "-y"],
    # --- Kali tool surface: same whitelisted-collect pattern -------------
    "nikto_scan":      ["intel", "collect", "{case}", "nikto-scan", "{target}",
                        "-p", "port", "{text}", "-p", "ssl", "{text2}", "-y"],
    "wpscan_audit":    ["intel", "collect", "{case}", "wpscan-audit", "{target}", "-y"],
    "exploit_lookup":  ["intel", "collect", "{case}", "exploit-lookup", "{target}", "-y"],
    "vuln_coverage":   ["intel", "vuln-coverage", "{case}"],
    "playbooks_list":  ["intel", "playbook", "list"],
    "dork_search_tor": ["intel", "collect", "{case}", "dork-search", "{target}",
                        "-p", "engine", "ahmia", "-p", "dork", "{text}",
                        "-p", "tld", "onion", "-y"],
    "browser_submit":  ["browser", "submit", "{case}", "{target}",
                        "--extract", "title,links,text"],
    "browser_result":  ["browser", "result", "{target}"],
    "scope_show":      ["case", "scope", "show", "{case}"],
    # --- approval queue: the GUI view onto pending high-risk actions -------
    # decide/approve carry the OPERATOR's explicit click; the broker still
    # re-validates scope/policy at decision time (tighten-only, fail-closed).
    "approvals_list":  ["approval", "list", "{case}"],
    "approval_decide": ["approval", "decide", "{case}", "{target}", "{text}"],
    "approval_run":    ["approval", "run", "{case}", "{target}"],
    "audit_show":      ["audit", "show", "{case}"],
    "surface_show":    ["surface", "show", "{case}"],
    "surface_build":   ["surface", "build", "{case}"],
    "evidence_verify": ["evidence", "verify", "{case}"],
}


def _case_ok(case: str) -> bool:
    """Case ids are hex-ish slugs; be strict anyway."""
    return bool(case) and len(case) <= 64 and all(
        ch.isalnum() or ch in "-_" for ch in case)


def _token_ok(token: str) -> bool:
    return bool(token) and " " not in token and "\t" not in token and len(token) <= 256


def _int_ok(value: str) -> bool:
    return value.isdigit() and len(value) <= 9


def build_argv(command: str, params: dict) -> list[str] | None:
    """Turn a whitelisted template + params into an argv list — or None.

    Never uses a shell: the caller spawns with argv arrays only. Free-text
    slots ({text}, {text2}, …) are read positionally from params by their
    own name, so one template can carry several independent strings.
    """
    template = CLI_WHITELIST.get(command)
    if template is None:
        return None
    argv: list[str] = []
    for piece in template:
        if piece.startswith("{") and piece.endswith("}"):
            slot = piece[1:-1]
            value = str(params.get(slot, ""))
            if slot == "case" and not _case_ok(value):
                return None
            if slot == "target" and not _token_ok(value):
                return None
            if slot.startswith("text") and not _token_ok(value):
                return None
            if slot == "int" and not _int_ok(value):
                return None
            argv.append(value)
        else:
            argv.append(piece)
    return argv


def run_cli(rp_binary: str, command: str, params: dict,
            output_mode: str = "json") -> tuple[int, object, str]:
    """Execute one whitelisted CLI command with `-o json*` enforced."""
    argv = build_argv(command, params)
    if argv is None:
        return 400, {"error": "unknown command or bad params",
                     "action": "Use one of the whitelisted commands."}, ""
    # Output mode is enforced last, so a client can never drop it.
    argv += ["-o", output_mode if output_mode in {"json", "jsonl"} else "json"]
    env = dict(os.environ)
    env.setdefault("RP_ACTOR", "gui-proxy")
    try:
        proc = subprocess.run(
            [rp_binary, *argv], capture_output=True, text=True,
            timeout=CLI_TIMEOUT, env=env, shell=False,
        )
    except subprocess.TimeoutExpired:
        return 504, {"error": "cli timeout", "action":
                     f"'{command}' exceeded {CLI_TIMEOUT}s."}, ""
    except FileNotFoundError:
        return 500, {"error": "rebel-profiler binary not found",
                     "action": "Pass --rp /path/to/rebel-profiler or put it on PATH."}, ""
    out = proc.stdout
    if output_mode == "jsonl":
        parsed: object = [json.loads(line) for line in out.splitlines()
                          if line.strip()]
    else:
        try:
            parsed = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            # Some commands print human text even in -o json on stderr paths.
            return 200, {"raw": out[-4000:], "returncode": proc.returncode}, proc.stderr
    if proc.returncode != 0:
        # The CLI prints structured errors — surface them verbatim at the
        # top level instead of an empty result + stderr blob.
        try:
            err_obj = json.loads(proc.stderr.strip())
        except json.JSONDecodeError:
            err_obj = None
        if isinstance(err_obj, dict) and "error" in err_obj:
            return 400, err_obj, ""
    return 200, parsed, proc.stderr


# ---------------------------------------------------------------------------
# Hermes SSE
# ---------------------------------------------------------------------------

def hermes_argv(rp_binary: str, goal: str, case: str, tier: str) -> list[str]:
    """One oneshot hermes run for the goal — the honest, raw stream."""
    argv = [rp_binary, "hermes", "--oneshot"]
    if tier:
        argv += ["--tier", tier]
    if case:
        argv += ["--case", case]
    argv += shlex.split(goal) if goal else []
    return argv


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class ProxyHandler(BaseHTTPRequestHandler):
    server_version = f"RPProxy/{PROXY_VERSION}"

    # injected by serve():
    api_port: int = 8899
    api_token: str = ""          # raw secret; the bearer hash is computed here
    rp_binary: str = "rebel-profiler"
    frontend_dir: str = ""
    bridge_port: int = 8765

    # -- hardening -------------------------------------------------------------

    def _origin_ok(self) -> bool:
        """Strict same-origin check for state-changing calls (POST /api/cli).

        The GUI is local-only, but a malicious page in ANY other tab can fire
        cross-origin POSTs at 127.0.0.1 unless the proxy refuses them. Browsers
        always send Origin on cross-site POSTs; localhost GET navigation may
        omit it, so GETs stay allowed and POSTs fail closed.
        """
        origin = self.headers.get("Origin", "")
        if not origin:
            return True   # same-origin form posts may omit Origin entirely
        host = self.headers.get("Host", "")
        return origin in {f"http://{host}", f"http://127.0.0.1:{self.server.server_address[1]}",
                          f"http://localhost:{self.server.server_address[1]}"}

    def _security_headers(self) -> None:
        """Baseline hardening headers on every response."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy",
                         "default-src 'self' 'unsafe-inline'; "
                         "connect-src 'self'; img-src 'self' data:; "
                         "frame-ancestors 'none'; form-action 'self'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    # -- helpers ------------------------------------------------------------

    def _json(self, code: int, data) -> None:
        body = json.dumps(data, sort_keys=True, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        # Local-only GUI: allow file:// or any localhost page to call the proxy.
        # (State-changing POSTs are gated separately by _origin_ok.)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def _gateway_get(self, path: str) -> tuple[int, object]:
        """Forward a GET to the read-only ApiGateway with the bearer header."""
        import hashlib
        url = f"http://127.0.0.1:{self.api_port}{path}"
        req = urllib.request.Request(url)
        if self.api_token:
            digest = hashlib.sha256(self.api_token.encode()).hexdigest()
            req.add_header("Authorization", f"Bearer {digest}")
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read().decode())
            except Exception:
                return exc.code, {"error": f"gateway http {exc.code}"}
        except (urllib.error.URLError, OSError):
            return 502, {"error": "gateway unreachable",
                         "action": f"Start it: rebel-profiler serve <case-id> "
                                   f"--port {self.api_port} --token SECRET"}

    def _static(self) -> None:
        index = os.path.join(self.frontend_dir, "index.html")
        if not os.path.isfile(index):
            self._json(404, {"error": "index.html missing",
                             "action": "Serve from the frontend/ directory."})
            return
        with open(index, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    # -- routes -------------------------------------------------------------

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in {"/", "/index.html"}:
            self._static()
        elif path == "/healthz":
            gw_code, gw = self._gateway_get("/healthz")
            self._json(200, {
                "ok": True, "proxy": PROXY_VERSION,
                "backend": {"reachable": gw_code == 200,
                            "status": gw_code, "detail": gw},
            })
        elif path == "/api/state":
            code, data = self._gateway_get("/state")
            self._json(code, data)
        elif path == "/api/events":
            code, data = self._gateway_get("/events")
            self._json(code, data)
        elif path == "/api/adapters":
            code, data = run_cli(self.rp_binary, "adapters", {})
            self._json(code, data)
        elif path == "/api/bridge_status":
            # Raw liveness probe of the browser bridge (127.0.0.1:8765).
            # No token needed: a refused socket is 'down', anything else
            # (200 or 401) proves a bridge process is listening.
            import socket as _socket

            try:
                with _socket.create_connection(("127.0.0.1", 8765), timeout=0.6):
                    self._json(200, {"up": True, "host": "127.0.0.1:8765"})
            except OSError:
                self._json(200, {"up": False, "host": "127.0.0.1:8765",
                                 "note": "start it with 'rp bridge'"})
        elif path == "/api/bridge_token":
            # The bridge token file, read for the extension setup popup.
            # Same file `rp bridge` prints; nothing beyond it is exposed.
            token_file = os.environ.get("RP_BRIDGE_TOKEN_FILE",
                                        "/tmp/rp_bridge_token")
            try:
                with open(token_file, "r", encoding="utf-8") as fh:
                    token = fh.read().strip()
            except OSError:
                token = ""
            self._json(200, {"token": token,
                             "source": token_file,
                             "note": "" if token else
                                     "no token file — start the bridge with 'rp bridge'"})
        elif path == "/api/hermes/stream":
            self._hermes_stream()
        else:
            self._json(404, {"error": "not found",
                             "endpoints": ["/", "/healthz", "/api/state",
                                           "/api/events", "/api/adapters",
                                           "/api/bridge_status",
                                           "/api/hermes/stream", "POST /api/cli"]})

    def do_POST(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/api/session_kill":
            # GUI hardening part 2: the operator's one-click session kill —
            # closes the gateway, the browser bridge and THIS proxy together
            # and stops any in-flight hermes run. Same-origin gated like the
            # whitelist; the response is best-effort because the server dies
            # mid-reply.
            if not self._origin_ok():
                self._json(403, {"error": "cross-origin request refused",
                                 "action": "Use the GUI served by this proxy."})
                return
            detail = session_kill(api_port=self.api_port,
                                  bridge_port=self.bridge_port,
                                  proxy_port=self.server.server_address[1])
            self._json(200, {"ok": True, "closed": detail,
                             "note": "session ending — all listeners closed"})
            # give the socket a moment to flush, then stop the whole process
            threading.Timer(0.4, _shutdown_everything).start()
            return
        if path != "/api/cli":
            self._json(405, {"error": "method not allowed", "allowed": ["GET"]})
            return
        # CSRF / cross-origin hardening: a page from another origin (even
        # another localhost port) never drives the whitelist.
        if not self._origin_ok():
            self._json(403, {"error": "cross-origin request refused",
                             "action": "Use the GUI served by this proxy."})
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > 65536:
            self._json(413, {"error": "payload too large"})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode() or "{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid JSON body"})
            return
        command = str(payload.get("cmd", ""))
        params = payload.get("params", {})
        if not isinstance(params, dict):
            self._json(400, {"error": "params must be an object"})
            return
        output_mode = str(payload.get("output", "json"))
        code, data, stderr = run_cli(self.rp_binary, command, params, output_mode)
        if code != 200:
            # structured error at the top level, like every other surface
            self._json(code, data)
            return
        body = {"result": data}
        if stderr.strip():
            body["stderr"] = stderr[-2000:]
        self._json(code, body)

    # -- hermes SSE ---------------------------------------------------------

    def _hermes_stream(self) -> None:
        query = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
        goal = (query.get("goal", [""])[0] or "").strip()
        case = (query.get("case", [""])[0] or "").strip()
        tier = (query.get("tier", [""])[0] or "").strip()
        if not goal:
            self._json(400, {"error": "goal required",
                             "action": "GET /api/hermes/stream?goal=…"}); return
        if len(goal) > 2000:
            self._json(400, {"error": "goal too long"}); return
        if case and not _case_ok(case):
            self._json(400, {"error": "bad case id"}); return
        if tier and tier not in {"tiny", "low", "mid", "high"}:
            self._json(400, {"error": "bad tier"}); return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        def emit(event: str, data: str) -> bool:
            try:
                chunk = f"event: {event}\ndata: {json.dumps(data)}\n\n"
                self.wfile.write(chunk.encode())
                self.wfile.flush()
                return True
            except (BrokenPipeError, ConnectionResetError, OSError):
                return False

        emit("start", {"goal": goal, "case": case, "tier": tier,
                       "note": "local model — first turn reads the whole tool "
                               "contract and can take minutes on CPU"})
        argv = hermes_argv(self.rp_binary, goal, case, tier)
        started = time.time()
        try:
            proc = subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, shell=False, env={**os.environ, "RP_ACTOR": "gui-proxy"},
            )
        except FileNotFoundError:
            emit("error", {"error": "rebel-profiler binary not found",
                           "action": "Pass --rp or put it on PATH."})
            return
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if not emit("line", line.rstrip("\n")):
                    proc.kill()
                    return
            code = proc.wait(timeout=CLI_TIMEOUT)
            emit("done", {"returncode": code,
                          "elapsed_s": round(time.time() - started, 1)})
        except subprocess.TimeoutExpired:
            proc.kill()
            emit("error", {"error": "hermes run exceeded the time bound"})
        finally:
            try:
                proc.kill()
            except Exception:
                pass

    def do_OPTIONS(self):  # noqa: N802 — CORS preflight for the local GUI
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):  # quiet
        return


# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# session kill: one decision, every local listener closed

_KILL_SENTINEL = "/tmp/rp_session_dead"


def _close_port(port: int, kind: str) -> dict:
    """Best-effort close of one local listener; never raises."""
    import socket as _socket

    try:
        with _socket.create_connection(("127.0.0.1", port), timeout=0.4):
            return {"kind": kind, "port": port, "was_up": True}
    except OSError:
        return {"kind": kind, "port": port, "was_up": False}


def session_kill(*, api_port: int, bridge_port: int, proxy_port: int) -> list[dict]:
    """Probe the three local listeners, then tear the session down.

    The gateway and the browser bridge are separate processes, so the proxy
    marks them dead by closing THEIR ports from outside: it sends SIGTERM to
    any process listening on those ports owned by the same user (a systemd-
    free Kali box has no supervisor — this IS the shutdown path). The proxy
    itself dies with os._exit from _shutdown_everything right after.
    """
    import signal

    detail = [_close_port(api_port, "gateway"),
              _close_port(bridge_port, "browser_bridge"),
              _close_port(proxy_port, "proxy")]
    # terminate the listener processes (same user only) via /proc scanning:
    # pids whose cmdline references the rp gateway/bridge and whose socket
    # sits on the target port. Conservative: exact match on our own argv
    # patterns, nothing else is ever signalled.
    me = os.getpid()
    for pid, cmdline in _own_user_processes():
        if pid == me:
            continue
        joined = " ".join(cmdline)
        if ("rebel-profiler" in joined
                and ("serve" in joined or "bridge" in joined)):
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
    try:
        Path(_KILL_SENTINEL).write_text(
            json.dumps({"at": time.time(), "closed": detail}) + "\n")
    except OSError:
        pass
    return detail


def _own_user_processes() -> list[tuple[int, list[str]]]:
    """(pid, cmdline) for processes owned by THIS user — /proc, no subprocess."""
    out: list[tuple[int, list[str]]] = []
    my_uid = os.getuid()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != my_uid:
                continue
            argv = (entry / "cmdline").read_bytes().split(b"\0")
            out.append((int(entry.name),
                        [a.decode(errors="replace") for a in argv if a]))
        except (OSError, ValueError):
            continue
    return out


def _shutdown_everything() -> None:
    """Last step of session kill: stop this proxy process hard."""
    os._exit(0)


def serve(args: argparse.Namespace) -> int:
    ProxyHandler.api_port = args.api_port
    ProxyHandler.api_token = args.api_token
    ProxyHandler.rp_binary = args.rp
    ProxyHandler.frontend_dir = os.path.dirname(os.path.abspath(__file__))
    server = ThreadingHTTPServer(("127.0.0.1", args.port), ProxyHandler)
    print(f"rp-gui proxy on http://127.0.0.1:{args.port}  "
          f"(gateway :{args.api_port} "
          f"{'token-gated' if args.api_token else 'no token — gateway calls will 503'})",
          flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Rebel Profiler GUI proxy")
    parser.add_argument("--port", type=int, default=8898)
    parser.add_argument("--api-port", type=int, default=8899)
    parser.add_argument("--api-token", default=os.environ.get("RP_API_TOKEN", ""))
    parser.add_argument("--rp", default=shutil.which("rebel-profiler") or "rebel-profiler")
    args = parser.parse_args(argv)
    return serve(args)


if __name__ == "__main__":
    sys.exit(main())
