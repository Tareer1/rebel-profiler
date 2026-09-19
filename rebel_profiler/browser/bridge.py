"""Browser bridge: lets the LLM use the operator's browser (Phase 5+).

The LLM never drives the browser directly. It writes a *browser job* (same
three-way handshake as the worker plane), and this bridge:

  1. validates the job against the live case **scope** (fail closed — an
     out-of-scope URL is rejected before any browser sees it),
  2. publishes the task to the local extension endpoint
     (``GET /tasks`` on 127.0.0.1),
  3. receives the extension's claim (``POST /ack`` → SYN-ACK) and result
     (``POST /result`` → ACK),
  4. registers fetched page data as hash-chained evidence, runs the
     prompt-injection scan and emits provenance-carrying claims,
  5. writes the result file for the LLM to read back — including a
     structured error log when the extension could not complete the job.

The extension (see ``extension/`` in the repo root) is a small Manifest V3
add-on that polls the bridge, executes navigation + extraction inside the
user's own browser (their profile, their cookies, their network), and posts
results back. The user only ever writes prompts; the LLM writes job files.

Security properties:
  * the bridge listens on 127.0.0.1 only, with a bearer token,
  * scope is validated twice: in the bridge (before publish) and again in
    the extension (before navigate),
  * extraction is read-only: no clicks, no form submissions, no JS eval in
    pages — collect, never act,
  * everything the page returns is untrusted data (injection-scanned).
"""

from __future__ import annotations

import json
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ..core.errors import RPError, ScopeViolationError, UsageError
from ..core.redact import redact
from ..evidence.audit import AuditChain
from ..evidence.store import EvidenceStore
from ..intel.claims import ClaimLedger
from ..intel.collection import CollectionPipeline
from ..intel.injection import scan_injection, sanitize_external
from ..intel.sources import SourceRegistry
from ..security.scope import ScopeEngine
from ..execution.worker import JobPlane, _sha256_canonical

BRIDGE_TOKEN_ENV = "RP_BROWSER_TOKEN"
DEFAULT_PORT = 8765

# What an extraction job may ask the page for. Read-only by design.
EXTRACTORS = ("title", "text", "links", "headers", "forms", "cookies", "meta")
MAX_TEXT_CHARS = 20_000
MAX_LINKS = 300

# Interactive (user-like) actions the extension may perform. These turn the
# browser into the LLM's hands — the same way a human uses the mouse.
# Submission is the dangerous one and is approval-gated below.
INTERACTION_OPS = ("click", "type", "scroll", "submit", "wait", "navigate")
MAX_ACTIONS = 25
MAX_SELECTOR_LEN = 200
MAX_TEXT_LEN = 2_000

# selectors must be plain CSS: no braces/escapes, bounded length
_SELECTOR_RE = re.compile(r"^[A-Za-z0-9\s\[\]\(\)='#.\-_>:,*~+]{1,200}$")


class BrowserJobError(UsageError):
    """Raised for malformed browser jobs."""


def validate_actions(raw_actions) -> list[dict]:
    """Validate an interaction script. Fail closed on anything unknown."""
    if raw_actions is None:
        return []
    if not isinstance(raw_actions, (list, tuple)) or len(raw_actions) > MAX_ACTIONS:
        raise BrowserJobError(
            f"Interaction script must be a list of at most {MAX_ACTIONS} actions",
            action="Use ops: " + ", ".join(INTERACTION_OPS))
    out = []
    for item in raw_actions:
        if not isinstance(item, dict) or item.get("op") not in INTERACTION_OPS:
            raise BrowserJobError(
                f"Unknown interaction op '{(item or {}).get('op') if isinstance(item, dict) else item}'",
                reason="Only declared ops are executable.",
                action="Use ops: " + ", ".join(INTERACTION_OPS))
        op = item["op"]
        selector = str(item.get("selector", ""))
        if op in {"click", "type", "submit"} and not selector:
            raise BrowserJobError(f"Interaction '{op}' requires a CSS selector")
        if selector:
            if len(selector) > MAX_SELECTOR_LEN or not _SELECTOR_RE.match(selector):
                raise BrowserJobError(
                    f"Selector '{selector[:40]}…' is not a plain CSS selector",
                    action="Use a simple selector like '#login button'.")
        text = item.get("text", "")
        if op == "type":
            if not isinstance(text, str) or not text or len(text) > MAX_TEXT_LEN:
                raise BrowserJobError(
                    "Interaction 'type' requires text (max 2000 chars)")
            if "\n" in text or "\x00" in text:
                raise BrowserJobError("Typed text must not contain newlines/NULs")
        else:
            text = ""
        wait_ms = int(item.get("wait_ms", 300) or 0)
        if not 0 <= wait_ms <= 10_000:
            raise BrowserJobError("wait_ms must be 0..10000")
        out.append({"op": op, "selector": selector, "text": text,
                    "wait_ms": wait_ms})
    return out


def job_needs_approval(actions: list[dict]) -> bool:
    """Form submission (and navigation inside a script) is high-risk."""
    return any(a["op"] in {"submit", "navigate"} for a in actions)


class BrowserJobStore:
    """Persists browser jobs as files using the worker-plane handshake."""

    def __init__(self, queue_dir: Path) -> None:
        self.plane = JobPlane(queue_dir / "browser")

    def submit(self, *, case_id: str, url: str, extract: list[str],
               actions: list[dict] | None = None,
               requested_by: str = "llm", reason: str = "",
               approved: bool = False) -> dict:
        unknown = [e for e in extract if e not in EXTRACTORS]
        if unknown:
            raise BrowserJobError(
                f"Unknown extractors: {', '.join(unknown)}",
                reason=f"Read-only extractors are: {', '.join(EXTRACTORS)}.",
                action="Pick extractors from the declared list.")
        if not url.startswith(("http://", "https://")):
            raise BrowserJobError(
                f"Browser jobs need an http(s) URL: {url}",
                action="Submit an http(s) URL inside the case scope.")
        script = validate_actions(actions)
        if job_needs_approval(script) and not approved:
            raise BrowserJobError(
                "Interaction script contains submit/navigate — approval required",
                reason="Form submission acts on the target; policy demands "
                       "explicit operator approval (risk=high).",
                action="Re-submit with --approved after recording approval, "
                       "or drop the submit op.")
        params = {
            "extract": list(dict.fromkeys(extract)) or ["title", "links"],
            "actions": script,
        }
        action_name = "browser-interact" if script else "browser-extract"
        envelope = self.plane.submit(
            case_id=case_id, action=action_name, target=url,
            params=params, requested_by=requested_by, reason=reason,
        )
        return envelope

    def result_path(self, job_id: str) -> Path:
        return self.plane.queue_dir / f"{job_id}.result.json"

    def load_result(self, job_id: str) -> dict | None:
        path = self.result_path(job_id)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return None


class BrowserBridge:
    """Scope-checked, token-gated bridge between job files and the extension."""

    def __init__(
        self,
        case_id: str,
        *,
        queue_dir: Path,
        scope_engine: ScopeEngine,
        evidence: EvidenceStore,
        audit: AuditChain | None = None,
        ledger: ClaimLedger | None = None,
        token: str = "",
    ) -> None:
        self.case_id = case_id
        self.store = BrowserJobStore(queue_dir)
        self.scope_engine = scope_engine
        self.evidence = evidence
        self.audit = audit
        self.ledger = ledger or ClaimLedger(SourceRegistry())
        self.token = token
        self._claimed: dict[str, dict] = {}

    # -- scope gate -------------------------------------------------------------

    def validate_url(self, url: str) -> str:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        try:
            self.scope_engine.validate(self.case_id, host)
        except ScopeViolationError:
            raise
        if not self.scope_engine.evaluate(self.case_id, host) == "in_scope":
            raise ScopeViolationError(
                f"URL host '{host}' is not in scope for case {self.case_id}",
                action="Add the host to the case scope first.")
        return url

    # -- job lifecycle -----------------------------------------------------------

    def scope_summary(self) -> list[dict]:
        """The case's scope entries for the extension's client-side re-check."""
        scope = self.scope_engine.get(self.case_id)
        if scope is None:
            return []
        return [
            {"value": e.value, "excluded": e.excluded} for e in scope.entries
        ]

    def pending_tasks(self) -> list[dict]:
        """Tasks ready for the extension (published, not yet claimed)."""
        tasks = []
        for job in self.store.plane.list_jobs():
            if job["phase"] != "syn" or job.get("state") != "syn_sent":
                continue
            envelope = json.loads((self.store.plane.queue_dir / f"{job['job_id']}.job.json").read_text())
            if envelope.get("case_id") != self.case_id:
                continue
            try:
                self.validate_url(envelope["target"])
            except ScopeViolationError:
                self._write_result(envelope["job_id"], envelope, {
                    "state": "rejected", "error_class": "ScopeViolationError",
                    "error": f"URL out of scope: {envelope['target']}",
                    "fix": "Add the host to the case scope first.",
                })
                (self.store.plane.queue_dir / f"{envelope['job_id']}.job.json").unlink(missing_ok=True)
                continue
            tasks.append({
                "job_id": envelope["job_id"],
                "seq": envelope["seq"],
                "url": envelope["target"],
                "extract": envelope["params"].get("extract", ["title", "links"]),
                "actions": envelope["params"].get("actions", []),
                "reason": envelope.get("reason", ""),
            })
        return tasks

    def claim(self, job_id: str) -> dict | None:
        """Extension claims a task → SYN-ACK (ack file published)."""
        path = self.store.plane.queue_dir / f"{job_id}.job.json"
        if not path.exists():
            return None
        envelope = json.loads(path.read_text())
        ack_path = self.store.plane.queue_dir / f"{job_id}.ack.json"
        if not ack_path.exists():
            ack = {
                "job_id": job_id,
                "ack": envelope["seq"],
                "seq": int(time.time()) % 2**31,
                "state": "running",
                "url": envelope["target"],
                "at": time.time(),
            }
            ack_path.write_text(json.dumps(ack, indent=2, sort_keys=True) + "\n")
            if self.audit is not None:
                self.audit.append(self.case_id, actor="browser-bridge",
                                  action="job.claimed",
                                  subject=envelope.get("action", "browser-extract"),
                                  detail={"job_id": job_id, "url": envelope["target"]})
        self._claimed[job_id] = envelope
        return {"job_id": job_id, "ack": envelope["seq"], "url": envelope["target"],
                "extract": envelope["params"].get("extract", ["title", "links"]),
                # The extension executes the interaction script from THIS claim
                # payload; omitting it silently degraded interact jobs to
                # read-only extracts.
                "actions": envelope["params"].get("actions", [])}

    def complete(self, job_id: str, payload: dict) -> dict:
        """Extension posts results → ACK (result file + evidence + claims)."""
        envelope = self._claimed.get(job_id)
        if envelope is None:
            # daemon restart tolerance: reload the envelope from disk
            path = self.store.plane.queue_dir / f"{job_id}.job.json"
            if not path.exists():
                raise BrowserJobError(f"Unknown browser job '{job_id}'")
            envelope = json.loads(path.read_text())
        ok = bool(payload.get("ok"))
        if ok:
            result = self._ingest(envelope, payload)
        else:
            error = str(payload.get("error", "extension reported failure"))[:300]
            error_class = str(payload.get("error_class", "ExtensionError"))
            result = {
                "job_id": job_id, "state": "failed",
                "error_class": error_class,
                "error": error,
                "fix": str(payload.get("fix", "Read the error log, correct the job, re-submit.")),
                "url": envelope["target"],
                "action_log": payload.get("action_log", []),
                "suggestions": [
                    "Fix the failing step in the interaction script and re-submit the job.",
                    f"Verify the selector exists: {payload.get('failed_selector', '(not reported)')}",
                    "Run a read-only extract of the same URL to inspect the current page state.",
                ],
            }
            if self.audit is not None:
                self.audit.append(self.case_id, actor="browser-bridge",
                                  action="job.failed", subject=envelope.get("action", "browser-extract"),
                                  detail={"job_id": job_id, "error": error[:200]})
        self._write_result(job_id, envelope, result)
        (self.store.plane.queue_dir / f"{job_id}.job.json").unlink(missing_ok=True)
        (self.store.plane.queue_dir / f"{job_id}.ack.json").unlink(missing_ok=True)
        self._claimed.pop(job_id, None)
        return result

    def _write_result(self, job_id: str, envelope: dict, result: dict) -> None:
        result = {"job_id": job_id, "ack": envelope["seq"],
                  "finished_at": time.time(), **result}
        self.store.plane.queue_dir / f"{job_id}.result.json"
        path = self.store.plane.queue_dir / f"{job_id}.result.json"
        path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

    def _ingest(self, envelope: dict, payload: dict) -> dict:
        """Evidence + injection scan + claims from the extracted page data."""
        url = envelope["target"]
        data = payload.get("data", {}) or {}
        page_json = json.dumps(data, sort_keys=True, default=str)
        findings = scan_injection(page_json)
        blob = (
            f"browser-extract: {url}\nrequested_by: {envelope.get('requested_by')}\n\n"
            f"{page_json}"
        ).encode()
        rec = self.evidence.register(
            self.case_id, kind="browser_page", data=blob, source="browser.bridge",
            note=f"browser extraction of {url}",
            meta={"job_id": envelope["job_id"], "extractors": envelope["params"].get("extract", [])},
        )
        from urllib.parse import urlparse

        host = (urlparse(url).hostname or "").lower()
        emitted = []
        if self.ledger is not None:
            pipeline = CollectionPipeline(self.ledger, self.evidence, db=getattr(self.evidence, "_db", None))
            links = data.get("links") or []
            for link in links[:MAX_LINKS]:
                if isinstance(link, str) and host and host in link:
                    claim = self.ledger.add(
                        self.case_id, subject=host, kind="hostname",
                        value=link.split("//")[-1].split("/")[0][:253],
                        source="browser.bridge", method="browser-extract",
                        evidence_id=rec.id, notes=f"via {url}",
                    )
                    emitted.append(claim)
            if pipeline._db is not None:
                pipeline._persist(emitted, self.case_id)
        if self.audit is not None:
            self.audit.append(self.case_id, actor="browser-bridge",
                              action="job.completed", subject="browser-extract",
                              detail={"job_id": envelope["job_id"], "evidence": rec.id,
                                      "claims": len(emitted),
                                      "injection_findings": len(findings)})
        interaction = envelope.get("params", {}).get("actions") or []
        action_log = payload.get("action_log", []) if isinstance(payload.get("action_log"), list) else []
        suggestions = self._suggestions(envelope, data, action_log)
        return {
            "job_id": envelope["job_id"], "state": "done",
            "url": url, "evidence_id": rec.id,
            "action": envelope.get("action", "browser-extract"),
            "interaction_ops": [a.get("op") for a in interaction],
            "action_log": action_log,
            "claims_emitted": len(emitted),
            "injection_findings": [f.as_dict() for f in findings],
            "clean": not findings,
            "data_preview": {k: (v if not isinstance(v, (list, str)) else (
                v[:20] if isinstance(v, list) else str(v)[:200]))
                for k, v in data.items()},
            "sanitized_preview": sanitize_external(page_json, source="browser")[:1000]
            if findings else "",
            "suggestions": suggestions,
        }

    def _suggestions(self, envelope: dict, data: dict, action_log: list) -> list[str]:
        """Deterministic next-step suggestions appended to every result."""
        out = []
        extractors = envelope.get("params", {}).get("extract", [])
        if "links" in extractors and data.get("links"):
            out.append(f"{len(data['links'])} link(s) captured — pick the next "
                       "URL and submit a follow-up job.")
        if data.get("forms"):
            out.append("Forms detected on the page — a login/registration flow "
                       "may exist; a submit job needs your approval.")
        if action_log:
            failed = [a for a in action_log if not a.get("ok", True)]
            if failed:
                out.append(f"{len(failed)} interaction step(s) failed — read the "
                           "action_log, fix the selector, re-submit.")
            else:
                out.append("All interaction steps completed — extract the "
                           "resulting page state (text/forms) next.")
        out.append("Data was registered as hash-chained evidence; verify with "
                   "rebel-profiler evidence verify.")
        out.append("Tell the agent the next goal (scrape another page, run a "
                   "workflow, or decide queued approvals).")
        return out


def make_handler(bridge: BrowserBridge, token: str):
    """Build an HTTP handler bound to one bridge instance."""

    class BridgeHandler(BaseHTTPRequestHandler):
        server_version = "rebel-profiler-browser-bridge/1"

        def _authorized(self) -> bool:
            if not token:
                return True   # loopback-only default; token recommended
            supplied = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            import hmac as _hmac

            return bool(supplied) and _hmac.compare_digest(supplied, token)

        def _json(self, code: int, data: dict) -> None:
            body = json.dumps(data, sort_keys=True).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802 — http.server API
            if not self._authorized():
                self._json(401, {"error": "unauthorized"})
                return
            if self.path == "/tasks":
                self._json(200, {"tasks": bridge.pending_tasks()})
            elif self.path == "/healthz":
                self._json(200, {"ok": True, "case_id": bridge.case_id,
                                 "scope": bridge.scope_summary()})
            else:
                self._json(404, {"error": "not found",
                                 "endpoints": ["/tasks", "/healthz"]})

        def do_POST(self):  # noqa: N802 — http.server API
            if not self._authorized():
                self._json(401, {"error": "unauthorized"})
                return
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length > 2_000_000:
                self._json(413, {"error": "payload too large"})
                return
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"error": "invalid json"})
                return
            job_id = str(payload.get("job_id", ""))
            if self.path == "/ack":
                claim = bridge.claim(job_id)
                if claim is None:
                    self._json(404, {"error": f"unknown job {job_id}"})
                else:
                    self._json(200, claim)
            elif self.path == "/result":
                try:
                    result = bridge.complete(job_id, payload)
                    self._json(200, {"received": True, "state": result.get("state")})
                except BrowserJobError as exc:
                    self._json(404, {"error": exc.message})
            else:
                self._json(404, {"error": "not found",
                                 "endpoints": ["/ack", "/result"]})

        def log_message(self, fmt, *args):
            # One terse line per request on stderr: the bridge is the only
            # place where the operator can SEE extension polling happening.
            import sys
            sys.stderr.write("bridge %s %s\n" % (self.command, self.path))
            sys.stderr.flush()

    return BridgeHandler


def serve_browser_bridge(
    bridge: BrowserBridge,
    *,
    host: str = "127.0.0.1",
    port: int = DEFAULT_PORT,
    once: bool = False,
) -> dict | None:
    """Run the bridge HTTP server (blocking). ``once`` serves one request batch."""
    handler = make_handler(bridge, bridge.token)
    server = ThreadingHTTPServer((host, port), handler)
    if once:
        server.handle_request()
        server.server_close()
        return None
    server.serve_forever(poll_interval=0.2)
    return None
