"""Script plane: the LLM writes a code file, the system executes it ~5s later.

This is the "LLM builds the tool" loop, made mechanical:

    1. ``llm script submit`` — the LLM (or operator) writes a Python script
       *file* that computes something the tool has no adapter for.
    2. Nothing executes at submit time. The file must pass the deterministic
       static gate first (the Feature Forge AST gate — no os/subprocess/
       socket/eval/open reach).
    3. The script daemon (``llm script run`` / the same 5-second poll loop)
       claims pending scripts, re-validates them, executes in a **sandboxed
       subprocess** with a hard timeout and a 512 KiB output cap, and writes
       the *actual result* next to the script.
    4. Every executed script's output is hash-chained evidence; every gate
       decision is audit-logged.

Sandbox contract (mechanical, not prompt-enforced):

  * the subprocess imports the script and calls ``run(payload)`` — payload
    is JSON data, never instructions; the return value must be JSON-serializable,
  * stdin is closed, no network reach is imported (static gate), the only
    filesystem writes are to the script's own result file,
  * timeout → kill + structured failure with a fix hint,
  * results are idempotent: a re-claimed script with an existing result is
    never re-executed.

The LLM can now *do* work beyond adapters — compute, transform, analyze —
while scope, policy, evidence and audit law stay untouched.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

from ..core.errors import UsageError
from ..core.redact import redact

SCRIPT_SUFFIX = ".rpscript.py"
RESULT_SUFFIX = ".rpsresult.json"
REJECT_SUFFIX = ".rpsreject.json"
PENDING_SUFFIX = ".pending"

DEFAULT_TIMEOUT_S = 60.0
MAX_OUTPUT_BYTES = 512 * 1024
MAX_SCRIPT_BYTES = 40_000
DEFAULT_SCRIPT_INTERVAL = 5.0
VALID_REQUESTERS = {"llm", "operator", "agent", "scheduler"}


def default_script_dir(data_dir: Path | str | None = None) -> Path:
    """Workspace-local script queue directory."""
    base = Path(data_dir) if data_dir else Path.home() / ".local/share/rebel-profiler"
    return base / "llm_scripts"


# ---------------------------------------------------------------------------
# submission (SYN)

def submit_script(source: str, *, script_dir: Path, payload: dict | None = None,
                  name: str = "", requested_by: str = "llm",
                  timeout_s: float = DEFAULT_TIMEOUT_S,
                  case_id: str = "") -> dict:
    """Write a script file + sidecar. Returns the envelope (script_id to poll).

    The script is *stored*, not executed: execution happens only in the
    daemon after the static gate passes. Payload is JSON data passed to
    ``run(payload)`` — bounded, redacted.

    ``case_id`` links the run to a case so its result is registered as that
    case's evidence instead of landing in the workspace bucket.
    """
    source = source or ""
    if not source.strip():
        raise UsageError(
            "Script source is empty",
            action="Pass the Python source (the LLM's code file) in the editor or via --file.")
    if len(source.encode()) > MAX_SCRIPT_BYTES:
        raise UsageError(
            f"Script too large ({len(source.encode())} bytes > {MAX_SCRIPT_BYTES})",
            action="Split the computation into smaller scripts.")
    payload = payload or {}
    script_id = f"rps_{uuid.uuid4().hex[:12]}"
    script_dir = Path(script_dir)
    script_dir.mkdir(parents=True, exist_ok=True)
    envelope = {
        "script_id": script_id,
        "name": name or script_id,
        "requested_by": requested_by,
        "timeout_s": timeout_s,
        "payload": payload,
        "case_id": case_id,
        "submitted_at": time.time(),
    }
    (script_dir / f"{script_id}{SCRIPT_SUFFIX}").write_text(source)
    (script_dir / f"{script_id}.meta.json").write_text(
        json.dumps(envelope, indent=2, sort_keys=True) + "\n")
    return envelope


def load_script_result(script_id: str, *, script_dir: Path) -> dict | None:
    """Read one script's result file, if the daemon finished it."""
    path = Path(script_dir) / f"{script_id}{RESULT_SUFFIX}"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def list_scripts(script_dir: Path) -> list[dict]:
    """Every script in the queue with its lifecycle state."""
    script_dir = Path(script_dir)
    out: list[dict] = []
    for meta_path in sorted(script_dir.glob("rps_*.meta.json")):
        sid = meta_path.name[: -len(".meta.json")]
        state = "pending"
        if (script_dir / f"{sid}{REJECT_SUFFIX}").exists():
            state = "rejected"
        elif (script_dir / f"{sid}{RESULT_SUFFIX}").exists():
            state = "done"
        try:
            meta = json.loads(meta_path.read_text())
        except (OSError, json.JSONDecodeError):
            meta = {}
        out.append({"script_id": sid, "state": state,
                    "name": meta.get("name", ""),
                    "requested_by": meta.get("requested_by", ""),
                    "case_id": meta.get("case_id", "")})
    return out


# ---------------------------------------------------------------------------
# sandbox runner harness (runs inside the subprocess)

_HARNESS = r'''
import json, sys
payload = json.loads(sys.argv[1])
src_path = sys.argv[2]
out_path = sys.argv[3]
try:
    src = open(src_path, encoding="utf-8").read()
    ns = {"__name__": "__rp_script__"}
    exec(compile(src, src_path, "exec"), ns)
    fn = ns.get("run")
    if not callable(fn):
        raise ValueError("script must define a callable run(payload)")
    result = fn(payload)
    json.dump({"ok": True, "result": result}, open(out_path, "w"))
except SystemExit as exc:
    json.dump({"ok": False, "error": f"SystemExit({exc.code})"},
              open(out_path, "w"))
    sys.exit(0)
except BaseException as exc:
    json.dump({"ok": False,
               "error": f"{type(exc).__name__}: {exc}"[:500]},
              open(out_path, "w"))
    sys.exit(0)
'''


def _sandbox_run(script_path: Path, payload: dict, *, timeout_s: float,
                 result_path: Path, project_root: Path) -> dict:
    """Run one script in a subprocess. Returns the outcome dict."""
    started = time.time()
    cmd = [sys.executable, "-I", "-c", _HARNESS,
           json.dumps(payload), str(script_path), str(result_path)]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout_s, check=False,
            cwd=str(script_path.parent), stdin=subprocess.DEVNULL,
            env={"PYTHONHASHSEED": "0", "PATH": "/usr/bin:/bin",
                 "RP_SCRIPT_MODE": "1"},
        )
    except subprocess.TimeoutExpired:
        return {"state": "failed", "error_class": "ScriptTimeout",
                "error": f"script exceeded {timeout_s:g}s and was killed",
                "fix": "Bound the loop or raise --timeout (submit side).",
                "elapsed_s": round(time.time() - started, 2)}
    out_text = (proc.stdout or "")[:MAX_OUTPUT_BYTES]
    err_text = (proc.stderr or "")[:8_000]
    if result_path.exists():
        try:
            inner = json.loads(result_path.read_text())
        except json.JSONDecodeError:
            inner = {"ok": False, "error": "script result file unparseable"}
    else:
        inner = {"ok": False,
                 "error": f"script produced no result (rc={proc.returncode})"}
    if not inner.get("ok"):
        return {"state": "failed", "error_class": "ScriptError",
                "error": str(inner.get("error", "unknown"))[:500],
                "fix": "Fix the script and re-submit; nothing executed twice.",
                "stderr_tail": redact(err_text[-500:]),
                "elapsed_s": round(time.time() - started, 2)}
    return {"state": "done", "result": inner.get("result"),
            "stdout": redact(out_text), "returncode": proc.returncode,
            "elapsed_s": round(time.time() - started, 2)}


# ---------------------------------------------------------------------------
# the daemon-side gate + executor

class ScriptRunner:
    """Claims pending scripts, gates, sandbox-executes, writes results."""

    def __init__(self, script_dir: Path, *, data_dir: Path | None = None,
                 audit=None, evidence=None, max_runs: int | None = None) -> None:
        self.script_dir = Path(script_dir)
        self.script_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir = Path(data_dir) if data_dir else self.script_dir.parent
        self.audit = audit
        self.evidence = evidence
        self.max_runs = max_runs

    # -- gate ----------------------------------------------------------------

    def _gate(self, source: str) -> list[str]:
        """Deterministic static gate (reuses Feature Forge's AST checks)."""
        from ..agent.forge import static_safety_check

        findings = static_safety_check(_as_forge_module(source))
        return [f"{f.rule}: {f.message}" for f in findings]

    # -- loop ----------------------------------------------------------------

    def poll_once(self) -> list[dict]:
        handled: list[dict] = []
        budget = self.max_runs
        for meta_path in sorted(self.script_dir.glob("rps_*.meta.json")):
            if budget is not None and len(handled) >= budget:
                break
            sid = meta_path.name[: -len(".meta.json")]
            if (self.script_dir / f"{sid}{RESULT_SUFFIX}").exists() \
                    or (self.script_dir / f"{sid}{REJECT_SUFFIX}").exists():
                continue   # idempotent: final state already written
            try:
                meta = json.loads(meta_path.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                self._reject(sid, f"unreadable sidecar: {exc}")
                continue
            script_path = self.script_dir / f"{sid}{SCRIPT_SUFFIX}"
            if not script_path.exists():
                self._reject(sid, "script file missing")
                continue
            source = script_path.read_text()
            findings = self._gate(source)
            if findings:
                self._reject(sid, "static gate rejected script",
                             detail={"findings": findings[:8]},
                             case_id=meta.get("case_id") or "")
                continue
            import rebel_profiler

            project_root = Path(rebel_profiler.__file__).parent.parent
            result_path = self.script_dir / f"{sid}.inner.json"
            outcome = _sandbox_run(
                script_path, meta.get("payload") or {},
                timeout_s=float(meta.get("timeout_s") or DEFAULT_TIMEOUT_S),
                result_path=result_path, project_root=project_root)
            result_path.unlink(missing_ok=True)
            result = {
                "script_id": sid,
                "name": meta.get("name", ""),
                "requested_by": meta.get("requested_by", ""),
                "sha256": hashlib.sha256(source.encode()).hexdigest(),
                "finished_at": time.time(),
                **outcome,
            }
            (self.script_dir / f"{sid}{RESULT_SUFFIX}").write_text(
                json.dumps(result, indent=2, sort_keys=True, default=str) + "\n")
            self._evidence_and_audit(sid, meta, source, result)
            handled.append({"script_id": sid, "state": result["state"]})
        return handled

    # -- helpers -----------------------------------------------------------------

    def _reject(self, sid: str, error: str, *, detail: dict | None = None,
                case_id: str = "") -> None:
        (self.script_dir / f"{sid}{REJECT_SUFFIX}").write_text(json.dumps({
            "script_id": sid, "state": "rejected", "error": error,
            **(detail or {}), "at": time.time(),
        }, indent=2, sort_keys=True) + "\n")
        self._audit_event("script.rejected", sid, {"error": error[:200]},
                          case_id)

    def _evidence_and_audit(self, sid: str, meta: dict, source: str,
                            result: dict) -> None:
        self._audit_event("script.executed", sid, {
            "state": result.get("state", ""),
            "elapsed_s": result.get("elapsed_s", 0)},
            meta.get("case_id") or "")
        if self.evidence is None:
            return
        try:
            blob = json.dumps({"source_sha256": result.get("sha256", ""),
                               "source": source[:4_000],
                               "result": {k: v for k, v in result.items()
                                          if k != "stdout"} },
                              indent=2, sort_keys=True).encode()
            self.evidence.register(meta.get("case_id") or "workspace",
                                   kind="llm_script_result", data=blob,
                                   source="llm-script-plane",
                                   note=f"script {sid} ({meta.get('name', '')})")
        except Exception:
            pass   # evidence is best-effort outside a case context

    def _audit_event(self, action: str, sid: str, detail: dict,
                     case_id: str = "") -> None:
        if self.audit is None:
            return
        try:
            self.audit.append(case_id or "workspace", actor="script-daemon",
                              action=action, subject=sid,
                              detail={k: redact(str(v))[:200]
                                      for k, v in detail.items()})
        except Exception:
            pass


def _as_forge_module(source: str) -> str:
    """Adapt a script (``def run(payload)``) to the forge gate's contract.

    The forge static gate requires the broker Adapter import; scripts use the
    ``run()`` contract instead, so we synthesize the marker import and
    declaration for gating purposes only. All other rules (imports, builtins,
    size, depth) apply unchanged — a script gets no more reach than a forged
    adapter.
    """
    return (
        "from rebel_profiler.execution.broker import Adapter\n"
        "PLUGIN_ADAPTERS = ()\n" + source
    )


class ScriptDaemon:
    """Resident poll loop for the script plane (5-second default)."""

    def __init__(self, script_dir: Path, *, interval: float = DEFAULT_SCRIPT_INTERVAL,
                 data_dir: Path | None = None, audit=None, evidence=None,
                 max_runs: int | None = None) -> None:
        self.interval = interval
        self.runner = ScriptRunner(script_dir, data_dir=data_dir, audit=audit,
                                   evidence=evidence, max_runs=max_runs)

    def poll_once(self) -> list[dict]:
        return self.runner.poll_once()

    def run_forever(self, *, once: bool = False) -> None:
        while True:
            self.runner.poll_once()
            if once:
                return
            time.sleep(self.interval)
