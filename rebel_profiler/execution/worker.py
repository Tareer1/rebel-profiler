"""File-based worker plane: the persistent assistant/executor.

The LLM (and the operator) communicate with the machine through *job files*
using a three-way, TCP-style handshake — so the LLM can go quiet (freeing
RAM/GPU) while the daemon keeps working:

  1. **SYN**     — a client writes ``<job-id>.job.json`` (work envelope)
  2. **SYN-ACK** — the daemon validates the checksum, claims the job and
     writes ``<job-id>.ack.json`` (ack=<syn-seq>, state=running)
  3. **ACK**     — on completion the daemon writes ``<job-id>.result.json``
     (state=done/failed, exit, error log, evidence id)

Handshake rules, enforced mechanically:

  * a job file carries ``seq`` (client sequence) and ``checksum`` (SHA-256
    over the canonical JSON without the checksum field); a mismatched job is
    never claimed — a ``.reject.json`` states why,
  * a claimed job is acknowledged with the daemon's own ``seq``; the client
    treats ``ack.seq == syn.seq`` as the connection being established,
  * results are final: a re-delivered job id is answered from the result
    file (idempotent, like TCP retransmit → duplicate ACK),
  * every dispatch still passes the broker's six gates — the file plane is a
    transport, never an authorization path.

The daemon is a bounded poll loop (default every 5 s, ``--interval``)
designed to sit as a background process while the LLM stays unloaded; the
CLI writes job files and reads results, so the LLM only touches two small
files per action instead of holding a session open.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path

from ..core.errors import RPError, UsageError
from ..evidence.audit import AuditChain
from ..execution.broker import ActionRequest, ExecutionBroker

JOB_SUFFIX = ".job.json"
ACK_SUFFIX = ".ack.json"
RESULT_SUFFIX = ".result.json"
REJECT_SUFFIX = ".reject.json"

DEFAULT_INTERVAL = 5.0
MAX_PAYLOAD_BYTES = 64_000


def _sha256_canonical(data: dict) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class JobValidationError(RPError):
    exit_code = 2
    title = "Job envelope rejected"


class JobPlane:
    """Client side: write SYN job files, read ACK/result files."""

    def __init__(self, queue_dir: Path) -> None:
        self.queue_dir = Path(queue_dir)
        self.queue_dir.mkdir(parents=True, exist_ok=True)

    def submit(
        self,
        *,
        case_id: str,
        action: str,
        target: str,
        params: dict | None = None,
        requested_by: str = "llm",
        reason: str = "",
        seq: int | None = None,
    ) -> dict:
        """Write a SYN job envelope. Returns the envelope for the caller."""
        job_id = f"job_{uuid.uuid4().hex[:12]}"
        seq = seq if seq is not None else int(time.time() * 1000) % 2**31
        envelope = {
            "job_id": job_id,
            "seq": seq,
            "case_id": case_id,
            "action": action,
            "target": target,
            "params": params or {},
            "requested_by": requested_by,
            "reason": reason,
            "submitted_at": time.time(),
        }
        envelope["checksum"] = _sha256_canonical(
            {k: v for k, v in envelope.items() if k != "checksum"})
        path = self.queue_dir / f"{job_id}{JOB_SUFFIX}"
        path.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n")
        return envelope

    def _read_json(self, path: Path) -> dict | None:
        try:
            return json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return None

    def status(self, job_id: str) -> dict:
        """Client view: where is this job in the handshake?"""
        base = self.queue_dir / job_id
        result = self._read_json(base.with_suffix(RESULT_SUFFIX)) \
            if base.with_suffix(RESULT_SUFFIX).exists() else None
        if result is not None:
            return {"job_id": job_id, "state": result.get("state", "unknown"),
                    "phase": "ack", "result": result}
        for suffix, phase in ((ACK_SUFFIX, "syn_ack"), (REJECT_SUFFIX, "rejected")):
            data = self._read_json(Path(str(base) + suffix))
            if data is not None:
                return {"job_id": job_id, "state": data.get("state", phase),
                        "phase": phase, "detail": data}
        job = self._read_json(Path(str(base) + JOB_SUFFIX))
        if job is not None:
            return {"job_id": job_id, "state": "syn_sent", "phase": "syn",
                    "detail": job}
        raise JobValidationError(f"Unknown job '{job_id}'",
                                 action="List jobs with: rebel-profiler worker list")

    def list_jobs(self) -> list[dict]:
        out = []
        for path in sorted(self.queue_dir.glob(f"*{JOB_SUFFIX}")):
            data = self._read_json(path)
            if data:
                st = self.status(data["job_id"])
                out.append({"job_id": data["job_id"], "action": data.get("action"),
                            "target": data.get("target"),
                            "state": st["state"], "phase": st["phase"]})
        return out


class WorkerDaemon:
    """The executor side: poll → validate → SYN-ACK → run → ACK result."""

    def __init__(
        self,
        queue_dir: Path,
        *,
        broker: ExecutionBroker,
        audit: AuditChain | None = None,
        interval: float = DEFAULT_INTERVAL,
        max_runs: int | None = None,
        collect=None,
    ) -> None:
        self.queue_dir = Path(queue_dir)
        self.broker = broker
        self.audit = audit
        self.interval = max(1.0, float(interval))
        self.max_runs = max_runs
        self.collect = collect          # callable(case_id, result, params) → collection
        self._seq = int(time.time()) % 2**31

    # -- handshake helpers -----------------------------------------------------

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) % 2**31
        return self._seq

    def _write(self, path: Path, data: dict) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        tmp.replace(path)   # atomic publish — clients never see partial files

    def _validate(self, envelope: dict) -> None:
        if not isinstance(envelope, dict):
            raise JobValidationError("Job envelope is not an object")
        for field in ("job_id", "seq", "case_id", "action", "target"):
            if not envelope.get(field):
                raise JobValidationError(f"Job missing field '{field}'")
        checksum = envelope.get("checksum", "")
        expected = _sha256_canonical(
            {k: v for k, v in envelope.items() if k != "checksum"})
        if not hmac_compare(checksum, expected):
            raise JobValidationError(
                "Job checksum mismatch",
                reason="The envelope was modified after submission.",
                action="Re-submit the job; the daemon never executes tampered files.",
            )
        if envelope.get("requested_by") not in {"llm", "operator", "agent", "scheduler"}:
            raise JobValidationError(
                f"Untrusted requester '{envelope.get('requested_by')}'")

    def _reject(self, job_id: str, exc: JobValidationError) -> None:
        self._write(self.queue_dir / f"{job_id}{REJECT_SUFFIX}", {
            "job_id": job_id, "state": "rejected",
            "error": exc.message, "reason": exc.reason,
            "action_hint": exc.action, "at": time.time(),
        })

    def _ack(self, job_id: str, envelope: dict) -> int:
        seq = self._next_seq()
        self._write(self.queue_dir / f"{job_id}{ACK_SUFFIX}", {
            "job_id": job_id,
            "ack": envelope["seq"],      # the SYN being acknowledged
            "seq": seq,                  # daemon's own sequence
            "state": "running",
            "action": envelope["action"],
            "target": envelope["target"],
            "at": time.time(),
        })
        return seq

    # -- the loop -----------------------------------------------------------------

    def poll_once(self) -> list[dict]:
        """One bounded pass: claim, acknowledge and execute due job files."""
        handled: list[dict] = []
        for path in sorted(self.queue_dir.glob(f"*{JOB_SUFFIX}")):
            if self.max_runs is not None and len(handled) >= self.max_runs:
                break
            job_id = path.name[: -len(JOB_SUFFIX)]
            if (self.queue_dir / f"{job_id}{RESULT_SUFFIX}").exists() \
                    or (self.queue_dir / f"{job_id}{REJECT_SUFFIX}").exists():
                continue   # idempotent: result/reject already final
            try:
                envelope = json.loads(path.read_text())
                self._validate(envelope)
            except (OSError, json.JSONDecodeError) as exc:
                self._reject(job_id, JobValidationError(f"Unreadable job file: {exc}"))
                continue
            except JobValidationError as exc:
                self._reject(job_id, exc)
                continue
            self._ack(job_id, envelope)
            outcome = self._execute(envelope)
            self._write(self.queue_dir / f"{job_id}{RESULT_SUFFIX}", outcome)
            if self.audit is not None:
                self.audit.append(envelope["case_id"], actor="worker",
                                  action="job.completed",
                                  subject=envelope["action"],
                                  detail={"job_id": job_id,
                                          "state": outcome["state"],
                                          "task_id": outcome.get("task_id", "")})
            handled.append({"job_id": job_id, "state": outcome["state"]})
            path.unlink(missing_ok=True)   # SYN consumed; ack+result remain
        return handled

    def run_forever(self, *, once: bool = False) -> None:
        """Bounded poll loop. ``once`` runs a single pass (tests/CI)."""
        while True:
            self.poll_once()
            if once:
                return
            time.sleep(self.interval)

    # -- execution ------------------------------------------------------------------

    def _execute(self, envelope: dict) -> dict:
        case_id = envelope["case_id"]
        params = envelope.get("params") or {}
        try:
            adapter = self.broker.adapters.get(envelope["action"])
            if adapter is None:
                raise UsageError(
                    f"No adapter for action '{envelope['action']}'",
                    action=f"Available: {', '.join(self.broker.adapters.names())}")
            request = ActionRequest(
                case_id=case_id,
                capability=adapter.capability_class,
                action=envelope["action"], target=envelope["target"],
                params=params, requested_by=envelope.get("requested_by", "llm"),
                reason=envelope.get("reason", ""),
            )
            result = self.broker.execute(request)
            outcome = {
                "job_id": envelope["job_id"],
                "state": result.outcome,
                "ack": envelope["seq"],
                "task_id": result.task_id,
                "evidence_id": result.evidence_id or "",
                "returncode": result.returncode,
                "stdout_preview": result.stdout[:400],
                "stderr_preview": result.stderr[:400],
                "policy": result.decision.outcome.value,
                "risk": result.decision.risk.level,
                "finished_at": time.time(),
            }
            if self.collect is not None and result.outcome == "succeeded":
                try:
                    collection = self.collect(case_id, result, params)
                    outcome["claims_emitted"] = len(collection.get("claims_emitted", []))
                    outcome["clean"] = collection.get("clean", True)
                except RPError as exc:
                    outcome["collection_error"] = exc.message
            return outcome
        except RPError as exc:
            return {
                "job_id": envelope["job_id"], "state": "failed",
                "ack": envelope["seq"], "error_class": type(exc).__name__,
                "exit_code": exc.exit_code,
                "error": exc.message, "reason": exc.reason, "fix": exc.action,
                "finished_at": time.time(),
            }


def hmac_compare(a: str, b: str) -> bool:
    """Constant-time string comparison for checksums/tags."""
    import hmac as _hmac

    return _hmac.compare_digest(str(a).encode(), str(b).encode())
