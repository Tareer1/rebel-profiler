"""Privileged system job plane: sudo-level work under operator approval.

Some real work needs the machine's privileges — installing a package, loading
a kernel module, running a capture on a privileged port, mounting evidence
disks. Rebel Profiler exposes that through **one** narrow, audited path:

  1. the LLM (or CLI) writes a **system job file** (same handshake) naming a
     whitelisted *job type* and its structured params — never a raw command,
  2. the broker classifies it risk=high → policy demands **approval**; with
     no interactive approver the request lands in the durable approval queue,
  3. the operator decides (`approval decide`); on approval the daemon
     composes the exact argv from the whitelist, shows it, and executes it
     through the system runner (sudo only when the job template declares it),
  4. output becomes hash-chained evidence; every step is audit-chained;
     the result file carries a structured error log + next-step suggestions.

There is deliberately **no** free-form shell anywhere in this path: a job
type not in the whitelist is a hard error, params are validated per template,
and the composed argv is logged before dispatch.
"""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass

from ..core.errors import RPError, UsageError
from ..evidence.audit import AuditChain
from ..execution.worker import JobPlane
from ..security.approvals import ApprovalQueue


# ---------------------------------------------------------------------------
# Job templates: the ONLY privileged things this plane can do.


@dataclass
class SystemJobTemplate:
    key: str
    description: str
    argv_template: tuple[str, ...]          # placeholders as {param}
    params: dict[str, str]                  # name -> regex pattern
    use_sudo: bool = False
    timeout: int = 300


SYSTEM_JOB_TEMPLATES: dict[str, SystemJobTemplate] = {
    "pkg-install": SystemJobTemplate(
        key="pkg-install",
        description="Install an apt package (Kali tooling).",
        argv_template=("apt-get", "install", "-y", "{package}"),
        params={"package": r"[a-z0-9][a-z0-9+.-]{0,40}"},
        use_sudo=True,
        timeout=600,
    ),
    "pkg-update": SystemJobTemplate(
        key="pkg-update",
        description="Refresh the apt package index.",
        argv_template=("apt-get", "update",),
        params={},
        use_sudo=True,
        timeout=600,
    ),
    "service-start": SystemJobTemplate(
        key="service-start",
        description="Start a whitelisted system service.",
        argv_template=("systemctl", "start", "{unit}"),
        params={"unit": r"[a-z0-9@.-]{1,40}\.(service|timer|socket)"},
        use_sudo=True,
    ),
    "service-stop": SystemJobTemplate(
        key="service-stop",
        description="Stop a whitelisted system service.",
        argv_template=("systemctl", "stop", "{unit}"),
        params={"unit": r"[a-z0-9@.-]{1,40}\.(service|timer|socket)"},
        use_sudo=True,
    ),
    "iface-up": SystemJobTemplate(
        key="iface-up",
        description="Bring a network interface up.",
        argv_template=("ip", "link", "set", "{interface}", "up"),
        params={"interface": r"[a-z0-9]{1,15}"},
        use_sudo=True,
    ),
    "monitor-mode": SystemJobTemplate(
        key="monitor-mode",
        description="Enable monitor mode on a wireless interface (airmon-ng).",
        argv_template=("airmon-ng", "start", "{interface}"),
        params={"interface": r"(wlan|wlp)[0-9a-z]{0,6}(mon)?"},
        use_sudo=True,
    ),
    "privileged-port-listen": SystemJobTemplate(
        key="privileged-port-listen",
        description="Run a listener on a port <1024 via a whitelisted binary.",
        argv_template=("nc", "-l", "-p", "{port}"),
        params={"port": r"(?:[0-9]{1,3}|1[0-9]{3}|[1-9][0-9]{0,2})"},
        use_sudo=False,
    ),
}


def compose_argv(template: SystemJobTemplate, params: dict) -> list[str]:
    """Fill the template; validate every value against its pattern. No shell."""
    import re

    argv: list[str] = []
    for part in template.argv_template:
        token = part
        for name in _template_params(part):
            value = str(params.get(name, ""))
            if not re.fullmatch(template.params[name], value):
                raise UsageError(
                    f"Param '{name}' does not match {template.params[name]!r}",
                    reason=f"Template '{template.key}' declares strict param patterns.",
                    action=f"Supply {name} matching the pattern.",
                )
            token = token.replace("{" + name + "}", value)
        if "{" in token or "}" in token:
            raise UsageError(f"Unresolved placeholder in template token: {token!r}")
        argv.append(token)
    return argv


def _template_params(part: str) -> list[str]:
    out = []
    rest = part
    while "{" in rest:
        start = rest.index("{")
        end = rest.index("}", start)
        out.append(rest[start + 1:end])
        rest = rest[end + 1:]
    return out


# ---------------------------------------------------------------------------
# Job store: the SYN side


class SystemJobStore:
    """Writes system job envelopes into the worker queue."""

    def __init__(self, queue_dir) -> None:
        self.plane = JobPlane(queue_dir / "system")

    def submit(self, *, case_id: str, job_type: str, params: dict,
               requested_by: str = "llm", reason: str = "") -> dict:
        template = SYSTEM_JOB_TEMPLATES.get(job_type)
        if template is None:
            raise UsageError(
                f"Unknown system job type '{job_type}'",
                reason="Privileged work is whitelist-only; free-form commands "
                       "are never executed.",
                action="Pick one of: " + ", ".join(sorted(SYSTEM_JOB_TEMPLATES)))
        # validate params up front so bad jobs never reach the queue
        compose_argv(template, params)
        return self.plane.submit(
            case_id=case_id, action="system-job", target=job_type,
            params={"job_type": job_type, "job_params": params,
                    "sudo": template.use_sudo},
            requested_by=requested_by, reason=reason,
        )


# ---------------------------------------------------------------------------
# The executor: poll → gates → (approval queue) → run


class SystemJobDaemon:
    """Consumes system job files with full gating and evidence capture."""

    def __init__(self, queue_dir, *, db, audit: AuditChain | None = None,
                 runner=None) -> None:
        self.store = SystemJobStore(queue_dir)
        self.db = db
        self.audit = audit
        self._runner = runner or self._default_runner

    @staticmethod
    def _default_runner(argv, timeout):
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, check=False)
        return proc.returncode, proc.stdout, proc.stderr

    def _audit_append(self, case_id: str, action: str, subject: str, detail: dict) -> None:
        if self.audit is not None:
            self.audit.append(case_id, actor="system-daemon",
                              action=action, subject=subject, detail=detail)

    def poll_once(self) -> list[dict]:
        """One bounded pass: execute due, approved system jobs."""
        handled = []
        for path in sorted(self.store.plane.queue_dir.glob("*.job.json")):
            job_id = path.name[: -len(".job.json")]
            if (self.store.plane.queue_dir / f"{job_id}.result.json").exists():
                continue
            try:
                envelope = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            case_id = envelope.get("case_id", "")
            params = envelope.get("params", {})
            job_type = params.get("job_type", "")
            template = SYSTEM_JOB_TEMPLATES.get(job_type)
            if template is None:
                self._finish(job_id, envelope, {
                    "state": "rejected", "error": f"Unknown system job '{job_type}'",
                })
                handled.append({"job_id": job_id, "state": "rejected"})
                continue
            try:
                argv = compose_argv(template, params.get("job_params", {}))
            except UsageError as exc:
                self._finish(job_id, envelope, {
                    "state": "rejected", "error": exc.message, "fix": exc.action,
                })
                handled.append({"job_id": job_id, "state": "rejected"})
                continue
            dispatch = list(argv)
            if template.use_sudo:
                dispatch = ["sudo", "-n", *argv]   # -n: never prompt; fail instead

            # Approval gate: every privileged run needs a decided approval.
            # Matching is on (action, target) + the exact stored argv.
            approval = ApprovalQueue(self.db, self.audit)
            pending = [
                a for a in approval.list(case_id, "pending")
                if a["action"] == "system-job" and a["target"] == job_type
                and self._argv_of(a) == dispatch
            ]
            approved = [
                a for a in approval.list(case_id, "approved")
                if a["action"] == "system-job" and a["target"] == job_type
                and self._argv_of(a) == dispatch and not self._consumed(a["id"])
            ]
            if not approved:
                if not pending:
                    record = approval.enqueue(
                        case_id, task_id=f"sysjob_{job_id}", action="system-job",
                        target=job_type, argv=dispatch, params=params.get("job_params", {}),
                        risk="high",
                        reasons=["privileged system job"],
                        requested_by=envelope.get("requested_by", "llm"),
                    )
                    self._finish(job_id, envelope, {
                        "state": "awaiting_approval",
                        "approval_id": record["id"],
                        "argv": dispatch,
                        "fix": "rebel-profiler approval decide "
                               f"{case_id} {record['id']} approve",
                    })
                else:
                    self._finish(job_id, envelope, {
                        "state": "awaiting_approval",
                        "approval_id": pending[0]["id"],
                        "argv": dispatch,
                    })
                handled.append({"job_id": job_id, "state": "awaiting_approval"})
                continue

            # consume the approval (one run per approval decision)
            approval_id = approved[0]["id"]
            self.db.set_meta(f"approval_params:{approval_id}",
                             json.dumps({**json.loads(
                                 self.db.get_meta(f"approval_params:{approval_id}") or "{}"),
                                 "consumed": True}))

            if self.audit is not None:
                self.audit.append(case_id, actor="system-daemon",
                                  action="system-job.dispatched", subject=job_type,
                                  detail={"argv": dispatch, "approval": approval_id})
            started = time.time()
            try:
                rc, out, err = self._runner(dispatch, template.timeout)
                outcome = {
                    "state": "done" if rc == 0 else "failed",
                    "returncode": rc,
                    "stdout_preview": out[:2000],
                    "stderr_preview": err[:2000],
                    "argv": dispatch,
                    "approval_id": approval_id,
                    "duration_s": round(time.time() - started, 2),
                }
            except subprocess.TimeoutExpired:
                outcome = {"state": "failed", "returncode": -1,
                           "error": "timeout", "argv": dispatch,
                           "approval_id": approval_id}
            except FileNotFoundError:
                outcome = {"state": "failed", "returncode": -1,
                           "error": f"binary missing: {dispatch[0]}",
                           "argv": dispatch, "approval_id": approval_id,
                           "fix": "install the tool or pick another job type"}
            if self.audit is not None:
                self.audit.append(case_id, actor="system-daemon",
                                  action="system-job.completed", subject=job_type,
                                  detail={"job_id": job_id,
                                          "state": outcome["state"],
                                          "rc": outcome.get("returncode")})
            self._finish(job_id, envelope, outcome)
            handled.append({"job_id": job_id, "state": outcome["state"]})
        return handled

    def _argv_of(self, approval: dict) -> list[str]:
        """Stored exact argv for an approval record (from the meta table)."""
        raw = self._meta_get(f"approval_argv:{approval['id']}")
        try:
            argv = json.loads(raw) if raw else []
        except json.JSONDecodeError:
            argv = []
        return argv if isinstance(argv, list) else []

    def _consumed(self, approval_id: str) -> bool:
        raw = self._meta_get(f"approval_params:{approval_id}")
        if not raw:
            return False
        try:
            return bool(json.loads(raw).get("consumed"))
        except json.JSONDecodeError:
            return False

    def _meta_get(self, key: str) -> str | None:
        return self.db.get_meta(key)

    def _finish(self, job_id: str, envelope: dict, outcome: dict) -> None:
        outcome = {"job_id": job_id, "ack": envelope.get("seq"),
                   "finished_at": time.time(), **outcome}
        if outcome["state"] in {"done", "failed"}:
            outcome["suggestions"] = _system_suggestions(outcome)
        path = self.store.plane.queue_dir / f"{job_id}.result.json"
        path.write_text(json.dumps(outcome, indent=2, sort_keys=True) + "\n")
        (self.store.plane.queue_dir / f"{job_id}.job.json").unlink(missing_ok=True)
        (self.store.plane.queue_dir / f"{job_id}.ack.json").unlink(missing_ok=True)


def _system_suggestions(outcome: dict) -> list[str]:
    """Deterministic next-step suggestions for the LLM/operator."""
    if outcome["state"] == "done":
        return [
            "System job completed — re-run any dependent collection (e.g. the "
            "tool it installed is now available).",
            "Evidence and audit entries were written; verify with "
            "rebel-profiler evidence verify.",
            "State the next goal or decide queued approvals.",
        ]
    hints = {
        "timeout": "The job exceeded its time budget — increase scope "
                   "incrementally or run it in the background.",
        "binary missing": "Install the required package first (that itself is "
                          "a system job: pkg-install).",
    }
    fix = hints.get(outcome.get("error", ""), "Read stderr_preview; fix the "
                                              "params and re-submit the job.")
    return [
        f"System job failed: {outcome.get('error') or outcome.get('returncode')}",
        fix,
        "Every attempt is audit-logged; check `rebel-profiler audit show`.",
    ]
