"""Workflow DSL + task DAG engine with approval gates and checkpoints (PDF 14).

A workflow is a step DAG written in a small, human-writable DSL::

    workflow "external footprint" {
      step dns     action passive-dns target=example.com param record_type=A
      step whois   action whois-lookup target=example.com
      step report  needs=dns,whois
    }

Grammar (line-oriented, order-free except for readability):

  * ``workflow "<name>" {``          — opens the workflow block
  * ``}``                            — closes it
  * ``step <key> action <action> target=<t>`` — an execution step; the
    broker's six gates decide every execution
  * ``param <k>=<v>``                — attaches a declared param to the
    most recent step (repeatable; values coerced bool/int/str)
  * ``needs=a,b``                    — dependencies on earlier step keys;
    cycles are rejected at parse time
  * ``approval``                     — a human checkpoint step: the run
    pauses until an authorized subject approves it by key
  * ``#`` / ``//`` comments and blank lines are ignored

Execution model:

  * steps run only when all dependencies succeeded (topological readiness),
  * execution steps go through the same broker as everything else — policy
    denials fail the step (or park it awaiting approval, when the broker
    queues one),
  * every completed step is a checkpoint: a crashed or paused run resumes
    from the persisted step states, never re-running finished work,
  * the whole run is audit-logged; the run report is machine-readable.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field

from ..core.errors import UsageError, WorkflowError
from ..evidence.audit import AuditChain


# ---------------------------------------------------------------------------
# Model


@dataclass
class Step:
    key: str
    kind: str = "action"          # action | approval
    action: str = ""
    target: str = ""
    params: dict = field(default_factory=dict)
    needs: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "key": self.key, "kind": self.kind, "action": self.action,
            "target": self.target, "params": dict(self.params),
            "needs": list(self.needs),
        }


@dataclass
class WorkflowSpec:
    name: str
    steps: list[Step]

    def as_dict(self) -> dict:
        return {"name": self.name, "steps": [s.as_dict() for s in self.steps]}


# ---------------------------------------------------------------------------
# DSL parser


_STEP_RE = re.compile(r"^step\s+([A-Za-z0-9_-]{1,40})(?:\s+(.*))?$")
_ACTION_RE = re.compile(r"^action\s+([A-Za-z0-9_-]{1,64})\s*$")
_TARGET_RE = re.compile(r"^target=(\S{1,200})$")
_PARAM_RE = re.compile(r"^param\s+([A-Za-z0-9_-]{1,40})\s*=\s*(\S{1,200})$")
_NEEDS_RE = re.compile(r"^needs=([A-Za-z0-9_,-]{1,200})$")
_APPROVAL_RE = re.compile(r"^approval(?:\s+([A-Za-z0-9_-]{1,40}))?(?:\s+(.*))?$")
_KV_RE = re.compile(r"^([A-Za-z0-9_-]{1,40})=(\S{1,200})")
_INLINE_KV_RE = re.compile(r"^(action|target|needs)\s+(\S{1,200})")
_INLINE_APPROVAL_RE = re.compile(r"^approval(?=\s|$)")


def _match_inline_kv(rest: str):
    """Match one inline attribute: `key=value`, `action|target|needs <v>`, or `approval`."""
    m = _KV_RE.match(rest)
    if m:
        return m, rest[m.end():].strip()
    m = _INLINE_KV_RE.match(rest)
    if m:
        return m, rest[m.end():].strip()
    m = _INLINE_APPROVAL_RE.match(rest)
    if m:
        # mark kind via a sentinel pseudo-match consumed below
        class _M:
            def group(self, i):
                return ("kind", "approval")[i - 1]
            end = m.end()
        return _M(), rest[m.end():].strip()
    return None, rest


def _coerce(value: str):
    low = value.lower()
    if low in {"true", "false"}:
        return low == "true"
    try:
        return int(value)
    except ValueError:
        return value


def parse_workflow(text: str) -> WorkflowSpec:
    """Parse the DSL into a WorkflowSpec; reject cycles and unknown syntax."""
    name = ""
    steps: list[Step] = []
    current: Step | None = None
    opened = False

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if not opened:
            match = re.match(r'^workflow\s+"([^"]{1,80})"\s*\{$', line)
            if not match:
                raise WorkflowError(
                    f"Line {lineno}: expected 'workflow \"name\" {{'",
                    reason=f"Got: {line[:80]}",
                    action="Start the workflow with: workflow \"name\" {",
                )
            name = match.group(1)
            opened = True
            continue
        if line == "}":
            break
        match = _STEP_RE.match(line)
        if match:
            current = Step(key=match.group(1))
            steps.append(current)
            # allow inline attributes on the step line: `step k action a target=t needs=x`
            rest = (match.group(2) or "").strip()
            while rest:
                inline, rest = _match_inline_kv(rest)
                if not inline:
                    raise WorkflowError(
                        f"Line {lineno}: bad inline attribute '{rest[:60]}'",
                        action="Use action=<name>, target=<t>, needs=<keys> or param k=v.")
                key, value = inline.group(1), inline.group(2)
                if key == "kind":
                    current.kind = value
                elif key == "action":
                    current.action = value
                elif key == "target":
                    current.target = value
                elif key == "needs":
                    current.needs = [d for d in value.split(",") if d]
                else:
                    current.params[key] = _coerce(value)
            continue
        if line.startswith("param ") and current is not None:
            # continuation params for the most recent step (also parsed below
            # when no step line consumed them inline)
            m = _PARAM_RE.match(line)
            if not m:
                raise WorkflowError(f"Line {lineno}: malformed param")
            current.params[m.group(1)] = _coerce(m.group(2))
            continue
        if line.startswith("approval"):
            match = _APPROVAL_RE.match(line)
            if not match:
                raise WorkflowError(f"Line {lineno}: malformed approval step")
            current = Step(key=match.group(1) or f"approval_{len(steps) + 1}",
                           kind="approval")
            steps.append(current)
            rest = (match.group(2) or "").strip()
            while rest:
                inline = _KV_RE.match(rest)
                if not inline:
                    raise WorkflowError(
                        f"Line {lineno}: bad inline attribute '{rest[:60]}'")
                key, value = inline.group(1), inline.group(2)
                if key == "needs":
                    current.needs = [d for d in value.split(",") if d]
                else:
                    current.params[key] = _coerce(value)
                rest = rest[inline.end():].strip()
            continue
        if line.startswith("action "):
            if current is None:
                raise WorkflowError(f"Line {lineno}: 'action' before any 'step'")
            m = _ACTION_RE.match(line)
            if not m:
                raise WorkflowError(f"Line {lineno}: malformed action")
            current.action = m.group(1)
            continue
        if line.startswith("target="):
            if current is None:
                raise WorkflowError(f"Line {lineno}: 'target=' before any 'step'")
            m = _TARGET_RE.match(line)
            if not m:
                raise WorkflowError(f"Line {lineno}: malformed target")
            current.target = m.group(1)
            continue
        if line.startswith("needs="):
            if current is None:
                raise WorkflowError(f"Line {lineno}: 'needs=' before any 'step'")
            m = _NEEDS_RE.match(line)
            if not m:
                raise WorkflowError(f"Line {lineno}: malformed needs")
            deps = [d for d in m.group(1).split(",") if d]
            for dep in deps:
                if dep == current.key:
                    raise WorkflowError(f"Line {lineno}: step '{current.key}' cannot need itself")
                if dep not in {s.key for s in steps}:
                    raise WorkflowError(
                        f"Line {lineno}: unknown dependency '{dep}'",
                        action="Declare dependencies after their steps exist.",
                    )
            current.needs = deps
            continue
        m = _KV_RE.match(line)
        if m and current is not None:
            # shorthand: target=x / action=y inline on the step line
            key, value = m.group(1), m.group(2)
            if key == "target":
                current.target = value
            elif key == "action":
                current.action = value
            elif key == "needs":
                current.needs = [d for d in value.split(",") if d]
            else:
                current.params[key] = _coerce(value)
            continue
        raise WorkflowError(
            f"Line {lineno}: unrecognized syntax '{line[:60]}'",
            action="See the workflow DSL reference in ARCHITECTURE.md.",
        )

    if not opened:
        raise WorkflowError("No workflow block found",
                            action='Start with: workflow "name" {')
    if not steps:
        raise WorkflowError("Workflow has no steps",
                            action="Add at least one step or approval line.")
    _validate_dag(steps)
    return WorkflowSpec(name=name, steps=steps)


def _validate_dag(steps: list[Step]) -> None:
    keys = [s.key for s in steps]
    if len(set(keys)) != len(keys):
        dupes = sorted({k for k in keys if keys.count(k) > 1})
        raise WorkflowError(f"Duplicate step keys: {', '.join(dupes)}")
    for step in steps:
        for dep in step.needs:
            if dep not in keys:
                raise WorkflowError(f"Step '{step.key}' needs unknown step '{dep}'")
    # Kahn's algorithm — cycle detection at parse time
    indeg = {s.key: 0 for s in steps}
    out: dict[str, list[str]] = {s.key: [] for s in steps}
    for s in steps:
        for dep in s.needs:
            out[dep].append(s.key)
            indeg[s.key] += 1
    queue = [k for k, d in indeg.items() if d == 0]
    seen = 0
    while queue:
        node = queue.pop()
        seen += 1
        for nxt in out[node]:
            indeg[nxt] -= 1
            if indeg[nxt] == 0:
                queue.append(nxt)
    if seen != len(steps):
        raise WorkflowError("Workflow contains a dependency cycle",
                            action="Break the cycle between 'needs' declarations.")


# ---------------------------------------------------------------------------
# Runner


class WorkflowRunner:
    """Durable, resumable DAG runner over the broker (six gates intact)."""

    def __init__(self, db, broker, audit: AuditChain | None = None) -> None:
        self._db = db
        self._broker = broker
        self._audit = audit

    def _audit_append(self, case_id: str, action: str, subject: str, detail: dict) -> None:
        if self._audit is not None:
            self._audit.append(case_id, actor="workflow", action=action,
                               subject=subject, detail=detail)

    def start(self, case_id: str, spec: WorkflowSpec) -> dict:
        wf_id = f"wf_{uuid.uuid4().hex[:12]}"
        self._db.record_workflow(wf_id, case_id, name=spec.name,
                                 spec=spec.as_dict(), state="pending")
        for step in spec.steps:
            self._db.record_workflow_step(
                case_id, wf_id, step.key, kind=step.kind,
                spec=step.as_dict(),
                state="pending" if step.kind == "approval" else "ready"
                if not step.needs else "pending",
            )
        self._audit_append(case_id, "workflow.created", spec.name,
                           {"workflow_id": wf_id, "steps": len(spec.steps)})
        return {"workflow_id": wf_id, "name": spec.name, "steps": len(spec.steps)}

    def resume(self, case_id: str, wf_id: str, *, max_steps: int = 50) -> dict:
        """Run all runnable steps until blocked, done or failed.

        Resumable: persisted step states are the checkpoint record; finished
        steps are never re-executed.
        """
        wf_row = self._db.get_workflow(wf_id)
        if wf_row is None or wf_row["case_id"] != case_id:
            raise WorkflowError(f"Workflow '{wf_id}' not found in case {case_id}")
        if wf_row["state"] in {"completed", "cancelled"}:
            return self.status(case_id, wf_id)
        if wf_row["state"] == "failed":
            raise WorkflowError(
                f"Workflow '{wf_id}' failed",
                action="Inspect step outcomes with: rebel-profiler workflow status",
            )

        self._db.set_workflow_state(wf_id, "running")
        self._audit_append(case_id, "workflow.started", wf_row["name"],
                           {"workflow_id": wf_id})
        executed = 0
        try:
            while executed < max_steps:
                progressed = False
                for row in self._db.workflow_steps(wf_id):
                    if row["state"] in {"pending", "ready"}:
                        step = self._step_from_row(row)
                        if self._ready(step, wf_id):
                            self._run_step(case_id, wf_id, step)
                            executed += 1
                            progressed = True
                if not progressed:
                    break
        finally:
            self._finalize(case_id, wf_id)
        return self.status(case_id, wf_id)

    def approve_gate(self, case_id: str, wf_id: str, step_key: str,
                     *, decided_by: str, approve: bool) -> dict:
        """Human decision on an approval-gate step."""
        row = self._db.get_workflow_step(wf_id, step_key)
        if row is None or row["kind"] != "approval":
            raise WorkflowError(f"No approval step '{step_key}' in workflow {wf_id}")
        if row["state"] != "awaiting_approval":
            raise WorkflowError(
                f"Step '{step_key}' is '{row['state']}', not awaiting approval")
        if approve:
            self._db.set_workflow_step_state(wf_id, step_key, "succeeded",
                                             outcome=f"approved by {decided_by}")
            self._audit_append(case_id, "workflow.gate_approved", step_key,
                               {"workflow_id": wf_id, "by": decided_by})
        else:
            self._db.set_workflow_step_state(wf_id, step_key, "cancelled",
                                             outcome=f"denied by {decided_by}")
            self._db.set_workflow_state(wf_id, "cancelled")
            self._audit_append(case_id, "workflow.gate_denied", step_key,
                               {"workflow_id": wf_id, "by": decided_by})
        return {"step": step_key, "approved": approve, "by": decided_by}

    # -- internals ------------------------------------------------------------

    def _step_from_row(self, row) -> Step:
        spec = json.loads(row["spec_json"])
        return Step(key=row["step_key"], kind=row["kind"],
                    action=spec.get("action", ""), target=spec.get("target", ""),
                    params=spec.get("params", {}), needs=spec.get("needs", []))

    def _ready(self, step: Step, wf_id: str) -> bool:
        if step.kind == "approval":
            # an approval step becomes runnable when its deps are done
            pass
        for dep in step.needs:
            dep_row = self._db.get_workflow_step(wf_id, dep)
            if dep_row is None or dep_row["state"] != "succeeded":
                return False
        return True

    def _run_step(self, case_id: str, wf_id: str, step: Step) -> None:
        if step.kind == "approval":
            self._db.set_workflow_step_state(wf_id, step.key, "awaiting_approval",
                                             outcome="waiting for human decision")
            self._db.set_workflow_state(wf_id, "paused")
            self._audit_append(case_id, "workflow.gate_waiting", step.key,
                               {"workflow_id": wf_id})
            return
        if not step.action or not step.target:
            self._db.set_workflow_step_state(wf_id, step.key, "failed",
                                             outcome="step has no action/target")
            raise WorkflowError(
                f"Step '{step.key}' has no action/target",
                action="Declare 'action <name>' and 'target=<t>' in the DSL.",
            )
        from ..execution.broker import ActionRequest

        adapter = self._broker.adapters.get(step.action)
        request = ActionRequest(
            case_id=case_id,
            capability=adapter.capability_class if adapter else "discovery",
            action=step.action, target=step.target,
            params=dict(step.params), requested_by="workflow", reason=wf_id,
        )
        self._db.set_workflow_step_state(wf_id, step.key, "running")
        try:
            result = self._broker.execute(request)
        except WorkflowError:
            raise
        except Exception as exc:  # broker raises RPError subclasses on denial
            self._db.set_workflow_step_state(
                wf_id, step.key, "failed", outcome=str(exc)[:200])
            raise WorkflowError(
                f"Step '{step.key}' was denied: {exc}",
                action="Check policy/scope or split the workflow.") from exc
        if result.outcome == "succeeded":
            self._db.set_workflow_step_state(
                wf_id, step.key, "succeeded", outcome=f"task={result.task_id}",
                detail={"task_id": result.task_id, "evidence_id": result.evidence_id})
        else:
            self._db.set_workflow_step_state(
                wf_id, step.key, "failed", outcome=result.outcome,
                detail={"task_id": result.task_id})

    def _finalize(self, case_id: str, wf_id: str) -> None:
        steps = self._db.workflow_steps(wf_id)
        states = {row["state"] for row in steps}
        if any(row["state"] == "awaiting_approval" for row in steps):
            self._db.set_workflow_state(wf_id, "paused")
        elif any(row["state"] in {"failed", "cancelled"} for row in steps):
            self._db.set_workflow_state(wf_id, "failed" if "failed" in states else "cancelled")
        elif all(row["state"] == "succeeded" for row in steps):
            self._db.set_workflow_state(wf_id, "completed")
            self._audit_append(case_id, "workflow.completed", wf_id, {})
        else:
            self._db.set_workflow_state(wf_id, "paused")

    def status(self, case_id: str, wf_id: str) -> dict:
        wf = self._db.get_workflow(wf_id)
        if wf is None or wf["case_id"] != case_id:
            raise WorkflowError(f"Workflow '{wf_id}' not found in case {case_id}")
        steps = [
            {
                "step": row["step_key"], "kind": row["kind"], "state": row["state"],
                "outcome": row["outcome"],
                "detail": json.loads(row["detail_json"]),
            }
            for row in self._db.workflow_steps(wf_id)
        ]
        return {
            "workflow_id": wf_id,
            "case_id": case_id,
            "name": wf["name"],
            "state": wf["state"],
            "steps": steps,
            "progress": f"{sum(1 for s in steps if s['state'] == 'succeeded')}/{len(steps)}",
        }
