"""Self-repair agent loop: work list → gated execution → error log → revise → retry.

The product behavior this module implements:

  1. **Work list** — the planner (LLM) states the goal as an ordered list of
     proposed actions. The list is persisted per case, so an interrupted
     session can be inspected later.
  2. **Gated execution** — every item runs through the broker's six gates
     exactly like a manual run. Nothing here bypasses scope, risk or policy.
  3. **Error log** — when an item fails, is denied or errors out, a
     structured repair entry is written: what was attempted, the error
     class, the message, and a deterministic fix hint. The log is persisted
     and audit-chained.
  4. **Revise & retry** — the reviser (LLM role) receives the failure
     feedback and may return a *corrected* proposal (bounded retries per
     item). Deterministic safety rules apply on top: scope violations and
     policy denials are never auto-retried against the same target — they
     need an operator decision, so the item is parked ``blocked`` (scope
     widening is never automatic).
  5. **Await the operator** — when the list finishes (done, blocked or
     awaiting approval), the session stops, prints a brief summary plus
     next-step suggestions, and asks the user what to do next. Suggestions
     map to whitelisted follow-up actions only; applying one requires
     explicit user approval.

The LLM proposes and revises; the system decides, logs and asks.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field

from ..core.errors import RPError
from ..evidence.audit import AuditChain
from ..execution.broker import ActionRequest, ExecutionBroker
from ..intel.claims import ClaimLedger
from ..intel.collection import CollectionPipeline
from ..intel.findings import generate_report
from ..intel.sources import SourceRegistry
from . import Proposal

ITEM_STATES = ("pending", "running", "done", "failed", "blocked", "awaiting_approval", "skipped")

MAX_REPAIR_ATTEMPTS_DEFAULT = 2


@dataclass
class WorkItem:
    """One entry of the persisted work list."""

    seq: int
    action: str
    target: str
    params: dict = field(default_factory=dict)
    reason: str = ""
    status: str = "pending"
    attempts: int = 0
    last_error: str = ""
    task_id: str = ""
    evidence_id: str = ""
    approval_id: str = ""

    def as_dict(self) -> dict:
        return {
            "seq": self.seq, "action": self.action, "target": self.target,
            "params": dict(self.params), "reason": self.reason,
            "status": self.status, "attempts": self.attempts,
            "last_error": self.last_error, "task_id": self.task_id,
            "evidence_id": self.evidence_id, "approval_id": self.approval_id,
        }

    @staticmethod
    def from_dict(data: dict) -> "WorkItem":
        return WorkItem(
            seq=data["seq"], action=data["action"], target=data["target"],
            params=data.get("params", {}), reason=data.get("reason", ""),
            status=data.get("status", "pending"), attempts=data.get("attempts", 0),
            last_error=data.get("last_error", ""), task_id=data.get("task_id", ""),
            evidence_id=data.get("evidence_id", ""),
            approval_id=data.get("approval_id", ""),
        )


@dataclass
class RepairEntry:
    """One structured error-log record."""

    seq: int
    item_seq: int
    action: str
    target: str
    error_class: str            # denied | scope | policy | failed | error | cancelled
    message: str
    fix_hint: str
    attempt: int
    at: float

    def as_dict(self) -> dict:
        return {
            "seq": self.seq, "item_seq": self.item_seq, "action": self.action,
            "target": self.target, "error_class": self.error_class,
            "message": self.message, "fix_hint": self.fix_hint,
            "attempt": self.attempt, "at": self.at,
        }

    @staticmethod
    def from_dict(data: dict) -> "RepairEntry":
        return RepairEntry(**data)


def _fix_hint_for(error_class: str, message: str) -> str:
    """Deterministic next-action hints — never an LLM opinion."""
    low = message.lower()
    if error_class == "scope" or "not authorized" in low or "scope" in low:
        return ("Scope violation: ask the operator to add the target to the case"
                " scope (rebel-profiler case scope add). Never auto-widened.")
    if "not whitelisted" in low or "no adapter" in low:
        return ("Unknown action/tool: pick one from"
                " 'rebel-profiler adapters' and restate the item.")
    if "approval" in low:
        return ("Policy needs approval: decide the queued approval with"
                " 'rebel-profiler approval decide'.")
    if "denied" in error_class or "policy denied" in low:
        return ("Policy denial: lower the risk (fewer flags, passive action)"
                " or request a policy exception.")
    if "not installed" in low or "dependency" in low:
        return ("Missing binary: install the tool (apt on Kali) or choose a"
                " different action.")
    if "invalid" in low or "usage" in low:
        return ("Contract violation: fix the params to match the adapter's"
                " declared allowed_params.")
    return ("Inspect the repair log and the evidence, correct the proposal,"
            " then retry.")


class SelfRepairSession:
    """The inspect → log → revise → retry loop over a persisted work list."""

    def __init__(
        self,
        case_id: str,
        goal: str,
        *,
        broker: ExecutionBroker,
        ledger: ClaimLedger,
        evidence,
        db,
        audit: AuditChain | None = None,
        registry: SourceRegistry | None = None,
        max_actions: int = 12,
        max_repair_attempts: int = MAX_REPAIR_ATTEMPTS_DEFAULT,
        actor: str = "planner",
    ) -> None:
        self.case_id = case_id
        self.goal = goal
        self.broker = broker
        self.ledger = ledger
        self.evidence = evidence
        self.db = db
        self.audit = audit
        self.registry = registry or SourceRegistry()
        self.max_actions = max_actions
        self.max_repair_attempts = max(0, max_repair_attempts)
        self.actor = actor
        self.session_id = f"wrk_{uuid.uuid4().hex[:12]}"
        self.items: list[WorkItem] = []
        self.repairs: list[RepairEntry] = []
        self.suggestions: list[dict] = []

    # -- persistence ------------------------------------------------------------

    def _persist(self) -> None:
        self.db.set_meta(f"worklist:{self.session_id}", json.dumps({
            "session_id": self.session_id,
            "case_id": self.case_id,
            "goal": self.goal,
            "created_at": time.time(),
            "items": [i.as_dict() for i in self.items],
        }, sort_keys=True))
        self.db.set_meta(f"repairs:{self.session_id}", json.dumps({
            "session_id": self.session_id,
            "case_id": self.case_id,
            "entries": [r.as_dict() for r in self.repairs],
        }, sort_keys=True))
        index = json.loads(self.db.get_meta("worklists") or "[]")
        if self.session_id not in index:
            index.append(self.session_id)
        self.db.set_meta("worklists", json.dumps(index))

    def load(self, session_id: str) -> None:
        raw = self.db.get_meta(f"worklist:{session_id}")
        if not raw:
            raise RPError(f"Work list '{session_id}' not found")
        data = json.loads(raw)
        self.session_id = data["session_id"]
        self.goal = data.get("goal", "")
        self.items = [WorkItem.from_dict(i) for i in data.get("items", [])]
        rraw = self.db.get_meta(f"repairs:{session_id}") or '{"entries": []}'
        self.repairs = [RepairEntry.from_dict(r) for r in json.loads(rraw).get("entries", [])]

    @staticmethod
    def list_sessions(db) -> list[dict]:
        out = []
        for sid in json.loads(db.get_meta("worklists") or "[]"):
            raw = db.get_meta(f"worklist:{sid}")
            if not raw:
                continue
            data = json.loads(raw)
            items = data.get("items", [])
            out.append({
                "session_id": sid,
                "case_id": data.get("case_id"),
                "goal": data.get("goal"),
                "items": len(items),
                "done": sum(1 for i in items if i.get("status") == "done"),
                "blocked": sum(1 for i in items if i.get("status") in {"blocked", "failed"}),
                "awaiting": sum(1 for i in items if i.get("status") == "awaiting_approval"),
            })
        return out

    # -- audit -------------------------------------------------------------------

    def _audit_append(self, action: str, subject: str, detail: dict) -> None:
        if self.audit is not None:
            self.audit.append(self.case_id, actor=self.actor, action=action,
                              subject=subject, detail=detail)

    # -- the loop ------------------------------------------------------------------

    def run(self, planner, reviser=None) -> dict:
        """Run the full loop; returns a machine-readable session report."""
        proposals = list(planner(self._view()))
        if not proposals:
            raise RPError(
                "Planner returned an empty work list",
                reason="A self-repair session needs at least one work item.",
                action="State the goal with an actionable step or pass --plan.",
            )
        if len(proposals) > self.max_actions:
            raise RPError(
                f"Work list has {len(proposals)} items; ceiling is {self.max_actions}",
                reason="Runaway work lists are capped.",
                action="Split the goal into multiple sessions.",
            )
        self.items = [
            WorkItem(seq=n, action=p.action, target=p.target,
                     params=dict(p.params), reason=p.reason or self.goal)
            for n, p in enumerate(proposals, start=1)
        ]
        self._persist()
        self._audit_append("worklist.created", self.session_id,
                           {"goal": self.goal, "items": len(self.items)})

        pipeline = CollectionPipeline(self.ledger, self.evidence, self.registry, db=self.db)
        for item in self.items:
            self._work_item(item, pipeline, reviser)
        self._persist()

        status = self._status()
        self.suggestions = self._suggestions(status)
        self._audit_append("worklist.finished", self.session_id,
                           {"status": status["state"], "done": status["done"],
                            "blocked": status["blocked"]})
        report = generate_report(self.ledger, self.case_id)
        return {
            "session_id": self.session_id,
            "case_id": self.case_id,
            "goal": self.goal,
            "status": status,
            "items": [i.as_dict() for i in self.items],
            "repairs": [r.as_dict() for r in self.repairs],
            "suggestions": self.suggestions,
            "awaiting_user": True,
            "report": report.as_dict(),
            "report_human": report.render_human(),
        }

    def _view(self) -> dict:
        return {
            "case_id": self.case_id,
            "goal": self.goal,
            "available_actions": [
                {"action": a.name, "allowed_params": list(a.allowed_params)}
                for a in self.broker.adapters.list()
            ],
            "rules": [
                "Return an ordered list of Proposal(action, target, params).",
                "Only declared actions and params are accepted.",
                "Failures are logged and returned to you for one bounded revision.",
                "Scope and policy are never negotiable.",
            ],
        }

    def _work_item(self, item: WorkItem, pipeline: CollectionPipeline, reviser) -> None:
        """Execute one item with bounded, logged repair."""
        current = Proposal(action=item.action, target=item.target,
                           params=dict(item.params), reason=item.reason)
        while True:
            item.attempts += 1
            item.status = "running"
            outcome = self._attempt(item, current, pipeline)
            if outcome is None:
                return  # done / awaiting_approval / blocked — item settled
            error_class, message = outcome
            self._log_repair(item, error_class, message)
            # Hard safety rules: scope/policy problems are never auto-retried.
            if error_class in {"scope", "policy"}:
                item.status = "blocked"
                self._audit_append("work.item_blocked", item.action,
                                   {"seq": item.seq, "why": error_class})
                return
            if item.attempts > self.max_repair_attempts:
                item.status = "failed"
                self._audit_append("work.item_failed", item.action,
                                   {"seq": item.seq, "attempts": item.attempts})
                return
            if reviser is None:
                item.status = "failed"
                return
            revised = reviser({
                "item": item.as_dict(),
                "error": {"class": error_class, "message": message},
                "fix_hint": _fix_hint_for(error_class, message),
                "available_actions": [a.name for a in self.broker.adapters.list()],
            })
            if revised is None:
                item.status = "failed"
                self._audit_append("work.item_failed", item.action,
                                   {"seq": item.seq, "why": "reviser gave up"})
                return
            current = revised
            item.action, item.target = revised.action, revised.target
            item.params = dict(revised.params)
            self._audit_append("work.revised", item.action,
                               {"seq": item.seq, "attempt": item.attempts})

    def _attempt(self, item: WorkItem, proposal: Proposal, pipeline: CollectionPipeline):
        """One execution attempt. Returns None when settled, else (class, message)."""
        adapter = self.broker.adapters.get(proposal.action)
        if adapter is None:
            return "error", f"No adapter for action '{proposal.action}'"
        request = ActionRequest(
            case_id=self.case_id,
            capability=adapter.capability_class,
            action=proposal.action, target=proposal.target,
            params=dict(proposal.params), requested_by=self.actor,
            reason=item.reason or self.goal,
        )
        try:
            result = self.broker.execute(request)
        except RPError as exc:
            cls = "scope" if exc.exit_code == 5 else "policy" if exc.exit_code == 4 else "error"
            return cls, exc.message
        if result.outcome == "succeeded":
            collection = pipeline.ingest(
                self.case_id, action=result.action, target=result.target,
                stdout=result.stdout, stderr=result.stderr,
                returncode=result.returncode or 1, task_id=result.task_id,
                evidence_id=result.evidence_id, params=dict(proposal.params),
            )
            item.status = "done"
            item.task_id = result.task_id
            item.evidence_id = result.evidence_id or ""
            self._audit_append("work.item_done", result.action,
                               {"seq": item.seq, "task_id": result.task_id,
                                "claims": len(collection["claims_emitted"])})
            return None
        if result.outcome == "cancelled":
            # approval-gated capability with no approver → queue for later
            approval_id = self._queue_approval(request, result)
            if approval_id:
                item.status = "awaiting_approval"
                item.approval_id = approval_id
                self._audit_append("work.item_awaiting_approval", result.action,
                                   {"seq": item.seq, "approval_id": approval_id})
                return None
            return "cancelled", f"execution cancelled ({result.task_id})"
        return "failed", f"returncode={result.returncode}"

    def _queue_approval(self, request: ActionRequest, result) -> str:
        """Queue the cancelled approval-gated action for an operator decision."""
        try:
            from ..security.approvals import ApprovalQueue

            gate = self.broker.plan(request)
            queue = ApprovalQueue(self.db, self.audit)
            record = queue.enqueue(
                self.case_id, task_id=result.task_id, action=request.action,
                target=request.target,
                argv=self.broker.adapters.get(request.action).build_argv(request),
                risk=gate.decision.risk.level,
                reasons=list(gate.decision.reasons),
                requested_by=self.actor,
            )
            return record["id"]
        except RPError:
            return ""

    def _log_repair(self, item: WorkItem, error_class: str, message: str) -> None:
        entry = RepairEntry(
            seq=len(self.repairs) + 1, item_seq=item.seq,
            action=item.action, target=item.target,
            error_class=error_class, message=message[:300],
            fix_hint=_fix_hint_for(error_class, message),
            attempt=item.attempts, at=time.time(),
        )
        self.repairs.append(entry)
        item.last_error = f"{error_class}: {message[:200]}"
        item.status = "pending"
        self._audit_append("work.repair_logged", item.action,
                           {"seq": entry.seq, "item": item.seq,
                            "class": error_class})
        self._persist()

    # -- wrap-up -------------------------------------------------------------------

    def _status(self) -> dict:
        done = sum(1 for i in self.items if i.status == "done")
        blocked = sum(1 for i in self.items if i.status in {"blocked", "failed"})
        awaiting = sum(1 for i in self.items if i.status == "awaiting_approval")
        pending = sum(1 for i in self.items if i.status in {"pending", "running"})
        state = "completed" if done == len(self.items) else (
            "awaiting_approval" if awaiting else
            "partial" if done else "blocked"
        )
        return {
            "state": state, "items": len(self.items), "done": done,
            "blocked": blocked, "awaiting_approval": awaiting, "pending": pending,
            "repair_entries": len(self.repairs),
        }

    def _suggestions(self, status: dict) -> list[dict]:
        """Brief, deterministic next-step suggestions for the operator."""
        suggestions: list[dict] = []
        if status["awaiting_approval"]:
            suggestions.append({
                "text": f"{status['awaiting_approval']} action(s) await your approval — "
                        "review and decide: rebel-profiler approval list <case-id>",
                "kind": "approval",
            })
        if status["blocked"]:
            first = next((i for i in self.items if i.status in {"blocked", "failed"}), None)
            hint = ""
            if self.repairs:
                hint = f" — {self.repairs[-1].fix_hint}"
            suggestions.append({
                "text": f"{status['blocked']} item(s) need a fix"
                        + (f" (item {first.seq}: {first.action})" if first else "")
                        + hint,
                "kind": "retry",
            })
        if status["done"]:
            suggestions.append({
                "text": "Generate the case report: rebel-profiler report "
                        f"{self.case_id}",
                "kind": "report",
            })
            suggestions.append({
                "text": "Build the surface graph + fusion view: "
                        f"rebel-profiler surface build {self.case_id} && "
                        f"rebel-profiler intel fusion {self.case_id}",
                "kind": "surface",
            })
        suggestions.append({
            "text": "Verify evidence integrity before trusting anything: "
                    f"rebel-profiler evidence verify {self.case_id}",
            "kind": "verify",
        })
        suggestions.append({
            "text": "Tell the agent what to do next — state a new goal for "
                    "'agent work', approve the queued items, or close the session.",
            "kind": "next_goal",
        })
        return suggestions


def render_session_human(session_report: dict) -> str:
    """Human rendering: status, work list, error log, suggestions, prompt."""
    status = session_report["status"]
    lines = [
        f"self-repair session {session_report['session_id']}: {status['state']}"
        f" — {status['done']}/{status['items']} done,"
        f" {status['blocked']} blocked, {status['awaiting_approval']} awaiting approval",
        f"  goal: {session_report['goal']}",
        "",
        "work list:",
    ]
    for item in session_report["items"]:
        mark = {"done": "+", "failed": "!", "blocked": "!",
                "awaiting_approval": "?", "pending": "·", "running": "·",
                "skipped": "-"}.get(item["status"], "?")
        extra = f" — {item['last_error']}" if item["last_error"] else ""
        approval = f" [approval {item['approval_id']}]" if item["approval_id"] else ""
        lines.append(f"  [{mark}] {item['seq']}. {item['action']} {item['target']}"
                     f" → {item['status']}{approval}{extra}")
    if session_report["repairs"]:
        lines.append("")
        lines.append("error log:")
        for entry in session_report["repairs"]:
            lines.append(f"  #{entry['seq']} item {entry['item_seq']}"
                         f" {entry['action']} [{entry['error_class']}]"
                         f" {entry['message'][:120]}")
            lines.append(f"     fix: {entry['fix_hint']}")
    lines.append("")
    lines.append("suggestions — sir, what should we do next?")
    for n, s in enumerate(session_report["suggestions"], start=1):
        lines.append(f"  {n}. {s['text']}")
    lines.append("")
    lines.append("session paused: awaiting operator decision (approve a suggestion,"
                 " decide queued approvals, or state the next goal).")
    return "\n".join(lines)
