"""Scheduler with authorization windows (Phase 4, PDF 14).

Schedules are persisted per case and carry an **authorization window**
(``not_before`` / ``not_after``, epoch seconds). ``Scheduler.tick`` is a
single, bounded, side-effect-pinned pass over due schedules:

  * a schedule fires only inside its window; outside it is skipped
    (``before_window`` / ``after_window``), and one past its end is expired,
  * execution goes through the broker's six gates like every other path —
    a tick never bypasses scope, risk or policy,
  * ``cron`` accepts the deterministic ``interval=<minutes>`` form (the only
    recurring shape that stays authorization-honest: a window that has ended
    still expires a recurring job),
  * results (task id, outcome) are recorded on the schedule for the CLI.

The scheduler never invents targets: every dispatch uses the exact persisted
action/target/params triple.
"""

from __future__ import annotations

import json
import time
import uuid

from ..core.errors import UsageError
from ..evidence.audit import AuditChain
from .workflow import WorkflowRunner, parse_workflow


class Scheduler:
    """Runs due, in-window schedules through the broker."""

    def __init__(self, db, broker, audit: AuditChain | None = None) -> None:
        self._db = db
        self._broker = broker
        self._audit = audit

    def _audit_append(self, case_id: str, action: str, subject: str, detail: dict) -> None:
        if self._audit is not None:
            self._audit.append(case_id, actor="scheduler", action=action,
                               subject=subject, detail=detail)

    def schedule(
        self,
        case_id: str,
        *,
        action: str,
        target: str,
        params: dict | None = None,
        not_before: float | None = None,
        not_after: float | None = None,
        cron: str = "",
        workflow_spec: str = "",
    ) -> dict:
        if not action and not workflow_spec:
            raise UsageError(
                "A schedule needs an action or a workflow spec",
                action="Pass --action <name> --target <t> or --workflow-spec <dsl>.",
            )
        if target and action:
            adapter = self._broker.adapters.get(action)
            if adapter is None:
                raise UsageError(
                    f"No adapter for action '{action}'",
                    reason="The no-fake-adapter policy applies to schedules too.",
                    action=f"Available actions: {', '.join(self._broker.adapters.names())}",
                )
        if not_before is not None and not_after is not None and not_before > not_after:
            raise UsageError(
                "Authorization window is inverted",
                reason="not_before is after not_after.",
                action="Fix the window so it starts before it ends.",
            )
        cron = cron.strip()
        if cron and not cron.startswith("interval="):
            raise UsageError(
                f"Unsupported cron expression '{cron}'",
                reason="Only the deterministic 'interval=<minutes>' form is offered.",
                action="Use e.g. --cron interval=60 for hourly runs.",
            )
        if cron:
            minutes = int(cron.split("=", 1)[1])
            if minutes < 1:
                raise UsageError("Interval must be at least 1 minute")

        sched_id = f"sched_{uuid.uuid4().hex[:12]}"
        workflow_id = ""
        next_due: float | None = None
        if workflow_spec:
            spec = parse_workflow(workflow_spec)
            runner = WorkflowRunner(self._db, self._broker, self._audit)
            started = runner.start(case_id, spec)
            workflow_id = started["workflow_id"]
            # scheduled workflows wait for their window before resuming
        else:
            next_due = not_before if not_before is not None else time.time()

        self._db.record_schedule(
            sched_id, case_id,
            action=action or "", target=target or "", params=params or {},
            workflow_id=workflow_id, cron=cron,
            not_before=not_before, not_after=not_after,
            next_due_at=next_due,
        )
        self._audit_append(case_id, "schedule.created", action or workflow_id,
                           {"schedule_id": sched_id, "target": target,
                            "window": [not_before, not_after], "cron": cron})
        return {
            "schedule_id": sched_id,
            "case_id": case_id,
            "action": action,
            "target": target,
            "workflow_id": workflow_id,
            "cron": cron,
            "not_before": not_before,
            "not_after": not_after,
            "next_due_at": next_due,
            "state": "active",
        }

    def tick(self, *, now: float | None = None) -> dict:
        """One bounded scheduler pass. Returns a machine-readable report."""
        now_ts = time.time() if now is None else now
        results = []
        for row in self._db.active_schedules():
            case_id = row["case_id"]
            nb, na = row["not_before"], row["not_after"]
            due = row["next_due_at"]

            if na is not None and now_ts > na:
                self._db.set_schedule_state(row["id"], "expired")
                results.append({"schedule_id": row["id"], "case_id": case_id,
                                "result": "expired"})
                continue
            if nb is not None and now_ts < nb:
                results.append({"schedule_id": row["id"], "case_id": case_id,
                                "result": "before_window"})
                continue
            if due is not None and now_ts < due:
                results.append({"schedule_id": row["id"], "case_id": case_id,
                                "result": "not_due"})
                continue

            if row["workflow_id"]:
                outcome = self._run_workflow(case_id, row)
            else:
                outcome = self._run_action(row)

            next_due = None
            if row["cron"]:
                minutes = int(row["cron"].split("=", 1)[1])
                next_due = now_ts + minutes * 60
            elif na is None:
                # one-shot without a window: done after firing
                self._db.set_schedule_state(row["id"], "expired" if outcome["ok"] else "active")
                if outcome["ok"]:
                    self._db.set_schedule_run(row["id"], last_run_at=now_ts,
                                              last_state=outcome["state"],
                                              next_due_at=None)
                    results.append({**outcome, "schedule_id": row["id"],
                                    "case_id": case_id, "result": "fired"})
                    continue
            self._db.set_schedule_run(row["id"], last_run_at=now_ts,
                                      last_state=outcome["state"],
                                      next_due_at=next_due)
            results.append({**outcome, "schedule_id": row["id"],
                            "case_id": case_id, "result": "fired"})
        return {"now": now_ts, "evaluated": len(results), "results": results}

    # -- dispatch ----------------------------------------------------------------

    def _run_action(self, row) -> dict:
        from ..execution.broker import ActionRequest

        case_id = row["case_id"]
        params = json.loads(row["params_json"])
        adapter = self._broker.adapters.get(row["action"])
        request = ActionRequest(
            case_id=case_id,
            capability=adapter.capability_class if adapter else "discovery",
            action=row["action"], target=row["target"],
            params=params, requested_by="scheduler",
        )
        try:
            result = self._broker.execute(request)
            return {"state": result.outcome, "ok": result.outcome == "succeeded",
                    "task_id": result.task_id}
        except Exception as exc:
            self._audit_append(case_id, "schedule.dispatch_denied", row["action"],
                               {"schedule_id": row["id"], "error": str(exc)[:200]})
            return {"state": "denied", "ok": False, "error": str(exc)[:200]}

    def _run_workflow(self, case_id: str, row) -> dict:
        runner = WorkflowRunner(self._db, self._broker, self._audit)
        try:
            status = runner.resume(case_id, row["workflow_id"])
            return {"state": status["state"], "ok": status["state"] == "completed",
                    "workflow_id": row["workflow_id"],
                    "progress": status["progress"]}
        except Exception as exc:
            return {"state": "failed", "ok": False, "error": str(exc)[:200]}
