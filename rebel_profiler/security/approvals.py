"""Approval queue (Phase 4, PDF 11).

When policy emits ``ALLOW_WITH_APPROVAL`` and no interactive approver is
available (headless/CI runs, agent sessions), the broker can queue the task
as a *pending approval* instead of executing or cancelling it. An authorized
subject (owner/operator) later decides the request:

  * ``approve`` → the exact stored argv is re-validated against the live
    scope and policy, then executed; the decision is audit-chained.
  * ``deny``    → nothing runs; the denial is audit-chained.

The queue is durable (SQLite) and the stored argv is the **exact** argv the
broker validated at request time. Re-validation at decision time means a
scope change between request and decision can still block execution — the
approval grants the decision, never the authorization.
"""

from __future__ import annotations

import json
import shlex
import time
import uuid

from ..core.errors import StateError, UsageError
from ..evidence.audit import AuditChain
from ..storage.database import Database


@classmethod
def _noop(cls):  # pragma: no cover - placeholder guard, never called
    return None


class ApprovalQueue:
    """Durable pending-approval queue backed by the case database."""

    def __init__(self, db: Database, audit: AuditChain | None = None) -> None:
        self._db = db
        self._audit = audit

    def _audit_append(self, case_id: str, action: str, subject: str, detail: dict) -> None:
        if self._audit is not None:
            self._audit.append(case_id, actor="approvals", action=action,
                               subject=subject, detail=detail)

    def enqueue(
        self,
        case_id: str,
        *,
        task_id: str,
        action: str,
        target: str,
        argv: list[str],
        params: dict | None = None,
        risk: str = "",
        reasons: list[str] | None = None,
        requested_by: str = "operator",
    ) -> dict:
        """Queue one approval request with the exact validated argv+params."""
        approval_id = f"apr_{uuid.uuid4().hex[:12]}"
        self._db.record_approval(
            approval_id, case_id,
            task_id=task_id, action=action, target=target,
            risk=risk, reasons="; ".join(reasons or []),
            requested_by=requested_by,
        )
        # argv is stored in the task detail via meta table (schema_meta) so the
        # approvals table stays free-form-free; the canonical storage is the
        # task's audit trail plus this record.
        self._db.set_meta(f"approval_argv:{approval_id}", json.dumps(argv))
        self._db.set_meta(f"approval_params:{approval_id}",
                          json.dumps(params or {}))
        record = {
            "id": approval_id,
            "case_id": case_id,
            "task_id": task_id,
            "action": action,
            "target": target,
            "risk": risk,
            "reasons": "; ".join(reasons or []),
            "requested_by": requested_by,
            "state": "pending",
            "argv": argv,
            "params": params or {},
        }
        self._audit_append(case_id, "approval.requested", action,
                           {"approval_id": approval_id, "task_id": task_id,
                            "target": target, "argv": argv})
        return record

    def get(self, approval_id: str) -> dict:
        row = self._db.get_approval(approval_id)
        if row is None:
            raise UsageError(
                f"Approval '{approval_id}' not found",
                action="List pending approvals with: rebel-profiler approval list <case-id>",
            )
        return self._row_to_dict(row)

    def list(self, case_id: str, state: str | None = "pending") -> list[dict]:
        return [self._row_to_dict(row) for row in self._db.approvals_for(case_id, state)]

    def decide(
        self,
        approval_id: str,
        decision: str,
        *,
        decided_by: str,
    ) -> dict:
        """Approve or deny one pending request. Returns the resolved record."""
        if decision not in {"approve", "deny", "cancel"}:
            raise UsageError(
                f"Unknown approval decision '{decision}'",
                reason="Decisions are: approve, deny, cancel.",
            )
        record = self.get(approval_id)
        if record["state"] != "pending":
            raise StateError(
                f"Approval '{approval_id}' is already '{record['state']}'",
                reason="Only pending approvals can be decided.",
            )
        state = {"approve": "approved", "deny": "denied", "cancel": "cancelled"}[decision]
        self._db.set_approval_state(approval_id, state, decided_by=decided_by)
        record["state"] = state
        record["decided_by"] = decided_by
        self._audit_append(record["case_id"], f"approval.{state}", record["action"],
                           {"approval_id": approval_id, "by": decided_by,
                            "task_id": record["task_id"]})
        return record

    def load_argv(self, approval_id: str) -> list[str]:
        raw = self._db.get_meta(f"approval_argv:{approval_id}")
        if not raw:
            raise StateError(
                f"Stored argv for approval '{approval_id}' is missing",
                reason="The queued approval has no executable record.",
                action="Re-request the action so a fresh approval is queued.",
            )
        argv = json.loads(raw)
        if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
            raise StateError(f"Corrupt argv record for approval '{approval_id}'")
        return argv

    def load_params(self, approval_id: str) -> dict:
        raw = self._db.get_meta(f"approval_params:{approval_id}") or "{}"
        params = json.loads(raw)
        if not isinstance(params, dict):
            raise StateError(f"Corrupt params record for approval '{approval_id}'")
        return params

    @staticmethod
    def _row_to_dict(row) -> dict:
        return {
            "id": row["id"],
            "case_id": row["case_id"],
            "task_id": row["task_id"],
            "action": row["action"],
            "target": row["target"],
            "risk": row["risk"],
            "reasons": row["reasons"],
            "requested_by": row["requested_by"],
            "state": row["state"],
            "decided_by": row["decided_by"],
            "decided_at": row["decided_at"],
            "created_at": row["created_at"],
        }
