"""Case RBAC: owner / operator / viewer (Phase 4, PDF 11).

Roles are stored per case in SQLite and enforced by the broker before any
execution gate:

  * ``owner``    — full control: scope, members, approvals, execution
  * ``operator`` — may propose/execute actions and work the approval queue,
                   but may not change membership
  * ``viewer``   — read-only; any execution attempt by a viewer is denied

Enforcement rules (deterministic):

  * A case with **no** members at all is operated in "single-operator" mode:
    the local CLI user is implicitly an operator. This keeps existing
    single-user workflows working while multi-user cases get strict checks.
  * Once membership exists, every execution actor must hold ``operator`` or
    ``owner``; viewers are denied with a structured, audited error.
  * Only ``owner`` may change membership. Only ``owner``/``operator`` may
    decide pending approvals.

The engine reads only from the database — never from LLM output — so role
decisions are as deterministic as the policy engine itself.
"""

from __future__ import annotations

import time
import uuid

from ..core.errors import PermissionDeniedError, UsageError
from ..storage.database import Database

ROLES = ("owner", "operator", "viewer")

# role -> allowed capabilities
_ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "owner": frozenset({
        "execute", "confirm", "approve", "manage_members", "manage_scope",
        "manage_credentials", "manage_plugins", "view",
    }),
    "operator": frozenset({
        "execute", "confirm", "approve", "view",
    }),
    "viewer": frozenset({"view"}),
}


def permissions_for(role: str) -> frozenset[str]:
    if role not in _ROLE_PERMISSIONS:
        return frozenset()
    return _ROLE_PERMISSIONS[role]


class RoleEngine:
    """Deterministic role resolution + permission checks for one case."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def role_of(self, case_id: str, subject: str) -> str:
        return self._db.member_role(case_id, subject)

    def is_empty(self, case_id: str) -> bool:
        return not self._db.members(case_id)

    def effective_role(self, case_id: str, subject: str) -> str:
        """Resolve the role, honouring single-operator mode.

        Empty membership ⇒ implicit operator (local CLI user). Unknown
        subject in a populated case ⇒ viewer (fail closed: read-only).
        """
        if not subject:
            return "viewer"
        role = self.role_of(case_id, subject)
        if role:
            return role
        if self.is_empty(case_id):
            return "operator"
        return "viewer"

    def require(self, case_id: str, subject: str, permission: str) -> str:
        """Return the effective role or raise PermissionDeniedError."""
        role = self.effective_role(case_id, subject)
        if permission in permissions_for(role):
            return role
        raise PermissionDeniedError(
            f"Role '{role or 'none'}' lacks permission '{permission}'"
            f" on case {case_id}",
            reason=f"Effective role for '{subject or 'anonymous'}' is"
                   f" '{role or 'none'}' (members exist: {not self.is_empty(case_id)}).",
            action="Ask a case owner for the required role"
                   " (rebel-profiler case member add <case> <subject> <role>).",
        )

    def can(self, case_id: str, subject: str, permission: str) -> bool:
        role = self.effective_role(case_id, subject)
        return permission in permissions_for(role)


class MemberManager:
    """Membership administration — owner-only operations, audit-logged."""

    def __init__(self, db: Database, audit=None, actor: str = "operator") -> None:
        self._db = db
        self._audit = audit
        self._actor = actor

    def _audit_append(self, case_id: str, action: str, subject: str, detail: dict) -> None:
        if self._audit is not None:
            self._audit.append(case_id, actor=self._actor, action=action,
                               subject=subject, detail=detail)

    def add(self, case_id: str, subject: str, role: str, *, actor: str | None = None) -> int:
        actor = actor or self._actor
        if role not in ROLES:
            raise UsageError(
                f"Unknown role '{role}'",
                reason=f"Roles are: {', '.join(ROLES)}.",
                action="Pick owner, operator or viewer.",
            )
        subject = subject.strip().lower()
        if not subject:
            raise UsageError("Member subject must be a non-empty identifier")
        if self._db.member_role(case_id, subject) == "owner" and role != "owner" \
                and self._db.has_owner(case_id) \
                and sum(1 for m in self._db.members(case_id) if m["role"] == "owner") == 1:
            raise UsageError(
                "Cannot demote the only owner",
                reason="Every populated case must keep at least one owner.",
                action="Promote another member to owner first.",
            )
        member_id = self._db.add_member(case_id, subject, role)
        self._audit_append(case_id, "member.added", subject,
                           {"role": role, "by": actor})
        return member_id

    def remove(self, case_id: str, subject: str, *, actor: str | None = None) -> None:
        actor = actor or self._actor
        subject = subject.strip().lower()
        if self._db.member_role(case_id, subject) == "owner" \
                and sum(1 for m in self._db.members(case_id) if m["role"] == "owner") == 1:
            raise UsageError(
                "Cannot remove the only owner",
                reason="Every populated case must keep at least one owner.",
                action="Promote another member to owner first.",
            )
        self._db.remove_member(case_id, subject)
        self._audit_append(case_id, "member.removed", subject, {"by": actor})

    def list(self, case_id: str) -> list[dict]:
        return [
            {"subject": row["subject"], "role": row["role"],
             "created_at": row["created_at"]}
            for row in self._db.members(case_id)
        ]
