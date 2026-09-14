"""Scope model and enforcement.

A scope is the set of targets an authorized case is allowed to touch.
Explicit exclusions always win over broad include rules, and scope entries
can expire (authorization windows).
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from ..core.errors import ScopeViolationError


class ScopeStatus(str, Enum):
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    ACTIVE = "active"
    EXPIRING = "expiring"
    EXPIRED = "expired"
    SUSPENDED = "suspended"
    CLOSED = "closed"


@dataclass
class ScopeEntry:
    """A single authorized (or excluded) target pattern."""

    value: str
    excluded: bool = False
    expires_at: datetime | None = None
    note: str = ""

    def matches(self, candidate: str) -> bool:
        """Match *candidate* against this entry.

        Supports exact match, wildcard (``*.example.test``) and ``*.`` suffix
        forms. Comparison is case-insensitive.
        """
        candidate = candidate.strip().lower().rstrip(".")
        pattern = self.value.strip().lower().rstrip(".")
        if candidate == pattern:
            return True
        if fnmatch.fnmatch(candidate, pattern):
            return True
        # "*.example.test" style pattern also matches "example.test"
        if pattern.startswith("*.") and candidate == pattern[2:]:
            return True
        return False


@dataclass
class Scope:
    case_id: str
    status: ScopeStatus = ScopeStatus.DRAFT
    entries: list[ScopeEntry] = field(default_factory=list)

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def is_expired(self, entry: ScopeEntry) -> bool:
        return entry.expires_at is not None and entry.expires_at <= self.now()

    def add(self, value: str, *, excluded: bool = False, expires_at=None, note: str = "") -> ScopeEntry:
        entry = ScopeEntry(value=value, excluded=excluded, expires_at=expires_at, note=note)
        self.entries.append(entry)
        return entry

    def decision(self, target: str) -> tuple[str, str]:
        """Return ``(status, matched_value)`` for *target*.

        Status is one of ``in_scope``, ``out_of_scope``, ``unknown``.
        Exclusions win; expired entries never authorize.
        """
        target = target.strip().lower().rstrip(".")
        included: str | None = None
        for entry in self.entries:
            if entry.excluded and entry.matches(target):
                return "out_of_scope", entry.value
        for entry in self.entries:
            if entry.excluded:
                continue
            if self.is_expired(entry):
                continue
            if entry.matches(target):
                included = entry.value
                break
        if included is not None:
            return "in_scope", included
        if self.entries:
            return "unknown", ""
        return "out_of_scope", ""

    def check(self, target: str) -> tuple[bool, str]:
        status, matched = self.decision(target)
        if status == "in_scope" and self.status is ScopeStatus.ACTIVE:
            return True, matched
        return False, matched or status


class ScopeEngine:
    """Runtime gate for target validation.

    ``fail closed``: if the engine cannot positively confirm a target is in an
    active scope, the action is blocked.
    """

    def __init__(self, scopes: dict[str, Scope] | None = None) -> None:
        self._scopes: dict[str, Scope] = scopes or {}

    def register(self, scope: Scope) -> None:
        self._scopes[scope.case_id] = scope

    def get(self, case_id: str) -> Scope | None:
        return self._scopes.get(case_id)

    def validate(self, case_id: str, target: str) -> str:
        """Return the canonical target when in scope, else raise."""
        scope = self._scopes.get(case_id)
        if scope is None:
            raise ScopeViolationError(
                f"No scope is registered for case {case_id}",
                reason="The active case has no authorized scope definition.",
                action="Define scope with: rebel-profiler case scope <case-id>",
            )
        allowed, matched = scope.check(target)
        if not allowed:
            status, _ = scope.decision(target)
            raise ScopeViolationError(
                f"Target '{target}' is not authorized in case {case_id}",
                reason=f"Scope evaluation result: {status}.",
                action="Add the target to the case scope through the required authorization process.",
            )
        return target.strip().lower().rstrip(".")

    def evaluate(self, case_id: str, target: str) -> str:
        """Non-raising evaluation used for planning/dry-run: returns a status string."""
        scope = self._scopes.get(case_id)
        if scope is None:
            return "no_scope"
        status, _ = scope.decision(target)
        return status
