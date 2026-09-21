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


def _host_of(value: str) -> str | None:
    """Extract the host from a URL-ish string; ``None`` when it has none.

    Handles scheme, userinfo, port, path/query/fragment and bracketed IPv6
    literals. Bare ``host/path`` forms (no scheme) yield the host too.
    """
    if "://" in value:
        value = value.split("://", 1)[1]
    host = value.split("/", 1)[0]
    host = host.split("?", 1)[0].split("#", 1)[0]
    host = host.rsplit("@", 1)[-1]
    host = host.split(":", 1)[0].strip().strip("[]")
    return host or None


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

        URL candidates are reduced to their host: for web actions operators
        (and the LLM) naturally speak in URLs while scope speaks in hosts,
        and authorizing ``www.example.test`` must cover its pages. A URL
        *pattern* is likewise compared by its host. Reduction applies only
        to ``://``-bearing strings — bare host-like entries (including
        port-suffix trick strings used as exclusions) keep their exact
        literal/fnmatch meaning. The candidate itself never grants anything
        a host match would not — fail-closed holds.
        """
        candidate = candidate.strip().lower().rstrip(".")
        pattern = self.value.strip().lower().rstrip(".")
        targets = [candidate]
        patterns = [pattern]
        if "://" in candidate:
            cand_host = _host_of(candidate)
            if cand_host:
                targets.append(cand_host)
        if "://" in pattern:
            patt_host = _host_of(pattern)
            if patt_host:
                patterns.append(patt_host)
        for target in targets:
            for pat in patterns:
                if target == pat or fnmatch.fnmatch(target, pat):
                    return True
                # "*.example.test" style pattern also matches "example.test"
                if pat.startswith("*.") and target == pat[2:]:
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
