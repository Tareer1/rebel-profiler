"""Scope engine tests: fail-closed authorization boundary (PDF 17)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from rebel_profiler.core.errors import ScopeViolationError
from rebel_profiler.security.scope import Scope, ScopeEngine, ScopeStatus


def test_exact_match_in_scope():
    scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
    scope.add("lab.example.test")
    allowed, matched = scope.check("lab.example.test")
    assert allowed and matched == "lab.example.test"


def test_wildcard_match():
    scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
    scope.add("*.lab.example.test")
    allowed, _ = scope.check("host1.lab.example.test")
    assert allowed


def test_wildcard_matches_apex():
    scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
    scope.add("*.lab.example.test")
    allowed, _ = scope.check("lab.example.test")
    assert allowed


def test_exclusion_wins_over_include():
    scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
    scope.add("*.lab.example.test")
    scope.add("admin.lab.example.test", excluded=True)
    allowed, _ = scope.check("admin.lab.example.test")
    assert not allowed


def test_draft_scope_never_authorizes():
    scope = Scope(case_id="c1", status=ScopeStatus.DRAFT)
    scope.add("lab.example.test")
    allowed, _ = scope.check("lab.example.test")
    assert not allowed


def test_expired_entry_never_authorizes():
    scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
    scope.add("lab.example.test", expires_at=datetime.now(timezone.utc) - timedelta(hours=1))
    allowed, _ = scope.check("lab.example.test")
    assert not allowed


def test_future_expiry_authorizes():
    scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
    scope.add("lab.example.test", expires_at=datetime.now(timezone.utc) + timedelta(days=1))
    allowed, _ = scope.check("lab.example.test")
    assert allowed


def test_empty_scope_is_out_of_scope_not_unknown():
    scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
    status, _ = scope.decision("anything.test")
    assert status == "out_of_scope"


def test_nonempty_scope_unknown_target_is_unknown():
    scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
    scope.add("lab.example.test")
    status, _ = scope.decision("other.test")
    assert status == "unknown"


def test_engine_validate_raises_for_unknown_case():
    engine = ScopeEngine()
    with pytest.raises(ScopeViolationError):
        engine.validate("nope", "host.test")


def test_engine_validate_fails_closed(scoped_engine):
    with pytest.raises(ScopeViolationError):
        scoped_engine.validate("case1", "evil.example.com")


def test_engine_validate_canonicalizes(scoped_engine):
    canonical = scoped_engine.validate("case1", "Host1.Lab.Example.Test.")
    assert canonical == "host1.lab.example.test"
