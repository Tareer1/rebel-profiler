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


def test_host_entry_authorizes_its_urls():
    # Web actions are spoken in URLs while scope speaks in hosts: an
    # authorized host must cover its pages (found live on a real target).
    scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
    scope.add("www.hplovecraft.com")
    allowed, matched = scope.check("https://www.hplovecraft.com/creation/tomes.aspx")
    assert allowed and matched == "www.hplovecraft.com"


def test_url_matching_is_host_scoped_and_fail_closed():
    # Scope decides WHO (host); policy decides WHAT (scheme/capability).
    # A different host stays out even under the same scheme, and a
    # lookalike suffix can never ride on an authorized name.
    scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
    scope.add("www.hplovecraft.com")
    assert scope.check("https://www.hplovecraft.com/tomes")[0]
    for stranger in ("https://evil.example.com/tomes",
                     "www.hplovecraft.com.evil.test/",
                     "https://hplovecraft.com/"):   # apex not authorized here
        status, _ = scope.decision(stranger)
        assert status != "in_scope", stranger


def test_wildcard_entry_authorizes_url_paths():
    scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
    scope.add("*.lab.example.test")
    allowed, _ = scope.check("https://host1.lab.example.test/deep/path?q=1#frag")
    assert allowed


def test_url_pattern_matches_by_host():
    # A URL-shaped scope entry is compared by its host, so entries pasted
    # from a browser bar still authorize the site's pages.
    scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
    scope.add("https://www.hplovecraft.com/creation/tomes.aspx")
    allowed, _ = scope.check("https://www.hplovecraft.com/creation/tomes.aspx")
    assert allowed
    allowed, _ = scope.check("https://www.hplovecraft.com/writing/fiction.aspx")
    assert allowed
