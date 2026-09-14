"""Error taxonomy and exit-code contract tests (PDF 3 section 36)."""

from __future__ import annotations

import pytest

from rebel_profiler.core.errors import (
    EXIT_SCOPE,
    EXIT_USAGE,
    RPError,
    ScopeViolationError,
    UsageError,
)


def test_all_errors_are_rprerrors():
    for exc_cls in (UsageError, ScopeViolationError):
        assert issubclass(exc_cls, RPError)


def test_exit_codes_are_distinct_and_stable():
    assert UsageError.exit_code == EXIT_USAGE
    assert ScopeViolationError.exit_code == EXIT_SCOPE
    assert UsageError.exit_code != ScopeViolationError.exit_code


def test_render_includes_what_why_action():
    err = UsageError("bad input", reason="missing field", action="provide --name")
    text = err.render()
    assert "bad input" in text
    assert "missing field" in text
    assert "provide --name" in text


@pytest.mark.parametrize(
    "exc_cls",
    [RPError, UsageError, ScopeViolationError],
)
def test_render_never_crashes(exc_cls):
    err = exc_cls("boom")
    assert isinstance(err.render(), str)
