"""Shared fixtures for Rebel Profiler tests."""

from __future__ import annotations

import pytest

from rebel_profiler.security.scope import Scope, ScopeEngine, ScopeStatus
from rebel_profiler.storage.database import Database


@pytest.fixture()
def db(tmp_path):
    database = Database(tmp_path / "case.db")
    database.migrate()
    yield database
    database.close()


@pytest.fixture()
def scoped_engine():
    """A scope engine with one active case authorizing *.lab.example.test."""
    scope = Scope(case_id="case1", status=ScopeStatus.ACTIVE)
    scope.add("*.lab.example.test", note="authorized lab range")
    scope.add("*.lab.example.test:5555.excluded.example.test", excluded=True)
    engine = ScopeEngine()
    engine.register(scope)
    return engine
