"""Execution broker tests: the gate sequence is the contract."""

from __future__ import annotations

import pytest

from rebel_profiler.core.errors import (
    DependencyUnavailableError,
    PermissionDeniedError,
    ScopeViolationError,
    UsageError,
)
from rebel_profiler.evidence import AuditChain
from rebel_profiler.execution import ActionRequest, ExecutionBroker
from rebel_profiler.storage.database import Database


@pytest.fixture()
def broker(db, scoped_engine):
    db.create_case("Case 1", case_id="case1")  # satisfy case FK
    return ExecutionBroker(
        db,
        scope_engine=scoped_engine,
        confirm=lambda r, g: True,
        approve=lambda r, g: True,
        runner=lambda argv: (0, " ".join(argv), ""),
    )


def make_request(**overrides) -> ActionRequest:
    base = dict(
        case_id="case1",
        capability="discovery",
        action="host-discovery",
        target="host1.lab.example.test",
        params={"mode": "discover"},
    )
    base.update(overrides)
    return ActionRequest(**base)


class TestGates:
    def test_out_of_scope_is_blocked(self, broker):
        with pytest.raises(ScopeViolationError):
            broker.execute(make_request(target="evil.example.com"))

    def test_no_scope_registered_blocks(self, db):
        broker = ExecutionBroker(db, runner=lambda a: (0, "", ""))
        with pytest.raises(ScopeViolationError):
            broker.execute(make_request())

    def test_unknown_action_rejected_no_fake_adapters(self, broker):
        with pytest.raises(UsageError):
            broker.plan(make_request(action="ghost-scan"))

    def test_rogue_params_rejected(self, broker):
        with pytest.raises(UsageError):
            broker.plan(make_request(params={"extra": "-oG /tmp/pwn"}))

    def test_missing_required_params_rejected(self, broker):
        # exploit-validation adapter requires nothing, so use a custom check:
        from rebel_profiler.execution.broker import PassiveDnsAdapter

        adapter = PassiveDnsAdapter()
        with pytest.raises(UsageError):
            adapter.build_argv(make_request(action="dns-lookup", params={"record_type": "A; x"}))


class TestExecution:
    def test_dry_run_never_runs(self, broker):
        result = broker.execute(make_request(), dry_run=True)
        assert result.outcome == "dry_run"
        assert result.returncode is None
        assert "nmap" in result.stdout

    def test_successful_execution_registers_evidence(self, broker, db):
        result = broker.execute(make_request())
        assert result.outcome == "succeeded"
        assert result.evidence_id
        count = db.conn.execute("SELECT COUNT(*) c FROM evidence_records").fetchone()["c"]
        assert count == 1

    def test_output_is_redacted(self, broker):
        result = broker.execute(
            make_request(action="echo", capability="info", params={"message": "password=supersecret9"})
        )
        assert "supersecret9" not in result.stdout
        assert "[REDACTED]" in result.stdout

    def test_audit_trail_records_lifecycle(self, broker, db):
        broker.execute(make_request())
        actions = [
            r["action"]
            for r in db.conn.execute("SELECT action FROM audit_events ORDER BY seq")
        ]
        assert "action.requested" in actions
        assert "action.dispatched" in actions
        assert "action.completed" in actions

class TestFailurePaths:
    def test_failed_tool_run_is_failed(self, db, scoped_engine):
        db.create_case("Case 1", case_id="case1")
        broker = ExecutionBroker(
            db, scope_engine=scoped_engine,
            confirm=lambda r, g: True, approve=lambda r, g: True,
            runner=lambda argv: (2, "", "boom"),
        )
        result = broker.execute(make_request())
        assert result.outcome == "failed"
        assert result.returncode == 2

    def test_missing_binary_raises_dependency_error(self, db, scoped_engine):
        from rebel_profiler.execution.broker import Adapter

        db.create_case("Case 1", case_id="case1")

        class GhostAdapter(Adapter):
            name = "ghost"
            binary = "definitely-not-installed-binary-xyz"
            capability_class = "passive_recon"
            allowed_params = ()

            def build_argv(self, request):
                return [self.binary]

        broker = ExecutionBroker(db, scope_engine=scoped_engine)
        broker._adapters.register(GhostAdapter())
        request = make_request(action="ghost", capability="passive_recon", params={})
        with pytest.raises(DependencyUnavailableError):
            broker.execute(request)


class TestPolicyDenial:
    def test_denied_critical_capability(self, db, scoped_engine):
        from rebel_profiler.execution.broker import Adapter

        db.create_case("Case 1", case_id="case1")

        class DoomAdapter(Adapter):
            name = "doom"
            binary = "doom"
            capability_class = "exploit_validation"
            allowed_params = ()

            def build_argv(self, request):
                return [self.binary]

        broker = ExecutionBroker(db, scope_engine=scoped_engine)
        broker._adapters.register(DoomAdapter())
        with pytest.raises(PermissionDeniedError):
            broker.execute(make_request(action="doom", capability="exploit_validation", params={}))
        # denial was audited
        actions = [r["action"] for r in db.conn.execute("SELECT action FROM audit_events")]
        assert "action.denied" in actions


class TestRefusals:
    def test_confirmation_refusal_cancels(self, db, scoped_engine):
        db.create_case("Case 1", case_id="case1")
        broker = ExecutionBroker(
            db, scope_engine=scoped_engine,
            confirm=lambda r, g: False, approve=lambda r, g: True,
            runner=lambda argv: (0, "", ""),
        )
        result = broker.execute(make_request())
        assert result.outcome == "cancelled"
        task = db.get_task(result.task_id)
        assert task["state"] == "cancelled"
