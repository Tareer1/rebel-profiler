"""Tests for the controlled exec-tool adapter."""

from __future__ import annotations

import pytest

from rebel_profiler.agent import AgentSession, Proposal
from rebel_profiler.core.errors import PermissionDeniedError, UsageError
from rebel_profiler.evidence.store import EvidenceStore
from rebel_profiler.execution import AdapterRegistry, ToolExecAdapter
from rebel_profiler.execution.broker import ActionRequest, ExecutionBroker
from rebel_profiler.intel.claims import ClaimLedger
from rebel_profiler.intel.sources import SourceRegistry
from rebel_profiler.security.scope import Scope, ScopeEngine, ScopeStatus
from rebel_profiler.storage.database import Database


def make_request(target="h1.lab.example.test", **params):
    params.setdefault("tool", "nmap")
    params.setdefault("args", ["-sT", "-Pn", "-p", "80"])
    return ActionRequest(case_id="c1", capability="active_recon",
                         action="exec-tool", target=target, params=params)


@pytest.fixture()
def env(tmp_path):
    db = Database(tmp_path / "case.db")
    db.migrate()
    db.create_case("c1", case_id="c1")
    store = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
    scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
    scope.add("*.lab.example.test")
    engine = ScopeEngine()
    engine.register(scope)
    broker = ExecutionBroker(db, scope_engine=engine, evidence=store,
                             confirm=lambda r, g: True, approve=lambda r, g: True,
                             runner=lambda argv: (0, "tool output\n", ""))
    return db, store, broker


class TestWhitelist:
    def test_whitelisted_tool_builds_argv(self):
        argv = ToolExecAdapter().build_argv(make_request())
        assert argv[0] == "nmap"
        assert "-sT" in argv and "-p" in argv and "80" in argv
        assert argv[-1] == "h1.lab.example.test"

    def test_unknown_tool_rejected(self):
        with pytest.raises(UsageError):
            ToolExecAdapter().build_argv(make_request(tool="sh"))

    def test_shell_interpreters_never_whitelisted(self):
        for bad in ("sh", "bash", "zsh", "python", "python3", "perl",
                    "curl", "wget", "nc", "ncat", "socat"):
            with pytest.raises(UsageError):
                ToolExecAdapter().build_argv(make_request(tool=bad))

    def test_tool_required(self):
        with pytest.raises(UsageError):
            ToolExecAdapter().build_argv(make_request(tool=""))


class TestFlagValidation:
    def test_unknown_flag_rejected(self):
        with pytest.raises(UsageError):
            ToolExecAdapter().build_argv(
                make_request(args=["--script", "malicious"]))

    def test_dangrous_flags_rejected(self):
        for flag in ("-e", "-iL", "-oG", "--datadir"):
            with pytest.raises(UsageError):
                ToolExecAdapter().build_argv(make_request(args=[flag, "x"]))

    def test_value_flag_requires_value(self):
        with pytest.raises(UsageError):
            ToolExecAdapter().build_argv(make_request(args=["-p"]))

    def test_metacharacters_rejected(self):
        for evil in ("80; rm -rf /", "$(id)", "`id`", "a&b", "a|b"):
            with pytest.raises(UsageError):
                ToolExecAdapter().build_argv(
                    make_request(args=["-p", evil]))

    def test_dig_flag_set(self):
        argv = ToolExecAdapter().build_argv(
            make_request(target="lab.example.test", tool="dig",
                         args=["+short", "-t", "MX"]))
        assert argv == ["dig", "+short", "-t", "MX", "lab.example.test"]

    def test_url_tool_requires_url_target(self):
        with pytest.raises(UsageError):
            ToolExecAdapter().build_argv(
                make_request(target="h1.lab.example.test", tool="nikto",
                             args=["-port", "80"]))

    def test_url_tool_accepts_url(self):
        argv = ToolExecAdapter().build_argv(
            make_request(target="https://h1.lab.example.test", tool="nikto",
                         args=["-port", "80"]))
        assert argv[0] == "nikto"
        assert argv[-1] == "https://h1.lab.example.test"


class TestBrokerGates:
    def test_executes_with_approval(self, env):
        db, store, broker = env
        request = make_request()
        result = broker.execute(request)
        assert result.outcome == "succeeded"
        assert result.decision.outcome.value == "allow_with_approval"
        assert result.evidence_id

    def test_out_of_scope_target_denied(self, env):
        _, _, broker = env
        with pytest.raises(Exception) as exc:
            broker.execute(make_request(target="evil.test"))
        assert "not authorized" in str(exc.value) or "Scope" in type(exc.value).__name__

    def test_without_approver_cancelled(self, tmp_path):
        db = Database(tmp_path / "case.db")
        db.migrate()
        db.create_case("c1", case_id="c1")
        store = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
        scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
        scope.add("*.lab.example.test")
        engine = ScopeEngine()
        engine.register(scope)
        broker = ExecutionBroker(db, scope_engine=engine, evidence=store,
                                 runner=lambda argv: (0, "out", ""))
        result = broker.execute(make_request())
        assert result.outcome == "cancelled"
        assert result.decision.outcome.value == "allow_with_approval"

    def test_argv_in_audit(self, env):
        db, store, broker = env
        broker.execute(make_request())
        events = [e.as_dict() for e in __import__(
            "rebel_profiler.evidence.audit", fromlist=["AuditChain"]
        ).AuditChain(db).events("c1")]
        dispatched = [e for e in events if e["action"] == "action.dispatched"]
        assert dispatched and dispatched[0]["detail"]["argv"][0] == "nmap"


NMAP_OUT = (
    "Starting Nmap 7.99 ( https://nmap.org )\n"
    "Nmap scan report for h1.lab.example.test (10.0.0.9)\n"
    "PORT      STATE SERVICE\n80/tcp open  http\n"
)


class TestAgentIntegration:
    def test_agent_proposes_exec_tool(self, env):
        db, store, broker = env
        session = AgentSession("c1", "run nmap on the lab host", broker=broker,
                               ledger=ClaimLedger(SourceRegistry()),
                               evidence=store, db=db)
        result = session.run(lambda view: [
            Proposal(action="exec-tool", target="h1.lab.example.test",
                     params={"tool": "nmap", "args": ["-sT", "-Pn", "-p", "80"]}),
        ])
        assert result["steps"][0]["outcome"] == "succeeded"

    def test_exec_tool_nmap_output_becomes_claims(self, tmp_path):
        """exec-tool wrapping nmap parses into port/ip claims (full loop)."""
        db = Database(tmp_path / "case.db")
        db.migrate()
        db.create_case("c1", case_id="c1")
        store = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
        scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
        scope.add("*.lab.example.test")
        engine = ScopeEngine()
        engine.register(scope)
        broker = ExecutionBroker(db, scope_engine=engine, evidence=store,
                                 confirm=lambda r, g: True, approve=lambda r, g: True,
                                 runner=lambda argv: (0, NMAP_OUT, ""))
        session = AgentSession("c1", "scan the lab host", broker=broker,
                               ledger=ClaimLedger(SourceRegistry()),
                               evidence=store, db=db)
        result = session.run(lambda view: [
            Proposal(action="exec-tool", target="h1.lab.example.test",
                     params={"tool": "nmap", "args": ["-sT", "-Pn", "-p", "80"]}),
        ])
        step = result["steps"][0]
        assert step["outcome"] == "succeeded"
        kinds = {c["kind"] for c in step["claims"]}
        assert {"ip", "port", "service"} <= kinds
        rows = db.claims_for("c1", "h1.lab.example.test")
        assert rows  # persisted

    def test_agent_cannot_propose_nonwhitelisted_tool(self, env):
        db, store, broker = env
        session = AgentSession("c1", "goal", broker=broker,
                               ledger=ClaimLedger(SourceRegistry()),
                               evidence=store, db=db)
        result = session.run(lambda view: [
            Proposal(action="exec-tool", target="h1.lab.example.test",
                     params={"tool": "bash", "args": []}),
        ])
        # the proposal fails at argv build → step error, never execution
        assert result["steps"][0]["outcome"] in {"error", "denied"}

    def test_registered(self):
        assert "exec-tool" in AdapterRegistry().names()


class TestRunnerIsNotShell:
    def test_default_runner_never_uses_shell(self):
        """The default runner must invoke argv directly, no shell=True."""
        import inspect

        from rebel_profiler.execution.broker import ExecutionBroker as B

        source = inspect.getsource(B._default_runner)
        assert "shell" not in source
        assert "subprocess.run" in source
