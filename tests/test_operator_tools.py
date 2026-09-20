"""Tests for the Hermes operator tools + the `hermes` front-door command.

The operator tools are what turn the CLI into a prompting surface: the
model must be able to create/activate cases, authorize targets, read
claims, generate reports, verify chains and reach the browser bridge — all
by tool call, all through the same gated machinery the CLI uses.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from rebel_profiler.cli.context import AppContext
from rebel_profiler.cli.main import _resolve_session_case, cmd_hermes
from rebel_profiler.llm import operator_tools as ot
from rebel_profiler.llm.hermes import (
    HermesAgentLoop,
    build_system_prompt,
    operator_tool_count,
)
from rebel_profiler.llm.budget import DEFAULT_LIMITS
from rebel_profiler.llm.operator_tools import OPERATOR_TOOLS, operator_schemas
from rebel_profiler.llm.inference import ModelPlane
from rebel_profiler.security.scope import Scope, ScopeEngine, ScopeStatus


# ---------------------------------------------------------------- helpers


class ScriptedEngine:
    kind = "scripted"
    loaded = True
    model_id = "scripted"

    def load(self):
        pass

    def unload(self):
        pass


class ScriptedPlane(ModelPlane):
    """Replays scripted replies; records prompts."""

    def __init__(self, replies):
        super().__init__(limits=DEFAULT_LIMITS["mid"])
        self.replies = list(replies)
        self.prompts = []
        self._engine = ScriptedEngine()
        self._engine_kind = "scripted"
        self._fallback_reason = "scripted test double"

    def generate(self, prompt, **kwargs):
        self.prompts.append(prompt)
        text = self.replies.pop(0) if self.replies else ""
        from rebel_profiler.llm.inference import GenerationResult

        return GenerationResult(text=text, engine="scripted", model="scripted",
                                input_tokens=1, output_tokens=1, elapsed_s=0.0,
                                peak_rss_mb=0.0, device="cpu")


@pytest.fixture()
def ws(tmp_path):
    """A real workspace: AppContext + one draft case + its open database."""
    ctx = AppContext(data_dir=tmp_path)
    rec = ctx.create_case("ops case", "from tests")
    db = ctx.open_case(rec["id"])
    return ctx, db, rec


def call(ctx, db, case_id, tool, **args):
    return ot.execute(ctx, db, case_id, tool, args)


# ---------------------------------------------------------------- registry


class TestRegistry:
    def test_expected_surface_exists(self):
        names = set(OPERATOR_TOOLS)
        assert {"case_list", "case_create", "scope_add", "scope_show",
                "case_activate", "claims_list", "report_generate",
                "evidence_verify", "audit_verify", "surface_map",
                "surface_build", "fusion_report", "case_search",
                "knowledge_search", "glossary", "browser_grab",
                "system_status"} <= names

    def test_schemas_are_valid_function_schemas(self):
        for schema in operator_schemas():
            fn = schema["function"]
            assert fn["name"] and fn["description"]
            assert schema["type"] == "function"
            required = set(fn["parameters"]["required"])
            assert required <= set(fn["parameters"]["properties"]), fn["name"]

    def test_merged_system_prompt_offers_both_planes(self, ws):
        from rebel_profiler.execution import AdapterRegistry

        prompt = build_system_prompt(
            operator_schemas() + [
                s for s in __import__(
                    "rebel_profiler.llm.hermes", fromlist=["tool_schema"]
                ).tool_schema(AdapterRegistry())])
        assert "scope_add" in prompt and "dns-lookup" in prompt
        assert "<tools>" in prompt

    def test_operator_tool_count_matches_registry(self):
        assert operator_tool_count() == len(OPERATOR_TOOLS)


# ---------------------------------------------------------------- validation


class TestValidateAndDispatch:
    def test_unknown_param_rejected(self, ws):
        ctx, db, rec = ws
        out = call(ctx, db, rec["id"], "case_list", bogus="1")
        assert out["error"] is True
        assert "undeclared params" in out["message"]

    def test_missing_required_rejected(self, ws):
        ctx, db, rec = ws
        out = call(ctx, db, rec["id"], "scope_add")
        assert out["error"] is True
        assert "scope_add" in out["message"]

    def test_unknown_tool_structured(self, ws):
        ctx, db, rec = ws
        out = call(ctx, db, rec["id"], "ghost-tool")
        assert out["error"] is True
        assert "unknown operator tool" in out["message"]

    def test_payloads_are_bounded(self, ws):
        ctx, db, rec = ws
        long = "A" * 10_000
        db.add_scope_entry(rec["id"], long, note=long)
        out = call(ctx, db, rec["id"], "scope_show")
        text = json.dumps(out)
        assert len(text) < 20_000


# ---------------------------------------------------------------- handlers


class TestCaseTools:
    def test_case_list_reports_active(self, ws):
        ctx, db, rec = ws
        ctx.set_case_status(rec["id"], "active")
        out = call(ctx, db, rec["id"], "case_list")
        assert any(c["id"] == rec["id"] for c in out["cases"])
        assert out["active_case"] == rec["id"]

    def test_scope_add_authorizes_and_activates(self, ws):
        ctx, db, rec = ws
        assert rec["status"] == "draft"
        out = call(ctx, db, rec["id"], "scope_add", value="*.lab.example.test")
        assert out["case_status"] == "active"
        entries = [dict(r) for r in db.scope_entries(rec["id"])]
        assert any(e["value"] == "*.lab.example.test" and not e["excluded"]
                   for e in entries)
        # the workspace index now says active too
        assert ctx.find_case(rec["id"])["status"] == "active"

    def test_scope_add_exclusion_keeps_status(self, ws):
        ctx, db, rec = ws
        out = call(ctx, db, rec["id"], "scope_add", value="admin.lab.test",
                   exclude="true")
        assert "unchanged" in out["case_status"]
        assert any(e["value"] == "admin.lab.test" and e["excluded"]
                   for e in out["entries"])

    def test_case_create_then_activate(self, ws):
        ctx, db, rec = ws
        out = call(ctx, db, rec["id"], "case_create", name="second job")
        new_id = out["case"]["id"]
        assert out["case"]["status"] == "draft"
        out = call(ctx, ctx.open_case(new_id), new_id, "case_activate")
        assert out["status"] == "active"


class TestAnalysisTools:
    def test_claims_report_and_chains_on_empty_case(self, ws):
        ctx, db, rec = ws
        claims = call(ctx, db, rec["id"], "claims_list")
        assert claims["count"] == 0
        report = call(ctx, db, rec["id"], "report_generate")
        assert "report" in report and report["case"] == rec["id"]
        ev = call(ctx, db, rec["id"], "evidence_verify")
        assert ev["chain_ok"] is True
        au = call(ctx, db, rec["id"], "audit_verify")
        assert au["chain_ok"] is True

    def test_surface_and_fusion_are_structured_on_empty(self, ws):
        ctx, db, rec = ws
        sm = call(ctx, db, rec["id"], "surface_map")
        assert "stats" in sm or "hosts" in sm
        sb = call(ctx, db, rec["id"], "surface_build")
        assert "nodes" in sb
        fu = call(ctx, db, rec["id"], "fusion_report")
        assert "stats" in fu

    def test_fusion_single_subject_missing_is_honest(self, ws):
        ctx, db, rec = ws
        out = call(ctx, db, rec["id"], "fusion_report", subject="nobody")
        assert out["profile"] is None

    def test_search_and_knowledge(self, ws):
        ctx, db, rec = ws
        s = call(ctx, db, rec["id"], "case_search", terms="anything")
        assert s["count"] == 0 and s["results"] == []
        k = call(ctx, db, rec["id"], "knowledge_search", query="reconnaissance")
        assert "matches" in k
        g = call(ctx, db, rec["id"], "glossary", term="osint")
        assert "definition" in g


class TestBrowserAndStatus:
    def test_browser_grab_reads_job_result_by_id(self, ws):
        from rebel_profiler.browser import BrowserJobStore

        ctx, db, rec = ws
        store = BrowserJobStore(ctx.data_dir / "queue")
        env = store.submit(case_id=rec["id"], url="https://lab.example.test/",
                           extract=["title"], requested_by="test")
        store.result_path(env["job_id"]).write_text(json.dumps(
            {"job_id": env["job_id"], "state": "done", "title": "hi"}))
        out = call(ctx, db, rec["id"], "browser_grab", job_id=env["job_id"])
        assert out["result"]["state"] == "done"

    def test_browser_grab_submits_when_url_given(self, ws, monkeypatch):
        ctx, db, rec = ws
        monkeypatch.setattr(ot, "BROWSER_WAIT_S", 0)
        out = call(ctx, db, rec["id"], "browser_grab",
                   url="https://lab.example.test/")
        assert out["state"] == "pending" and out["job_id"]

    def test_browser_grab_pending_when_no_result(self, ws, monkeypatch):
        ctx, db, rec = ws
        monkeypatch.setattr(ot, "BROWSER_WAIT_S", 0)
        out = call(ctx, db, rec["id"], "browser_grab",
                   url="https://lab.example.test/")
        assert out["state"] == "pending" and out["job_id"]

    def test_system_status_probe(self, ws):
        ctx, db, rec = ws
        out = call(ctx, db, rec["id"], "system_status")
        assert out["case"]["id"] == rec["id"]
        assert out["evidence_chain_ok"] is True
        assert "up" in out["bridge"]


# ---------------------------------------------------------------- the loop


class TestLoopWithOperatorTools:
    def test_model_can_authorize_then_collect(self, ws):
        ctx, db, rec = ws
        plane = ScriptedPlane([
            '<tool_call>{"name": "scope_add", "arguments": '
            '{"value": "*.lab.example.test"}}</tool_call>',
            '<tool_call>{"name": "echo", "arguments": '
            '{"target": "h1.lab.example.test", "message": "hi"}}</tool_call>',
            "Authorized and collected.",
        ])
        from rebel_profiler.execution.broker import ExecutionBroker
        from rebel_profiler.evidence.store import EvidenceStore

        store = EvidenceStore(db, blobs_dir=ctx.case_dir(rec["id"]) / "blobs")
        engine = ScopeEngine()
        engine.register(Scope(case_id=rec["id"], status=ScopeStatus.DRAFT))
        broker = ExecutionBroker(db, scope_engine=engine, evidence=store,
                                 confirm=lambda r, g: True,
                                 approve=lambda r, g: True,
                                 runner=lambda argv: (0, "out\n", ""))
        loop = HermesAgentLoop(rec["id"], "authorize then collect", plane=plane,
                               broker=broker, evidence=store, db=db,
                               ctx=ctx, max_turns=5)
        report = loop.run()
        assert report["final_answer"] == "Authorized and collected."
        assert report["calls"][0]["action"] == "scope_add"
        assert report["calls"][0]["error"] is False
        assert report["calls"][1]["outcome"] == "succeeded"
        assert ctx.find_case(rec["id"])["status"] == "active"

    def test_operator_error_is_feedback_not_crash(self, ws):
        ctx, db, rec = ws
        plane = ScriptedPlane([
            '<tool_call>{"name": "scope_add", "arguments": '
            '{"value": "x", "hax": "1"}}</tool_call>',
            "Understood, stopping.",
        ])
        from rebel_profiler.execution.broker import ExecutionBroker
        from rebel_profiler.evidence.store import EvidenceStore

        store = EvidenceStore(db, blobs_dir=ctx.case_dir(rec["id"]) / "blobs")
        broker = ExecutionBroker(db, scope_engine=ScopeEngine(), evidence=store,
                                 confirm=lambda r, g: True,
                                 approve=lambda r, g: True)
        loop = HermesAgentLoop(rec["id"], "goal", plane=plane, broker=broker,
                               evidence=store, db=db, ctx=ctx, max_turns=3)
        report = loop.run()
        assert report["calls"][0]["error"] is True
        assert "undeclared params" in report["calls"][0]["message"]


# ---------------------------------------------------------------- front door


class TestFrontDoor:
    def test_resolve_case_prefers_explicit_then_active_then_newest(self, ws):
        ctx, db, rec = ws
        assert _resolve_session_case(ctx, rec["id"])["id"] == rec["id"]
        newer = ctx.create_case("newer", "")
        assert _resolve_session_case(ctx)["id"] == newer["id"]  # newest wins
        ctx.set_case_status(rec["id"], "active")
        assert _resolve_session_case(ctx)["id"] == rec["id"]  # active beats newest

    def test_resolve_case_creates_when_empty(self, tmp_path):
        ctx = AppContext(data_dir=tmp_path)
        rec = _resolve_session_case(ctx)
        assert rec["id"] and rec["name"] == "Hermes Session"

    def test_one_shot_goal_answers_from_llm(self, ws, capsys):
        ctx, db, rec = ws
        plane = ScriptedPlane(["Plain-language answer from the model."])
        args = SimpleNamespace(goal="what is in scope?", case=rec["id"],
                               max_turns=4, llm="", output="human")
        rc = cmd_hermes(ctx, args, plane=plane)
        out = capsys.readouterr().out
        assert rc == 0
        assert "Plain-language answer from the model." in out
        assert "hermes agent session" in out

    def test_one_shot_on_empty_workspace_creates_case(self, tmp_path, capsys,
                                                       monkeypatch):
        ctx = AppContext(data_dir=tmp_path)
        plane = ScriptedPlane(["hi there"])
        args = SimpleNamespace(goal="", case="", max_turns=4, llm="",
                               output="human")

        # no goal → REPL; feed EOF immediately
        def fake_input(prompt=""):
            raise EOFError

        monkeypatch.setattr("builtins.input", fake_input)
        rc = cmd_hermes(ctx, args, plane=plane)
        assert rc == 0
        assert len(ctx.list_cases()) == 1   # the session case was created
