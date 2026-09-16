"""Tests for the Hermes agent: ChatML rendering, tool-call parsing, gated loop."""

from __future__ import annotations

import json

import pytest

from rebel_profiler.agent import Proposal
from rebel_profiler.core.errors import DependencyUnavailableError, UsageError
from rebel_profiler.evidence.store import EvidenceStore
from rebel_profiler.execution.broker import ExecutionBroker
from rebel_profiler.intel.claims import ClaimLedger
from rebel_profiler.intel.sources import SourceRegistry
from rebel_profiler.llm.budget import DEFAULT_LIMITS
from rebel_profiler.llm.hermes import (
    HermesAgentLoop,
    HermesSession,
    build_system_prompt,
    parse_tool_calls,
    render_chatml,
    strip_tool_call_blocks,
    tool_schema,
)
from rebel_profiler.llm.inference import (
    GenerationResult,
    ModelPlane,
    TinyLlmEngine,
)
from rebel_profiler.security.scope import Scope, ScopeEngine, ScopeStatus
from rebel_profiler.storage.database import Database


# ---------------------------------------------------------------- helpers


class ScriptedEngine:
    """A duck-typed engine that never generates — the plane overrides generate."""

    kind = "scripted"
    loaded = True
    compressed = False
    last_device = "cpu"

    def __init__(self, model_id: str = "scripted") -> None:
        self.model_id = model_id

    def load(self) -> None:
        pass

    def unload(self) -> None:
        pass


class ScriptedPlane(ModelPlane):
    """A ModelPlane whose generate() replays scripted replies in order."""

    def __init__(self, replies: list[str]) -> None:
        super().__init__(limits=DEFAULT_LIMITS["mid"])
        self.replies = list(replies)
        self.prompts: list[str] = []
        self._engine = ScriptedEngine()
        self._engine_kind = "scripted"
        self._fallback_reason = "scripted test double"

    def generate(self, prompt, **kwargs):  # noqa: D102 — test double
        self.prompts.append(prompt)
        text = self.replies.pop(0) if self.replies else ""
        return GenerationResult(
            text=text, engine="scripted", model="scripted",
            input_tokens=1, output_tokens=1, elapsed_s=0.0,
            peak_rss_mb=0.0, device="cpu",
        )


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
                             runner=lambda argv: (0, " ".join(argv[1:]) + "\n", ""))
    return db, store, broker


def make_loop(replies, env, **kwargs):
    db, store, broker = env
    plane = ScriptedPlane(replies)
    loop = HermesAgentLoop("c1", "collect one DNS record", plane=plane,
                           broker=broker, evidence=store, db=db, **kwargs)
    return loop, plane


# ---------------------------------------------------------------- schema + prompts


class TestToolSchema:
    def test_schema_comes_from_live_registry(self, env):
        db, store, broker = env
        tools = tool_schema(broker.adapters)
        names = {t["function"]["name"] for t in tools}
        assert "echo" in names and "dns-lookup" in names

    def test_system_prompt_embeds_tools_block(self, env):
        db, store, broker = env
        prompt = build_system_prompt(tool_schema(broker.adapters))
        assert "<tools>" in prompt and "</tools>" in prompt
        assert "<tool_call>" in prompt and "dns-lookup" in prompt

    def test_schema_params_are_allowed_params(self, env):
        db, store, broker = env
        tools = {t["function"]["name"]: t for t in tool_schema(broker.adapters)}
        props = tools["dns-lookup"]["function"]["parameters"]["properties"]
        assert set(props) == {"record_type"}


class TestChatML:
    def test_basic_render(self):
        messages = [
            {"role": "system", "content": "SYS"},
            {"role": "user", "content": "GOAL: x"},
            {"role": "assistant", "content": "hi"},
            {"role": "tool", "content": '{"ok": true}'},
        ]
        prompt = render_chatml(messages)
        assert prompt.startswith("<|im_start|>system\nSYS<|im_end|>\n")
        assert "<|im_start|>user\nGOAL: x<|im_end|>\n" in prompt
        assert "<|im_start|>tool\n<tool_response>\n" in prompt
        assert prompt.endswith("<|im_start|>assistant\n")

    def test_tool_role_wraps_tool_response(self):
        prompt = render_chatml([{"role": "tool", "content": "DATA"}])
        assert "<|im_start|>tool\n<tool_response>\nDATA\n</tool_response><|im_end|>\n" in prompt


# ---------------------------------------------------------------- parsing


class TestParseToolCalls:
    def test_single_call(self):
        reply = 'Thinking... <tool_call>{"name": "dns-lookup", "arguments": {"target": "h1.lab.example.test", "record_type": "A"}}</tool_call>'
        calls = parse_tool_calls(reply)
        assert calls == [{"name": "dns-lookup",
                          "arguments": {"target": "h1.lab.example.test",
                                        "record_type": "A"}}]

    def test_arguments_optional(self):
        calls = parse_tool_calls('<tool_call>{"name": "echo"}</tool_call>')
        assert calls == [{"name": "echo", "arguments": {}}]

    def test_malformed_json_skipped(self):
        assert parse_tool_calls("<tool_call>{not json}</tool_call>") == []

    def test_missing_name_skipped(self):
        assert parse_tool_calls('<tool_call>{"arguments": {}}</tool_call>') == []

    def test_non_object_skipped(self):
        assert parse_tool_calls("<tool_call>[1, 2]</tool_call>") == []

    def test_multiple_calls_extracted(self):
        reply = ('<tool_call>{"name": "a"}</tool_call>'
                 '<tool_call>{"name": "b"}</tool_call>')
        assert [c["name"] for c in parse_tool_calls(reply)] == ["a", "b"]

    def test_strip_blocks(self):
        text = strip_tool_call_blocks(
            'answer <tool_call>{"name": "x"}</tool_call> tail')
        assert text == "answer  tail"


# ---------------------------------------------------------------- the loop


class TestHermesAgentLoop:
    def test_final_answer_without_calls(self, env):
        loop, plane = make_loop(["All done, nothing to call."], env)
        report = loop.run()
        assert report["final_answer"] == "All done, nothing to call."
        assert report["turns_used"] == 1
        assert report["calls"] == []

    def test_tool_call_executes_through_broker(self, env):
        call = ('<tool_call>{"name": "echo", "arguments": '
                '{"target": "h1.lab.example.test", "message": "hermes-was-here"}}'
                "</tool_call>")
        loop, plane = make_loop([call, "Goal met."], env)
        report = loop.run()
        assert len(report["calls"]) == 1
        executed = report["calls"][0]
        assert executed["outcome"] == "succeeded"
        assert executed["evidence_id"]
        assert executed["stdout"].strip() == "hermes-was-here"
        # the tool result went back as a tool-role message in ChatML
        second_prompt = plane.prompts[1]
        assert '"outcome": "succeeded"' in second_prompt
        assert "<|im_start|>tool" in second_prompt

    def test_denied_call_is_feedback_not_crash(self, env):
        call = ('<tool_call>{"name": "echo", "arguments": '
                '{"target": "evil.test", "message": "x"}}</tool_call>')
        loop, _ = make_loop([call, "Understood; stopping."], env)
        report = loop.run()
        assert report["calls"][0]["outcome"] == "denied"

    def test_unknown_tool_reports_error(self, env):
        call = '<tool_call>{"name": "ghost-scan", "arguments": {"target": "h1.lab.example.test"}}</tool_call>'
        loop, _ = make_loop([call, "Stopping."], env)
        report = loop.run()
        entry = report["calls"][0]
        assert entry["error"] is True
        assert "unknown action" in entry["message"]

    def test_undeclared_param_reports_error(self, env):
        call = ('<tool_call>{"name": "echo", "arguments": '
                '{"target": "h1.lab.example.test", "extra": "x"}}</tool_call>')
        loop, _ = make_loop([call, "Stopping."], env)
        report = loop.run()
        assert "undeclared params" in report["calls"][0]["message"]

    def test_turn_budget_bounds_the_loop(self, env):
        call = ('<tool_call>{"name": "echo", "arguments": '
                '{"target": "h1.lab.example.test"}}</tool_call>')
        loop, _ = make_loop([call] * 50, env, max_turns=3)
        report = loop.run()
        assert report["turns_used"] == 3
        assert len(report["calls"]) == 3

    def test_transcript_is_redacted_and_bounded(self, env):
        loop, _ = make_loop(["done"], env)
        report = loop.run()
        assert report["transcript"][0]["reply"] == "done"

    def test_report_fields(self, env):
        loop, _ = make_loop(["finished"], env)
        report = loop.run()
        assert report["mode"] == "hermes-agent"
        assert report["case_id"] == "c1"
        assert report["engine"] == "scripted"
        assert "elapsed_s" in report


# ---------------------------------------------------------------- safety rails


class TestHermesSafety:
    def test_tiny_engine_is_a_structured_refusal(self, env):
        db, store, broker = env
        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"], prefer_engine="tiny")
        plane.load_tiny()
        loop = HermesAgentLoop("c1", "goal", plane=plane, broker=broker,
                               evidence=store, db=db)
        with pytest.raises(DependencyUnavailableError) as excinfo:
            loop.run()
        assert "tiny engine" in excinfo.value.message

    def test_goal_is_redacted_into_prompts(self, env):
        db, store, broker = env
        plane = ScriptedPlane(["ok"])
        loop = HermesAgentLoop("c1", "goal with PASSWORD=supersecret inside",
                               plane=plane, broker=broker, evidence=store, db=db)
        loop.run()
        assert "supersecret" not in plane.prompts[0]

    def test_evidence_chain_receives_hermes_steps(self, env):
        call = ('<tool_call>{"name": "echo", "arguments": '
                '{"target": "h1.lab.example.test", "message": "evidenced"}}</tool_call>')
        loop, _ = make_loop([call], env)
        report = loop.run()
        assert report["calls"][0]["evidence_id"]


# ---------------------------------------------------------------- session + human view


class TestHermesSession:
    def test_ask_appends_and_strips_chat_tags(self):
        plane = ScriptedPlane(["<|im_end|>plain answer"])
        session = HermesSession(plane, system="SYS")
        out = session.ask("hello")
        assert out == "plain answer"
        assert session.messages[-1]["role"] == "assistant"

    def test_tool_call_blocks_removed_from_session_text(self):
        plane = ScriptedPlane(['<tool_call>{"name": "x"}</tool_call>final text'])
        session = HermesSession(plane, system="SYS")
        assert session.ask("q") == "final text"


class TestRenderHuman:
    def test_human_summary(self, env):
        call = ('<tool_call>{"name": "echo", "arguments": '
                '{"target": "h1.lab.example.test", "message": "hi"}}</tool_call>')
        loop, _ = make_loop([call, "Done."], env)
        report = loop.run()
        text = render_human_report(report)
        assert "hermes agent session" in text
        assert "final answer:" in text
        assert "Done." in text


def render_human_report(report):
    from rebel_profiler.llm.hermes import render_human

    return render_human(report)


# ---------------------------------------------------------------- interactive REPL


class TestAgentChatRepl:
    """`agent chat` with no goal opens the interactive Hermes chat."""

    def _run_repl(self, monkeypatch, capsys, replies, lines, env_fixture,
                  case_id="c1"):
        db, store, broker = env_fixture
        plane = ScriptedPlane(replies)
        fed = list(lines)

        def fake_input(prompt=""):
            if not fed:
                raise EOFError
            head = fed.pop(0)
            if isinstance(head, Exception):
                raise head
            return head

        monkeypatch.setattr("builtins.input", fake_input)

        from types import SimpleNamespace

        from rebel_profiler.cli.main import _cmd_agent_chat_repl

        args = SimpleNamespace(case_id=case_id, goal="", max_turns=4,
                               llm="", output="human")

        class FakeCtx:
            def __init__(self):
                self._db = db
                self._broker = broker

            def find_case(self, cid):
                return {"id": cid}

            def open_case(self, cid):
                return db

            def broker(self, db_):
                return broker

            def evidence_store(self, db_, cid):
                return store

        rc = _cmd_agent_chat_repl(FakeCtx(), args, plane=plane)
        return rc, capsys.readouterr().out

    def test_repl_runs_loops_and_quits(self, env, monkeypatch, capsys):
        call = ('<tool_call>{"name": "echo", "arguments": '
                '{"target": "h1.lab.example.test", "message": "hi"}}</tool_call>')
        rc, out = self._run_repl(
            monkeypatch, capsys,
            replies=[call, "Goal met.", "Just answering."],
            lines=["do a thing", "what happened?", "/exit"],
            env_fixture=env)
        assert rc == 0
        assert "hermes interactive" in out
        assert "hermes> Goal met." in out
        assert "hermes> Just answering." in out

    def test_repl_tools_command(self, env, monkeypatch, capsys):
        rc, out = self._run_repl(
            monkeypatch, capsys, replies=[],
            lines=["/tools", "/exit"], env_fixture=env)
        assert rc == 0
        assert "dns-lookup" in out

    def test_repl_tiny_engine_refuses(self, env, monkeypatch, capsys):
        from types import SimpleNamespace

        from rebel_profiler.cli.main import _cmd_agent_chat_repl
        from rebel_profiler.llm.budget import DEFAULT_LIMITS
        from rebel_profiler.llm.inference import ModelPlane

        db, store, broker = env
        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"], prefer_engine="tiny")
        plane.load_tiny()

        Args = SimpleNamespace(case_id="c1", goal="", max_turns=4, llm="")

        class FakeCtx:
            def find_case(self, cid):
                return {"id": cid}

            def open_case(self, cid):
                return db

        with pytest.raises(DependencyUnavailableError):
            _cmd_agent_chat_repl(FakeCtx(), Args, plane=plane)
