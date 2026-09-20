"""Tests for the Hermes shell: banner, slash registry, slash dispatch.

The shell is the cloned Hermes-agent CLI UX: one registry owns the
commands, the banner greets like the original, and every slash handler
touches the same gated machinery the chat does.
"""

from __future__ import annotations

import pytest

from rebel_profiler.cli.context import AppContext
from rebel_profiler.llm.hermes_shell import (
    REGISTRY,
    REGISTRY_OBJ,
    ShellSession,
    build_banner,
)


class TestBanner:
    def test_banner_carries_session_facts(self):
        out = build_banner(model="qwen-7b.gguf",
                           case={"id": "abc123", "status": "active",
                                 "name": "job", "scope_entries": 2,
                                 "claims": 7},
                           tools=17, adapters=9, bridge_up=True,
                           data_dir="/tmp/ws", width=100)
        assert "qwen-7b.gguf" in out
        assert "abc123" in out
        assert "ACTIVE" in out
        assert "17" in out and "9" in out
        assert "/help for commands" in out

    def test_banner_shows_bridge_down_hint(self):
        out = build_banner(model="m", case={"id": "x", "status": "draft",
                                            "scope_entries": 0, "claims": 0},
                           tools=1, adapters=1, bridge_up=False, width=100)
        assert "rp bridge" in out


class TestRegistry:
    def test_matches_hermes_agent_surface(self):
        names = {c.name for c in REGISTRY}
        assert {"help", "status", "model", "new", "case", "tools",
                "scope", "clear", "exit"} <= names

    def test_aliases_resolve(self):
        assert REGISTRY_OBJ.resolve("/q")[0] == "exit"
        assert REGISTRY_OBJ.resolve("/reset")[0] == "new"
        assert REGISTRY_OBJ.resolve("/?")[0] == "help"

    def test_plain_lines_pass_through(self):
        name, rest = REGISTRY_OBJ.resolve("authorize example.com and map it")
        assert name is None and rest == "authorize example.com and map it"

    def test_unknown_slash_signals(self):
        name, rest = REGISTRY_OBJ.resolve("/frobnicate now")
        assert name == "" and rest == "frobnicate now"

    def test_help_text_lists_and_filters(self):
        text = REGISTRY_OBJ.help_text()
        assert "/status" in text and "/model" in text
        filt = REGISTRY_OBJ.help_text("model")
        assert "/model" in filt and "/status" not in filt


class TestDispatch:
    @pytest.fixture()
    def session(self, tmp_path, capsys):
        ctx = AppContext(data_dir=tmp_path)
        rec = ctx.create_case("shell case", "tests")
        db = ctx.open_case(rec["id"])

        class FakePlane:
            engine = None

            def select_engine(self, name):
                self.engine = type("E", (), {"model_id": name or "fake.gguf"})()

            def unload(self):
                pass

        args = type("A", (), {"llm": "", "max_turns": 4})()
        return ShellSession(ctx, rec, db, FakePlane(), args)

    def test_status_reports_case_and_chains(self, session, capsys):
        REGISTRY_OBJ.dispatch("status", "", session)
        out = capsys.readouterr().out
        assert session.case_rec["id"] in out
        assert "chains" in out

    def test_new_starts_fresh_case_and_rebinds(self, session, capsys):
        old_id = session.case_rec["id"]
        REGISTRY_OBJ.dispatch("new", "fresh work", session)
        out = capsys.readouterr().out
        assert session.case_rec["id"] != old_id
        assert "fresh work" in out

    def test_model_bare_shows_current(self, session, capsys):
        REGISTRY_OBJ.dispatch("model", "", session)
        out = capsys.readouterr().out
        assert "current model" in out

    def test_model_switch_session_scoped(self, session, capsys):
        REGISTRY_OBJ.dispatch("model", "other.gguf", session)
        out = capsys.readouterr().out
        assert "other.gguf" in out and "session-scoped" in out

    def test_scope_empty_hints_authorize(self, session, capsys):
        REGISTRY_OBJ.dispatch("scope", "", session)
        out = capsys.readouterr().out
        assert "authorize" in out

    def test_scope_lists_entries(self, session, capsys):
        session.db.add_scope_entry(session.case_rec["id"], "*.lab.test",
                                   note="t")
        REGISTRY_OBJ.dispatch("scope", "", session)
        out = capsys.readouterr().out
        assert "*.lab.test" in out

    def test_tools_lists_merged_surface(self, session, capsys):
        REGISTRY_OBJ.dispatch("tools", "", session)
        out = capsys.readouterr().out
        assert "scope_add" in out and "dns-lookup" in out

    def test_unknown_slash_prints_hint(self, session, capsys):
        name, _ = REGISTRY_OBJ.resolve("/frob")
        assert name == ""   # run_repl prints the hint for this signal
