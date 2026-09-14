"""Tests for the Autonomous Engineer (plan → execute → repair → forge)."""

from __future__ import annotations

import json

import pytest

from rebel_profiler.agent.forge import static_safety_check
from rebel_profiler.cli.main import main
from rebel_profiler.llm.autonomous import (
    _guess_binary,
    _missing_capabilities,
    _render_adapter,
    _rewrite_against_findings,
    parse_repair_reply,
    render_auto_human,
)


# ---------------------------------------------------------------- pure helpers

class TestMissingCapabilities:
    def test_detects_no_adapter_signature(self):
        class R:
            def names(self):
                return ("passive-dns",)

        repairs = [{"action": "subdomain-brute", "target": "h1",
                    "message": "No adapter for action 'subdomain-brute'"}]
        specs = _missing_capabilities(repairs, R())
        assert len(specs) == 1
        assert specs[0]["capability"] == "subdomain-brute"

    def test_ignores_known_actions_and_other_errors(self):
        class R:
            def names(self):
                return ("passive-dns",)

        repairs = [
            {"action": "passive-dns", "target": "h1",
             "message": "returncode=1"},
            {"action": "subdomain-brute", "target": "h1",
             "message": "No adapter for action 'subdomain-brute'"},
        ]
        specs = _missing_capabilities(repairs, R())
        assert [s["capability"] for s in specs] == ["subdomain-brute"]

    def test_dedupes_repeated_failures(self):
        class R:
            def names(self):
                return ()

        repairs = [{"action": "x-scan", "target": "h1",
                    "message": "no adapter for 'x-scan'"}] * 3
        assert len(_missing_capabilities(repairs, R())) == 1


class TestAdapterTemplate:
    def test_rendered_source_passes_static_gate(self):
        source = _render_adapter({"capability": "subdomain-brute",
                                  "example_target": "h1.lab.example.test"})
        findings = static_safety_check(source)
        assert not [f for f in findings if f.severity == "high"], \
            [f.message for f in findings]

    def test_rendered_source_builds_argv_in_sandbox_shape(self):
        source = _render_adapter({"capability": "subdomain-brute",
                                  "example_target": "h1.lab.example.test"})
        namespace: dict = {}
        exec(compile(source, "<forge>", "exec"), namespace)  # noqa: S102 — test
        adapters = namespace["PLUGIN_ADAPTERS"]
        instance = adapters[0]()
        from rebel_profiler.execution.broker import ActionRequest

        req = ActionRequest(case_id="c", capability="forge",
                            action=instance.name,
                            target="h1.lab.example.test",
                            params={"mode": "aggressive"})
        argv = instance.build_argv(req)
        assert argv[0] == instance.binary
        assert "h1.lab.example.test" in argv
        assert all(isinstance(a, str) for a in argv)

    def test_binary_guessing(self):
        assert _guess_binary("dns-enum") == "dig"
        assert _guess_binary("port-scan") == "nmap"
        assert _guess_binary("mystery") == "dig"


class TestRepairParsing:
    def test_valid_correction(self):
        class Adapter:
            name = "passive-dns"
            allowed_params = ("record_type",)

        class R:
            def get(self, name):
                return Adapter() if name == "passive-dns" else None

        proposals = parse_repair_reply(
            '{"action": "passive-dns", "target": "h1", "params": {}}', R())
        assert proposals is not None
        assert proposals[0].action == "passive-dns"

    def test_give_up_is_none(self):
        assert parse_repair_reply("{}", None) is None
        assert parse_repair_reply("", None) is None

    def test_unknown_action_is_none_not_crash(self):
        class R:
            def get(self, name):
                return None

        # An unknown action must come back as 'give up' (None) — the reviser
        # never invents; forging is the EXTEND phase's job, not the repair's.
        assert parse_repair_reply(
            '{"action": "ghost-tool", "target": "h1"}', R()) is None

    def test_garbage_is_none_not_crash(self):
        assert parse_repair_reply("sorry, cannot", None) is None


class TestRewriteLoop:
    def test_dangerous_literal_rewrite_changes_source(self):
        source = 'x = "run rm -rf now"'
        new = _rewrite_against_findings(
            source, [{"rule": "dangerous_literal"}])
        assert new is not None and new != source

    def test_unfixable_returns_none(self):
        source = "x = 1"
        assert _rewrite_against_findings(
            source, [{"rule": "ast_size"}]) is None
        assert _rewrite_against_findings(
            source, [{"rule": "forbidden_import"}]) is None


# ---------------------------------------------------------------- CLI surface

@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return ["--data-dir", str(tmp_path / "data")]


class TestAgentAutoCli:
    def test_auto_requires_case(self, workspace, capsys):
        rc = main([*workspace, "agent", "auto", "ghost", "goal", "-o", "json"])
        assert rc != 0
        err = json.loads(capsys.readouterr().err)
        assert err["error"]["exit_code"] != 0

    def test_auto_with_tiny_engine_reports_honestly(self, workspace, capsys):
        # No airllm installed in CI: the planner falls back to tiny, which
        # must fail HONESTLY (structured error) — never invented proposals.
        main([*workspace, "case", "create", "T", "d"])
        case_id = _first_case_id(workspace)
        main([*workspace, "case", "activate", case_id])
        rc = main([*workspace, "agent", "auto", case_id,
                   "map lab.example.test", "--llm", "Qwen/Qwen2.5-0.5B",
                   "-o", "json"])
        assert rc != 0   # tiny engine cannot plan; honest failure is correct
        err = capsys.readouterr().err
        assert "tiny" in err.lower() or "weights" in err.lower()

    def test_auto_registered_in_help(self, workspace, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main([*workspace, "agent", "--help"])
        assert excinfo.value.code == 0   # argparse exits help via SystemExit
        assert "auto" in capsys.readouterr().out


def _first_case_id(workspace) -> str:
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        main([*workspace, "case", "list", "-o", "json"])
    return json.loads(buf.getvalue())["data"][0]["id"]
