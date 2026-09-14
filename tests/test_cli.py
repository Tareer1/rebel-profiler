"""CLI tests: dispatch, output modes, exit codes."""

from __future__ import annotations

import json

import pytest

from rebel_profiler.cli.main import main


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    data_dir = tmp_path / "data"
    return ["--data-dir", str(data_dir)]


def create_active_case(workspace, tmp_domain="*.lab.example.test"):
    assert main([*workspace, "case", "create", "T", "d"]) == 0
    listing = main([*workspace, "case", "list", "-o", "json"])  # prints to stdout
    # extract id by running a fresh json parse through capsys-free approach:
    return workspace


class TestCaseCommands:
    def test_create_and_list(self, workspace, capsys):
        assert main([*workspace, "case", "create", "Alpha", "first"]) == 0
        out = capsys.readouterr().out
        assert "Created case" in out
        assert main([*workspace, "case", "list"]) == 0
        out = capsys.readouterr().out
        assert "Alpha" in out

    def test_json_output_mode(self, workspace, capsys):
        main([*workspace, "case", "create", "Beta"])
        capsys.readouterr()
        assert main([*workspace, "case", "list", "-o", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["data"][0]["name"] == "Beta"

    def test_csv_output_mode(self, workspace, capsys):
        main([*workspace, "case", "create", "Gamma"])
        capsys.readouterr()
        assert main([*workspace, "case", "list", "-o", "csv"]) == 0
        out = capsys.readouterr().out
        assert out.splitlines()[0].startswith("id,")

    def test_unknown_case_is_structured_error(self, workspace, capsys):
        rc = main([*workspace, "case", "show", "ghost", "-o", "json"])
        assert rc != 0
        err = capsys.readouterr().err
        payload = json.loads(err)
        assert payload["error"]["exit_code"] != 0


class TestScopeFlow:
    @pytest.fixture()
    def active_case(self, workspace, capsys):
        main([*workspace, "case", "create", "T"])
        capsys.readouterr()
        payload = json.loads(
            capsys.readouterr().out or "{}"
        ) if False else None
        # Get the case id via json list
        main([*workspace, "case", "list", "-o", "json"])
        case_id = json.loads(capsys.readouterr().out)["data"][0]["id"]
        main([*workspace, "case", "scope", "add", case_id, "*.lab.example.test"])
        capsys.readouterr()
        main([*workspace, "case", "activate", case_id])
        capsys.readouterr()
        return case_id

    def test_scope_check_in_scope(self, workspace, active_case, capsys):
        rc = main([*workspace, "scope-check", active_case, "h.lab.example.test"])
        assert rc == 0

    def test_scope_check_out_of_scope_exit5(self, workspace, active_case, capsys):
        rc = main([*workspace, "scope-check", active_case, "evil.test"])
        assert rc == 5

    def test_plan_shows_command_and_policy(self, workspace, active_case, capsys):
        rc = main([*workspace, "plan", active_case, "host-discovery",
                   "h.lab.example.test", "-p", "mode", "discover"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "nmap -sn" in out
        assert "policy" in out

    def test_run_echo_with_evidence(self, workspace, active_case, capsys):
        rc = main([*workspace, "run", active_case, "echo", "h.lab.example.test",
                   "-p", "message", "hi", "--capability", "info"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "succeeded" in out
        assert "evidence" in out

    def test_run_out_of_scope_denied(self, workspace, active_case, capsys):
        rc = main([*workspace, "run", active_case, "echo", "evil.test",
                   "--capability", "info", "-o", "json"])
        assert rc != 0
        payload = json.loads(capsys.readouterr().err)
        assert payload["error"]["exit_code"] == 5


class TestKnowledgeCommands:
    def test_domains_lists_fifteen(self, workspace, capsys):
        assert main([*workspace, "knowledge", "domains"]) == 0
        out = capsys.readouterr().out
        assert "15" in out

    def test_domain_detail(self, workspace, capsys):
        assert main([*workspace, "knowledge", "domain", "13"]) == 0
        assert "Cryptography" in capsys.readouterr().out

    def test_planner_context_json(self, workspace, capsys):
        assert main([*workspace, "knowledge", "planner-context", "-o", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert len(payload["domains"]) == 15

    def test_tools_for_domain(self, workspace, capsys):
        assert main([*workspace, "knowledge", "tools", "scanning"]) == 0
        assert "host-discovery" in capsys.readouterr().out


class TestAdaptersAndDoctor:
    def test_adapters_listing(self, workspace, capsys):
        assert main([*workspace, "adapters"]) == 0
        out = capsys.readouterr().out
        assert "host-discovery" in out and "dns-lookup" in out

    def test_doctor_passes(self, workspace, capsys):
        rc = main([*workspace, "doctor"])
        assert rc == 0

    def test_no_args_shows_help_exit2(self, capsys):
        assert main([]) == 2
