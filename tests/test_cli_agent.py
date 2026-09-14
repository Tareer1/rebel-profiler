"""CLI end-to-end tests: agent run, report, intel collect, run --collect."""

from __future__ import annotations

import json

import pytest

from rebel_profiler.cli.main import main


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return ["--data-dir", str(tmp_path / "data")]


@pytest.fixture()
def active_case(workspace, capsys):
    main([*workspace, "case", "create", "AgentCase"])
    capsys.readouterr()
    main([*workspace, "case", "list", "-o", "json"])
    case_id = json.loads(capsys.readouterr().out)["data"][0]["id"]
    main([*workspace, "case", "scope", "add", case_id, "*.lab.example.test"])
    capsys.readouterr()
    main([*workspace, "case", "activate", case_id])
    capsys.readouterr()
    return case_id


class TestAgentCLI:
    def test_agent_run_deterministic_plan(self, workspace, active_case, capsys):
        rc = main([*workspace, "agent", "run", active_case, "map the lab",
                   "--plan", "echo:h.lab.example.test:message=hello-agent",
                   "-o", "json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["data"]["steps"][0]["outcome"] == "succeeded"
        assert "report" in payload["data"]

    def test_agent_denial_in_step_log(self, workspace, active_case, capsys):
        rc = main([*workspace, "agent", "run", active_case, "evil goal",
                   "--plan", "echo:evil.test:;echo:h.lab.example.test:message=fine"])
        # one step denied, one succeeded → still exit 0 because ok>0
        out = capsys.readouterr().out
        assert "denied" in out and "succeeded" in out

    def test_agent_report_section(self, workspace, active_case, capsys):
        main([*workspace, "agent", "run", active_case, "map",
              "--plan", "echo:h.lab.example.test:message=x"])
        out = capsys.readouterr().out
        assert "Case report" in out

    def test_agent_unknown_plan_action_fails_clean(self, workspace, active_case, capsys):
        rc = main([*workspace, "agent", "run", active_case, "goal",
                   "--plan", "no-such-action:h.lab.example.test", "-o", "json"])
        assert rc == 2
        err = capsys.readouterr().err
        payload = json.loads(err)
        assert payload["error"]["exit_code"] == 2


class TestIntelCollectCLI:
    def test_collect_echo_no_claims_but_clean_exit(self, workspace, active_case, capsys):
        rc = main([*workspace, "intel", "collect", active_case, "echo",
                   "h.lab.example.test", "-p", "message", "hi"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "claims   : 0" in out
        assert "clean    : True" in out


class TestRunCollectFlag:
    def test_run_collect_echo(self, workspace, active_case, capsys):
        rc = main([*workspace, "run", active_case, "echo", "h.lab.example.test",
                   "-p", "message", "x", "--capability", "info", "--collect",
                   "-o", "json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["data"]["collection"]["clean"] is True
        assert payload["data"]["collection"]["claims_emitted"] == []


class TestReportCLI:
    def test_report_empty_case(self, workspace, active_case, capsys):
        rc = main([*workspace, "report", active_case])
        assert rc == 0
        out = capsys.readouterr().out
        assert "No reportable findings" in out

    def test_report_json_schema(self, workspace, active_case, capsys):
        main([*workspace, "report", active_case, "-o", "json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["data"]["schema_version"] == 1
        assert payload["data"]["stats"]["claims_total"] == 0

    def test_report_after_dns_collection(self, workspace, active_case, capsys, tmp_path):
        # seed claims through the pipeline directly (dig not guaranteed present)
        from rebel_profiler.cli.context import AppContext
        from rebel_profiler.intel import ClaimLedger, CollectionPipeline, SourceRegistry

        ctx = AppContext(data_dir=tmp_path / "data")
        db = ctx.open_case(active_case)
        pipeline = CollectionPipeline(
            ClaimLedger(SourceRegistry()),
            ctx.evidence_store(db, active_case), db=db,
        )
        pipeline.ingest(active_case, action="passive-dns", target="h.lab.example.test",
                        stdout="1.2.3.4\n", returncode=0, task_id="t1",
                        params={"record_type": "A"})
        pipeline.ingest(active_case, action="passive-dns", target="h.lab.example.test",
                        stdout="10 mail.lab.example.test.\n", returncode=0, task_id="t2",
                        params={"record_type": "MX"})
        db.close()
        capsys.readouterr()
        rc = main([*workspace, "report", active_case])
        assert rc == 0
        out = capsys.readouterr().out
        assert "h.lab.example.test" in out
        assert "1.2.3.4" in out
        assert "mail.lab.example.test" in out
