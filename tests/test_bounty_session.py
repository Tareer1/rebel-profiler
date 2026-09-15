"""Tests for the bounty session: one goal in → evidenced report out.

The session is the orchestration layer, so these tests exercise it against real
components wherever possible: a real ACTIVE case, a real scope engine, a real
loopback HTTP target, the real static gate and the real sandbox. Only the model
itself is scripted (``codegen._generate``), because there is no engine with
weights in the test environment — everything downstream of the model is real.
"""

from __future__ import annotations

import json

import pytest

from rebel_profiler.cli.main import main
from rebel_profiler.core.errors import UsageError
from rebel_profiler.intel.bounty_session import BountySession, seed_url, split_asset
from rebel_profiler.llm import codegen


# ---------------------------------------------------------------- asset splitting

class TestSplitAsset:
    def test_plain_host(self):
        assert split_asset("Example.TEST") == ("example.test", None)

    def test_host_and_port_kept_apart(self):
        # The scope engine matches hostnames, so the port must not join the
        # value being authorized — but it must survive into the seed URL.
        assert split_asset("127.0.0.1:8080") == ("127.0.0.1", 8080)

    def test_wildcard_prefix_stripped(self):
        assert split_asset("*.example.test") == ("example.test", None)

    def test_url_reduced_to_host_and_port(self):
        assert split_asset("https://api.example.test:8443/v1/x?y=1") == (
            "api.example.test", 8443)

    def test_ipv6_literal_with_port(self):
        assert split_asset("https://[2001:db8::1]:8443/") == ("2001:db8::1", 8443)

    def test_ipv6_literal_without_scheme(self):
        assert split_asset("[2001:db8::1]:8443") == ("2001:db8::1", 8443)

    def test_bare_ipv6_not_mistaken_for_port(self):
        assert split_asset("2001:db8::1") == ("2001:db8::1", None)

    def test_blank_and_wildcard_only_rejected(self):
        assert split_asset("   ") is None
        assert split_asset("*.") is None

    def test_bad_port_in_url_rejected(self):
        assert split_asset("https://h.test:notaport/") is None


class TestSeedUrl:
    def test_plain(self):
        assert seed_url("https", "h.test", None) == "https://h.test/"

    def test_port(self):
        assert seed_url("http", "127.0.0.1", 8080) == "http://127.0.0.1:8080/"

    def test_ipv6_rebracketed(self):
        assert seed_url("http", "2001:db8::1", 8443) == "http://[2001:db8::1]:8443/"


# ---------------------------------------------------------------- script planning

class TestParseScriptPlan:
    def test_none_means_no_scripts(self):
        plan = codegen.parse_script_plan("NONE")
        assert plan["scripts"] == [] and plan["dropped"] == 0
        assert "note" in plan

    def test_none_is_case_insensitive(self):
        assert codegen.parse_script_plan("none.")["scripts"] == []

    def test_fenced_json_array(self):
        plan = codegen.parse_script_plan(
            'Sure!\n```json\n[{"goal": "sum the ports", "payload": {"a": 1}}]\n```')
        assert plan["scripts"] == [{"goal": "sum the ports", "payload": {"a": 1}}]

    def test_bare_json_array(self):
        plan = codegen.parse_script_plan('[{"goal": "g", "payload": {}}]')
        assert len(plan["scripts"]) == 1

    def test_single_object_accepted(self):
        plan = codegen.parse_script_plan('{"goal": "g", "payload": {}}')
        assert len(plan["scripts"]) == 1

    def test_entries_without_a_goal_are_dropped_not_guessed(self):
        plan = codegen.parse_script_plan(
            '[{"goal": "", "payload": {}}, {"goal": "real", "payload": {}}, "junk"]')
        assert [s["goal"] for s in plan["scripts"]] == ["real"]
        assert plan["dropped"] == 2

    def test_extra_scripts_are_capped_and_counted(self):
        raw = json.dumps([{"goal": f"g{i}", "payload": {}} for i in range(6)])
        plan = codegen.parse_script_plan(raw, max_scripts=2)
        assert len(plan["scripts"]) == 2
        assert plan["dropped"] == 4

    def test_dict_without_a_goal_is_dropped_not_guessed(self):
        # A single object is accepted as a one-entry plan; without a usable
        # goal it is dropped and counted rather than invented.
        plan = codegen.parse_script_plan('{"not": "a plan"}')
        assert plan["scripts"] == [] and plan["dropped"] == 1

    def test_non_json_rejected(self):
        with pytest.raises(UsageError):
            codegen.parse_script_plan("I think you should scan more hosts.")

    def test_empty_reply_rejected(self):
        with pytest.raises(UsageError):
            codegen.parse_script_plan("   ")

    def test_long_goal_is_truncated(self):
        plan = codegen.parse_script_plan(
            json.dumps([{"goal": "x" * 5000, "payload": {}}]))
        assert len(plan["scripts"][0]["goal"]) == codegen.GOAL_MAX_CHARS


# ---------------------------------------------------------------- sessions

@pytest.fixture()
def case_env(tmp_path, monkeypatch, local_site):
    """A real ACTIVE case, authorized for the loopback site, wired end to end."""
    from rebel_profiler.cli.context import AppContext

    monkeypatch.setenv("HOME", str(tmp_path))
    ctx = AppContext(data_dir=str(tmp_path / "data"))
    rec = ctx.create_case("Bug bounty", "session tests")
    port = int(local_site.rstrip("/").rsplit(":", 1)[1])
    db = ctx.open_case(rec["id"])
    # Both entries are needed, and that is the real shape of the rule: the
    # auditor authorizes urlsplit(url).hostname, so the bare host must be
    # authorized for the port-qualified asset to be usable at all.
    db.add_scope_entry(rec["id"], "127.0.0.1", excluded=False,
                       note="loopback test site")
    db.add_scope_entry(rec["id"], f"127.0.0.1:{port}", excluded=False,
                       note="port-qualified form")
    ctx.set_case_status(rec["id"], "active")
    record = ctx.find_case(rec["id"])
    yield ctx, record, db, port, tmp_path
    db.close()


def make_session(env, *, goal="find what you can and report", **kwargs):
    from rebel_profiler.evidence.audit import AuditChain
    from rebel_profiler.intel.claims import ClaimLedger
    from rebel_profiler.intel.sources import SourceRegistry

    ctx, rec, db, _port, tmp_path = env
    defaults = dict(
        db=db, scope_engine=ctx.scope_engine(),
        case_dir=ctx.case_dir(rec["id"]), case_status=rec["status"],
        ledger=ClaimLedger(SourceRegistry()),
        evidence=ctx.evidence_store(db, rec["id"]), audit=AuditChain(db),
        script_dir=tmp_path / "scripts", scheme="http",
    )
    defaults.update(kwargs)
    return BountySession(rec["id"], goal=goal, **defaults)


class TestSessionGuardrails:
    def test_case_without_scope_is_refused(self, tmp_path, monkeypatch):
        from rebel_profiler.cli.context import AppContext

        monkeypatch.setenv("HOME", str(tmp_path))
        ctx = AppContext(data_dir=str(tmp_path / "data"))
        rec = ctx.create_case("Empty", "")
        db = ctx.open_case(rec["id"])
        try:
            session = make_session((ctx, rec, db, 0, tmp_path))
            with pytest.raises(UsageError) as exc:
                session.run()
            assert "bounty import" in exc.value.action
        finally:
            db.close()

    def test_inactive_case_is_refused_and_nothing_runs(self, case_env, monkeypatch):
        ctx, rec, db, _port, tmp_path = case_env
        ctx.set_case_status(rec["id"], "draft")
        session = make_session((ctx, ctx.find_case(rec["id"]), db, 0, tmp_path))
        with pytest.raises(UsageError) as exc:
            session.run()
        assert "case activate" in exc.value.action
        # Refused before any stage ran: no recon happened at all.
        assert session.result.stages == []


class TestSessionChain:
    def test_full_chain_produces_real_evidence_backed_findings(self, case_env):
        session = make_session(case_env, author_scripts=False)
        result = session.run()

        # The port-qualified asset is seeded with its port; the bare host is
        # seeded without one and lands on a closed port.
        assert f"http://127.0.0.1:{case_env[3]}/" in result.assets
        stats = result.audit["stats"]
        assert stats["pages_audited"] > 0
        # An unreachable seed is recorded and skipped — it never kills the run.
        assert stats["pages_blocked_or_errored"] >= 1

        # The loopback site sends no security headers, so real findings exist.
        findings = result.report["findings"]
        assert findings, "expected the audit to produce reportable findings"
        for finding in findings:
            assert finding["evidence_ids"], "a finding without evidence is not a finding"
            assert finding["cwe"].startswith("CWE-")
            assert "127.0.0.1" in finding["reproduce"]

        stages = {s["stage"]: s["status"] for s in result.stages}
        assert stages["scope"] == "done"
        assert stages["recon"] == "done"
        assert stages["assess"] == "done"
        assert stages["author"] == "skipped"        # authoring disabled
        assert stages["execute"] == "skipped"
        assert stages["repair"] == "skipped"
        assert stages["report"] == "done"

        assert result.stats["authoring_available"] is False
        assert result.stats["findings"] == len(findings)
        assert "Findings:" in result.render_human()

    def test_stages_are_recorded_once_in_chain_order(self, case_env):
        # The final report re-assesses (scripts may have added evidence), but
        # that must not show up as a second `assess` line.
        result = make_session(case_env, author_scripts=False).run()
        assert [s["stage"] for s in result.stages] == [
            "scope", "recon", "assess", "author", "execute", "repair", "report"]

    def test_network_ranges_are_skipped_with_a_reason(self, case_env):
        ctx, rec, db, _port, tmp_path = case_env
        db.add_scope_entry(rec["id"], "10.0.0.0/24", excluded=False, note="range")
        session = make_session((ctx, ctx.find_case(rec["id"]), db, 0, tmp_path),
                               author_scripts=False)
        result = session.run()
        skipped = {row["asset"]: row["reason"] for row in result.skipped_assets}
        assert "10.0.0.0/24" in skipped
        assert "network range" in skipped["10.0.0.0/24"]

    def test_out_of_scope_asset_is_never_seeded(self, case_env):
        ctx, rec, db, _port, tmp_path = case_env
        session = make_session((ctx, ctx.find_case(rec["id"]), db, 0, tmp_path),
                               author_scripts=False)
        # The engine was built from live scope *before* this entry appeared, so
        # the session must validate against the engine, not the raw entry list
        # — that is the fail-closed rule, not a convenience.
        db.add_scope_entry(rec["id"], "elsewhere.test", excluded=False, note="added")
        result = session.run()
        assert all("elsewhere.test" not in seed for seed in result.assets)
        assert any(row["asset"] == "elsewhere.test" for row in result.skipped_assets)


# ---------------------------------------------------------------- authoring loop

class _Reply:
    """Stands in for ``GenerationResult``: text plus which engine wrote it."""

    def __init__(self, text: str, engine: str = "stub", model: str = "stub-1b"):
        self.text, self.engine, self.model = text, engine, model


class _ScriptedModel:
    """A scripted model: real prompts in, canned replies out, calls counted."""

    def __init__(self, *, plan, author, repair=""):
        self.plan, self.author, self.repair = plan, author, repair
        self.calls: list[str] = []

    def __call__(self, prompt, *, model=None, plane=None, max_new_tokens=None):
        if "reply exactly: NONE" in prompt:
            self.calls.append("plan")
            return _Reply(self.plan if isinstance(self.plan, str)
                          else json.dumps(self.plan))
        if "You are fixing a Python script" in prompt:
            self.calls.append("repair")
            return _Reply(self.repair)
        self.calls.append("author")
        return _Reply(self.author)


def _plan(goal="count the authorized assets"):
    return [{"goal": goal, "payload": {"note": "from the plan"}}]


WORKING_SCRIPT = """\
```python
def run(payload):
    assets = payload.get("assets") or []
    findings = payload.get("findings") or []
    return {"assets": len(assets), "findings": len(findings)}
```
"""

RAISING_SCRIPT = """\
```python
def run(payload):
    raise ValueError("deliberate failure")
```
"""

GATE_REJECTED_SCRIPT = """\
```python
import os


def run(payload):
    return {"cwd": os.getcwd()}
```
"""


class TestAuthoringLoop:
    def test_model_written_script_runs_through_the_real_gate(
            self, case_env, monkeypatch):
        model = _ScriptedModel(plan=_plan(), author=WORKING_SCRIPT)
        monkeypatch.setattr(codegen, "_generate", model)

        session = make_session(case_env)
        result = session.run()

        assert model.calls == ["plan", "author"]
        assert result.authoring["available"] is True
        assert result.authoring["engine"] == "stub"
        assert len(result.scripts) == 1
        script = result.scripts[0]
        assert script["state"] == "done"
        # Real output computed in the sandbox over the real payload the
        # session handed it — the two authorized seeds.
        assert script["result"]["assets"] == len(result.assets) == 2
        assert script["result"]["findings"] == len(
            (result.report or {}).get("findings") or [])
        assert script["elapsed_s"] >= 0
        assert result.stats["scripts_succeeded"] == 1

        # The run is registered as case evidence, not just printed.
        kinds = {r.kind for r in session.evidence.list_records(result.case_id)}
        assert "llm_script_result" in kinds

        stages = {s["stage"]: s["status"] for s in result.stages}
        assert stages["author"] == "done"
        assert stages["execute"] == "done"
        assert stages["repair"] == "skipped"

    def test_model_may_decide_no_script_is_needed(self, case_env, monkeypatch):
        model = _ScriptedModel(plan="NONE", author="")
        monkeypatch.setattr(codegen, "_generate", model)
        result = make_session(case_env).run()
        assert model.calls == ["plan"]
        assert result.scripts == []
        assert result.authoring["available"] is True
        stages = {s["stage"]: s["status"] for s in result.stages}
        assert stages["author"] == "done"
        assert stages["execute"] == "skipped"
        assert stages["repair"] == "skipped"

    def test_no_engine_skips_authoring_honestly(self, case_env, monkeypatch):
        from rebel_profiler.core.errors import DependencyUnavailableError

        def _no_weights(prompt, *, model=None, plane=None, max_new_tokens=None):
            raise DependencyUnavailableError(
                "Writing a script needs real weights",
                action="pip install llama-cpp-python")

        monkeypatch.setattr(codegen, "_generate", _no_weights)
        result = make_session(case_env).run()

        assert result.authoring["available"] is False
        assert "llama-cpp-python" in result.authoring["action"]
        assert result.scripts == []
        # The deterministic half still delivered a report.
        assert result.report["findings"], "findings must survive a skipped authoring"
        assert "No scripts:" in result.render_human()

    def test_runtime_failure_is_repaired(self, case_env, monkeypatch):
        model = _ScriptedModel(plan=_plan(), author=RAISING_SCRIPT,
                               repair=WORKING_SCRIPT)
        monkeypatch.setattr(codegen, "_generate", model)

        result = make_session(case_env).run()

        assert model.calls == ["plan", "author", "repair"]
        first = result.scripts[0]
        assert first["state"] == "failed"
        assert "deliberate failure" in first["error"]
        assert first["repair_rounds"] == 1
        repaired = [s for s in result.scripts if s.get("parent_script_id")]
        assert len(repaired) == 1 and repaired[0]["state"] == "done"
        assert first["repaired_by"] == repaired[0]["script_id"]
        stages = {s["stage"]: s["status"] for s in result.stages}
        assert stages["repair"] == "done"

    def test_gate_rejection_is_reported_and_repaired(self, case_env, monkeypatch):
        model = _ScriptedModel(plan=_plan(), author=GATE_REJECTED_SCRIPT,
                               repair=WORKING_SCRIPT)
        monkeypatch.setattr(codegen, "_generate", model)

        result = make_session(case_env).run()

        first = result.scripts[0]
        # A gate refusal leaves a rejection file, not a result file — the
        # session must say "rejected", never leave it looking pending.
        assert first["state"] == "rejected"
        assert first["fix"]
        repaired = [s for s in result.scripts if s.get("parent_script_id")]
        assert repaired and repaired[0]["state"] == "done"

    def test_repair_is_bounded(self, case_env, monkeypatch):
        model = _ScriptedModel(plan=_plan(), author=RAISING_SCRIPT,
                               repair=RAISING_SCRIPT)
        monkeypatch.setattr(codegen, "_generate", model)
        result = make_session(case_env, max_repair_rounds=2).run()

        assert model.calls.count("repair") == 2
        first = result.scripts[0]
        assert first["repair_rounds"] == 2
        assert not first.get("repaired_by")

    def test_max_scripts_zero_disables_authoring(self, case_env, monkeypatch):
        def _explode(*a, **kw):      # pragma: no cover - must never be called
            raise AssertionError("the model must not be consulted")

        monkeypatch.setattr(codegen, "_generate", _explode)
        result = make_session(case_env, max_scripts=0).run()
        assert result.scripts == []
        assert result.authoring["available"] is False
        assert "disabled" in result.authoring["reason"]


# ---------------------------------------------------------------- CLI surface

@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return ["--data-dir", str(tmp_path / "data")]


class TestBountyAutoCli:
    def test_auto_requires_scope(self, workspace, capsys):
        assert main([*workspace, "case", "create", "Prog", "d", "-o", "json"]) == 0
        case_id = json.loads(capsys.readouterr().out)["data"]["id"]
        rc = main([*workspace, "bounty", "auto", case_id, "find what you can",
                   "-o", "json"])
        assert rc == 2
        err = json.loads(capsys.readouterr().err)["error"]
        assert "bounty import" in err["action"]

    def test_auto_requires_an_active_case(self, workspace, capsys, tmp_path):
        assert main([*workspace, "case", "create", "Prog", "d", "-o", "json"]) == 0
        case_id = json.loads(capsys.readouterr().out)["data"]["id"]
        scope = tmp_path / "s.txt"
        scope.write_text("127.0.0.1\n")
        assert main([*workspace, "bounty", "import", case_id, str(scope),
                     "-o", "json"]) == 0
        capsys.readouterr()
        rc = main([*workspace, "bounty", "auto", case_id, "go", "-o", "json"])
        assert rc == 2
        err = json.loads(capsys.readouterr().err)["error"]
        assert "case activate" in err["action"]

    def test_auto_runs_the_chain_against_a_real_target(
            self, workspace, capsys, tmp_path, local_site):
        port = local_site.rstrip("/").rsplit(":", 1)[1]
        scope = tmp_path / "h1.csv"
        scope.write_text(
            "Asset Identifier,Asset Type,Eligible for Submission,Instruction\n"
            f"127.0.0.1,PURL,true,loopback\n"
            f"127.0.0.1:{port},URL,true,loopback port\n")
        assert main([*workspace, "case", "create", "Prog", "d", "-o", "json"]) == 0
        case_id = json.loads(capsys.readouterr().out)["data"]["id"]
        assert main([*workspace, "bounty", "import", case_id, str(scope),
                     "--program", "loopback", "--activate", "-o", "json"]) == 0
        capsys.readouterr()

        rc = main([*workspace, "bounty", "auto", case_id,
                   "this scope came from a program: find what you can, test it, "
                   "and give me a report with real results, no demos",
                   "--scheme", "http", "--no-author", "--save", "-o", "json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)["data"]

        assert payload["goal"].startswith("this scope came from a program")
        assert f"http://127.0.0.1:{port}/" in payload["assets"]
        findings = payload["report"]["findings"]
        assert findings
        assert all(f["evidence_ids"] for f in findings)
        assert payload["stats"]["authoring_available"] is False
        # --save wrote the full session next to the case
        from pathlib import Path

        report_path = Path(payload["stats"]["report_path"])
        saved = json.loads(report_path.read_text())
        assert saved["case_id"] == case_id
        assert saved["report"]["findings"] == findings

    def test_auto_human_output_is_readable(self, workspace, capsys, tmp_path,
                                           local_site):
        port = local_site.rstrip("/").rsplit(":", 1)[1]
        scope = tmp_path / "s.txt"
        scope.write_text(f"127.0.0.1\n127.0.0.1:{port}\n")
        assert main([*workspace, "case", "create", "Prog", "d", "-o", "json"]) == 0
        case_id = json.loads(capsys.readouterr().out)["data"]["id"]
        assert main([*workspace, "bounty", "import", case_id, str(scope),
                     "--activate", "-o", "json"]) == 0
        capsys.readouterr()
        rc = main([*workspace, "bounty", "auto", case_id, "report please",
                   "--scheme", "http", "--no-author"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Bounty session" in out
        assert "[+] recon" in out
        assert "Findings:" in out
        assert "evidence verify" in out
