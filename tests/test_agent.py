"""Tests for CT/passive-DNS parsing, new adapter, findings report and agent session."""

from __future__ import annotations

import json

import pytest

from rebel_profiler.agent import AgentSession, PlannerView, Proposal
from rebel_profiler.core.errors import UsageError
from rebel_profiler.execution import AdapterRegistry
from rebel_profiler.execution.adapters import PassiveDnsMultiAdapter
from rebel_profiler.execution.broker import ActionRequest, ExecutionBroker
from rebel_profiler.intel.claims import ClaimLedger
from rebel_profiler.intel.collection import CollectionPipeline
from rebel_profiler.intel.findings import generate_report
from rebel_profiler.intel.sources import SourceRegistry
from rebel_profiler.security.scope import Scope, ScopeEngine, ScopeStatus
from rebel_profiler.storage.database import Database


# ---------------------------------------------------------------- adapter


class TestPassiveDnsMultiAdapter:
    def test_basic_argv(self):
        request = ActionRequest(case_id="c", capability="passive_recon",
                                action="passive-dns", target="lab.example.test",
                                params={"record_type": "MX"})
        assert PassiveDnsMultiAdapter().build_argv(request) == \
            ["dig", "+short", "-t", "MX", "lab.example.test"]

    def test_default_a(self):
        request = ActionRequest(case_id="c", capability="passive_recon",
                                action="passive-dns", target="lab.example.test")
        assert "-t" in PassiveDnsMultiAdapter().build_argv(request)

    def test_rejects_unknown_rtype(self):
        request = ActionRequest(case_id="c", capability="passive_recon",
                                action="passive-dns", target="lab.example.test",
                                params={"record_type": "ANY"})
        with pytest.raises(UsageError):
            PassiveDnsMultiAdapter().build_argv(request)

    def test_rejects_injection_target(self):
        request = ActionRequest(case_id="c", capability="passive_recon",
                                action="passive-dns", target="x.test; id")
        with pytest.raises(UsageError):
            PassiveDnsMultiAdapter().build_argv(request)

    def test_registered(self):
        assert "passive-dns" in AdapterRegistry().names()


# ---------------------------------------------------------------- parsers


class TestRecordTypeParsing:
    @pytest.fixture()
    def pipeline(self, tmp_path):
        db = Database(tmp_path / "c.db")
        db.migrate()
        db.create_case("c1", case_id="c1")
        from rebel_profiler.evidence.store import EvidenceStore

        store = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
        return CollectionPipeline(ClaimLedger(SourceRegistry()), store, db=db)

    def _ingest(self, pipeline, rtype, stdout):
        return pipeline.ingest(
            "c1", action="passive-dns", target="lab.example.test",
            stdout=stdout, returncode=0, task_id="t", params={"record_type": rtype},
        )

    def test_mx_pref_stripped(self, pipeline):
        report = self._ingest(pipeline, "MX", "10 mail.example.test.\n20 mail2.example.test.\n")
        kinds = {(c["kind"], c["value"]) for c in report["claims"]}
        assert ("mx", "mail.example.test") in kinds
        assert ("mx", "mail2.example.test") in kinds
        assert not any(c["kind"] == "ip" for c in report["claims"])

    def test_a_records(self, pipeline):
        report = self._ingest(pipeline, "A", "93.184.216.34\n")
        assert report["claims"][0]["kind"] == "ip"

    def test_txt_kept_verbatim(self, pipeline):
        report = self._ingest(pipeline, "TXT", '"v=spf1 include:_spf.example.test ~all"\n')
        assert report["claims"][0]["kind"] == "txt"
        assert "spf" in report["claims"][0]["value"]

    def test_soa_two_claims(self, pipeline):
        report = self._ingest(pipeline, "SOA",
                              "ns1.example.test. hostmaster.example.test. 2024010101 7200 3600 1209600 3600\n")
        kinds = {c["kind"] for c in report["claims"]}
        assert kinds == {"nameserver", "soa_contact"}

    def test_type_mismatch_yields_nothing(self, pipeline):
        # A-type output fed as AAAA parse → no invented claims
        report = self._ingest(pipeline, "AAAA", "93.184.216.34\n")
        assert report["claims"] == []

    def test_ns_records(self, pipeline):
        report = self._ingest(pipeline, "NS", "ns1.example.test.\n")
        assert report["claims"][0]["kind"] == "nameserver"

    def test_ct_json(self, pipeline):
        entries = [
            {"id": 101, "common_name": "lab.example.test",
             "name_value": "lab.example.test\nwww.lab.example.test"},
            {"id": 102, "common_name": "www.lab.example.test",
             "name_value": "www.lab.example.test"},
        ]
        report = self._ingest_ct = pipeline.ingest(
            "c1", action="cert-transparency", target="lab.example.test",
            stdout=json.dumps(entries), returncode=0, task_id="t2",
        )
        kinds = {(c["kind"], c["value"]) for c in report["claims"]}
        assert ("hostname", "www.lab.example.test") in kinds
        assert any(k == "certificate" for k, _ in kinds)

    def test_ct_malformed_json_yields_nothing(self, pipeline):
        report = pipeline.ingest(
            "c1", action="cert-transparency", target="lab.example.test",
            stdout="<html>error</html>", returncode=0, task_id="t3",
        )
        assert report["claims"] == []
        assert report["evidence_id"]  # evidence still registered

    def test_dedupe_within_batch(self, pipeline):
        report = self._ingest(pipeline, "MX", "10 mail.example.test.\n10 mail.example.test.\n")
        assert len(report["claims"]) == 1

    def test_provenance_fields(self, pipeline):
        report = self._ingest(pipeline, "A", "1.2.3.4\n")
        claim = report["claims"][0]
        assert claim["source"] == "dns.authoritative"
        assert claim["method"] == "passive-dns"
        assert claim["evidence_id"]
        assert claim["notes"].startswith("task=")


# ---------------------------------------------------------------- findings


class TestFindings:
    def _ledger_with(self):
        ledger = ClaimLedger(SourceRegistry())
        now = 1000.0
        ledger.add("c1", subject="lab.example.test", kind="ip", value="1.2.3.4",
                   source="dns.authoritative", observed_at=now)
        ledger.add("c1", subject="lab.example.test", kind="ip", value="1.2.3.4",
                   source="ct.logs", observed_at=now)  # corroborates
        ledger.add("c1", subject="lab.example.test", kind="mx", value="mail.example.test",
                   source="dns.authoritative", observed_at=now)
        return ledger

    def test_corroborated_state_in_report(self):
        ledger = self._ledger_with()
        report = generate_report(ledger, "c1")
        by_kind = {f.kind: f for f in report.findings}
        assert by_kind["ip"].state == "corroborated"
        assert "ct.logs" in by_kind["ip"].corroborated_by
        assert by_kind["mx"].state == "open"

    def test_stats_and_human_render(self):
        ledger = self._ledger_with()
        report = generate_report(ledger, "c1")
        assert report.stats["claims_total"] == 3
        assert report.stats["findings"] == 2
        text = report.render_human()
        assert "corroborated" in text
        assert "evidence verify" in text

    def test_contradicted_never_a_finding(self):
        ledger = ClaimLedger(SourceRegistry())
        now = 1000.0
        # same observing domain, deterministic scores: iana(1.0) > registrar(0.9)
        ledger.add("c1", subject="a.test", kind="registrar", value="Real",
                   source="whois.iana", observed_at=now)
        ledger.add("c1", subject="a.test", kind="registrar", value="Maybe",
                   source="whois.registrar", observed_at=now)
        report = generate_report(ledger, "c1")
        # the contradicted loser never becomes a finding; the live winner does
        assert not any(f.value == "Maybe" for f in report.findings)
        assert any(f.value == "Real" for f in report.findings)
        assert report.stats["conflicts"] == 1
        assert report.conflicts  # surfaced explicitly in the report

    def test_empty_case_report(self):
        ledger = ClaimLedger(SourceRegistry())
        report = generate_report(ledger, "empty")
        assert report.findings == []
        assert "No reportable findings" in report.render_human()


# ---------------------------------------------------------------- agent


@pytest.fixture()
def env(tmp_path):
    db = Database(tmp_path / "case.db")
    db.migrate()
    db.create_case("AgentCase", case_id="c1")
    from rebel_profiler.evidence.store import EvidenceStore

    store = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
    scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
    scope.add("*.lab.example.test")
    engine = ScopeEngine()
    engine.register(scope)
    broker = ExecutionBroker(db, scope_engine=engine, evidence=store)
    ledger = ClaimLedger(SourceRegistry())
    session = AgentSession("c1", "map lab.example.test", broker=broker,
                           ledger=ledger, evidence=store, db=db)
    return db, session


class TestAgentSession:
    def test_successful_plan_collects_claims(self, env):
        _, session = env
        plan = [
            Proposal(action="echo", target="h.lab.example.test",
                     params={"message": "recon step"}),
        ]
        result = session.run(lambda view: plan)
        assert result["steps"][0]["outcome"] == "succeeded"
        assert result["report"]["stats"]["claims_total"] >= 0  # echo parses to nothing

    def test_planner_cannot_propose_unknown_action(self, env):
        _, session = env
        with pytest.raises(UsageError):
            session.run(lambda view: [Proposal(action="rm-rf", target="h.lab.example.test")])

    def test_planner_cannot_propose_undeclared_params(self, env):
        _, session = env
        with pytest.raises(UsageError):
            session.run(lambda view: [
                Proposal(action="echo", target="h.lab.example.test",
                         params={"cmd": "evil"}),
            ])

    def test_out_of_scope_is_feedback_not_crash(self, env):
        _, session = env
        plan = [
            Proposal(action="echo", target="evil.test", params={}),
            Proposal(action="echo", target="h.lab.example.test",
                     params={"message": "ok"}),
        ]
        result = session.run(lambda view: plan)
        outcomes = [s["outcome"] for s in result["steps"]]
        assert outcomes == ["denied", "succeeded"]
        assert result["steps"][0]["note"]  # denial reason surfaced

    def test_view_shows_only_declared_actions(self, env):
        _, session = env
        view = PlannerView("c1", "goal", session.broker.adapters)
        actions = view.available_actions()
        assert {"echo", "whois-lookup", "passive-dns"} <= {a["action"] for a in actions}
        assert all("allowed_params" in a for a in actions)

    def test_no_proposals_rejected(self, env):
        _, session = env
        with pytest.raises(UsageError):
            session.run(lambda view: [])

    def test_runaway_plan_capped(self, env):
        _, session = env
        session.max_actions = 2
        plan = [Proposal(action="echo", target="h.lab.example.test") for _ in range(5)]
        with pytest.raises(UsageError):
            session.run(lambda view: plan)
