"""Tests for the authorized bug-bounty workflow: scope import + triage."""

from __future__ import annotations

import json

import pytest

from rebel_profiler.cli.main import main
from rebel_profiler.core.errors import ScopeViolationError, UsageError
from rebel_profiler.intel.bounty import assess, assess_claims
from rebel_profiler.intel.claims import ClaimLedger
from rebel_profiler.intel.program import (
    normalize_asset,
    parse_scope_document,
)


# ---------------------------------------------------------------- parsing

class TestNormalizeAsset:
    def test_plain_host(self):
        assert normalize_asset("Example.TEST") == "example.test"

    def test_wildcard_kept(self):
        assert normalize_asset("*.example.test") == "*.example.test"

    def test_url_reduced_to_host(self):
        assert normalize_asset("https://api.example.test:8443/v1/x?y=1") == "api.example.test"

    def test_cidr_kept(self):
        assert normalize_asset("10.0.0.0/24", "CIDR") == "10.0.0.0/24"

    def test_ipv6_port_not_truncated(self):
        # IPv6 has many colons; a naive split would destroy the address.
        assert normalize_asset("https://[2001:db8::1]/") == "[2001:db8::1]"

    def test_non_host_type_returns_none(self):
        assert normalize_asset("github.com/acme/repo", "SOURCE_CODE") is None
        assert normalize_asset("com.acme.app", "GOOGLE_PLAY_APP_ID") is None

    def test_blank_returns_none(self):
        assert normalize_asset("   ") is None


class TestParseScopeDocument:
    def test_hackerone_csv(self):
        text = (
            "Asset Identifier,Asset Type,Eligible for Submission,Max Severity,Instruction\n"
            "*.example.test,WILDCARD,true,critical,no DoS\n"
            "api.example.test,URL,true,high,rate limit\n"
            "admin.example.test,URL,false,low,not eligible\n"
            "github.com/acme/repo,SOURCE_CODE,true,medium,review only\n"
        )
        doc = parse_scope_document(text, program="acme")
        values = {e["value"] for e in doc["includes"]}
        assert values == {"*.example.test", "api.example.test"}
        # ineligible asset -> exclusion, not an include
        excluded = {e["value"] for e in doc["excludes"]}
        assert "admin.example.test" in excluded
        assert any("not eligible" in e["note"] for e in doc["excludes"])
        # non-host asset skipped with a reason, never mis-mapped
        assert [s["asset"] for s in doc["skipped"]] == ["github.com/acme/repo"]
        assert doc["stats"]["includes"] == 2

    def test_hackerone_json_attributes(self):
        doc = parse_scope_document(json.dumps({"data": [
            {"attributes": {"asset_identifier": "*.lab.test", "asset_type": "WILDCARD",
                            "eligible_for_submission": True, "instruction": "lab"}},
            {"attributes": {"asset_identifier": "10.0.0.0/24", "asset_type": "CIDR",
                            "eligible_for_submission": True}},
        ]}), program="lab")
        assert {e["value"] for e in doc["includes"]} == {"*.lab.test", "10.0.0.0/24"}

    def test_explicit_in_scope_lists(self):
        doc = parse_scope_document(json.dumps({
            "in_scope": [{"target": "a.test"}, {"target": "b.test"}],
        }))
        assert {e["value"] for e in doc["includes"]} == {"a.test", "b.test"}

    def test_plain_list_with_exclusions(self):
        doc = parse_scope_document(
            "# a scope file\n"
            "in-scope.test   # primary\n"
            "!out.test\n"
            "-also-out.test\n"
            "out:third-out.test\n"
        )
        assert [e["value"] for e in doc["includes"]] == ["in-scope.test"]
        assert {e["value"] for e in doc["excludes"]} == {
            "out.test", "also-out.test", "third-out.test"}
        assert doc["includes"][0]["note"] == "primary"

    def test_blank_document_rejected(self):
        with pytest.raises(ValueError):
            parse_scope_document("   \n  ")


# ---------------------------------------------------------------- triage

def _ledger_with(registry=None, *, case_id="c1"):
    ledger = ClaimLedger(registry)

    def add(subject, kind, value, *, conf_source="scan.web", notes="", evidence="ev1"):
        return ledger.add(case_id, subject=subject, kind=kind, value=value,
                          source=conf_source, method="web-audit",
                          evidence_id=evidence, notes=notes)

    return ledger, add


class TestBountyTriage:
    def test_cleartext_password_form_is_high(self):
        ledger, add = _ledger_with()
        add("h1.test", "web_finding",
            "cleartext_password_form:password field(s) pw submitted over http to /login",
            notes="url=http://h1.test/login")
        report = assess(ledger, "c1")
        assert len(report.findings) == 1
        finding = report.findings[0]
        assert finding.severity == "high"
        assert finding.cwe == "CWE-319"
        assert finding.evidence_ids == ("ev1",)
        # reproduction is built from the URL the evidence actually came from
        assert "http://h1.test/login" in finding.reproduce

    def test_missing_header_maps_to_informational(self):
        ledger, add = _ledger_with()
        add("h1.test", "web_finding", "header:CSP:missing")
        report = assess(ledger, "c1")
        assert report.findings[0].severity == "informational"
        assert report.findings[0].cwe == "CWE-693"

    def test_cookie_flags_are_low(self):
        ledger, add = _ledger_with()
        add("h1.test", "web_finding", "cookie:Secure:cookie 'sid' lacks Secure")
        report = assess(ledger, "c1")
        assert report.findings[0].severity == "low"
        assert report.findings[0].cwe == "CWE-614"

    def test_legacy_tls_is_medium(self):
        ledger, add = _ledger_with()
        add("h1.test", "web_finding", "tls:protocol:legacy protocol TLSv1 in use",
            notes="url=https://h1.test/")
        report = assess(ledger, "c1")
        assert report.findings[0].severity == "medium"
        assert report.findings[0].cwe == "CWE-326"
        assert "h1.test:443" in report.findings[0].reproduce

    def test_severity_sorting_high_first(self):
        ledger, add = _ledger_with()
        add("a.test", "web_finding", "header:CSP:missing")
        add("b.test", "web_finding",
            "cleartext_password_form:password submitted over http")
        report = assess(ledger, "c1")
        assert [f.severity for f in report.findings] == ["high", "informational"]
        assert report.stats["by_severity"]["high"] == 1

    def test_duplicate_class_per_asset_collapsed(self):
        ledger, add = _ledger_with()
        add("h1.test", "web_finding", "header:HSTS:missing")
        add("h1.test", "web_finding", "header:HSTS:missing")
        report = assess(ledger, "c1")
        assert len(report.findings) == 1

    def test_risky_service_mapped(self):
        ledger, add = _ledger_with()
        add("h1.test", "service", "telnet", conf_source="scan.nmap")
        report = assess(ledger, "c1")
        assert report.findings[0].severity == "medium"
        assert "Telnet" in report.findings[0].remediation

    def test_unmapped_observation_kept_not_reported(self):
        ledger, add = _ledger_with()
        add("h1.test", "web_finding", "some_new_check:unexpected value")
        report = assess(ledger, "c1")
        assert report.findings == []
        assert len(report.unmapped) == 1
        assert report.unmapped[0]["asset"] == "h1.test"

    def test_contradicted_claim_never_ships(self):
        ledger, add = _ledger_with()
        claim = add("h1.test", "web_finding", "header:CSP:missing")
        claim.state = "contradicted"
        assert assess(ledger, "c1").findings == []

    def test_low_confidence_claim_excluded(self):
        ledger, add = _ledger_with()
        claim = add("h1.test", "web_finding", "header:CSP:missing")
        claim.confidence = 0.05
        assert assess(ledger, "c1").findings == []

    def test_unrelated_claim_kind_ignored(self):
        ledger, add = _ledger_with()
        add("h1.test", "hostname", "h1.test", conf_source="scan.web")
        report = assess(ledger, "c1")
        assert report.findings == [] and report.unmapped == []

    def test_empty_case_is_honest(self):
        report = assess(ClaimLedger(), "c9")
        assert report.findings == []
        assert "No reportable findings" in report.render_human()

    def test_report_dict_shape(self):
        ledger, add = _ledger_with()
        add("h1.test", "web_finding", "header:HSTS:missing")
        payload = assess(ledger, "c1", program="acme").as_dict()
        assert payload["program"] == "acme"
        assert payload["schema_version"] == 1
        assert "Advisory" in payload["severity_note"]
        assert payload["findings"][0]["asset"] == "h1.test"


# ---------------------------------------------------------------- CLI

@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return ["--data-dir", str(tmp_path / "data")]


def _case_id(capsys) -> str:
    """Read the id from a preceding `case create -o json` call."""
    return json.loads(capsys.readouterr().out)["data"]["id"]


class TestBountyCli:
    def test_import_then_scope_is_enforced(self, workspace, capsys, tmp_path):
        assert main([*workspace, "case", "create", "Prog", "d", "-o", "json"]) == 0
        case_id = _case_id(capsys)
        scope = tmp_path / "scope.csv"
        scope.write_text(
            "Asset Identifier,Asset Type,Eligible for Submission,Instruction\n"
            "*.example.test,WILDCARD,true,no DoS\n"
            "admin.example.test,URL,false,ineligible\n")
        assert main([*workspace, "bounty", "import", case_id, str(scope),
                     "--program", "acme", "-o", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)["data"]
        assert payload["includes"] == 1 and payload["excludes"] == 1
        assert payload["activated"] is False

        assert main([*workspace, "case", "activate", case_id, "-o", "json"]) == 0
        capsys.readouterr()
        # in scope
        assert main([*workspace, "scope-check", case_id, "h1.example.test",
                     "-o", "json"]) == 0
        capsys.readouterr()
        # the ineligible asset was imported as an exclusion and fails closed
        assert main([*workspace, "scope-check", case_id, "admin.example.test",
                     "-o", "json"]) == 5

    def test_import_activate_flag(self, workspace, capsys, tmp_path):
        assert main([*workspace, "case", "create", "P", "d", "-o", "json"]) == 0
        case_id = _case_id(capsys)
        scope = tmp_path / "s.txt"
        scope.write_text("in.test\n")
        assert main([*workspace, "bounty", "import", case_id, str(scope),
                     "--activate", "-o", "json"]) == 0
        assert json.loads(capsys.readouterr().out)["data"]["activated"] is True

    def test_import_bad_file_is_structured_error(self, workspace, capsys, tmp_path):
        assert main([*workspace, "case", "create", "P", "d", "-o", "json"]) == 0
        case_id = _case_id(capsys)
        rc = main([*workspace, "bounty", "import", case_id,
                   str(tmp_path / "missing.csv"), "-o", "json"])
        assert rc == 2      # UsageError exit code
        err = json.loads(capsys.readouterr().err)["error"]
        assert err["action"]

    def test_run_defaults_to_plan_only(self, workspace, capsys, tmp_path):
        assert main([*workspace, "case", "create", "P", "d", "-o", "json"]) == 0
        case_id = _case_id(capsys)
        scope = tmp_path / "s.txt"
        scope.write_text("h1.example.test\n10.0.0.0/24\n")
        assert main([*workspace, "bounty", "import", case_id, str(scope),
                     "-o", "json"]) == 0
        capsys.readouterr()
        assert main([*workspace, "bounty", "run", case_id, "-o", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)["data"]
        assert payload["executed"] is False
        assert payload["seeds"] == ["https://h1.example.test/"]
        # the CIDR is skipped for a web audit, with a reason
        assert any("network range" in row["reason"] for row in payload["skipped"])

    def test_execute_refuses_inactive_case(self, workspace, capsys, tmp_path):
        assert main([*workspace, "case", "create", "P", "d", "-o", "json"]) == 0
        case_id = _case_id(capsys)
        scope = tmp_path / "s.txt"
        scope.write_text("h1.example.test\n")
        assert main([*workspace, "bounty", "import", case_id, str(scope),
                     "-o", "json"]) == 0
        capsys.readouterr()
        rc = main([*workspace, "bounty", "run", case_id, "--execute", "-o", "json"])
        assert rc == 2
        err = json.loads(capsys.readouterr().err)["error"]
        assert "activate" in err["action"]

    def test_assess_cli_reads_real_ledger(self, workspace, capsys, tmp_path):
        assert main([*workspace, "case", "create", "P", "d", "-o", "json"]) == 0
        case_id = _case_id(capsys)
        # write a real web_finding claim into the case DB, then assess it
        from rebel_profiler.cli.context import AppContext
        from rebel_profiler.intel import ClaimLedger, SourceRegistry

        ctx = AppContext(data_dir=str(tmp_path / "data"))
        rec = ctx.find_case(case_id)
        db = ctx.open_case(rec["id"])
        try:
            ledger = ClaimLedger(SourceRegistry())
            claim = ledger.add(
                rec["id"], subject="h1.example.test", kind="web_finding",
                value="header:CSP:missing", source="scan.web",
                method="web-audit", evidence_id="ev-1",
                notes="url=https://h1.example.test/")
            db.record_claim(
                claim.id, rec["id"], subject=claim.subject, kind=claim.kind,
                value=claim.value, source=claim.source, method=claim.method,
                observed_at=claim.observed_at, confidence=claim.confidence,
                evidence_id=claim.evidence_id, state=claim.state,
                notes=claim.notes)
        finally:
            db.close()

        assert main([*workspace, "bounty", "assess", case_id, "-o", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)["data"]
        assert payload["stats"]["findings"] == 1
        assert payload["findings"][0]["asset"] == "h1.example.test"
        assert payload["findings"][0]["evidence_ids"] == ["ev-1"]

    def test_scope_check_out_of_scope_exits_5(self, workspace, capsys):
        assert main([*workspace, "case", "create", "P", "d", "-o", "json"]) == 0
        case_id = _case_id(capsys)
        assert main([*workspace, "case", "activate", case_id, "-o", "json"]) == 0
        capsys.readouterr()
        assert main([*workspace, "scope-check", case_id, "nope.test", "-o", "json"]) == 5


# ---------------------------------------------------------------- crawl persistence

class TestCrawlFindingsPersist:
    """Regression: web-audit findings must reach the claim ledger.

    The auditor supports `db=` and only persists when it is passed. Forgetting
    it in the CLI left every crawl finding stranded in a discarded in-memory
    ledger, so `report`, `surface build`, `intel fusion` and `bounty assess`
    all reported nothing despite a successful audit.
    """

    def test_crawl_then_assess(self, workspace, capsys, local_site):
        assert main([*workspace, "case", "create", "P", "d", "-o", "json"]) == 0
        case_id = _case_id(capsys)
        assert main([*workspace, "case", "scope", "add", case_id, "127.0.0.1",
                     "-o", "json"]) == 0
        assert main([*workspace, "case", "activate", case_id, "-o", "json"]) == 0
        capsys.readouterr()

        assert main([*workspace, "intel", "crawl", case_id, local_site,
                     "--max-pages", "1", "-o", "json"]) == 0
        audit = json.loads(capsys.readouterr().out)["data"]
        assert audit["stats"]["findings"] > 0

        # a generic report must see the claim as well
        assert main([*workspace, "report", case_id, "-o", "json"]) == 0
        report = json.loads(capsys.readouterr().out)["data"]
        assert report["stats"]["claims_total"] > 0

        # and the bounty triage must turn it into real, evidence-backed findings
        rc = main([*workspace, "bounty", "assess", case_id, "-o", "json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)["data"]
        assert payload["stats"]["findings"] > 0
        finding = payload["findings"][0]
        assert finding["asset"] == "127.0.0.1"
        assert finding["evidence_ids"]                       # real evidence id
        assert "127.0.0.1" in finding["reproduce"]            # real repro target
        assert finding["cwe"].startswith("CWE-")
