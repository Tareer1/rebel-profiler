"""Tests for the Phase 12 reach items: zipapp self-update (ops update),
SARIF / Markdown report exporters, and hunt playbooks.

Offline discipline: no network in any test. The self-update is exercised
against a LOCAL http.server serving a fixture release; the exporters get a
hand-built report dict; playbooks are validated against the live
AdapterRegistry the same way vulncov is.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import threading
import zipfile
from pathlib import Path

import pytest

from rebel_profiler.core.errors import StateError, UsageError
from rebel_profiler.core.ops import update_zipapp
from rebel_profiler.execution.broker import AdapterRegistry
from rebel_profiler.intel.collection import _parse_nmap
from rebel_profiler.intel.playbooks import (
    expand_playbook,
    get_playbook,
    load_playbooks,
    validate_playbook,
)
from rebel_profiler.intel.report_export import to_markdown, to_sarif
from rebel_profiler.security.scope import ScopeEntry


# ------------------------------------------------------------ self-update

def _make_zipapp(path: Path, version: str) -> str:
    """A minimal valid pyz: __main__ + __init__ carrying the version."""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("rebel_profiler/__init__.py",
                    f'__version__ = "{version}"\n')
        zf.writestr("__main__.py", "import rebel_profiler\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


class _FixtureRelease:
    """Serves one zipapp + sha256 as a 'latest release' on 127.0.0.1."""

    def __init__(self, tmp_path: Path, version: str):
        tmp_path.mkdir(parents=True, exist_ok=True)
        pyz_path = tmp_path / "rebel-profiler.pyz"
        digest = _make_zipapp(pyz_path, version)
        (tmp_path / "rebel-profiler.pyz.sha256").write_text(
            digest + "  rebel-profiler.pyz\n")
        self.root = tmp_path
        handler = lambda *a, **kw: http.server.SimpleHTTPRequestHandler(  # noqa: E731
            directory=str(tmp_path), *a, **kw)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class TestSelfUpdate:
    def test_update_replaces_and_reports(self, tmp_path):
        rel = _FixtureRelease(tmp_path / "rel", "9.9.9")
        try:
            target = tmp_path / "installed.pyz"
            _make_zipapp(target, "1.0.0")
            rec = update_zipapp(target, base_url=rel.base)
            assert rec["updated"] is True
            assert rec["version"] == "9.9.9"
            # the bytes on disk now match the published checksum
            published = (rel.root / "rebel-profiler.pyz.sha256").read_text().split()[0]
            assert hashlib.sha256(target.read_bytes()).hexdigest() == published
        finally:
            rel.stop()

    def test_same_version_is_noop(self, tmp_path):
        rel = _FixtureRelease(tmp_path / "rel", "1.0.0")
        try:
            target = tmp_path / "installed.pyz"
            _make_zipapp(target, "1.0.0")
            rec = update_zipapp(target, base_url=rel.base, expect_version="1.0.0")
            assert rec["updated"] is False
            assert "already" in rec["reason"]
        finally:
            rel.stop()

    def test_checksum_mismatch_never_installs(self, tmp_path):
        rel = _FixtureRelease(tmp_path / "rel", "9.9.9")
        try:
            # tamper: the served checksum no longer matches the zipapp
            (rel.root / "rebel-profiler.pyz.sha256").write_text("0" * 64 + "  x\n")
            target = tmp_path / "installed.pyz"
            before = _make_zipapp(target, "1.0.0")
            with pytest.raises(StateError, match="MISMATCH"):
                update_zipapp(target, base_url=rel.base)
            # the old tool is untouched — nothing half-installed
            assert hashlib.sha256(target.read_bytes()).hexdigest() == before
        finally:
            rel.stop()

    def test_offline_is_structured(self, tmp_path):
        target = tmp_path / "installed.pyz"
        _make_zipapp(target, "1.0.0")
        # port 1 is unusable → connection refused, not a traceback
        with pytest.raises(StateError, match="unreachable"):
            update_zipapp(target, base_url="http://127.0.0.1:1")

    def test_missing_target_is_usage_error(self, tmp_path):
        with pytest.raises(UsageError):
            update_zipapp(tmp_path / "nope.pyz")


# ------------------------------------------------------------- exporters

def _report() -> dict:
    return {
        "case_id": "c1", "program": "acme", "generated_at": 1790000000.0,
        "severity_note": "Advisory mapping only.",
        "stats": {"assets": 1, "findings": 1},
        "findings": [{
            "asset": "h1.test", "title": "Missing HSTS", "severity": "low",
            "cwe": "CWE-319", "detail": "missing", "impact": "downgrade",
            "reproduce": "curl -sSI http://h1.test", "remediation": "Send HSTS",
            "confidence": 0.88, "evidence_ids": ["ev_1"], "claim_ids": ["cl_1"],
            "source": "scan.web", "method": "header-audit", "observed_at": 1.0,
            "url": "http://h1.test/",
        }],
        "unmapped_observations": [{"kind": "x", "value": "y"}],
    }


class TestSarif:
    def test_valid_sarif_shape(self):
        d = json.loads(to_sarif(_report()))
        assert d["version"] == "2.1.0"
        run = d["runs"][0]
        assert run["tool"]["driver"]["name"] == "rebel-profiler"
        assert len(run["results"]) == 1
        res = run["results"][0]
        assert res["ruleId"].startswith("CWE-")
        assert res["level"] == "warning"          # low → warning
        uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "http://h1.test/"

    def test_severity_mapping(self):
        assert to_sarif({"findings": [{"severity": "high", "cwe": "CWE-1"}]})
        d = json.loads(to_sarif({
            "findings": [
                {"severity": "high", "cwe": "CWE-1", "asset": "a"},
                {"severity": "informational", "cwe": "CWE-2", "asset": "a"},
            ]}))
        levels = [r["level"] for r in d["runs"][0]["results"]]
        assert levels == ["error", "note"]

    def test_empty_report_stays_empty(self):
        d = json.loads(to_sarif({"findings": []}))
        assert d["runs"][0]["results"] == []


class TestMarkdown:
    def test_sections_present(self):
        md = to_markdown(_report())
        assert "# Bounty report — acme" in md
        assert "| 1 | low | Missing HSTS | h1.test | CWE-319 |" in md
        assert "curl -sSI http://h1.test" in md
        assert "`ev_1`" in md
        assert "evidence verify c1" in md

    def test_empty_is_honest(self):
        md = to_markdown({"case_id": "c1", "findings": [], "stats": {}})
        assert "No reportable findings" in md

    def test_unmapped_kept(self):
        md = to_markdown(_report())
        assert "Unmapped observations" in md and "y" in md


# ------------------------------------------------------------- playbooks

class TestPlaybooks:
    def test_builtins_validate_against_live_registry(self):
        for pb in load_playbooks():
            v = validate_playbook(pb)
            assert v["healthy"], f"{pb.name}: {v['problems']}"
            assert len(pb.steps) >= 2

    def test_unknown_playbook_is_structured(self):
        with pytest.raises(UsageError):
            get_playbook("does-not-exist")

    def test_expansion_is_plan_only(self):
        pb = get_playbook("web-audit")
        ex = expand_playbook(pb, "h1.test")
        assert ex["target"] == "h1.test"
        assert all("why" in e for e in ex["entries"])
        # header-audit ships scheme=https; a real http-only host needs the
        # operator override (-p scheme http) — the recipe records intent
        first = ex["entries"][0]
        assert first["action"] == "header-audit"

    def test_operator_file_loads_and_bad_file_rejected(self, tmp_path):
        pdir = tmp_path / "playbooks"
        pdir.mkdir()
        good = {
            "name": "site-specific", "version": "2",
            "description": "d", "author": "op", "tags": ["x"],
            "steps": [{"action": "dns-lookup", "why": "resolve"}],
        }
        (pdir / "site-specific.json").write_text(json.dumps(good))
        names = [p.name for p in load_playbooks(tmp_path)]
        assert "site-specific" in names
        pb = get_playbook("site-specific", tmp_path)
        assert pb.source.endswith("site-specific.json")

        (pdir / "broken.json").write_text("{not json")
        with pytest.raises(UsageError, match="broken.json"):
            load_playbooks(tmp_path)

    def test_drifted_step_is_reported_not_run(self):
        raw = {
            "name": "drifted", "version": "1", "description": "d",
            "steps": [{"action": "no-such-action", "why": "w"}],
        }
        pb = get_playbook("web-audit")  # valid base for construction path
        # build a drifted playbook through the parser by injecting a raw step
        from rebel_profiler.intel.playbooks import _parse_playbook
        drifted = _parse_playbook(raw, source="test")
        v = validate_playbook(drifted)
        assert v["healthy"] is False
        assert v["problems"][0]["problem"] == "no such adapter"
        ex = expand_playbook(drifted, "h1.test")
        assert ex["entries"] == []          # invalid steps never expand
        assert get_playbook is not None     # (parser sanity)
        assert pb.name == "web-audit"

    def test_step_param_must_be_allowed(self):
        from rebel_profiler.intel.playbooks import _parse_playbook
        pb = _parse_playbook({
            "name": "bad-param", "version": "1", "description": "d",
            "steps": [{"action": "header-audit", "params": {"evil": "x"},
                       "why": "w"}],
        }, source="test")
        v = validate_playbook(pb)
        assert v["healthy"] is False
        assert "evil" in v["problems"][0]["problem"]

    def test_lan_inventory_playbook_valid(self):
        pb = get_playbook("lan-inventory")
        v = validate_playbook(pb)
        assert v["healthy"]
        ex = expand_playbook(pb, "192.168.55.0/24")
        assert ex["entries"][0]["action"] == "host-discovery"
        assert ex["entries"][1]["action"] == "port-scan"


# ------------------------------------------------- LAN sweep + CIDR scope

class TestLanSweepParsing:
    SWEEP = (
        "Starting Nmap 7.95 ( https://nmap.org )\n"
        "Nmap scan report for 192.168.55.1\n"
        "Host is up (0.013s latency).\n"
        "MAC Address: E4:A8:B6:33:A5:63 (Huawei Technologies)\n"
        "Nmap scan report for 192.168.55.9\n"
        "Host is up (0.012s latency).\n"
        "MAC Address: 1C:5F:2B:FF:28:84 (D-Link International)\n"
        "Nmap done: 256 IP addresses (2 hosts up) scanned in 8.92 seconds\n"
    )

    def test_sweep_yields_per_host_device_claims(self):
        pairs, observed = _parse_nmap(self.SWEEP)
        devices = [v for k, v in pairs if k == "lan_device"]
        assert "192.168.55.1" in devices
        assert "192.168.55.9" in devices
        assert "192.168.55.1 E4:A8:B6:33:A5:63 (Huawei Technologies)" in devices
        assert "192.168.55.9 1C:5F:2B:FF:28:84 (D-Link International)" in devices
        assert observed == "192.168.55.1"

    def test_summary_noise_never_becomes_a_claim(self):
        pairs, _ = _parse_nmap(self.SWEEP)
        assert not any("256 IP" in v for _, v in pairs)
        assert not any("Host is up" in v for _, v in pairs)


class TestCidrScope:
    def test_cidr_matches_members(self):
        e = ScopeEntry("192.168.55.0/24")
        assert e.matches("192.168.55.39")
        assert e.matches("192.168.55.1")
        assert not e.matches("192.168.56.1")
        assert not e.matches("lab.example.test")

    def test_cidr_matches_network_literal_itself(self):
        e = ScopeEntry("192.168.55.0/24")
        assert e.matches("192.168.55.0/24")

    def test_url_reduced_to_host_for_cidr(self):
        e = ScopeEntry("192.168.55.0/24")
        assert e.matches("http://192.168.55.39/admin")

    def test_host_bits_entry_does_not_widen(self):
        # 192.168.55.9/24 is not a valid network (host bits set): the entry
        # becomes CIDR-inert — it matches NOTHING by address semantics, not
        # even itself, so a typo can never silently widen into a whole /24
        e = ScopeEntry("192.168.55.9/24")
        assert not e.matches("192.168.55.9")
        assert not e.matches("192.168.55.10")
        assert not e.matches("192.168.55.9/24")
