"""Tests: CWE knowledge module — offline seed, cache round-trip, blind spots.

The live MITRE fetch is tested against a LOCAL fixture (the real network
is never touched by the suite); the parser must reject a truncated
catalog rather than caching half a truth.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from rebel_profiler.intel import cwe as cwe_mod
from rebel_profiler.intel.claims import ClaimLedger
from rebel_profiler.intel.sources import SourceRegistry


class TestBuiltinSeed:
    def test_seed_covers_tool_referenced_cwes(self):
        """Every CWE the coverage matrix references exists offline."""
        from rebel_profiler.intel.vulncov import VULN_CLASSES

        catalog = cwe_mod.builtin_catalog()
        missing = [vc.cwe for vc in VULN_CLASSES if vc.cwe not in catalog]
        assert not missing, f"coverage rows missing from the CWE seed: {missing}"

    def test_lookup_by_id_and_name(self):
        e = cwe_mod.lookup("79")
        assert e.cwe_id == "CWE-79"
        assert "scripting" in e.name.lower() or "neutralization" in e.name.lower()
        e2 = cwe_mod.lookup("CWE-1336")
        assert e2 is not None
        e3 = cwe_mod.lookup("cross-site scripting")
        assert e3 is not None

    def test_search_short_query_returns_nothing(self):
        assert cwe_mod.search("ab") == []


class TestCatalogCacheRoundTrip:
    def test_refresh_parses_fixture_and_caches(self, tmp_path, monkeypatch):
        """A synthetic MITRE-shaped XML round-trips through the parser.

        The <500-entry refusal is bypassed with a tiny fixture: patch the
        floor for this test only (the refusal itself is tested separately).
        """
        xml = (
            '<Weakness ID="79" Name="XSS" Abstraction="Base" Structure="Simple">'
            "<Description><p>Injects scripts.</p></Description>"
            '<Likelihood_Of_Exploit><Likelihood>High</Likelihood></Likelihood_Of_Exploit>'
            "<Mitigation><Phase>Implementation</Phase><Strategy>Output Encoding</Strategy>"
            "<Description>Encode output.</Description></Mitigation></Weakness>"
            '<Category ID="16" Name="Configuration">'
            "</Category>"
        )
        import rebel_profiler.intel.cwe as cwe_module

        monkeypatch.setattr(cwe_module, "_MIN_CATALOG_ENTRIES", 2)
        with mock.patch.object(cwe_mod, "_fetch_catalog_zip",
                               return_value=(xml, "4.99")):
            rec = cwe_mod.refresh_catalog(tmp_path)
        assert rec["version"] == "4.99"
        assert rec["count"] == 2   # one weakness + one category
        st = cwe_mod.catalog_status(tmp_path)
        assert st["cached"] is True and st["version"] == "4.99"
        entry = cwe_mod.lookup("79", tmp_path)
        assert entry.likelihood == "high"
        assert entry.mitigations and "Encode output." in entry.mitigations[0]

    def test_truncated_catalog_is_refused(self, tmp_path):
        """A parse yielding <500 entries must NOT overwrite a good cache."""
        xml = '<Weakness ID="79" Name="XSS"></Weakness>'
        with mock.patch.object(cwe_mod, "_fetch_catalog_zip",
                               return_value=(xml, "0.1")):
            with pytest.raises(ValueError):
                cwe_mod.refresh_catalog(tmp_path)

    def test_cache_corruption_falls_back_to_builtin(self, tmp_path):
        path = cwe_mod.cache_path(tmp_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{corrupt json")
        st = cwe_mod.catalog_status(tmp_path)
        assert st["cached"] is False and st["source"] == "builtin"


class TestBlindSpots:
    def _ledger(self):
        ledger = ClaimLedger(SourceRegistry())
        ledger.add("bs", subject="h1.lab.example.test", kind="ip",
                   value="10.0.0.9", source="scan.nmap",
                   method="host-discovery", observed_at=1000.0)
        return ledger

    def test_ranked_deterministic(self):
        ledger = self._ledger()
        r1 = cwe_mod.blind_spots(ledger, "bs")
        r2 = cwe_mod.blind_spots(ledger, "bs")
        assert [b["cwe"] for b in r1["blind_spots"]] == \
               [b["cwe"] for b in r2["blind_spots"]]

    def test_high_likelihood_first(self):
        ledger = self._ledger()
        report = cwe_mod.blind_spots(ledger, "bs")
        rows = report["blind_spots"]
        highs = [i for i, r in enumerate(rows) if r["likelihood"] == "high"]
        unranked = [i for i, r in enumerate(rows) if not r["likelihood"]]
        if highs and unranked:
            assert min(highs) < max(unranked)

    def test_covered_classes_are_excluded(self):
        ledger = self._ledger()
        # tech-fingerprint probe covers tech_exposure (CWE-1104)
        ledger.add("bs", subject="https://h1.lab.example.test",
                   kind="tech", value="nginx", source="scan.web",
                   method="tech-fingerprint", observed_at=1000.0)
        report = cwe_mod.blind_spots(ledger, "bs")
        cwes = {b["cwe"] for b in report["blind_spots"]}
        assert "CWE-1104" not in cwes


class TestCliSurface:
    def test_cwe_parsers_exist(self):
        from rebel_profiler.cli.main import build_parser

        parser = build_parser()
        args = parser.parse_args(["intel", "cwe", "lookup", "79"])
        assert args.ref == "79"
        args = parser.parse_args(["intel", "cwe", "blind-spots", "c1"])
        assert args.case_id == "c1"
        args = parser.parse_args(["intel", "cwe", "search", "open", "redirect"])
        assert args.terms == ["open", "redirect"]

    def test_lookup_command_live(self, tmp_path, capsys):
        from rebel_profiler.cli.main import main

        rc = main(["--data-dir", str(tmp_path), "intel", "cwe", "lookup", "79"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "CWE-79" in out
