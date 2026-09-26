"""Tests: unknown-vulnerability detection (anomaly plane).

Rules are deterministic and computed only over the case's own claims:
drift = same subject+kind with differing values across collections;
rare = a value exactly one subject holds while peers differ; first_seen =
first observation of an attribute. Candidates carry claim provenance and
are never findings until verified through the gates.
"""

from __future__ import annotations

import pytest

from rebel_profiler.intel.anomaly import detect_anomalies
from rebel_profiler.intel.claims import ClaimLedger
from rebel_profiler.intel.sources import SourceRegistry


def _ledger_with_drift_and_rare() -> ClaimLedger:
    ledger = ClaimLedger(SourceRegistry())
    # drift: tech changed on h1
    ledger.add("c1", subject="h1.lab.test", kind="tech", value="nginx 1.24",
               source="scan.web", method="tech-fingerprint", observed_at=1000.0)
    ledger.add("c1", subject="h1.lab.test", kind="tech", value="nginx 1.25",
               source="scan.web", method="tech-fingerprint", observed_at=2000.0)
    # rare: h3 alone carries the odd header (5 subjects, so the rare rule fires)
    for host in ("h1.lab.test", "h2.lab.test", "h3.lab.test",
                 "h4.lab.test", "h5.lab.test"):
        hdr = ("X-Odd-Header: on" if host == "h3.lab.test"
               else "X-Standard: on")
        ledger.add("c1", subject=host, kind="header_obs", value=hdr,
                   source="scan.web", method="header-audit",
                   observed_at=1500.0)
    # first-seen: a brand-new surface
    ledger.add("c1", subject="admin.lab.test", kind="httpx_status",
               value="200 /admin", source="scan.web", method="httpx-probe",
               observed_at=3000.0)
    return ledger


class TestDrift:
    def test_value_change_is_detected(self):
        report = detect_anomalies(_ledger_with_drift_and_rare(), "c1")
        drifts = [f for f in report["anomalies"] if f["type"] == "drift"]
        assert any(f["subject"] == "h1.lab.test" and f["kind"] == "tech"
                   and "nginx 1.24" in f["detail"]
                   and "nginx 1.25" in f["detail"] for f in drifts)

    def test_drift_finding_carries_claim_provenance(self):
        report = detect_anomalies(_ledger_with_drift_and_rare(), "c1")
        drifts = [f for f in report["anomalies"] if f["type"] == "drift"]
        assert drifts and all(f["claim_ids"] for f in drifts)


class TestRare:
    def test_unique_value_flagged(self):
        report = detect_anomalies(_ledger_with_drift_and_rare(), "c1")
        rares = [f for f in report["anomalies"] if f["type"] == "rare"]
        assert any(f["subject"] == "h3.lab.test"
                   and "X-Odd-Header" in f["detail"] for f in rares)

    def test_common_value_not_flagged(self):
        report = detect_anomalies(_ledger_with_drift_and_rare(), "c1")
        rares = [f for f in report["anomalies"] if f["type"] == "rare"]
        assert not any("X-Standard" in f["detail"] for f in rares)

    def test_small_fleet_skips_rare_rule(self):
        """With <4 subjects the rare rule stays silent (noise guard)."""
        ledger = ClaimLedger(SourceRegistry())
        for host in ("a.lab.test", "b.lab.test", "c.lab.test"):
            hdr = ("X-Odd: on" if host == "a.lab.test" else "X-Std: on")
            ledger.add("c1", subject=host, kind="header_obs", value=hdr,
                       source="scan.web", method="header-audit",
                       observed_at=1000.0)
        report = detect_anomalies(ledger, "c1")
        assert report["counts"]["rare"] == 0


class TestFirstSeen:
    def test_new_surface_reported(self):
        report = detect_anomalies(_ledger_with_drift_and_rare(), "c1")
        firsts = [f for f in report["anomalies"] if f["type"] == "first_seen"]
        assert any(f["subject"] == "admin.lab.test"
                   and "/admin" in f["detail"] for f in firsts)


class TestDiscipline:
    def test_deterministic_ordering(self):
        ledger = _ledger_with_drift_and_rare()
        r1 = detect_anomalies(ledger, "c1")
        r2 = detect_anomalies(ledger, "c1")
        keys1 = [(f["type"], f["subject"], f["kind"]) for f in r1["anomalies"]]
        keys2 = [(f["type"], f["subject"], f["kind"]) for f in r2["anomalies"]]
        assert keys1 == keys2

    def test_drift_sorts_before_first_seen(self):
        report = detect_anomalies(_ledger_with_drift_and_rare(), "c1")
        types = [f["type"] for f in report["anomalies"]]
        assert types.index("drift") < types.index("first_seen")

    def test_no_network_no_llm(self):
        """Pure ledger computation — no egress anywhere in the module."""
        import inspect
        from rebel_profiler.intel import anomaly

        src = inspect.getsource(anomaly)
        assert "urllib" not in src and "socket" not in src
        assert "subprocess" not in src


class TestCliWiring:
    def test_anomalies_parser(self):
        from rebel_profiler.cli.main import build_parser

        parser = build_parser()
        args = parser.parse_args(["intel", "anomalies", "c1"])
        assert args.case_id == "c1"

    def test_anomalies_command_runs(self, tmp_path, capsys):
        from rebel_profiler.cli.context import AppContext
        from rebel_profiler.cli.main import main

        ctx_dir = tmp_path / "data"
        ctx = AppContext(data_dir=ctx_dir)
        ctx.create_case("anom", "fixture")
        cases = ctx.list_cases()
        case_id = cases[0]["id"]
        rc = main(["--data-dir", str(ctx_dir), "intel", "anomalies", case_id])
        assert rc == 0
        assert "Anomaly analysis" in capsys.readouterr().out
