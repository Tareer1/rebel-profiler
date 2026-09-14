"""Tests: law-enforcement complaint package builder."""

from __future__ import annotations

import hashlib
import json

import pytest

from rebel_profiler.core.errors import UsageError
from rebel_profiler.evidence.audit import AuditChain
from rebel_profiler.evidence.store import EvidenceStore
from rebel_profiler.storage.database import Database


@pytest.fixture()
def env(db, tmp_path):
    db.create_case("comp", case_id="case1")
    evidence = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
    audit = AuditChain(db)
    # seed one verified evidence record + a claim
    evidence.register("case1", kind="tool_output", data=b"scan output",
                      source="scan.nmap", note="port scan")
    db.record_claim("cl1", "case1", subject="c2.evil.example", kind="hostname",
                    value="c2.evil.example", source="ct.logs", observed_at=1000.0)
    db.record_claim("cl2", "case1", subject="c2.evil.example", kind="ip",
                    value="203.0.113.7", source="dns.authoritative", observed_at=1000.0)
    from rebel_profiler.intel.complaint import ComplaintPackageBuilder

    builder = ComplaintPackageBuilder("case1", case_dir=tmp_path / "case",
                                      db=db, evidence=evidence, audit=audit)
    return builder, evidence, audit


class TestComplaintPackage:
    def test_build_package_with_verified_evidence(self, env, tmp_path):
        builder, _, _ = env
        record = builder.build(
            agency="fia_ccw", incident_type="beaconing_c2",
            narrative="C2 beaconing observed from lab host.",
            complainant="operator", subject_targets=["c2.evil.example"])
        assert record["agency"].startswith("FIA")
        assert record["evidence_records"] >= 1
        assert record["iocs"] >= 2
        package = json.loads(open(record["path"]).read())
        assert package["bundle_sha256"]
        # bundle hash is reproducible
        canonical = json.dumps(
            {k: v for k, v in package.items() if k != "bundle_sha256"},
            sort_keys=True, separators=(",", ":"))
        assert hashlib.sha256(canonical.encode()).hexdigest() == package["bundle_sha256"]

    def test_broken_evidence_blocks_package(self, env, tmp_path):
        builder, evidence, _ = env
        record = evidence.list_records("case1")[0]
        # tamper with a blob → chain verification fails
        blob = tmp_path / "blobs" / record.sha256[:2] / record.sha256
        blob.write_bytes(b"tampered")
        with pytest.raises(UsageError):
            builder.build(agency="ic3", incident_type="phishing")

    def test_unknown_agency_and_incident(self, env):
        builder, _, _ = env
        with pytest.raises(UsageError):
            builder.build(agency="interpol_direct")
        with pytest.raises(UsageError):
            builder.build(incident_type="hacking_back")

    def test_human_rendering(self, env):
        from rebel_profiler.intel.complaint import render_complaint_human

        builder, _, _ = env
        record = builder.build(agency="generic_cert",
                               incident_type="scam_fraud",
                               narrative="Fraud site hosted on scoped host.")
        package = json.loads(open(record["path"]).read())
        human = render_complaint_human(record, package)
        assert "COMPLAINT PACKAGE" in human
        assert "bundle sha256" in human
        assert "next steps" in human

    def test_list_packages(self, env):
        builder, _, _ = env
        builder.build(agency="ic3", incident_type="other")
        rows = builder.list_packages()
        assert len(rows) == 1 and rows[0]["agency"] == "ic3"
