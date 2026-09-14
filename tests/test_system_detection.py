"""Tests: system job plane (approval-gated privileged work) + detection lab."""

from __future__ import annotations

import json

import pytest

from rebel_profiler.core.errors import UsageError
from rebel_profiler.evidence.audit import AuditChain
from rebel_profiler.evidence.store import EvidenceStore
from rebel_profiler.security.approvals import ApprovalQueue
from rebel_profiler.storage.database import Database


@pytest.fixture(autouse=True)
def _case(db):
    db.create_case("syscase", case_id="case1")
    yield


# ---------------------------------------------------------------- system jobs


class TestSystemJobs:
    def test_template_whitelist_and_argv_composition(self):
        from rebel_profiler.execution.system_jobs import (
            SYSTEM_JOB_TEMPLATES,
            compose_argv,
        )

        argv = compose_argv(SYSTEM_JOB_TEMPLATES["pkg-install"],
                            {"package": "nmap"})
        assert argv == ["apt-get", "install", "-y", "nmap"]
        with pytest.raises(UsageError):
            compose_argv(SYSTEM_JOB_TEMPLATES["pkg-install"],
                         {"package": "nmap; rm -rf /"})
        with pytest.raises(UsageError):
            compose_argv(SYSTEM_JOB_TEMPLATES["service-start"], {"unit": "x"})

    def test_submit_rejects_unknown_job_type(self, tmp_path):
        from rebel_profiler.execution.system_jobs import SystemJobStore

        store = SystemJobStore(tmp_path / "queue")
        with pytest.raises(UsageError):
            store.submit(case_id="case1", job_type="run-my-script",
                         params={"cmd": "anything"})

    def test_submit_validates_params_before_queueing(self, tmp_path):
        from rebel_profiler.execution.system_jobs import SystemJobStore

        store = SystemJobStore(tmp_path / "queue")
        with pytest.raises(UsageError):
            store.submit(case_id="case1", job_type="pkg-install",
                         params={"package": "../etc/passwd"})
        env = store.submit(case_id="case1", job_type="pkg-install",
                           params={"package": "sslscan"}, reason="need tool")
        assert env["action"] == "system-job"
        assert env["params"]["sudo"] is True

    def test_daemon_queues_approval_then_executes(self, db, tmp_path):
        from rebel_profiler.execution.system_jobs import (
            SystemJobDaemon,
            SystemJobStore,
        )

        queue = tmp_path / "queue"
        store = SystemJobStore(queue)
        env = store.submit(case_id="case1", job_type="pkg-install",
                           params={"package": "sslscan"})

        ran = []
        daemon = SystemJobDaemon(queue, db=db, audit=AuditChain(db),
                                 runner=lambda argv, t: ran.append(argv) or (0, "ok", ""))
        handled = daemon.poll_once()
        assert handled[0]["state"] == "awaiting_approval"
        assert ran == []                      # nothing ran without approval
        approvals = ApprovalQueue(db).list("case1", "pending")
        assert len(approvals) == 1
        approval_id = approvals[0]["id"]

        # operator approves; re-submit the identical request (the first pass
        # consumed the job file while parking the approval); it now matches
        # the approved argv and executes
        ApprovalQueue(db, AuditChain(db)).decide(approval_id, "approve",
                                                 decided_by="owner")
        store.submit(case_id="case1", job_type="pkg-install",
                     params={"package": "sslscan"})
        handled2 = daemon.poll_once()
        assert handled2 and handled2[0]["state"] == "done", handled2
        assert ran and ran[0][:3] == ["sudo", "-n", "apt-get"]
        result2 = next(r for r in (json.loads(p.read_text())
                                   for p in (queue / "system").glob("*.result.json"))
                       if r["state"] == "done")
        assert result2["suggestions"]
        events = [e.action for e in AuditChain(db).events("case1")]
        assert "system-job.dispatched" in events
        assert "system-job.completed" in events

    def test_denied_approval_never_runs(self, db, tmp_path):
        from rebel_profiler.execution.system_jobs import (
            SystemJobDaemon,
            SystemJobStore,
        )

        queue = tmp_path / "queue"
        store = SystemJobStore(queue)
        store.submit(case_id="case1", job_type="service-stop",
                     params={"unit": "nginx.service"})
        ran = []
        daemon = SystemJobDaemon(queue, db=db,
                                 runner=lambda argv, t: ran.append(argv) or (0, "", ""))
        daemon.poll_once()
        pending = ApprovalQueue(db).list("case1", "pending")
        ApprovalQueue(db).decide(pending[0]["id"], "deny", decided_by="owner")
        # no execution: nothing matching an *approved* approval exists
        store.submit(case_id="case1", job_type="service-stop",
                     params={"unit": "nginx.service"})
        handled = daemon.poll_once()
        assert handled[0]["state"] == "awaiting_approval"
        assert ran == []


# ---------------------------------------------------------------- detection lab


class TestDetectionLab:
    def _lab(self, db, tmp_path):
        from rebel_profiler.intel.detection import DetectionLab

        evidence = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
        return DetectionLab("case1", case_dir=tmp_path / "case",
                            evidence=evidence, audit=AuditChain(db))

    def test_eicar_artifact_is_registered_and_contained(self, db, tmp_path):
        lab = self._lab(db, tmp_path)
        record = lab.generate("eicar_test_file", name="av-check")
        assert record["path"].startswith(str(tmp_path / "case" / "detections"))
        assert record["risk"] == "moderate"
        assert record["evidence_id"]
        data = open(record["path"], "rb").read()
        assert b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in data

    def test_canary_tripwire_token(self, db, tmp_path):
        lab = self._lab(db, tmp_path)
        record = lab.generate("canary_tripwire", name="decoy-payroll",
                              canary_note="fake payroll export")
        assert record["token"]
        assert b"CANARY TRIPWIRE" in open(record["path"], "rb").read()

    def test_ioc_bundle_and_yara_ruleset(self, db, tmp_path):
        lab = self._lab(db, tmp_path)
        report_text = (
            "Beacon to http://203.0.113.7/gate and c2.evil.example\n"
            "Sample hash 64d Vol hashes: "
            "a]b"  # noise
        )
        record = lab.generate("ioc_bundle", name="case-iocs",
                              ioc_text="203.0.113.7 c2.evil.example "
                                       "http://203.0.113.7/gate")
        assert "ipv4" in record["iocs"]
        yara = lab.generate("yara_ruleset", name="case-detect",
                            iocs=record["iocs"])
        assert yara["path"].endswith(".yar")
        rules = open(yara["path"]).read()
        assert rules.startswith("rule RP_")
        assert "condition:" in rules and "of them" in rules

    def test_unknown_kind_denied(self, db, tmp_path):
        lab = self._lab(db, tmp_path)
        with pytest.raises(UsageError):
            lab.generate("ransomware_builder", name="x")

    def test_no_iocs_no_rules(self, db, tmp_path):
        lab = self._lab(db, tmp_path)
        with pytest.raises(UsageError):
            lab.generate("yara_ruleset", name="empty", ioc_text="nothing here")

    def test_every_generation_is_evidence_and_audit(self, db, tmp_path):
        lab = self._lab(db, tmp_path)
        lab.generate("eicar_test_file", name="t1")
        lab.generate("canary_tripwire", name="t2")
        report = lab.evidence.verify_case("case1")
        assert report["chain_ok"] is True
        actions = [e.action for e in AuditChain(db).events("case1")]
        assert actions.count("artifact.generated") == 2
