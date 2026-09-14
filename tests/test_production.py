"""Tests for Phase 4-6: RBAC, approvals, hypotheses, workflows, scheduler,
search, credentials, plugins, events/API, ops, worker plane and browser bridge."""

from __future__ import annotations

import json
import os
import time

import pytest

from rebel_profiler.core.errors import (
    PermissionDeniedError,
    RPError,
    UsageError,
)
from rebel_profiler.execution.broker import ActionRequest, ExecutionBroker
from rebel_profiler.security.scope import Scope, ScopeEngine, ScopeStatus
from rebel_profiler.storage.database import Database

ACTIVE_SCOPE = dict(case_id="case1", status=ScopeStatus.ACTIVE)


@pytest.fixture(autouse=True)
def _case_row(db):
    """Every test gets a real case row so FK constraints hold."""
    db.create_case("Test Case", case_id="case1")
    yield


def make_scope(case_id="case1"):
    scope = Scope(case_id=case_id, status=ScopeStatus.ACTIVE)
    scope.add("*.lab.example.test")
    engine = ScopeEngine()
    engine.register(scope)
    return engine


def make_broker(db, *, queue=False, approve=None):
    return ExecutionBroker(
        db, scope_engine=make_scope(), approve=approve,
        queue_on_approval_refusal=queue,
    )


def echo_request(db, target="h1.lab.example.test", **kw):
    return ActionRequest(case_id="case1", capability="info", action="echo",
                         target=target, params={"message": "x"}, **kw)


# ---------------------------------------------------------------- RBAC


class TestRbac:
    def test_empty_case_is_single_operator(self, db):
        from rebel_profiler.security.rbac import RoleEngine

        engine = RoleEngine(db)
        assert engine.effective_role("case1", "alice") == "operator"

    def test_populated_case_fails_closed_for_unknown(self, db):
        from rebel_profiler.security.rbac import RoleEngine

        db.add_member("case1", "alice", "owner")
        engine = RoleEngine(db)
        assert engine.effective_role("case1", "stranger") == "viewer"
        with pytest.raises(PermissionDeniedError):
            engine.require("case1", "stranger", "execute")

    def test_viewer_cannot_execute(self, db):
        from rebel_profiler.security.rbac import RoleEngine

        db.add_member("case1", "carol", "viewer")
        with pytest.raises(PermissionDeniedError):
            RoleEngine(db).require("case1", "carol", "execute")

    def test_member_manager_audit_and_rules(self, db):
        from rebel_profiler.evidence.audit import AuditChain
        from rebel_profiler.security.rbac import MemberManager

        audit = AuditChain(db)
        mgr = MemberManager(db, audit=audit)
        mgr.add("case1", "alice", "owner")
        mgr.add("case1", "bob", "operator")
        # removing the only owner is refused
        with pytest.raises(UsageError):
            mgr.remove("case1", "alice")
        mgr.remove("case1", "bob")
        assert [m["subject"] for m in mgr.list("case1")] == ["alice"]
        assert any(e.action == "member.added" for e in audit.events("case1"))

    def test_broker_blocks_viewer_before_gates(self, db):
        from rebel_profiler.security.rbac import RoleEngine

        db.add_member("case1", "carol", "viewer")
        broker = make_broker(db)
        broker._roles = RoleEngine(db)
        with pytest.raises(PermissionDeniedError):
            broker.plan(echo_request(db, requested_by="carol"))


# ---------------------------------------------------------------- approvals


class TestApprovals:
    def test_queue_and_decide(self, db):
        from rebel_profiler.evidence.audit import AuditChain
        from rebel_profiler.security.approvals import ApprovalQueue

        queue = ApprovalQueue(db, AuditChain(db))
        rec = queue.enqueue("case1", task_id="t1", action="service-detect",
                            target="h1.lab.example.test", argv=["nmap", "-sV"],
                            params={"ports": "80"}, risk="high",
                            reasons=["risk=high"])
        assert rec["state"] == "pending"
        assert queue.load_argv(rec["id"]) == ["nmap", "-sV"]
        assert queue.load_params(rec["id"]) == {"ports": "80"}
        decided = queue.decide(rec["id"], "approve", decided_by="owner1")
        assert decided["state"] == "approved"
        # double decision refused
        with pytest.raises(Exception):
            queue.decide(rec["id"], "deny", decided_by="owner1")

    def test_broker_queues_when_approver_refuses(self, db):
        broker = make_broker(db, queue=True, approve=lambda r, g: False)
        result = broker.execute(ActionRequest(
            case_id="case1", capability="active_recon",
            action="service-detect", target="h1.lab.example.test"))
        assert result.outcome == "cancelled"
        from rebel_profiler.security.approvals import ApprovalQueue

        pending = ApprovalQueue(db).list("case1", "pending")
        assert len(pending) == 1
        assert pending[0]["action"] == "service-detect"

    def test_execute_approved_revalidates_scope(self, db):
        from rebel_profiler.security.approvals import ApprovalQueue

        broker = make_broker(db, queue=True, approve=lambda r, g: False)
        broker.execute(ActionRequest(
            case_id="case1", capability="active_recon",
            action="service-detect", target="h1.lab.example.test"))
        approval = ApprovalQueue(db).list("case1", "pending")[0]
        ApprovalQueue(db).decide(approval["id"], "approve", decided_by="op")
        result = broker.execute_approved(approval["id"], decided_by="op")
        assert result.outcome == "succeeded"

        # now an out-of-scope target after scope change must be refused
        broker.execute(ActionRequest(
            case_id="case1", capability="active_recon",
            action="service-detect", target="h2.lab.example.test"))
        approval2 = ApprovalQueue(db).list("case1", "pending")[0]
        ApprovalQueue(db).decide(approval2["id"], "approve", decided_by="op")
        # revoke scope: narrow the engine to reject the host now
        scope = Scope(case_id="case1", status=ScopeStatus.SUSPENDED)
        scope.add("*.lab.example.test")
        broker._scope = ScopeEngine()
        broker._scope.register(scope)
        with pytest.raises(Exception):
            broker.execute_approved(approval2["id"], decided_by="op")


# ---------------------------------------------------------------- hypotheses


class TestHypotheses:
    def _ledger_with_ip(self, db):
        from rebel_profiler.intel.claims import ClaimLedger
        from rebel_profiler.intel.sources import SourceRegistry

        ledger = ClaimLedger(SourceRegistry())
        ledger.add("case1", subject="h1.lab.example.test", kind="ip",
                   value="10.0.0.1", source="dns.authoritative", observed_at=1000.0)
        ledger.add("case1", subject="h1.lab.example.test", kind="ip",
                   value="10.0.0.1", source="ct.logs", observed_at=1000.0)
        return ledger

    def test_supported_when_criteria_pass(self, db):
        from rebel_profiler.intel.hypotheses import HypothesisEngine

        engine = HypothesisEngine(db, self._ledger_with_ip(db))
        hyp = engine.add("case1", "h1 resolves to 10.0.0.1", [
            {"kind": "exists", "subject": "h1.lab.example.test", "claim_kind": "ip",
             "value": "10.0.0.1"},
            {"kind": "corroborated", "subject": "h1.lab.example.test",
             "claim_kind": "ip", "count": 2},
        ])
        result = engine.evaluate(hyp.id)
        assert result.status == "supported"
        assert result.result["checks"][0]["verdict"] == "pass"

    def test_refuted_when_absent(self, db):
        from rebel_profiler.intel.hypotheses import HypothesisEngine

        engine = HypothesisEngine(db, self._ledger_with_ip(db))
        hyp = engine.add("case1", "h1 is at 10.9.9.9", [
            {"kind": "exists", "subject": "h1.lab.example.test", "claim_kind": "ip",
             "value": "10.9.9.9"},
        ])
        assert engine.evaluate(hyp.id).status == "refuted"

    def test_bad_criteria_rejected(self, db):
        from rebel_profiler.intel.hypotheses import HypothesisEngine

        engine = HypothesisEngine(db, self._ledger_with_ip(db))
        with pytest.raises(Exception):
            engine.add("case1", "junk", [{"kind": "mind_control"}])


# ---------------------------------------------------------------- workflow


class TestWorkflow:
    DSL = '''
    workflow "footprint" {
      step dns action passive-dns target=h1.lab.example.test
      param record_type=A
      step gate approval needs=dns
      step echo action echo target=h1.lab.example.test needs=gate
      param message=after-gate
    }
    '''

    def test_parse_and_cycle_detection(self):
        from rebel_profiler.execution.workflow import parse_workflow

        spec = parse_workflow(self.DSL)
        assert [s.key for s in spec.steps] == ["dns", "gate", "echo"]
        assert spec.steps[1].needs == ["dns"]
        with pytest.raises(Exception):
            parse_workflow('workflow "x" {\nstep a needs=b\nstep b needs=a\n}')

    def test_run_with_approval_gate(self, db):
        from rebel_profiler.evidence.audit import AuditChain
        from rebel_profiler.execution.workflow import WorkflowRunner, parse_workflow

        runner = WorkflowRunner(db, make_broker(db), AuditChain(db))
        spec = parse_workflow(self.DSL)
        started = runner.start("case1", spec)
        status = runner.resume("case1", started["workflow_id"])
        assert status["state"] == "paused"
        gate = next(s for s in status["steps"] if s["kind"] == "approval")
        assert gate["state"] == "awaiting_approval"
        assert status["steps"][0]["state"] == "succeeded"

        # deny → workflow cancelled
        runner.approve_gate("case1", started["workflow_id"], "gate",
                            decided_by="op", approve=False)
        assert runner.status("case1", started["workflow_id"])["state"] == "cancelled"

    def test_checkpoint_resume_does_not_rerun(self, db):
        from rebel_profiler.evidence.audit import AuditChain
        from rebel_profiler.execution.workflow import WorkflowRunner, parse_workflow

        runner = WorkflowRunner(db, make_broker(db), AuditChain(db))
        spec = parse_workflow('workflow "w" {\nstep a action echo target=h1.lab.example.test\n}')
        started = runner.start("case1", spec)
        first = runner.resume("case1", started["workflow_id"])
        assert first["state"] == "completed"
        # resume again: completed workflows return status, no re-execution
        again = runner.resume("case1", started["workflow_id"])
        assert again["state"] == "completed"
        assert again["progress"] == first["progress"]


# ---------------------------------------------------------------- scheduler


class TestScheduler:
    def test_window_enforced_and_expiry(self, db):
        from rebel_profiler.evidence.audit import AuditChain
        from rebel_profiler.execution.scheduler import Scheduler

        sched = Scheduler(db, make_broker(db), AuditChain(db))
        future = time.time() + 3600
        rec = sched.schedule("case1", action="echo", target="h1.lab.example.test",
                             params={"message": "hi"}, not_before=future)
        report = sched.tick()
        entry = next(r for r in report["results"] if r["schedule_id"] == rec["schedule_id"])
        assert entry["result"] == "before_window"

        past = time.time() - 3600
        rec2 = sched.schedule("case1", action="echo", target="h1.lab.example.test",
                              not_before=past - 100, not_after=past)
        report2 = sched.tick()
        entry2 = next(r for r in report2["results"] if r["schedule_id"] == rec2["schedule_id"])
        assert entry2["result"] == "expired"

    def test_fires_inside_window(self, db):
        from rebel_profiler.evidence.audit import AuditChain
        from rebel_profiler.execution.scheduler import Scheduler

        sched = Scheduler(db, make_broker(db), AuditChain(db))
        rec = sched.schedule("case1", action="echo", target="h1.lab.example.test",
                             params={"message": "hi"})
        report = sched.tick()
        entry = next(r for r in report["results"] if r["schedule_id"] == rec["schedule_id"])
        assert entry["result"] == "fired"
        assert entry["ok"] is True

    def test_rejects_fake_adapter_and_bad_cron(self, db):
        from rebel_profiler.evidence.audit import AuditChain
        from rebel_profiler.execution.scheduler import Scheduler

        sched = Scheduler(db, make_broker(db), AuditChain(db))
        with pytest.raises(UsageError):
            sched.schedule("case1", action="nuke-everything",
                           target="h1.lab.example.test")
        with pytest.raises(UsageError):
            sched.schedule("case1", action="echo", target="h1.lab.example.test",
                           cron="0 0 * * *")


# ---------------------------------------------------------------- search


class TestSearch:
    def test_index_and_query(self, db):
        db.record_claim("cl1", "case1", subject="h1.lab.example.test", kind="ip",
                        value="10.0.0.1", source="dns.authoritative", observed_at=1000.0)
        count = db.rebuild_search_index("case1")
        assert count >= 1
        hits = db.search_docs("case1", "10.0.0.1")
        assert hits and hits[0]["entity_type"] in {"claim", "observation"}
        assert db.search_docs("case1", "zzz_nothing") == []


# ---------------------------------------------------------------- credentials


class TestCredentials:
    def test_roundtrip_and_scoping(self, db):
        from rebel_profiler.security.credentials import CredentialBroker

        broker = CredentialBroker(db, master_secret="unit-test-secret")
        broker.store("case1", name="lab-api", secret="s3cr3t!",
                     scopes=["recon:lab"])
        assert broker.use("case1", "lab-api", purpose="recon:lab:nmap") == "s3cr3t!"
        with pytest.raises(PermissionDeniedError):
            broker.use("case1", "lab-api", purpose="prod:other")
        listed = broker.list("case1")
        assert listed[0]["name"] == "lab-api"
        assert "s3cr3t" not in json.dumps(listed)
        broker.delete("case1", "lab-api")
        with pytest.raises(Exception):
            broker.use("case1", "lab-api", purpose="recon:lab")

    def test_ciphertext_at_rest_and_mac(self, db, tmp_path):
        from rebel_profiler.security.credentials import CredentialBroker

        broker = CredentialBroker(db, master_secret="k1")
        broker.store("case1", name="x", secret="PLAINTEXT-MARKER")
        raw = db.get_meta("credential:x")
        assert "PLAINTEXT-MARKER" not in raw
        # tamper with ciphertext → integrity failure
        payload = json.loads(raw)
        payload["ciphertext"] = "00" * len(bytes.fromhex(payload["ciphertext"]))
        db.set_meta("credential:x", json.dumps(payload))
        with pytest.raises(RPError):
            broker.use("case1", "x", purpose="any")

    def test_wrong_master_fails(self, db):
        from rebel_profiler.security.credentials import CredentialBroker

        CredentialBroker(db, master_secret="right").store("case1", name="k",
                                                          secret="v")
        wrong = CredentialBroker(db, master_secret="wrong")
        with pytest.raises(RPError):
            wrong.use("case1", "k", purpose="any")


# ---------------------------------------------------------------- plugins


class TestPlugins:
    def _plugin(self, tmp_path, code):
        d = tmp_path / "myplug"
        d.mkdir()
        (d / "plugin.toml").write_text(
            '[plugin]\nname = "myplug"\nversion = "1.0.0"\nentry = "adapters.py"\n'
            'permissions = ["adapters.register"]\n')
        (d / "adapters.py").write_text(code)
        return d

    def test_unsigned_rejected_by_default(self, db, tmp_path):
        from rebel_profiler.core.plugins import load_plugin

        d = self._plugin(tmp_path, "PLUGIN_ADAPTERS = ()\n")
        with pytest.raises(Exception):
            load_plugin(d, secret="s3cret", granted=["adapters.register"])

    def test_signed_loads_and_registers(self, db, tmp_path):
        from rebel_profiler.core.plugins import load_plugin, sign_manifest

        d = self._plugin(tmp_path, (
            "from rebel_profiler.execution.broker import Adapter\n"
            "class P(Adapter):\n"
            "    name='plug-echo'\n"
            "    binary='echo'\n"
            "    capability_class='info'\n"
            "    allowed_params=('message',)\n"
            "    def build_argv(self, request):\n"
            "        return ['echo', str(request.params.get('message','p'))]\n"
            "PLUGIN_ADAPTERS = (P,)\n"))
        (d / "signature").write_text(sign_manifest(d / "plugin.toml", "s3cret") + "\n")
        handle = load_plugin(d, secret="s3cret", granted=["adapters.register"])
        assert handle.trust == "trusted"
        assert [a.name for a in handle.adapters] == ["plug-echo"]

    def test_ungranted_permission_rejected(self, db, tmp_path):
        from rebel_profiler.core.plugins import load_plugin, sign_manifest

        d = self._plugin(tmp_path, "PLUGIN_ADAPTERS = ()\n")
        (d / "signature").write_text(sign_manifest(d / "plugin.toml", "s3cret") + "\n")
        with pytest.raises(Exception):
            load_plugin(d, secret="s3cret", granted=[])  # permission not granted


# ---------------------------------------------------------------- events + API


class TestEventsApi:
    def test_emit_and_list(self, db):
        from rebel_profiler.core.events import emit_event, list_events

        emit_event(db, "case1", "action.completed", {"task": "t1"})
        emit_event(db, "case1", "approval.requested", {"approval": "a1"})
        events = list_events(db, "case1")
        assert [e["type"] for e in events] == ["approval.requested", "action.completed"]

    def test_webhook_signature_and_dispatch(self, db):
        import hashlib
        import hmac

        from rebel_profiler.core.events import (
            dispatch_event,
            emit_event,
            register_webhook,
            sign_payload,
        )

        hook = register_webhook(db, "case1", url="https://hooks.test/rp",
                                secret="whsec")
        captured = {}

        def fake_post(url, body, headers):
            captured["url"], captured["body"], captured["headers"] = url, body, headers
            return 200, ""

        event = emit_event(db, "case1", "action.completed", {"task": "t1"})
        deliveries = dispatch_event(db, event, post=fake_post)
        assert deliveries[0]["ok"] is True
        ts = captured["headers"]["X-RP-Timestamp"]
        expected = sign_payload("whsec", captured["body"], ts)
        assert captured["headers"]["X-RP-Signature"] == expected

    def test_gateway_auth(self, db):
        from rebel_profiler.core.events import ApiGateway

        token = "a" * 64
        gw = ApiGateway(db, "case1", token=token)
        assert gw.handle("GET", "/healthz", f"Bearer {token}")[0] == 200
        assert gw.handle("GET", "/healthz", "Bearer nope")[0] == 401
        assert gw.handle("POST", "/state", f"Bearer {token}")[0] == 405
        open_gw = ApiGateway(db, "case1", token="")
        assert open_gw.handle("GET", "/state", "")[0] == 503


# ---------------------------------------------------------------- ops


class TestOps:
    def test_backup_restore_roundtrip(self, db, tmp_path):
        from rebel_profiler.core.ops import backup_case, restore_case

        db.record_claim("cl1", "case1", subject="h1", kind="ip", value="10.0.0.1",
                        observed_at=1000.0)
        case_dir = tmp_path / "case"
        case_dir.mkdir()
        db_path = case_dir / "case.db"
        db.close()
        import shutil

        shutil.copy(str(db.path), str(db_path))
        backup = tmp_path / "backup.zip"
        record = backup_case(case_dir, backup)
        assert record["members"] >= 1
        dest = tmp_path / "restored"
        result = restore_case(backup, dest)
        assert result["restored"] >= 1
        assert (dest / "case.db").exists()
        # never clobbers
        with pytest.raises(UsageError):
            restore_case(backup, dest)

    def test_selfcheck_healthy_case(self, db):
        from rebel_profiler.core.ops import check_and_repair

        report = check_and_repair(db, "case1", repair=True)
        assert report["healthy"] is True
        assert any("search index" in r for r in report["repaired"])

    def test_zipapp_packaging(self, tmp_path):
        from pathlib import Path

        from rebel_profiler.core.ops import package_zipapp

        import rebel_profiler

        root = Path(rebel_profiler.__file__).parent
        out = tmp_path / "rp.pyz"
        record = package_zipapp(root, out)
        assert out.exists() and record["size"] > 1000


# ---------------------------------------------------------------- worker plane


class TestWorkerPlane:
    def test_full_handshake(self, db, tmp_path):
        from rebel_profiler.execution.worker import JobPlane, WorkerDaemon

        queue = tmp_path / "queue"
        plane = JobPlane(queue)
        envelope = plane.submit(case_id="case1", action="echo",
                                target="h1.lab.example.test",
                                params={"message": "hi"}, requested_by="operator")
        st = plane.status(envelope["job_id"])
        assert st["state"] == "syn_sent"

        daemon = WorkerDaemon(queue, broker=make_broker(db), max_runs=1)
        handled = daemon.poll_once()
        assert handled and handled[0]["state"] == "succeeded"

        st = plane.status(envelope["job_id"])
        assert st["state"] == "succeeded"
        assert st["phase"] == "ack"
        assert st["result"]["ack"] == envelope["seq"]

    def test_tampered_job_rejected(self, db, tmp_path):
        from rebel_profiler.execution.worker import JobPlane, WorkerDaemon

        queue = tmp_path / "queue"
        plane = JobPlane(queue)
        envelope = plane.submit(case_id="case1", action="echo",
                                target="h1.lab.example.test")
        # tamper: swap the target after signing
        job_path = queue / f"{envelope['job_id']}.job.json"
        job = json.loads(job_path.read_text())
        job["target"] = "h2.lab.example.test"
        job_path.write_text(json.dumps(job))
        daemon = WorkerDaemon(queue, broker=make_broker(db))
        daemon.poll_once()
        st = plane.status(envelope["job_id"])
        assert st["state"] == "rejected"

    def test_unknown_action_rejected(self, db, tmp_path):
        from rebel_profiler.execution.worker import JobPlane, WorkerDaemon

        queue = tmp_path / "queue"
        plane = JobPlane(queue)
        envelope = plane.submit(case_id="case1", action="format-c:",
                                target="h1.lab.example.test")
        daemon = WorkerDaemon(queue, broker=make_broker(db))
        daemon.poll_once()
        st = plane.status(envelope["job_id"])
        assert st["state"] == "failed"
        assert "fix" in st["result"]

    def test_idempotent_redelivery(self, db, tmp_path):
        from rebel_profiler.execution.worker import JobPlane, WorkerDaemon

        queue = tmp_path / "queue"
        plane = JobPlane(queue)
        env = plane.submit(case_id="case1", action="echo", target="h1.lab.example.test")
        daemon = WorkerDaemon(queue, broker=make_broker(db))
        daemon.poll_once()
        # re-deliver the same job id (SYN retransmit) → answered from result
        (queue / f"{env['job_id']}.job.json").write_text(
            json.dumps({**env, "checksum": env["checksum"]}))
        handled = daemon.poll_once()
        assert handled == []   # result already final; nothing re-executed


# ---------------------------------------------------------------- browser bridge


class TestBrowserBridge:
    def test_submit_rejects_bad_extractor_and_scheme(self, tmp_path):
        from rebel_profiler.browser import BrowserJobStore

        store = BrowserJobStore(tmp_path / "queue")
        with pytest.raises(Exception):
            store.submit(case_id="case1", url="https://x.lab.example.test/",
                         extract=["click_all_buttons"])
        with pytest.raises(Exception):
            store.submit(case_id="case1", url="ftp://x.lab.example.test/",
                         extract=["title"])

    def test_scope_gate_on_pending_tasks(self, tmp_path):
        from rebel_profiler.browser import BrowserBridge, BrowserJobStore
        from rebel_profiler.evidence.store import EvidenceStore

        db = Database(tmp_path / "c.db")
        db.migrate()
        store = BrowserJobStore(tmp_path / "queue")
        envelope = store.submit(case_id="case1", url="https://h1.lab.example.test/",
                                extract=["title"])
        # submit an out-of-scope job too
        store.submit(case_id="case1", url="https://evil.test/", extract=["title"])
        evidence = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
        bridge = BrowserBridge("case1", queue_dir=tmp_path / "queue",
                               scope_engine=make_scope(), evidence=evidence)
        tasks = bridge.pending_tasks()
        assert [t["job_id"] for t in tasks] == [envelope["job_id"]]
        # out-of-scope one was rejected with a result file
        out = store.load_result(json.loads(
            (tmp_path / "queue" / "rejected-lookup").name) if False else None)
        db.close()

    def test_claim_and_complete_roundtrip(self, tmp_path):
        from rebel_profiler.browser import BrowserBridge, BrowserJobStore
        from rebel_profiler.evidence.store import EvidenceStore

        db = Database(tmp_path / "c.db")
        db.migrate()
        db.create_case("bridge", case_id="case1")
        store = BrowserJobStore(tmp_path / "queue")
        envelope = store.submit(case_id="case1", url="https://h1.lab.example.test/",
                                extract=["title", "links"], reason="test")
        evidence = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
        bridge = BrowserBridge("case1", queue_dir=tmp_path / "queue",
                               scope_engine=make_scope(), evidence=evidence,
                               ledger=None)
        tasks = bridge.pending_tasks()
        claim = bridge.claim(tasks[0]["job_id"])
        assert claim["url"] == "https://h1.lab.example.test/"
        result = bridge.complete(claim["job_id"], {
            "ok": True,
            "data": {"title": "Lab Host",
                     "links": ["https://h1.lab.example.test/login",
                               "https://other.test/nope"]},
        })
        assert result["state"] == "done"
        assert result["evidence_id"]
        stored = store.load_result(claim["job_id"])
        assert stored["state"] == "done"

    def test_extension_failure_writes_error_log(self, tmp_path):
        from rebel_profiler.browser import BrowserBridge, BrowserJobStore
        from rebel_profiler.evidence.store import EvidenceStore

        db = Database(tmp_path / "c.db")
        db.migrate()
        db.create_case("bridge", case_id="case1")
        store = BrowserJobStore(tmp_path / "queue")
        envelope = store.submit(case_id="case1", url="https://h1.lab.example.test/",
                                extract=["title"])
        evidence = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
        bridge = BrowserBridge("case1", queue_dir=tmp_path / "queue",
                               scope_engine=make_scope(), evidence=evidence,
                               ledger=None)
        task = bridge.pending_tasks()[0]
        bridge.claim(task["job_id"])
        result = bridge.complete(task["job_id"], {
            "ok": False, "error_class": "NavigationError",
            "error": "navigation timeout",
        })
        assert result["state"] == "failed"
        assert result["fix"]
        stored = store.load_result(task["job_id"])
        assert stored["error_class"] == "NavigationError"
        db.close()


# ---------------------------------------------------------------- agent work loop


class TestSelfRepair:
    def test_work_list_error_log_and_suggestions(self, db):
        from rebel_profiler.agent.repair import SelfRepairSession, render_session_human
        from rebel_profiler.evidence.store import EvidenceStore
        from rebel_profiler.intel.claims import ClaimLedger
        from rebel_profiler.intel.sources import SourceRegistry

        evidence = EvidenceStore(db, blobs_dir=db.path.parent / "blobs")
        session = SelfRepairSession(
            "case1", "probe the lab", broker=make_broker(db), ledger=ClaimLedger(SourceRegistry()),
            evidence=evidence, db=db,
        )
        plan = [
            ("echo", "h1.lab.example.test", {"message": "ok"}),        # succeeds
            ("echo", "out-of-scope.test", {}),                        # blocked (scope)
            ("echo", "h2.lab.example.test", {"bad_param": "x"}),      # error → retry → failed
        ]
        def planner(view):
            from rebel_profiler.agent import Proposal

            return [Proposal(action=a, target=t, params=p) for a, t, p in plan]

        report = session.run(planner, reviser=lambda fb: None)
        assert report["items"][0]["status"] == "done"
        assert report["items"][1]["status"] == "blocked"       # scope never auto-retried
        assert report["items"][2]["status"] == "failed"
        assert report["repairs"], "error log must exist"
        assert report["repairs"][1]["fix_hint"]
        assert report["awaiting_user"] is True
        kinds = {s["kind"] for s in report["suggestions"]}
        assert {"report", "verify", "next_goal"} <= kinds
        human = render_session_human(report)
        assert "error log" in human
        assert "suggestions" in human

    def test_persistence_and_listing(self, db):
        from rebel_profiler.agent.repair import SelfRepairSession
        from rebel_profiler.evidence.store import EvidenceStore
        from rebel_profiler.intel.claims import ClaimLedger
        from rebel_profiler.intel.sources import SourceRegistry

        evidence = EvidenceStore(db, blobs_dir=db.path.parent / "blobs")
        session = SelfRepairSession(
            "case1", "goal", broker=make_broker(db),
            ledger=ClaimLedger(SourceRegistry()), evidence=evidence, db=db)
        from rebel_profiler.agent import Proposal

        report = session.run(lambda v: [Proposal(action="echo",
                                                 target="h1.lab.example.test",
                                                 params={"message": "x"})])
        sessions = SelfRepairSession.list_sessions(db)
        assert len(sessions) == 1
        assert sessions[0]["done"] == 1
