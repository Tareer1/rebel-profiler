"""Storage + evidence + audit tests: isolation, integrity, tamper evidence."""

from __future__ import annotations

import pytest

from rebel_profiler.core.errors import EvidenceError, StateError, UsageError
from rebel_profiler.evidence import AuditChain, EvidenceStore, compute_sha256
from rebel_profiler.storage.database import CURRENT_SCHEMA_VERSION, Database


class TestDatabase:
    def test_migrate_is_idempotent(self, db):
        v1 = db.schema_version()
        db.migrate()
        assert db.schema_version() == v1 == CURRENT_SCHEMA_VERSION

    def test_create_and_get_case(self, db):
        cid = db.create_case("Test", "desc")
        row = db.get_case(cid)
        assert row["name"] == "Test"
        assert row["status"] == "draft"

    def test_explicit_case_id(self, db):
        cid = db.create_case("Test", case_id="fixed-id")
        assert cid == "fixed-id"

    def test_case_status_transitions(self, db):
        cid = db.create_case("T")
        db.set_case_status(cid, "active")
        assert db.get_case(cid)["status"] == "active"
        with pytest.raises(UsageError):
            db.set_case_status(cid, "bogus")

    def test_unknown_case_raises(self, db):
        with pytest.raises(StateError):
            db.set_case_status("ghost", "active")

    def test_scope_entries_roundtrip(self, db):
        cid = db.create_case("T")
        db.add_scope_entry(cid, "*.lab.test", note="n")
        db.add_scope_entry(cid, "bad.test", excluded=True)
        rows = db.scope_entries(cid)
        assert len(rows) == 2
        assert bool(rows[1]["excluded"]) is True

    def test_target_and_observation_roundtrip(self, db):
        cid = db.create_case("T")
        tid = db.record_target(cid, "host.lab.test", "domain")
        assert db.record_target(cid, "host.lab.test", "domain") == tid
        db.record_observation(cid, "dns.a", "1.2.3.4", target_id=tid, confidence=0.9, source="dig")
        obs = db.observations_for(cid)
        assert len(obs) == 1
        assert obs[0]["confidence"] == pytest.approx(0.9)

    def test_task_lifecycle(self, db):
        cid = db.create_case("T")
        db.record_task("t1", cid, "discovery", "host.lab.test", risk="moderate")
        db.set_task_state("t1", "running")
        db.set_task_state("t1", "succeeded", outcome="rc=0")
        assert db.get_task("t1")["state"] == "succeeded"
        with pytest.raises(UsageError):
            db.set_task_state("t1", "not-a-state")


class TestEvidenceStore:
    @pytest.fixture(autouse=True)
    def _case(self, db):
        db.create_case("Case", case_id="c1")

    def test_register_and_read(self, db, tmp_path):
        store = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
        rec = store.register("c1", kind="tool_output", data=b"payload", source="nmap")
        assert store.read_bytes(rec) == b"payload"
        assert rec.sha256 == compute_sha256(b"payload")

    def test_content_addressing_dedupes(self, db, tmp_path):
        store = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
        r1 = store.register("c1", kind="x", data=b"same")
        r2 = store.register("c1", kind="x", data=b"same")
        assert r1.sha256 == r2.sha256

    def test_chain_links_records(self, db, tmp_path):
        store = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
        r1 = store.register("c1", kind="x", data=b"1")
        r2 = store.register("c1", kind="x", data=b"2")
        assert r1.prev_hash == "GENESIS"
        assert r2.prev_hash == r1.sha256

    def test_verify_detects_tampered_hash(self, db, tmp_path):
        store = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
        rec = store.register("c1", kind="x", data=b"data")
        db.conn.execute("UPDATE evidence_records SET sha256='x' WHERE id=?", (rec.id,))
        db.conn.commit()
        assert not store.verify_case("c1")["chain_ok"]

    def test_verify_detects_missing_blob(self, db, tmp_path):
        store = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
        rec = store.register("c1", kind="x", data=b"data")
        store._blob_path(rec.sha256).unlink()
        assert not store.verify_case("c1")["chain_ok"]

    def test_read_detects_corrupt_blob(self, db, tmp_path):
        store = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
        rec = store.register("c1", kind="x", data=b"data")
        store._blob_path(rec.sha256).write_bytes(b"corrupted!")
        with pytest.raises(EvidenceError):
            store.read_bytes(rec)


class TestAuditChain:
    def test_append_and_events(self, db):
        chain = AuditChain(db)
        chain.append("c1", actor="op", action="a1")
        chain.append("c1", actor="op", action="a2", detail={"k": "v"})
        events = chain.events("c1")
        assert [e.action for e in events] == ["a1", "a2"]
        assert events[1].detail == {"k": "v"}

    def test_chain_links(self, db):
        chain = AuditChain(db)
        e1 = chain.append("c1", actor="op", action="a1")
        e2 = chain.append("c1", actor="op", action="a2")
        assert e1.prev_hash == AuditChain.GENESIS
        assert e2.prev_hash == e1.hash

    def test_verify_detects_content_tamper(self, db):
        chain = AuditChain(db)
        chain.append("c1", actor="op", action="a1")
        chain.append("c1", actor="op", action="a2")
        db.conn.execute("UPDATE audit_events SET action='evil' WHERE seq=1")
        db.conn.commit()
        result = chain.verify("c1")
        assert not result["chain_ok"]
        assert any("hash mismatch" in p for p in result["problems"])

    def test_verify_detects_deletion(self, db):
        chain = AuditChain(db)
        chain.append("c1", actor="op", action="a1")
        chain.append("c1", actor="op", action="a2")
        chain.append("c1", actor="op", action="a3")
        db.conn.execute("DELETE FROM audit_events WHERE seq=2")
        db.conn.commit()
        result = chain.verify("c1")
        assert not result["chain_ok"]

    def test_verify_detects_detail_tamper(self, db):
        chain = AuditChain(db)
        chain.append("c1", actor="op", action="a1", detail={"approved": False})
        db.conn.execute('UPDATE audit_events SET detail_json=\'{"approved": true}\' WHERE seq=1')
        db.conn.commit()
        assert not chain.verify("c1")["chain_ok"]


class TestCaseIsolation:
    def test_separate_databases_are_isolated(self, tmp_path):
        db1 = Database(tmp_path / "a.db"); db1.migrate()
        db2 = Database(tmp_path / "b.db"); db2.migrate()
        c1 = db1.create_case("A")
        c2 = db2.create_case("B")
        db1.add_scope_entry(c1, "a.test")
        assert len(db2.scope_entries(c2)) == 0
        db1.close(); db2.close()
