"""Tests for cross-domain fusion (PDF 9) and the persistent graph store (PDF 8/10)."""

from __future__ import annotations

import json

import pytest

from rebel_profiler.cli.main import main
from rebel_profiler.intel.claims import ClaimLedger
from rebel_profiler.intel.fusion import FusionEngine, noisy_or
from rebel_profiler.intel.graphstore import RelationshipGraphStore
from rebel_profiler.intel.sources import SourceRegistry
from rebel_profiler.storage.database import Database


@pytest.fixture()
def ledger_multidomain():
    ledger = ClaimLedger(SourceRegistry())
    now = 1000.0
    # dns channel
    ledger.add("c1", subject="h1.lab.test", kind="ip", value="10.0.0.1",
               source="dns.authoritative", method="passive-dns", observed_at=now)
    # scan channel (same fact, independent source) → cross-domain corroboration
    ledger.add("c1", subject="h1.lab.test", kind="ip", value="10.0.0.1",
               source="scan.nmap", method="port-scan", observed_at=now)
    # multi-valued attributes from scanning
    ledger.add("c1", subject="h1.lab.test", kind="port", value="80/tcp",
               source="scan.nmap", method="port-scan", observed_at=now)
    ledger.add("c1", subject="h1.lab.test", kind="product", value="80/tcp:nginx",
               source="scan.nmap", method="service-detect", observed_at=now)
    # web channel finding
    ledger.add("c1", subject="h1.lab.test", kind="web_finding",
               value="header:CSP: missing", source="scan.web", method="web-audit",
               observed_at=now)
    # contradiction across domains: registrar value differs by source
    ledger.add("c1", subject="h1.lab.test", kind="registrar", value="Maybe Registrar",
               source="crowd.urlhaus", method="whois-lookup", observed_at=now)
    ledger.add("c1", subject="h1.lab.test", kind="registrar", value="Real Registrar",
               source="whois.registrar", method="whois-lookup", observed_at=now)
    return ledger


class TestNoisyOr:
    def test_two_independent_observations(self):
        assert noisy_or([0.6, 0.6]) == pytest.approx(0.84, abs=0.001)

    def test_single_passthrough(self):
        assert noisy_or([0.5]) == pytest.approx(0.5)

    def test_bounded_by_one(self):
        assert noisy_or([0.9, 0.9, 0.9]) < 1.0

    def test_empty(self):
        assert noisy_or([]) == 0.0


class TestFusionEngine:
    def test_cross_domain_corroboration(self, ledger_multidomain):
        engine = FusionEngine(ledger_multidomain, "c1")
        report = engine.report()
        profile = report["subjects"]["h1.lab.test"]
        ip_entries = [e for e in profile["attributes"]["ip"]["values"]]
        assert len(ip_entries) == 1  # fused into one value
        entry = ip_entries[0]
        assert set(entry["sources"]) == {"dns.authoritative", "scan.nmap"}
        assert entry["corroborated"] is True
        assert entry["confidence"] > 0.9  # two strong sources fused
        assert report["stats"]["cross_domain_subjects"] == 1

    def test_multi_valued_never_conflicts(self, ledger_multidomain):
        engine = FusionEngine(ledger_multidomain, "c1")
        report = engine.report()
        conflicts = report["conflicts"]
        assert all(c["attribute"] != "port" for c in conflicts)

    def test_cross_domain_contradiction_surfaced(self, ledger_multidomain):
        engine = FusionEngine(ledger_multidomain, "c1")
        report = engine.report()
        conflicts = report["conflicts"]
        assert len(conflicts) == 1
        conflict = conflicts[0]
        assert conflict["attribute"] == "registrar"
        assert conflict["winner"]["value"] == "Real Registrar"
        assert "crowd.urlhaus" in conflict["loser"]["sources"]
        # both sides remain in the ledger — kept, never deleted
        values = {c.value for c in ledger_multidomain.for_subject("c1", "h1.lab.test")
                  if c.kind == "registrar"}
        assert values == {"Maybe Registrar", "Real Registrar"}

    def test_deterministic(self, ledger_multidomain):
        a = FusionEngine(ledger_multidomain, "c1").report()
        b = FusionEngine(ledger_multidomain, "c1").report()
        assert a == b

    def test_empty_case(self):
        report = FusionEngine(ClaimLedger(SourceRegistry()), "empty").report()
        assert report["stats"]["subjects"] == 0

    def test_single_subject_profile(self, ledger_multidomain):
        engine = FusionEngine(ledger_multidomain, "c1")
        profiles = engine.fuse()
        profile = profiles["h1.lab.test"]
        assert {"dns", "scanning", "web"} <= profile.domains_seen
        attrs = profile.as_dict()["attributes"]
        assert "web_finding" in attrs and "product" in attrs


class TestGraphStore:
    def test_build_persists(self, ledger_multidomain, tmp_path):
        db = Database(tmp_path / "c.db")
        db.migrate()
        db.create_case("c1", case_id="c1")
        store = RelationshipGraphStore(ledger_multidomain, "c1", db)
        stats = store.build()
        assert stats["nodes"] > 0 and stats["edges"] > 0
        # persisted: re-read from db
        assert len(db.graph_nodes("c1")) == stats["nodes"]
        assert len(db.graph_edges("c1")) == stats["edges"]

    def test_topology_from_storage(self, ledger_multidomain, tmp_path):
        db = Database(tmp_path / "c.db")
        db.migrate()
        db.create_case("c1", case_id="c1")
        store = RelationshipGraphStore(ledger_multidomain, "c1", db)
        store.build()
        host_neighbors = store.neighbors("host:h1.lab.test")
        targets = {n["node"]["node_id"] for n in host_neighbors}
        assert "ip:10.0.0.1" in targets
        assert "port:80/tcp" in targets
        # incoming edges: web finding reported_on the host
        incoming = store.neighbors("host:h1.lab.test", direction="in")
        assert any(n["node"]["kind"] == "web_finding" for n in incoming)

    def test_paths(self, ledger_multidomain, tmp_path):
        db = Database(tmp_path / "c.db")
        db.migrate()
        db.create_case("c1", case_id="c1")
        store = RelationshipGraphStore(ledger_multidomain, "c1", db)
        store.build()
        paths = store.paths("host:h1.lab.test", "product:nginx")
        assert paths and paths[0][0] == "host:h1.lab.test" and paths[0][-1] == "product:nginx"

    def test_related_hosts(self, tmp_path):
        ledger = ClaimLedger(SourceRegistry())
        now = 1000.0
        for host in ("h1.lab.test", "h2.lab.test"):
            ledger.add("c1", subject=host, kind="port", value="80/tcp",
                       source="scan.nmap", method="port-scan", observed_at=now)
            ledger.add("c1", subject=host, kind="product", value="80/tcp:nginx",
                       source="scan.nmap", method="service-detect", observed_at=now)
        db = Database(tmp_path / "c.db")
        db.migrate()
        db.create_case("c1", case_id="c1")
        store = RelationshipGraphStore(ledger, "c1", db)
        store.build()
        peers = store.related("host:h1.lab.test", via_kind="host")
        assert any(p["node_id"] == "host:h2.lab.test" for p in peers)

    def test_rebuild_is_idempotent(self, ledger_multidomain, tmp_path):
        db = Database(tmp_path / "c.db")
        db.migrate()
        db.create_case("c1", case_id="c1")
        store = RelationshipGraphStore(ledger_multidomain, "c1", db)
        first = store.build()
        second = store.build()
        assert first["nodes"] == second["nodes"]
        assert first["edges"] == second["edges"]

    def test_stats_breakdown(self, ledger_multidomain, tmp_path):
        db = Database(tmp_path / "c.db")
        db.migrate()
        db.create_case("c1", case_id="c1")
        store = RelationshipGraphStore(ledger_multidomain, "c1", db)
        stats = store.build()
        assert stats["nodes_by_kind"].get("host") == 1
        assert stats["edges_by_relation"].get("reported_on") == 1


class TestFusionGraphCLI:
    @pytest.fixture()
    def seeded(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_dir = str(tmp_path / "data")
        assert main(["--data-dir", data_dir, "case", "create", "FusionCase"]) == 0
        capsys.readouterr()
        main(["--data-dir", data_dir, "case", "list", "-o", "json"])
        case_id = json.loads(capsys.readouterr().out)["data"][0]["id"]

        # seed claims through the pipeline (persisted)
        from rebel_profiler.cli.context import AppContext
        from rebel_profiler.intel import ClaimLedger, CollectionPipeline, SourceRegistry

        ctx = AppContext(data_dir=tmp_path / "data")
        db = ctx.open_case(case_id)
        pipeline = CollectionPipeline(
            ClaimLedger(SourceRegistry()),
            ctx.evidence_store(db, case_id), db=db,
        )
        pipeline.ingest(case_id, action="port-scan", target="h1.lab.example.test",
                        stdout=("Nmap scan report for h1.lab.example.test (10.0.0.9)\n"
                                "PORT STATE SERVICE\n80/tcp open http\n"),
                        returncode=0, task_id="t1")
        db.close()
        capsys.readouterr()
        return data_dir, case_id

    def test_fusion_command(self, seeded, capsys):
        data_dir, case_id = seeded
        rc = main(["--data-dir", data_dir, "intel", "fusion", case_id])
        assert rc == 0
        out = capsys.readouterr().out
        assert "h1.lab.example.test" in out

    def test_fusion_subject_profile(self, seeded, capsys):
        data_dir, case_id = seeded
        rc = main(["--data-dir", data_dir, "intel", "fusion", case_id,
                   "h1.lab.example.test"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Fused profile" in out
        assert "scan.nmap" in out

    def test_surface_build_then_show(self, seeded, capsys):
        data_dir, case_id = seeded
        assert main(["--data-dir", data_dir, "surface", "build", case_id]) == 0
        capsys.readouterr()
        rc = main(["--data-dir", data_dir, "surface", "show", case_id])
        assert rc == 0
        out = capsys.readouterr().out
        assert "host:h1.lab.example.test" in out

    def test_surface_persist_across_invocations(self, seeded, capsys):
        data_dir, case_id = seeded
        main(["--data-dir", data_dir, "surface", "build", case_id])
        capsys.readouterr()
        # a fresh CLI invocation still sees the persisted graph
        main(["--data-dir", data_dir, "surface", "show", case_id, "-o", "json"])
        payload = json.loads(capsys.readouterr().out)
        node_ids = {n["node"] for n in payload["data"]["nodes"]}
        assert "host:h1.lab.example.test" in node_ids

    def test_surface_paths(self, seeded, capsys):
        data_dir, case_id = seeded
        main(["--data-dir", data_dir, "surface", "build", case_id])
        capsys.readouterr()
        rc = main(["--data-dir", data_dir, "surface", "paths", case_id,
                   "host:h1.lab.example.test", "service:http"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "1 path(s)" in out

    def test_surface_paths_none(self, seeded, capsys):
        data_dir, case_id = seeded
        main(["--data-dir", data_dir, "surface", "build", case_id])
        capsys.readouterr()
        rc = main(["--data-dir", data_dir, "surface", "paths", case_id,
                   "host:h1.lab.example.test", "host:ghost.test"])
        assert rc == 1

    def test_surface_related(self, seeded, capsys):
        data_dir, case_id = seeded
        main(["--data-dir", data_dir, "surface", "build", case_id])
        capsys.readouterr()
        rc = main(["--data-dir", data_dir, "surface", "related", case_id,
                   "host:h1.lab.example.test"])
        assert rc == 0
