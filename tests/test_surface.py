"""Phase 3 tests: nmap adapters, nmap parsing, surface graph, exposure map, CLI."""

from __future__ import annotations

import json

import pytest

from rebel_profiler.cli.main import main
from rebel_profiler.core.errors import UsageError
from rebel_profiler.execution import (
    ActionRequest,
    AdapterRegistry,
    OsFingerprintAdapter,
    PortScanAdapter,
    ServiceDetectAdapter,
)
from rebel_profiler.execution.broker import ExecutionBroker
from rebel_profiler.intel.claims import ClaimLedger
from rebel_profiler.intel.collection import CollectionPipeline
from rebel_profiler.intel.sources import SourceRegistry
from rebel_profiler.intel.surface import (
    OPEN_PORT,
    RESOLVES_TO,
    RUNS,
    VERSIONED_AS,
    ExposureMapper,
)
from rebel_profiler.security.scope import Scope, ScopeEngine, ScopeStatus
from rebel_profiler.storage.database import Database


def _request(action: str, target: str = "h1.lab.example.test", params: dict | None = None):
    capability = "discovery" if action == "port-scan" else "active_recon"
    return ActionRequest(case_id="c1", capability=capability, action=action,
                         target=target, params=params or {})


# ---------------------------------------------------------------- adapters


class TestNmapAdapters:
    def test_port_scan_basic(self):
        argv = PortScanAdapter().build_argv(_request("port-scan"))
        assert argv[0] == "nmap" and "-sT" in argv and "-Pn" in argv and "-T3" in argv
        assert argv[-1] == "h1.lab.example.test"

    def test_port_scan_ports_and_timing(self):
        argv = PortScanAdapter().build_argv(
            _request("port-scan", params={"ports": "22,80,443", "timing": "T4"}))
        assert "-p" in argv and "22,80,443" in argv and "-T4" in argv

    def test_port_scan_rejects_t5(self):
        with pytest.raises(UsageError):
            PortScanAdapter().build_argv(_request("port-scan", params={"timing": "T5"}))

    def test_port_scan_rejects_bad_ports(self):
        with pytest.raises(UsageError):
            PortScanAdapter().build_argv(
                _request("port-scan", params={"ports": "80; rm -rf /"}))

    def test_service_detect_flags(self):
        argv = ServiceDetectAdapter().build_argv(
            _request("service-detect", params={"intensity": "5", "ports": "80"}))
        assert "-sV" in argv and "--version-intensity=5" in argv and "-p" in argv

    def test_service_detect_bad_intensity(self):
        with pytest.raises(UsageError):
            ServiceDetectAdapter().build_argv(
                _request("service-detect", params={"intensity": "12"}))

    def test_os_fingerprint_flags(self):
        argv = OsFingerprintAdapter().build_argv(_request("os-fingerprint"))
        assert "-O" in argv and "--osscan-limit" in argv

    def test_registered_in_default_registry(self):
        names = AdapterRegistry().names()
        assert {"port-scan", "service-detect", "os-fingerprint"} <= set(names)

    def test_no_metacharacters_anywhere(self):
        for action in ("port-scan", "service-detect", "os-fingerprint"):
            with pytest.raises(UsageError):
                adapter = AdapterRegistry().get(action)
                adapter.build_argv(_request(action, target="h1.test $(id)"))


# ---------------------------------------------------------------- nmap parsing


NMAP_LIST_OUTPUT = """Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for h1.lab.example.test (10.20.30.40)
Host is up (0.00042s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1
80/tcp   open  http    nginx 1.24.0
443/tcp  open  ssl/https
9999/tcp filtered unknown
"""

NMAP_GREPABLE_OUTPUT = (
    "Host: 10.20.30.40 ()\tStatus: Up\n"
    "Host: 10.20.30.40 ()\tPorts: 22/open/tcp//ssh//OpenSSH 9.2p1/., "
    "80/open/tcp//http//nginx 1.24.0/, 443/filtered/tcp//https///\n"
)


class TestNmapParsing:
    @pytest.fixture()
    def pipeline(self, tmp_path):
        db = Database(tmp_path / "c.db")
        db.migrate()
        db.create_case("c1", case_id="c1")
        from rebel_profiler.evidence.store import EvidenceStore

        return CollectionPipeline(
            ClaimLedger(SourceRegistry()),
            EvidenceStore(db, blobs_dir=tmp_path / "blobs"), db=db,
        )

    def _ingest(self, pipeline, action, stdout):
        return pipeline.ingest("c1", action=action, target="h1.lab.example.test",
                               stdout=stdout, returncode=0, task_id="t")

    def test_list_output_ports_services(self, pipeline):
        report = self._ingest(pipeline, "port-scan", NMAP_LIST_OUTPUT)
        kinds = {(c["kind"], c["value"]) for c in report["claims"]}
        assert ("port", "22/tcp") in kinds
        assert ("port", "80/tcp") in kinds
        assert ("port", "443/tcp") in kinds
        assert not any(v.startswith("9999") for k, v in kinds if k == "port")
        assert ("ip", "10.20.30.40") in kinds
        assert ("product", "80/tcp:nginx") in kinds
        assert ("version", "80/tcp:1.24.0") in kinds
        assert ("product", "22/tcp:OpenSSH 9.2p1") in kinds  # OpenSSH: single version token stays with product

    def test_service_detect_products_versions(self, pipeline):
        report = self._ingest(pipeline, "service-detect", NMAP_LIST_OUTPUT)
        kinds = {(c["kind"], c["value"]) for c in report["claims"]}
        assert ("service", "22/tcp:ssh") in kinds
        assert ("product", "80/tcp:nginx") in kinds
        assert ("version", "80/tcp:1.24.0") in kinds

    def test_grepable_output(self, pipeline):
        report = self._ingest(pipeline, "port-scan", NMAP_GREPABLE_OUTPUT)
        kinds = {(c["kind"], c["value"]) for c in report["claims"]}
        assert ("port", "22/tcp") in kinds
        assert ("service", "22/tcp:ssh") in kinds
        assert not any(k == "port" and v.startswith("443") for k, v in kinds)

    def test_provenance_scan_source(self, pipeline):
        report = self._ingest(pipeline, "port-scan", NMAP_LIST_OUTPUT)
        claim = report["claims"][0]
        assert claim["source"] == "scan.nmap"
        assert claim["method"] == "port-scan"
        assert claim["evidence_id"]

    def test_empty_scan_no_claims(self, pipeline):
        report = self._ingest(pipeline, "port-scan", "")
        assert report["claims"] == []
        assert report["evidence_id"]


# ---------------------------------------------------------------- surface


@pytest.fixture()
def ledger_with_surface():
    ledger = ClaimLedger(SourceRegistry())
    now = 1000.0
    # host1: resolves to ip, 22+80 open, nginx on 80
    ledger.add("c1", subject="h1.lab.test", kind="ip", value="10.0.0.1",
               source="scan.nmap", observed_at=now)
    ledger.add("c1", subject="h1.lab.test", kind="port", value="22/tcp",
               source="scan.nmap", observed_at=now)
    ledger.add("c1", subject="h1.lab.test", kind="port", value="80/tcp",
               source="scan.nmap", observed_at=now)
    ledger.add("c1", subject="h1.lab.test", kind="product", value="80/tcp:nginx",
               source="scan.nmap", observed_at=now)
    ledger.add("c1", subject="h1.lab.test", kind="version", value="80/tcp:1.24.0",
               source="scan.nmap", observed_at=now)
    # host2: same nginx product → lateral hint
    ledger.add("c1", subject="h2.lab.test", kind="port", value="80/tcp",
               source="scan.nmap", observed_at=now)
    ledger.add("c1", subject="h2.lab.test", kind="product", value="80/tcp:nginx",
               source="scan.nmap", observed_at=now)
    return ledger


class TestSurfaceGraph:
    def test_graph_topology(self, ledger_with_surface):
        mapper = ExposureMapper(ledger_with_surface, "c1")
        graph = mapper.build_graph()
        host1 = graph.node("host:h1.lab.test")
        assert host1 is not None
        ip_targets = [n.node_id for n in graph.neighbors(host1.node_id, RESOLVES_TO)]
        assert "ip:10.0.0.1" in ip_targets
        port_targets = [n.node_id for n in graph.neighbors(host1.node_id, OPEN_PORT)]
        assert {"port:22/tcp", "port:80/tcp"} <= set(port_targets)
        nginx = graph.node("product:nginx")
        assert nginx is not None
        # port 80 runs nginx; version is a separate node linked by versioned_as
        port80 = graph.node("port:80/tcp")
        runs = [n.node_id for n in graph.neighbors(port80.node_id, RUNS)]
        assert "product:nginx" in runs
        versioned = [n.node_id for n in graph.neighbors(port80.node_id, VERSIONED_AS)]
        assert "version:1.24.0" in versioned
        assert graph.node("product:1.24.0") is None

    def test_summary_density_and_lateral(self, ledger_with_surface):
        mapper = ExposureMapper(ledger_with_surface, "c1")
        summary = mapper.summary()
        by_host = {row["host"]: row for row in summary["hosts"]}
        assert by_host["h1.lab.test"]["exposure_density"] == 2
        assert by_host["h1.lab.test"]["products"]["80/tcp"] == ["nginx"]
        # h2 shares nginx with h1 → lateral hint
        assert by_host["h2.lab.test"]["lateral_hints"]["80/tcp"] == ["h1.lab.test"]
        assert summary["stats"]["hosts"] == 2

    def test_empty_ledger(self):
        mapper = ExposureMapper(ClaimLedger(SourceRegistry()), "empty")
        summary = mapper.summary()
        assert summary["hosts"] == []
        assert mapper.build_graph().nodes() == []

    def test_build_machine_view(self, ledger_with_surface):
        view = ExposureMapper(ledger_with_surface, "c1").build()
        assert view["schema_version"] == 1
        assert view["graph"]["nodes"] and view["graph"]["edges"]


# ---------------------------------------------------------------- broker + CLI


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return ["--data-dir", str(tmp_path / "data")]


@pytest.fixture()
def active_case(workspace, capsys):
    main([*workspace, "case", "create", "SurfaceCase"])
    capsys.readouterr()
    main([*workspace, "case", "list", "-o", "json"])
    case_id = json.loads(capsys.readouterr().out)["data"][0]["id"]
    main([*workspace, "case", "scope", "add", case_id, "*.lab.example.test"])
    capsys.readouterr()
    main([*workspace, "case", "activate", case_id])
    capsys.readouterr()
    return case_id


class TestBrokerIntegration:
    def test_broker_executes_port_scan_with_fake_nmap(self, tmp_path, monkeypatch):
        """Runner stub proves the broker path works end-to-end without nmap."""
        db = Database(tmp_path / "case.db")
        db.migrate()
        db.create_case("c1", case_id="c1")
        from rebel_profiler.evidence.store import EvidenceStore

        store = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
        scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
        scope.add("*.lab.example.test")
        engine = ScopeEngine()
        engine.register(scope)
        broker = ExecutionBroker(
            db, scope_engine=engine, evidence=store,
            confirm=lambda request, gate: True,   # programmatic confirmation
            runner=lambda argv: (0, NMAP_LIST_OUTPUT, ""),
        )
        request = ActionRequest(case_id="c1", capability="discovery",
                                action="port-scan", target="h1.lab.example.test")
        result = broker.execute(request)
        assert result.outcome == "succeeded"
        pipeline = CollectionPipeline(ClaimLedger(SourceRegistry()), store, db=db)
        report = pipeline.ingest(
            "c1", action="port-scan", target="h1.lab.example.test",
            stdout=result.stdout, returncode=0, task_id=result.task_id,
            evidence_id=result.evidence_id,
        )
        assert any(c["kind"] == "port" for c in report["claims"])
        rows = db.claims_for("c1", "h1.lab.example.test")
        assert rows


class TestSurfaceCLI:
    def _seed_surface(self, workspace, tmp_path, active_case, capsys):
        from rebel_profiler.cli.context import AppContext
        from rebel_profiler.intel import ClaimLedger, CollectionPipeline, SourceRegistry

        ctx = AppContext(data_dir=tmp_path / "data")
        db = ctx.open_case(active_case)
        pipeline = CollectionPipeline(
            ClaimLedger(SourceRegistry()),
            ctx.evidence_store(db, active_case), db=db,
        )
        pipeline.ingest(active_case, action="port-scan", target="h1.lab.example.test",
                        stdout=NMAP_LIST_OUTPUT, returncode=0, task_id="t1")
        db.close()
        capsys.readouterr()

    def test_surface_map(self, workspace, active_case, capsys, tmp_path):
        self._seed_surface(workspace, tmp_path, active_case, capsys)
        rc = main([*workspace, "surface", "map", active_case])
        assert rc == 0
        out = capsys.readouterr().out
        assert "host:h1.lab.example.test" in out
        assert "port:80/tcp" in out

    def test_surface_exposure(self, workspace, active_case, capsys, tmp_path):
        self._seed_surface(workspace, tmp_path, active_case, capsys)
        rc = main([*workspace, "surface", "exposure", active_case])
        assert rc == 0
        out = capsys.readouterr().out
        assert "h1.lab.example.test" in out
        assert "22/tcp" in out

    def test_surface_map_empty(self, workspace, active_case, capsys):
        rc = main([*workspace, "surface", "map", active_case])
        assert rc == 0
        out = capsys.readouterr().out
        assert "empty" in out

    def test_surface_json(self, workspace, active_case, capsys, tmp_path):
        self._seed_surface(workspace, tmp_path, active_case, capsys)
        main([*workspace, "surface", "exposure", active_case, "-o", "json"])
        payload = json.loads(capsys.readouterr().out)
        rows = payload["data"]
        assert len(rows) == 1
        assert rows[0]["host"] == "h1.lab.example.test"
        assert "22/tcp" in rows[0]["open_ports"]
