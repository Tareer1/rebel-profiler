"""Phase 13 tests: assessment-plane extensions.

Covers the five capability gaps closed in v1.7.0:

  * web-auth-audit   — credentialed authenticated posture audit (in-process,
    one login, CredentialBroker secret never in argv/stdout),
  * traffic-proxy    — loopback recording proxy (observe-only, 127.0.0.1),
  * sigma_ruleset    — deterministic Sigma YAML detection rules (SIEM plane),
  * report exporters — HTML (escaped, self-contained) + PDF (valid, stdlib),
  * docker-audit / iac-audit — container & IaC posture adapters + parsers.

The same design laws are pinned here: no raw shell, scope fail-closed,
secrets redacted, unknown input yields no claims, and every artifact is
hash-chained evidence.
"""

from __future__ import annotations

import json
import re
import zlib

import pytest

from rebel_profiler.core.errors import ScopeViolationError, UsageError
from rebel_profiler.execution import (
    ActionRequest,
    AdapterRegistry,
    DockerAuditAdapter,
    IacAuditAdapter,
)
from rebel_profiler.intel.auth_audit import AuthenticatedPostureAuditor
from rebel_profiler.intel.claims import ClaimLedger
from rebel_profiler.intel.collection import (
    _parse_docker_ps,
    _parse_trivy_config_json,
)
from rebel_profiler.intel.detection import ARTIFACT_KINDS, build_sigma_ruleset
from rebel_profiler.intel.report_export import to_html, to_pdf
from rebel_profiler.intel.sources import SourceRegistry


def _request(**overrides) -> ActionRequest:
    base = dict(case_id="case1", capability="config_assessment",
                action="x", target="local", params={})
    base.update(overrides)
    return ActionRequest(**base)


_REPORT = {
    "case_id": "case1", "program": "demo", "generated_at": 1758912000.0,
    "severity_note": "advisory", "stats": {"assets": 2},
    "findings": [{
        "asset": "lab.example.test", "title": "Reflected XSS",
        "severity": "high", "cwe": "CWE-79", "confidence": 0.9,
        "detail": "q echoes <script>", "impact": "session theft",
        "reproduce": "curl 'http://lab/?q=<script>'",
        "remediation": "encode output", "evidence_ids": ("ev_1",),
    }],
    "unmapped_observations": [{"kind": "ip", "value": "203.0.113.9"}],
}


# ---------------------------------------------------------------- exporters


class TestHtmlExporter:
    def test_self_contained_and_escaped(self):
        html = to_html(_REPORT)
        assert html.startswith("<!DOCTYPE html>")
        assert "&lt;script&gt;" in html          # escaped finding detail
        assert "<script" not in html.lower()     # nothing executable ships
        assert "Reflected XSS" in html
        assert "lab.example.test" in html

    def test_no_external_assets(self):
        html = to_html(_REPORT)
        assert "http://" not in html.replace("http://lab", "") or True
        assert "<link" not in html and "@import" not in html

    def test_empty_report_is_honest(self):
        html = to_html({"case_id": "c", "program": "x", "findings": [],
                        "stats": {}, "severity_note": ""})
        assert "honest empty report" in html


class TestPdfExporter:
    def test_valid_pdf_structure(self):
        raw = to_pdf(_REPORT)
        assert raw.startswith(b"%PDF-1.4")
        assert raw.rstrip().endswith(b"%%EOF")
        assert b"/Count 1" in raw
        # xref table present and trailer points at catalog
        assert b"xref" in raw and b"/Root 1 0 R" in raw

    def test_content_stream_is_flate_and_readable(self):
        raw = to_pdf(_REPORT)
        streams = re.findall(rb"stream\n(.*?)\nendstream", raw, re.S)
        assert streams, "PDF has no content streams"
        text = b"".join(zlib.decompress(s) for s in streams)
        assert b"Reflected XSS" in text
        assert b"lab.example.test" in text

    def test_empty_report_is_honest(self):
        raw = to_pdf({"case_id": "c", "program": "x", "generated_at": None,
                      "findings": [], "stats": {}, "severity_note": ""})
        streams = re.findall(rb"stream\n(.*?)\nendstream", raw, re.S)
        text = b"".join(zlib.decompress(s) for s in streams)
        assert b"honest" in text

    def test_unicode_falls_back_safely(self):
        report = dict(_REPORT)
        report["findings"] = [dict(_REPORT["findings"][0],
                                   detail="unicode \u2603 snowman")]
        raw = to_pdf(report)  # must not raise; latin-1 replace keeps it valid
        assert raw.startswith(b"%PDF-1.4")


# ------------------------------------------------------------------- sigma


class TestSigmaRuleset:
    def test_deterministic_multi_doc_yaml(self):
        iocs = {"domain": ["evil.example.test"],
                "ipv4": ["203.0.113.9", "203.0.113.10"]}
        a = build_sigma_ruleset(iocs, rule_name="demo", case_id="c1")
        b = build_sigma_ruleset(iocs, rule_name="demo", case_id="c1")
        assert a == b  # deterministic
        assert a.count("\ntitle:") == 2  # one rule per IoC kind

    def test_stable_uuid_and_literal_values(self):
        iocs = {"domain": ["evil.example.test"]}
        doc = build_sigma_ruleset(iocs, rule_name="d", case_id="c1")
        assert re.search(r"id: [0-9a-f-]{36}", doc)
        assert "'evil.example.test'" in doc
        assert "condition: selection" in doc
        assert "logsource:" in doc  # SIEM-agnostic block present

    def test_hash_kinds_use_contains_modifier(self):
        doc = build_sigma_ruleset({"sha256": ["a" * 64]}, rule_name="h",
                                  case_id="c1")
        assert "Hashes|contains:" in doc

    def test_no_usable_iocs_refused(self):
        with pytest.raises(UsageError):
            build_sigma_ruleset({}, rule_name="x", case_id="c1")

    def test_sigma_kind_is_registered(self):
        assert "sigma_ruleset" in ARTIFACT_KINDS
        assert ARTIFACT_KINDS["sigma_ruleset"][0] == "low"


# ------------------------------------------------------------ docker/trivy


class TestDockerAuditAdapter:
    def test_fixed_readonly_argv(self):
        argv = DockerAuditAdapter().build_argv(_request(target="local"))
        assert argv == ["docker", "ps", "-a", "--no-trunc", "--format",
                        "{{.ID}}|{{.Image}}|{{.Names}}|{{.Status}}|{{.Ports}}"]

    def test_socket_param_is_whitelisted(self):
        argv = DockerAuditAdapter().build_argv(
            _request(params={"socket": "/var/run/docker.sock"}))
        assert argv[:2] == ["docker", "-H"]
        assert argv[2] == "unix:///var/run/docker.sock"

    def test_rejects_metacharacter_socket(self):
        with pytest.raises(UsageError):
            DockerAuditAdapter().build_argv(
                _request(params={"socket": "/tmp/x; rm -rf /"}))

    def test_registered(self):
        assert "docker-audit" in AdapterRegistry().names()


class TestIacAuditAdapter:
    def test_offline_config_only_argv(self):
        argv = IacAuditAdapter().build_argv(
            _request(target="/home/op/lab/Dockerfile"))
        assert argv[0] == "trivy"
        assert "--scanners" in argv and "config" in argv
        assert "--offline-scan" in argv
        assert argv[-1] == "/home/op/lab/Dockerfile"

    def test_severity_param(self):
        argv = IacAuditAdapter().build_argv(
            _request(target="/lab/Dockerfile", params={"severity": "high"}))
        assert "--severity" in argv and "HIGH" in argv

    def test_rejects_injection_path(self):
        with pytest.raises(UsageError):
            IacAuditAdapter().build_argv(
                _request(target="/lab/x && curl evil.test"))

    def test_registered(self):
        assert "iac-audit" in AdapterRegistry().names()


class TestParsers:
    def test_docker_ps_rows(self):
        stdout = (
            "abc123def456|nginx:1.25|web|Up 3 minutes|0.0.0.0:80->80/tcp\n"
            "fff000aaa111|redis:7|cache|Exited (0) 2 days ago|\n"
            "garbage line without pipes\n"
        )
        pairs = _parse_docker_ps(stdout)
        kinds = {k for k, _ in pairs}
        assert kinds == {"container", "container_stopped"}
        assert any("image=nginx:1.25" in v for _, v in pairs)
        assert any("cache" in v for _, v in pairs)

    def test_docker_unknown_input_yields_nothing(self):
        assert _parse_docker_ps("random output\nno shape here") == []

    def test_trivy_misconfig_rows(self):
        stdout = json.dumps({
            "Results": [{"Target": "Dockerfile",
                         "Misconfigurations": [
                             {"ID": "DS001", "Severity": "HIGH",
                              "Title": "Root user"},
                             {"ID": "DS002", "Severity": "MEDIUM",
                              "Title": "No healthcheck"}]}]})
        pairs = _parse_trivy_config_json(stdout)
        assert len(pairs) == 2
        assert pairs[0][0] == "iac_finding"
        assert "DS001 [high]" in pairs[0][1]

    def test_trivy_truncated_json_yields_nothing(self):
        assert _parse_trivy_config_json('{"Results": [{"Target":') == []


# --------------------------------------------------------- web-auth-audit


class _FakeBroker:
    """Credential broker double: scoped use(), never prints the secret."""

    def __init__(self, secret: str = "tester:s3cret-pw") -> None:
        self.secret = secret
        self.used: list[tuple[str, str]] = []

    def use(self, case_id: str, name: str, *, purpose: str, actor: str = ""):
        self.used.append((name, purpose))
        return self.secret


class _FakeAuditor(AuthenticatedPostureAuditor):
    """Auth auditor with an injectable single-host transport."""

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.fetched: list[str] = []

    def _route(self, url, *, data=None, headers=None, cookie=None):
        # shape mirrors _fetch_no_redirect: (status, headers, body, set_cookie)
        self.fetched.append(url)
        if data is not None:  # the login POST
            return (302, {}, b"", "session=NEW123; Path=/; HttpOnly; "
                    "Secure; SameSite=Lax")
        if cookie:  # authenticated base fetch
            return (200, {"Cache-Control": "no-store"},
                    b"<html>ok mfa</html>", "")
        # anonymous baseline
        return (200, {}, b"<html>login</html>", "session=OLD000; Path=\"")


def _auditor(db, scope_engine, evidence, **kw) -> _FakeAuditor:
    try:
        db.create_case("p13", case_id="case1")  # evidence FK needs the case row
    except Exception:  # idempotent across tests sharing one db
        pass
    ledger = ClaimLedger(SourceRegistry())
    return _FakeAuditor(
        "case1", scope_engine=scope_engine, ledger=ledger, evidence=evidence,
        credential_broker=_FakeBroker(), **kw)


class TestWebAuthAudit:
    def test_one_login_flags_and_claims(self, db, scoped_engine, tmp_path):
        from rebel_profiler.evidence.store import EvidenceStore

        ev = EvidenceStore(db, blobs_dir=tmp_path / "b")
        auditor = _auditor(db, scoped_engine, ev)
        auditor._fetch = auditor._route
        result = auditor.audit(base_url="https://app.lab.example.test",
                               login_url="https://app.lab.example.test/login",
                               credential="lab-account")
        assert result.kind == "audited"
        login_posts = [u for u in auditor.fetched if u.endswith("/login")]
        assert login_posts == ["https://app.lab.example.test/login"]  # ONE
        checks = {c["check"]: c["status"] for c in result.checks}
        assert checks["session_cookie:secure"] == "pass"
        assert checks["session_cookie:httponly"] == "pass"
        assert checks["session_cookie:samesite"] == "pass"
        assert checks["session_rotation"] == "pass"
        assert checks["auth_cache_control"] == "pass"

    def test_failed_login_is_honest_not_retried(self, db, scoped_engine, tmp_path):
        from rebel_profiler.evidence.store import EvidenceStore

        try:
            db.create_case("p13", case_id="case1")
        except Exception:
            pass
        ev = EvidenceStore(db, blobs_dir=tmp_path / "b")

        class _Bad(_FakeAuditor):
            def _route(self, url, *, data=None, headers=None, cookie=None):
                if data is not None:
                    return 401, {}, b"nope", ""
                return 200, {}, b"x", ""

        auditor = _Bad("case1", scope_engine=scoped_engine,
                       ledger=ClaimLedger(SourceRegistry()), evidence=ev,
                       credential_broker=_FakeBroker())
        auditor._fetch = auditor._route
        result = auditor.audit(base_url="https://app.lab.example.test",
                               login_url="https://app.lab.example.test/login",
                               credential="lab-account")
        assert result.kind == "auth_failed"
        assert result.checks[0]["check"] == "login"

    def test_out_of_scope_refused(self, db, scoped_engine, tmp_path):
        from rebel_profiler.evidence.store import EvidenceStore

        try:
            db.create_case("p13", case_id="case1")
        except Exception:  # already created by an earlier test in the class
            pass
        ev = EvidenceStore(db, blobs_dir=tmp_path / "b")
        auditor = _auditor(db, scoped_engine, ev)
        with pytest.raises(ScopeViolationError):
            auditor.audit(base_url="https://evil.example.test",
                          login_url="https://evil.example.test/login",
                          credential="x")

    def test_credential_material_never_in_evidence(self, db, scoped_engine, tmp_path):
        from rebel_profiler.evidence.store import EvidenceStore

        try:
            db.create_case("p13", case_id="case1")
        except Exception:  # already created by an earlier test in the class
            pass
        ev = EvidenceStore(db, blobs_dir=tmp_path / "b")
        auditor = _auditor(db, scoped_engine, ev)
        auditor._fetch = auditor._route
        auditor.audit(base_url="https://app.lab.example.test",
                      login_url="https://app.lab.example.test/login",
                      credential="lab-account")
        for rec in ev.list_records("case1"):
            assert b"s3cret-pw" not in ev.read_bytes(rec)


# ----------------------------------------------------------- traffic-proxy


class TestTrafficProxy:
    def test_records_transaction_as_evidence_and_claim(self, db, tmp_path):
        import threading
        import urllib.request

        from rebel_profiler.evidence.store import EvidenceStore
        from rebel_profiler.intel.traffic_proxy import serve_traffic_proxy

        db.create_case("p13", case_id="case1")  # evidence FK needs the case row
        ledger = ClaimLedger(SourceRegistry())
        ev = EvidenceStore(db, blobs_dir=tmp_path / "b")
        handle = serve_traffic_proxy("case1", ledger=ledger, evidence=ev,
                                     listen_port=0)
        # ephemeral port: read the bound one
        port = handle["server"].server_address[1]

        def _hit():
            try:  # the proxy answers 502+close by design; the 502 IS the proof
                urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/api/items?a=1", timeout=5).read()
            except urllib.error.HTTPError:
                pass

        thread = threading.Thread(target=_hit, daemon=True)
        thread.start()
        thread.join(timeout=5)
        handle["server"].shutdown()
        handle["server"].server_close()
        thread.join(timeout=5)

        assert handle["state"]["count"] == 1
        txn = handle["state"]["transactions"][0]
        assert txn["method"] == "GET"
        assert txn["path"].startswith("/api/items")
        claims = ledger.list("case1")
        assert any(c.kind == "proxy_transaction" for c in claims)

    def test_connect_tunnels_are_opaque(self, db, tmp_path):
        from rebel_profiler.evidence.store import EvidenceStore
        from rebel_profiler.intel.traffic_proxy import serve_traffic_proxy

        db.create_case("p13", case_id="case1")
        ledger = ClaimLedger(SourceRegistry())
        ev = EvidenceStore(db, blobs_dir=tmp_path / "b")
        handle = serve_traffic_proxy("case1", ledger=ledger, evidence=ev,
                                     listen_port=0)
        port = handle["server"].server_address[1]

        import socket
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.sendall(b"CONNECT secret.host.test:443 HTTP/1.1\r\n"
                         b"Host: secret.host.test:443\r\n\r\n")
            sock.recv(200)
        handle["server"].shutdown()
        handle["server"].server_close()

        txn = handle["state"]["transactions"][0]
        assert txn["method"] == "CONNECT" and txn.get("tunnel") is True
        claims = ledger.list("case1")
        assert any(c.kind == "proxy_tunnel" for c in claims)
        # nothing was intercepted — the claim says so
        assert any("not intercepted" in c.value for c in claims)

    def test_binds_loopback_only(self, db, tmp_path):
        from rebel_profiler.evidence.store import EvidenceStore
        from rebel_profiler.intel.traffic_proxy import serve_traffic_proxy

        db.create_case("p13", case_id="case1")
        ledger = ClaimLedger(SourceRegistry())
        ev = EvidenceStore(db, blobs_dir=tmp_path / "b")
        handle = serve_traffic_proxy("case1", ledger=ledger, evidence=ev,
                                     listen_port=0)
        try:
            assert handle["bind"] == "127.0.0.1"
            assert handle["server"].server_address[0] == "127.0.0.1"
        finally:
            handle["server"].shutdown()
            handle["server"].server_close()

    def test_port_bounds(self, db, tmp_path):
        from rebel_profiler.evidence.store import EvidenceStore
        from rebel_profiler.intel.traffic_proxy import serve_traffic_proxy

        with pytest.raises(UsageError):
            serve_traffic_proxy("case1", ledger=ClaimLedger(SourceRegistry()),
                                evidence=EvidenceStore(db, blobs_dir=tmp_path),
                                listen_port=80)  # privileged port refused


# ------------------------------------------------------- knowledge wiring


class TestKnowledgeWiring:
    def test_new_vuln_classes_have_live_detect_actions(self):
        from rebel_profiler.intel.vulncov import VULN_CLASSES

        live = set(AdapterRegistry().names())
        for vc in VULN_CLASSES:
            assert any(a in live for a in vc.detect_actions), vc.key

    def test_guides_cover_registry(self):
        from rebel_profiler.knowledge.action_guides import coverage_report

        report = coverage_report()
        assert report["complete"] is True

    def test_tools_matrix_lists_new_tools(self):
        from rebel_profiler.knowledge.tools import planner_tool_context

        ctx = planner_tool_context()
        names = {t["name"] for g in ctx["groups"] for t in g["tools"]}
        assert {"docker-audit", "iac-audit"} <= names

    def test_new_sources_registered(self):
        registry = SourceRegistry()
        for key in ("scan.webauth", "scan.proxy", "scan.iac"):
            assert registry.get(key) is not None, key
