"""Tests for the bounty-recon set: js-intel, wayback-urls, probe.

All extraction is hermetic (fixture text, no network). Adapter tests pin
argv contracts; parser tests pin claim kinds; one policy test proves the
probe action lands in the approval queue, not a plain allow.
"""

from __future__ import annotations

import pytest

from rebel_profiler.core.errors import UsageError
from rebel_profiler.execution.adapters import (
    JsIntelAdapter,
    ProbeAdapter,
    WaybackUrlsAdapter,
)
from rebel_profiler.execution.broker import ActionRequest
from rebel_profiler.intel.collection import (
    _parse_js_intel,
    _parse_probe,
    _parse_wayback,
)
from rebel_profiler.intel.jsintel import extract


def _req(action: str, target: str, capability: str = "passive_recon",
         **params) -> ActionRequest:
    return ActionRequest(case_id="case1", capability=capability,
                         action=action, target=target, params=params)


class TestJsIntelExtractor:
    def test_extracts_api_paths_and_urls(self):
        js = ('fetch("/api/users/" + id);'
              'var base = "https://api.example.test/v2";')
        report = extract(js)
        values = [e["value"] for e in report["endpoints"]]
        assert "/api/users/" in values
        assert "https://api.example.test/v2" in values

    def test_secret_kinds_are_tagged(self):
        js = ('var k = "AIza' + 'a' * 35 + '";'
              'var s = "https://myapp.firebaseio.com/";'
              'var b = "https://my-bucket.s3.us-east-1.amazonaws.com/";')
        report = extract(js)
        kinds = {s["kind"] for s in report["secrets"]}
        assert "google_api_key" in kinds
        assert "firebase_url" in kinds
        assert "aws_s3_url" in kinds

    def test_high_confidence_for_real_key_shapes(self):
        js = 'var k = "AIza' + 'a' * 35 + '";'
        report = extract(js)
        assert report["secrets"][0]["confidence"] == "high"

    def test_garbage_never_crashes_and_is_bounded(self):
        report = extract("<html>not js</html>" * 1000)
        assert report["endpoints"] == []
        report = extract("x" * 500_000)
        assert isinstance(report, dict)

    def test_findings_are_capped(self):
        js = "".join(f'"/api/route{i}/x" ' for i in range(500))
        report = extract(js)
        assert len(report["endpoints"]) <= 200


class TestAdapterArgv:
    def test_js_intel_single_curl_get(self):
        argv = JsIntelAdapter().build_argv(
            _req("js-intel", "https://app.example.test/static/app.js"))
        assert argv[0] == "curl" and "-fsS" in argv
        assert argv[-1] == "https://app.example.test/static/app.js"

    def test_js_intel_rejects_metachar_url(self):
        with pytest.raises(UsageError):
            JsIntelAdapter().build_argv(
                _req("js-intel", "https://x.test/a.js; rm -rf"))

    def test_wayback_hits_archive_not_target(self):
        argv = WaybackUrlsAdapter().build_argv(
            _req("wayback-urls", "example.test"))
        joined = " ".join(argv)
        assert "web.archive.org/cdx" in joined
        assert "example.test" in joined

    def test_wayback_limit_validated(self):
        with pytest.raises(UsageError):
            WaybackUrlsAdapter().build_argv(
                _req("wayback-urls", "example.test", limit=";id"))

    def test_probe_requires_explicit_method_and_url(self):
        argv = ProbeAdapter().build_argv(_req(
            "probe", "https://api.example.test/v1/user/1",
            capability="vuln_validation", method="GET"))
        assert "-X" in argv and "GET" in argv

    def test_probe_post_with_data_and_header(self):
        argv = ProbeAdapter().build_argv(_req(
            "probe", "https://api.example.test/v1/login",
            capability="vuln_validation", method="POST",
            data="user=a&pass=b", header="Content-Type: application/json"))
        assert "--data-raw" in argv
        assert "-H" in argv
        assert "user=a&pass=b" in argv

    def test_probe_rejects_shell_metachars_in_data(self):
        with pytest.raises(UsageError):
            ProbeAdapter().build_argv(_req(
                "probe", "https://api.example.test/x",
                capability="vuln_validation", method="POST",
                data="a=1; id"))

    def test_probe_is_vuln_validation_class(self):
        assert ProbeAdapter().capability_class == "vuln_validation"


class TestParsers:
    def test_js_intel_parser_kinds(self):
        js = ('fetch("/api/admin/dump");'
              'var b = "https://x.s3.amazonaws.com/";')
        pairs = _parse_js_intel(js)
        kinds = {k for k, _ in pairs}
        assert "js_endpoint" in kinds
        assert any(k.startswith("js_secret:") for k in kinds)

    def test_wayback_parser_keeps_subject_only(self):
        stdout = ("https://test.com/old/path\n"
                  "https://evil.test/steal\n"
                  "https://sub.test.com/deep?q=1\n")
        pairs = _parse_wayback(stdout, "test.com")
        values = [v for _, v in pairs]
        assert "https://test.com/old/path" in values
        assert "https://sub.test.com/deep?q=1" in values
        assert not any("evil.test" in v for v in values)

    def test_probe_parser_status_and_headers(self):
        raw = ("HTTP/1.1 200 OK\r\nServer: nginx\r\n"
               "Content-Type: application/json\r\n\r\n{\"ok\":true}")
        pairs = _parse_probe(raw)
        assert ("probe_status", "200") in pairs
        assert ("probe_header", "server: nginx") in pairs


class TestProbeGating:
    def test_probe_risk_is_high_and_needs_approval(self):
        from rebel_profiler.security.policy import (
            PolicyEngine,
            PolicyOutcome,
        )
        from rebel_profiler.security.risk import RiskEngine

        risk = RiskEngine().classify("vuln_validation")
        assert risk.level == "high"
        decision = PolicyEngine().evaluate(scope_status="in_scope", risk=risk)
        assert decision.outcome is PolicyOutcome.ALLOW_WITH_APPROVAL


class TestJsIntelCollection:
    def test_js_intel_emits_claims(self):
        js = 'fetch("/api/internal/flag");'
        claims = _parse_js_intel(js)
        assert ("js_endpoint", "/api/internal/flag") in claims
