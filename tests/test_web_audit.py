"""Tests for the scope-enforced web auditor (Phase 3, PDF 7)."""

from __future__ import annotations

import json

import pytest

from rebel_profiler.cli.main import main
from rebel_profiler.core.errors import ScopeViolationError, UsageError
from rebel_profiler.evidence.store import EvidenceStore
from rebel_profiler.intel.claims import ClaimLedger
from rebel_profiler.intel.sources import SourceRegistry
from rebel_profiler.intel.web import ScopeEnforcedWebAuditor
from rebel_profiler.security.scope import Scope, ScopeEngine, ScopeStatus
from rebel_profiler.storage.database import Database


HTML_PAGE = b"""<html><body>
<a href="/about">about</a>
<a href="https://other.example.test/x">external</a>
<a href="ftp://files.lab.example.test/f">ftp</a>
<form action="/login" method="post"><input type="password" name="pw"></form>
</body></html>"""

SECURE_HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=63072000",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}

WEAK_HEADERS = {
    "Content-Type": "text/html",
    "Set-Cookie": "sid=abc123; Path=/",
    "Location": "http://insecure.lab.example.test/login",
}


def make_auditor(tmp_path, *, fetch=None, tls_probe=None, scope_hosts=("*.lab.example.test",), **kwargs):
    db = Database(tmp_path / "c.db")
    db.migrate()
    db.create_case("web", case_id="c1")
    store = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
    scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
    for pattern in scope_hosts:
        scope.add(pattern)
    engine = ScopeEngine()
    engine.register(scope)
    auditor = ScopeEnforcedWebAuditor(
        "c1", scope_engine=engine,
        ledger=ClaimLedger(SourceRegistry()), evidence=store,
        fetch=fetch, tls_probe=tls_probe, db=db, **kwargs,
    )
    return db, store, auditor


def fetch_ok(url, *_args, **_kwargs):
    return 200, dict(SECURE_HEADERS), HTML_PAGE


def fetch_weak(url, *_args, **_kwargs):
    return 200, dict(WEAK_HEADERS), HTML_PAGE


def tls_ok(host, port):
    return {"protocol": "TLSv1.3"}


def tls_legacy(host, port):
    return {"protocol": "TLSv1.0"}


class TestScopeEnforcement:
    def test_out_of_scope_seed_blocked(self, tmp_path):
        _, _, auditor = make_auditor(tmp_path, fetch=fetch_ok)
        with pytest.raises(ScopeViolationError):
            auditor.crawl(["https://evil.test/"])

    def test_out_of_scope_links_skipped_silently(self, tmp_path):
        fetched = []

        def recording_fetch(url, *a, **k):
            fetched.append(url)
            return fetch_ok(url)

        _, _, auditor = make_auditor(
            tmp_path, fetch=recording_fetch, max_pages=1,
        )
        report = auditor.crawl(["https://h1.lab.example.test/"])
        assert report["stats"]["pages_audited"] == 1
        assert fetched == ["https://h1.lab.example.test/"]  # external link never fetched
        # the /about link stays in-scope, ftp scheme filtered
        assert all("ftp" not in u for u in fetched)

    def test_non_http_scheme_rejected(self, tmp_path):
        _, _, auditor = make_auditor(tmp_path, fetch=fetch_ok)
        with pytest.raises(ScopeViolationError):
            auditor.crawl(["file:///etc/passwd"])

    def test_wildcard_scope_allows_subdomain(self, tmp_path):
        _, _, auditor = make_auditor(tmp_path, fetch=fetch_ok, max_pages=1)
        report = auditor.crawl(["https://h1.lab.example.test/"])
        assert report["stats"]["pages_audited"] == 1


class TestHeaderChecks:
    def test_secure_headers_pass(self, tmp_path):
        _, _, auditor = make_auditor(tmp_path, fetch=fetch_ok)
        report = auditor.crawl(["https://h1.lab.example.test/"])
        checks = report["pages"][0]["checks"]
        header_checks = [c for c in checks if c["check"].startswith("header:")]
        assert all(c["status"] == "pass" for c in header_checks)
        assert report["stats"]["findings"] == 0

    def test_missing_headers_are_findings(self, tmp_path):
        _, _, auditor = make_auditor(
            tmp_path,
            fetch=lambda url: (200, {"Content-Type": "text/html"}, b"<html></html>"),
        )
        report = auditor.crawl(["https://h1.lab.example.test/"])
        checks = report["pages"][0]["checks"]
        missing = [c for c in checks if c["status"] == "finding"]
        assert {c["check"] for c in missing} >= {
            "header:CSP", "header:HSTS", "header:X-Frame-Options",
        }

    def test_cleartext_redirect_flagged(self, tmp_path):
        _, _, auditor = make_auditor(tmp_path, fetch=fetch_weak)
        report = auditor.crawl(["https://h1.lab.example.test/"])
        checks = report["pages"][0]["checks"]
        assert any(c["check"] == "redirect_cleartext" and c["status"] == "finding"
                   for c in checks)


class TestCookieChecks:
    def test_missing_cookie_flags(self, tmp_path):
        _, _, auditor = make_auditor(tmp_path, fetch=fetch_weak)
        report = auditor.crawl(["https://h1.lab.example.test/"])
        checks = report["pages"][0]["checks"]
        cookie_findings = {c["check"] for c in checks
                           if c["check"].startswith("cookie:") and c["status"] == "finding"}
        assert cookie_findings == {"cookie:Secure", "cookie:HttpOnly", "cookie:SameSite"}

    def test_flagged_cookie_passes(self, tmp_path):
        headers = dict(SECURE_HEADERS)
        headers["Set-Cookie"] = "sid=abc; Secure; HttpOnly; SameSite=Strict"
        _, _, auditor = make_auditor(
            tmp_path, fetch=lambda url: (200, headers, b"<html></html>"))
        report = auditor.crawl(["https://h1.lab.example.test/"])
        cookie_findings = [c for c in report["pages"][0]["checks"]
                           if c["check"].startswith("cookie:")]
        assert cookie_findings == []


class TestFormChecks:
    def test_http_password_form_flagged(self, tmp_path):
        _, _, auditor = make_auditor(
            tmp_path,
            fetch=lambda url: (
                200, {"Content-Type": "text/html"},
                b'<form action="/login" method="post">'
                b'<input type="password" name="pw"></form>',
            ),
        )
        report = auditor.crawl(["http://h1.lab.example.test/"])
        checks = report["pages"][0]["checks"]
        assert any(c["check"] == "cleartext_password_form" for c in checks)

    def test_https_password_form_not_flagged(self, tmp_path):
        _, _, auditor = make_auditor(
            tmp_path,
            fetch=lambda url: (
                200, {"Content-Type": "text/html"},
                b'<form action="/login" method="post">'
                b'<input type="password" name="pw"></form>',
            ),
        )
        report = auditor.crawl(["https://h1.lab.example.test/"])
        checks = report["pages"][0]["checks"]
        assert not any(c["check"] == "cleartext_password_form" for c in checks)


class TestTlsChecks:
    def test_modern_tls_passes(self, tmp_path):
        _, _, auditor = make_auditor(
            tmp_path, fetch=fetch_ok, tls_probe=tls_ok)
        report = auditor.crawl(["https://h1.lab.example.test/"])
        tls_checks = [c for c in report["pages"][0]["checks"]
                      if c["check"] == "tls:protocol"]
        assert tls_checks and tls_checks[0]["status"] == "pass"

    def test_legacy_tls_is_finding(self, tmp_path):
        _, _, auditor = make_auditor(
            tmp_path, fetch=fetch_ok, tls_probe=tls_legacy)
        report = auditor.crawl(["https://h1.lab.example.test/"])
        tls_checks = [c for c in report["pages"][0]["checks"]
                      if c["check"] == "tls:protocol"]
        assert tls_checks[0]["status"] == "finding"
        assert "TLSv1.0" in tls_checks[0]["detail"]

    def test_tls_error_surfaced(self, tmp_path):
        def failing_probe(host, port):
            raise UsageError(f"probe failed for {host}")

        _, _, auditor = make_auditor(
            tmp_path, fetch=fetch_ok, tls_probe=failing_probe)
        report = auditor.crawl(["https://h1.lab.example.test/"])
        tls_checks = [c for c in report["pages"][0]["checks"]
                      if c["check"] == "tls:protocol"]
        assert tls_checks[0]["status"] == "error"


class TestCrawlBoundsAndEvidence:
    def test_max_pages_bound(self, tmp_path):
        def many_links(url, *a, **k):
            body = b"".join(
                b'<a href="/p%d">x</a>' % i for i in range(10)
            )
            return 200, dict(SECURE_HEADERS), body

        _, _, auditor = make_auditor(
            tmp_path, fetch=many_links, max_pages=3)
        report = auditor.crawl(["https://h1.lab.example.test/"])
        assert report["stats"]["pages_audited"] == 3

    def test_fetch_error_recorded_not_fatal(self, tmp_path):
        def failing(url, *a, **k):
            raise UsageError(f"cannot fetch {url}")

        _, _, auditor = make_auditor(
            tmp_path, fetch=failing)
        report = auditor.crawl(["https://h1.lab.example.test/"])
        assert report["pages"][0]["kind"] == "error"
        assert report["stats"]["pages_audited"] == 0

    def test_non_html_skipped(self, tmp_path):
        _, _, auditor = make_auditor(
            tmp_path,
            fetch=lambda url: (200, {"Content-Type": "application/json"}, b"{}"),
        )
        report = auditor.crawl(["https://h1.lab.example.test/api"])
        assert report["pages"][0]["kind"] == "non_html"

    def test_pages_become_evidence(self, tmp_path):
        db, store, auditor = make_auditor(tmp_path, fetch=fetch_ok)
        auditor.crawl(["https://h1.lab.example.test/"])
        records = store.list_records("c1")
        assert records and records[0].kind == "web_page"
        assert store.verify_case("c1")["chain_ok"]


class TestWebClaimsAndCLI:
    def test_findings_emit_claims(self, tmp_path):
        db, store, auditor = make_auditor(tmp_path, fetch=fetch_weak)
        report = auditor.crawl(["https://h1.lab.example.test/"])
        assert report["stats"]["findings"] > 0
        rows = db.claims_for("c1", "h1.lab.example.test")
        assert rows
        assert rows[0]["kind"] == "web_finding"

    def test_cli_crawl_runs(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_dir = str(tmp_path / "data")
        assert main(["--data-dir", data_dir, "case", "create", "WebCase"]) == 0
        capsys.readouterr()
        main(["--data-dir", data_dir, "case", "list", "-o", "json"])
        case_id = json.loads(capsys.readouterr().out)["data"][0]["id"]
        main(["--data-dir", data_dir, "case", "scope", "add", case_id, "*.lab.example.test"])
        capsys.readouterr()
        main(["--data-dir", data_dir, "case", "activate", case_id])
        capsys.readouterr()

        # inject a stub fetch into the CLI path
        from rebel_profiler.intel import web as web_module

        original = web_module._default_fetch
        monkeypatch.setattr(
            web_module, "_default_fetch",
            lambda url: (200, dict(SECURE_HEADERS), b"<html><a href='/b'>b</a></html>"),
        )
        rc = main(["--data-dir", data_dir, "intel", "crawl", case_id,
                   "https://h1.lab.example.test/", "--max-pages", "2"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "header" in out
