"""Dork-search end-to-end: adapter argv → broker → claims (tests use fakes)."""

from __future__ import annotations

import json

import pytest

from rebel_profiler.core.errors import DependencyUnavailableError, UsageError
from rebel_profiler.intel.dorks import (
    DORK_TEMPLATES,
    build_dork_argv,
    parse_dork_stdout,
)


@pytest.fixture()
def env(tmp_path):
    from rebel_profiler.evidence.store import EvidenceStore
    from rebel_profiler.intel.claims import ClaimLedger
    from rebel_profiler.intel.sources import SourceRegistry
    from rebel_profiler.storage.database import Database

    db = Database(tmp_path / "case.db")
    db.migrate()
    db.create_case("c1", "test case", case_id="c1")
    store = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
    ledger = ClaimLedger(SourceRegistry())
    return db, store, ledger


class TestDorkArgv:
    def test_named_template_builds_curl_argv(self):
        argv = build_dork_argv(engine="duckduckgo", dork="open-directories",
                               target="example.test")
        assert argv[0] == "curl"
        assert "--max-time" in argv
        assert any("api.duckduckgo.com" in a for a in argv)
        assert any("index.of" in a for a in argv)          # dork operators present
        assert any("site%3Aexample.test" in a for a in argv)

    def test_google_engine_builds_search_url(self):
        argv = build_dork_argv(engine="google", dork="site-files",
                               target="example.test")
        assert argv[0] == "curl" and "torsocks" not in argv
        assert any("google.com/search" in a for a in argv)

    def test_ahmia_routes_through_torsocks(self):
        argv = build_dork_argv(engine="ahmia", dork="open-directories",
                               target="example", tld="onion")
        assert argv[0] == "torsocks" and argv[1] == "curl"
        assert any("ahmia.fi" in a for a in argv)

    def test_unknown_engine_and_dork_rejected(self):
        with pytest.raises(UsageError):
            build_dork_argv(engine="bing", dork="site-files", target="e.test")
        with pytest.raises(UsageError):
            build_dork_argv(engine="google", dork="free-form DROP TABLE",
                            target="e.test")

    def test_target_validation(self):
        with pytest.raises(UsageError):
            build_dork_argv(engine="google", dork="site-files",
                            target="not a domain; rm -rf")
        with pytest.raises(UsageError):
            build_dork_argv(engine="google", dork="site-files",
                            target="e.test", tld="onion; id")

    def test_every_template_has_claim_kind(self):
        for template in DORK_TEMPLATES.values():
            assert template.kind and template.description
            assert "{}" in template.query


class TestDorkParsing:
    def test_google_href_decoding(self):
        page = ('<a href="/url?q=https%3A%2F%2Fexample.test%2Fx&amp;sa=U">'
                't</a><a href="/url?q=https%3A%2F%2Fexample.test%2Fx&amp;ved=b">'
                'dup</a>')
        hits = parse_dork_stdout("google", page)
        assert [h["url"] for h in hits] == ["https://example.test/x"]

    def test_ddg_json(self):
        page = json.dumps({"RelatedTopics": [
            {"FirstURL": "https://a.test/1", "Text": "one"},
            {"Topics": [{"FirstURL": "https://a.test/2", "Text": "two"}]},
        ], "AbstractURL": "https://a.test/abs", "Heading": "abs"})
        hits = parse_dork_stdout("duckduckgo", page)
        assert [h["url"] for h in hits] == [
            "https://a.test/1", "https://a.test/2", "https://a.test/abs"]

    def test_ahmia_onion_hits(self):
        page = ('<a href="/about/">about</a>'
                '<a href="http://abcxyz.onion/">hidden service</a>')
        hits = parse_dork_stdout("ahmia", page)
        assert [h["url"] for h in hits] == ["http://abcxyz.onion/"]
        assert hits[0]["title"] == "hidden service"

    def test_engine_garbage_never_crashes(self):
        for engine in ("google", "duckduckgo", "ahmia"):
            assert parse_dork_stdout(engine, "<html>consent</html>") == []
            assert parse_dork_stdout(engine, "") == []
            assert parse_dork_stdout(engine, "not html at all 502 error") == []


class TestDorkCollection:
    def test_dork_search_emits_claims(self, env, tmp_path):
        """Full pipeline with a faked runner: broker gates → evidence → claims."""
        db, store, ledger = env
        from rebel_profiler.execution import AdapterRegistry
        from rebel_profiler.execution.broker import (
            ActionRequest,
            ExecutionBroker,
        )
        from rebel_profiler.intel.collection import CollectionPipeline
        from rebel_profiler.intel.sources import SourceRegistry
        from rebel_profiler.security.scope import Scope, ScopeEngine, ScopeStatus

        scope = Scope(case_id="c1", status=ScopeStatus.ACTIVE)
        scope.add("*.example.test")
        engine = ScopeEngine()
        engine.register(scope)
        registry = AdapterRegistry()

        fake_page = ('<a href="/url?q=https%3A%2F%2Ffiles.example.test%2F'
                     'secret.pdf&amp;sa=U">pdf</a>')
        broker = ExecutionBroker(
            db, scope_engine=engine, evidence=store, adapters=registry,
            runner=lambda argv: (0, fake_page, ""))

        request = ActionRequest(
            case_id="c1", capability="passive_recon", action="dork-search",
            target="files.example.test",
            params={"engine": "google", "dork": "site-files"})
        result = broker.execute(request)
        assert result.outcome == "succeeded"

        pipeline = CollectionPipeline(ledger, store, SourceRegistry(), db=db)
        report = pipeline.ingest("c1", action=result.action,
                                 target=result.target, stdout=result.stdout,
                                 stderr=result.stderr,
                                 returncode=result.returncode or 0,
                                 task_id=result.task_id,
                                 evidence_id=result.evidence_id,
                                 params={"engine": "google",
                                         "dork": "site-files"})
        kinds = {(c["kind"], c["value"]) for c in report["claims"]}
        assert any(k == "search_hit" and "files.example.test/secret.pdf" in v
                   for k, v in kinds)
        assert any(k == "hostname" and v == "files.example.test"
                   for k, v in kinds)
