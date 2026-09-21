"""Hermetic tests for the autonomous JS hunter (intel hunt).

Fake fetch + fake scope engine: no network, no real targets. Pins the
three contracts that matter: scope enforcement on every script URL,
correct priority ranking, and evidence registration.
"""

from __future__ import annotations

import json

import pytest

from rebel_profiler.core.errors import ScopeViolationError
from rebel_profiler.evidence.store import EvidenceStore
from rebel_profiler.intel.hunt import JsHunter, _suggestion
from rebel_profiler.storage.database import Database


PAGE = b"""<html><head>
<script src="/static/app.js"></script>
<script src="https://cdn.outside.test/lib.js"></script>
<script>var inline = "https://inline.test/x";</script>
</head><body>hi</body></html>"""

APPJS = (b'var base="https://api.shop.test/v2";'
         b'fetch("/api/cart/"+uid);'
         b'var fb="https://shopapp.firebaseio.com/";'
         b'var k="AIzaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";'
         b'var bucket="https://shop-backups.s3.eu-west-1.amazonaws.com/";'
         b'var ns="http://www.w3.org/2000/svg";')


class Allow:
    def evaluate(self, case_id: str, target: str) -> str:
        return "in_scope"


class DenyOutside:
    """Everything in scope except the outside CDN."""

    def evaluate(self, case_id: str, target: str) -> str:
        return "in_scope" if target.endswith("shop.test") else "unknown"


@pytest.fixture()
def env(tmp_path):
    db = Database(tmp_path / "case.db")
    db.migrate()
    db.create_case("c1", "t", case_id="c1")
    evidence = EvidenceStore(db, blobs_dir=tmp_path / "blobs")
    return db, evidence


def _fake_fetch(calls: list):
    def fetch(url: str):
        calls.append(url)
        if url.endswith("/"):
            return 200, {}, PAGE
        if url.endswith("app.js"):
            return 200, {}, APPJS
        return 404, {}, b""
    return fetch


class TestScopeEnforcement:
    def test_out_of_scope_script_is_never_fetched(self, env):
        _, evidence = env
        calls: list[str] = []
        hunter = JsHunter("c1", scope_engine=DenyOutside(), evidence=evidence,
                          fetch=_fake_fetch(calls))
        report = hunter.hunt("http://shop.test/", include_wayback=False)
        assert "https://cdn.outside.test/lib.js" not in calls
        assert any(s["src"] == "https://cdn.outside.test/lib.js"
                   and s["reason"] == "out_of_scope"
                   for s in report["skipped"])

    def test_out_of_scope_seed_is_refused(self, env):
        _, evidence = env

        class Deny:
            def evaluate(self, case_id, target):
                return "unknown"

        hunter = JsHunter("c1", scope_engine=Deny(), evidence=evidence,
                          fetch=lambda u: (200, {}, b""))
        with pytest.raises(ScopeViolationError):
            hunter.hunt("http://shop.test/", include_wayback=False)


class TestRanking:
    def test_secrets_rank_p1_above_endpoints(self, env):
        _, evidence = env
        hunter = JsHunter("c1", scope_engine=Allow(), evidence=evidence,
                          fetch=_fake_fetch([]))
        report = hunter.hunt("http://shop.test/", include_wayback=False)
        items = report["items"]
        assert items, "expected findings"
        assert items[0]["priority"] == 1
        assert items[0]["category"] == "secret"
        assert report["stats"]["p1"] >= 3

    def test_namespace_noise_demoted_behind_findings(self, env):
        _, evidence = env
        hunter = JsHunter("c1", scope_engine=Allow(), evidence=evidence,
                          fetch=_fake_fetch([]))
        report = hunter.hunt("http://shop.test/", include_wayback=False)
        w3 = [i for i in report["items"] if "w3.org" in i["value"]]
        real = [i for i in report["items"]
                if i["category"] in {"secret", "endpoint", "cloud"}]
        assert w3 and real
        assert all(w["priority"] >= 3 for w in w3)
        assert report["items"].index(real[0]) < report["items"].index(w3[0])

    def test_inline_script_is_mined_without_fetch(self, env):
        _, evidence = env
        calls: list[str] = []
        hunter = JsHunter("c1", scope_engine=Allow(), evidence=evidence,
                          fetch=_fake_fetch(calls))
        report = hunter.hunt("http://shop.test/", include_wayback=False)
        origins = [i["origin"] for i in report["items"]]
        assert any("#inline[0]" in o for o in origins)
        assert sum(1 for c in calls if c.endswith("app.js")) == 1


class TestEvidenceAndSuggestions:
    def test_evidence_registered_and_blob_matches(self, env):
        _, evidence = env
        hunter = JsHunter("c1", scope_engine=Allow(), evidence=evidence,
                          fetch=_fake_fetch([]))
        report = hunter.hunt("http://shop.test/", include_wayback=False)
        assert report["evidence_id"]
        rec = evidence.get("c1", report["evidence_id"])
        blob = json.loads(evidence.read_bytes(rec).decode("utf-8"))
        assert blob["seed"] == "http://shop.test/"
        assert len(blob["items"]) == len(report["items"])

    def test_every_item_carries_an_actionable_suggestion(self, env):
        _, evidence = env
        hunter = JsHunter("c1", scope_engine=Allow(), evidence=evidence,
                          fetch=_fake_fetch([]))
        report = hunter.hunt("http://shop.test/", include_wayback=False)
        for item in report["items"]:
            assert item["suggestion"].strip()

    def test_secret_suggestion_says_revoke_not_exploit(self):
        text = _suggestion("secret", "google_api_key", "AIza…")
        assert "revoke" in text

    def test_binary_script_body_is_skipped_not_fatal(self, env):
        _, evidence = env

        def fetch(url: str):
            if url.endswith("font.js"):
                return 200, {}, b"\x00\x01\x02binary\xff\xfe"
            return 200, {}, PAGE.replace(b"/static/app.js", b"/static/font.js")

        hunter = JsHunter("c1", scope_engine=Allow(), evidence=evidence,
                          fetch=fetch)
        report = hunter.hunt("http://shop.test/", include_wayback=False)
        reasons = {s.get("reason", "") for s in report["skipped"]}
        assert "binary body" in reasons, report["skipped"]
