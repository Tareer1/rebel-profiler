"""Tests for the hunt→triage→probe Hermes operator tools.

The workflow tools are the bridge between the autonomous hunter and the
operator-owned probe: Hermes runs the hunt, triage ranks candidates with
full provenance, and probe_suggest queues a high-risk request through the
same broker gates the CLI uses. All hermetic: fake hunt fetch, no network
(wayback skipped), real database, real scope + policy + approval queue.
"""

from __future__ import annotations

import time

import pytest

from rebel_profiler.cli.context import AppContext
from rebel_profiler.evidence.store import EvidenceStore
from rebel_profiler.intel.claims import ClaimLedger
from rebel_profiler.intel.collection import CollectionPipeline
from rebel_profiler.intel.sources import SourceRegistry
from rebel_profiler.llm.operator_tools import (
    OPERATOR_TOOLS,
    execute as ot_execute,
    operator_schemas,
)
from rebel_profiler.intel.triage import _probe_url
from rebel_profiler.storage.database import Database


PAGE = (b"<html><head>"
        b'<script src="/static/app.js"></script>'
        b"</head><body>hi</body></html>")

APPJS = (b'var k="AIzaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";'
         b'fetch("/api/cart/"+uid);'
         b'var b="https://shop-backups.s3.eu-west-1.amazonaws.com/";')


class FakeFetch:
    """JsHunter fetch double: the landing page and one in-scope script."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, url: str):
        self.calls.append(url)
        if url.endswith("/") or url.endswith("/landing"):
            return 200, {}, PAGE
        if url.endswith("app.js"):
            return 200, {}, APPJS
        return 404, {}, b""


@pytest.fixture()
def ws(tmp_path):
    """Real workspace: AppContext (refusal→durable queue) + one case + db."""
    ctx = AppContext(data_dir=tmp_path, queue_on_approval_refusal=True)
    rec = ctx.create_case("hunt case", "workflow tools")
    db = ctx.open_case(rec["id"])
    yield ctx, db, rec["id"]
    db.close()


def _hunt(ctx, db, case_id, monkeypatch):
    """Authorize the host, then run hunt_run with the fetch double."""
    fake = FakeFetch()
    monkeypatch.setattr("rebel_profiler.intel.hunt._hunt_fetch", fake)
    scope = ot_execute(ctx, db, case_id, "scope_add", {"value": "shop.test"})
    assert scope["error"] is False, scope
    hunt = ot_execute(ctx, db, case_id, "hunt_run",
                      {"url": "http://shop.test/", "no_wayback": "yes"})
    assert hunt["error"] is False, hunt
    return hunt


def _add_claim(ctx, db, case_id, *, subject, kind, value, observed_at):
    ledger = ClaimLedger(SourceRegistry())
    pipeline = CollectionPipeline(
        ledger, EvidenceStore(db, blobs_dir=ctx.case_dir(case_id) / "blobs"),
        SourceRegistry(), db=db)
    claim = ledger.add(case_id, subject=subject, kind=kind, value=value,
                       source="js.static", method="test",
                       observed_at=observed_at)
    pipeline._persist([claim], case_id)
    return claim


# ---------------------------------------------------------------- schemas


def test_workflow_tools_are_declared():
    names = {s["function"]["name"] for s in operator_schemas()}
    assert {"hunt_run", "hunt_triage", "probe_suggest",
            "probe_execute"} <= names
    hunt = next(s for s in operator_schemas()
                if s["function"]["name"] == "hunt_run")
    assert hunt["function"]["parameters"]["required"] == ["url"]


def test_hunt_run_rejects_unknown_params(ws):
    ctx, db, case_id = ws
    payload = ot_execute(ctx, db, case_id, "hunt_run",
                         {"url": "http://shop.test/", "bogus": "1"})
    assert payload["error"] is True
    assert "bogus" in payload["message"]


# ---------------------------------------------------------------- hunt_run


def test_hunt_run_mines_and_claims(ws, monkeypatch):
    ctx, db, case_id = ws
    hunt = _hunt(ctx, db, case_id, monkeypatch)

    stats = hunt["stats"]
    assert stats["scripts_mined"] == 1
    assert stats["claims_added"] >= 3          # secret + endpoint + cloud
    assert hunt["evidence_id"]
    priorities = {item["priority"] for item in hunt["top_items"]}
    assert 1 in priorities                      # the secret ranks P1

    # the claims are in the ledger, not just the payload. The fixture's
    # bucket URL classifies as a secret-shaped s3 url (jsintel rule), so
    # cloud_host is not guaranteed from this page — pin what the miner
    # actually produces.
    ledger = ClaimLedger.load_from_db(db, case_id, SourceRegistry())
    kinds = {c.kind for c in ledger.list(case_id)}
    assert any(k.startswith("js_secret:") for k in kinds)
    assert "js_endpoint" in kinds


def test_hunt_run_needs_active_case(ws, monkeypatch):
    ctx, db, case_id = ws
    monkeypatch.setattr("rebel_profiler.intel.hunt._hunt_fetch", FakeFetch())
    # scope_add activates; simulate a deactivated case
    ctx.set_case_status(case_id, "draft")
    payload = ot_execute(ctx, db, case_id, "hunt_run",
                         {"url": "http://shop.test/", "no_wayback": "yes"})
    assert payload["error"] is True
    assert "active" in payload["message"]


# ---------------------------------------------------------------- triage


def test_triage_ranks_secrets_first_with_provenance(ws, monkeypatch):
    ctx, db, case_id = ws
    _hunt(ctx, db, case_id, monkeypatch)

    payload = ot_execute(ctx, db, case_id, "hunt_triage", {})
    assert payload["error"] is False
    assert payload["count"] >= 3
    top = payload["candidates"][0]
    assert top["provenance"]["kind"].startswith("js_secret:")
    assert top["priority"] == 1
    prov = top["provenance"]
    assert prov["source"] == "js.static"        # provenance chain intact
    assert prov["method"] == "js-hunt"
    assert prov["evidence_id"]                  # links to the hunt blob


def test_triage_probe_url_for_storage_and_paths(ws, monkeypatch):
    ctx, db, case_id = ws
    _hunt(ctx, db, case_id, monkeypatch)

    payload = ot_execute(ctx, db, case_id, "hunt_triage", {})
    urls = {c["provenance"]["value"]: c["probe_url"]
            for c in payload["candidates"]}
    # scheme-less storage host gets a runnable scheme
    assert "https://shop-backups.s3.eu-west-1.amazonaws.com" in urls.values()
    # hunt's space-joined seed+path claim collapses into one runnable URL
    assert "http://shop.test/api/cart/" in urls.values()
    # secrets never get a fabricated probe URL
    secret_values = (v for k, v in urls.items() if k.startswith("AIza"))
    assert all(_probe_url(k, "shop.test") == "" for k in secret_values)


def test_triage_demotes_stale_observations(ws):
    ctx, db, case_id = ws
    now = time.time()
    _add_claim(ctx, db, case_id, subject="shop.test", kind="js_endpoint",
               value="/fresh-path", observed_at=now)
    _add_claim(ctx, db, case_id, subject="old.test", kind="js_endpoint",
               value="/stale-path", observed_at=now - 400 * 86400)

    ledger = ClaimLedger.load_from_db(db, case_id, SourceRegistry())
    from rebel_profiler.intel.triage import triage

    payload = triage(case_id, ledger)
    scores = {c["provenance"]["value"]: c["score"]
              for c in payload["candidates"]}
    assert scores["/fresh-path"] > scores["/stale-path"]


# ---------------------------------------------------------------- probe


def test_probe_suggest_queues_high_risk_request(ws, monkeypatch):
    ctx, db, case_id = ws
    _hunt(ctx, db, case_id, monkeypatch)

    payload = ot_execute(ctx, db, case_id, "probe_suggest",
                         {"url": "http://shop.test/api/cart"})
    assert payload["error"] is False
    # headless context: refusal becomes a DURABLE queue entry. The broker's
    # ExecutionResult still says "cancelled" — the tool surfaces the queue
    # truth (approval id + state) on top of it.
    assert payload["outcome"] == "cancelled"
    assert payload["queued_for_approval"] is True
    assert payload["approval_id"].startswith("apr_")
    assert payload["approval_state"] == "pending"

    from rebel_profiler.security.approvals import ApprovalQueue

    pending = ApprovalQueue(db).list(case_id)
    assert len(pending) == 1
    assert pending[0]["action"] == "probe"


def test_probe_suggest_rejects_non_url(ws):
    ctx, db, case_id = ws
    payload = ot_execute(ctx, db, case_id, "probe_suggest",
                         {"url": "/api/cart"})
    assert payload["error"] is True
    assert "http" in payload["message"]


def test_probe_execute_unknown_id_is_safe(ws):
    ctx, db, case_id = ws
    payload = ot_execute(ctx, db, case_id, "probe_execute",
                         {"approval_id": "ap_nonexistent"})
    assert payload["error"] is False
    assert payload["found"] is False
