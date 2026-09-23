"""Tests for the approval operator tools: approval_list + approval_decide.

The loop these close: probe_suggest queues a high-risk action → hermes lists
the queue → the OPERATOR decides in chat → the approved action executes
through the broker and lands in the evidence ledger. The model can carry the
conversation to the endpoint, but it can never manufacture the decision.

The probe target resolves to a loopback port a stub HTTP server owns, so the
"execute" path runs the real curl through the real broker offline.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from rebel_profiler.llm import operator_tools as ot
from rebel_profiler.security.approvals import ApprovalQueue


@pytest.fixture(scope="module")
def loop_http():
    """A tiny loopback HTTP server for live-probe executions."""

    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):  # quiet
            return

    server = HTTPServer(("127.0.0.1", 0), H)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/api/ping"
    server.shutdown()
    thread.join(timeout=5)


@pytest.fixture()
def ws(tmp_path):
    from rebel_profiler.cli.context import AppContext

    # queue_on_approval_refusal=True mirrors the real CLI entrypoint: a
    # headless approval-gated action lands in the durable queue instead of
    # being silently cancelled.
    ctx = AppContext(data_dir=tmp_path, queue_on_approval_refusal=True)
    rec = ctx.create_case("approval ops", "from tests")
    db = ctx.open_case(rec["id"])
    return ctx, db, rec


def _call(ctx, db, case_id, name, args):
    return ot.execute(ctx, db, case_id, name, args)


class TestApprovalList:
    def test_empty_queue_is_a_clean_empty_list(self, ws):
        ctx, db, rec = ws
        out = _call(ctx, db, rec["id"], "approval_list", {})
        assert out["error"] is False
        assert out["count"] == 0
        assert out["approvals"] == []
        assert "operator" in out["next"].lower()

    def test_lists_pending_probe(self, ws, loop_http):
        ctx, db, rec = ws
        _call(ctx, db, rec["id"], "scope_add", {"value": "127.0.0.1"})
        # a probe_suggest through the broker queues a durable approval
        queued = _call(ctx, db, rec["id"], "probe_suggest", {"url": loop_http})
        assert queued.get("queued_for_approval") is True
        out = _call(ctx, db, rec["id"], "approval_list", {})
        assert out["count"] == 1
        row = out["approvals"][0]
        assert row["action"] == "probe"
        assert row["state"] == "pending"
        assert row["id"] == queued["approval_id"]


class TestApprovalDecide:
    def test_model_cannot_invent_a_decision(self, ws):
        ctx, db, rec = ws
        out = _call(ctx, db, rec["id"], "approval_decide",
                    {"approval_id": "apr_x", "decision": "sure-whatever"})
        assert out["error"] is True
        assert "approve or deny" in out["fix"]

    def test_unknown_id_is_structured(self, ws):
        ctx, db, rec = ws
        out = _call(ctx, db, rec["id"], "approval_decide",
                    {"approval_id": "apr_nope", "decision": "approve"})
        assert out["error"] is True
        assert "approval_list" in out["fix"]

    def test_deny_closes_the_loop_without_execution(self, ws, loop_http):
        ctx, db, rec = ws
        _call(ctx, db, rec["id"], "scope_add", {"value": "127.0.0.1"})
        queued = _call(ctx, db, rec["id"], "probe_suggest", {"url": loop_http})
        aid = queued["approval_id"]
        out = _call(ctx, db, rec["id"], "approval_decide",
                    {"approval_id": aid, "decision": "deny"})
        assert out["state"] == "denied"
        assert "execution" not in out
        # the queue no longer shows it as pending
        pending = ApprovalQueue(db).list(rec["id"], "pending")
        assert pending == []

    def test_approve_runs_to_the_evidence_endpoint(self, ws, loop_http):
        ctx, db, rec = ws
        _call(ctx, db, rec["id"], "scope_add", {"value": "127.0.0.1"})
        queued = _call(ctx, db, rec["id"], "probe_suggest", {"url": loop_http})
        aid = queued["approval_id"]
        out = _call(ctx, db, rec["id"], "approval_decide",
                    {"approval_id": aid, "decision": "approve"})
        assert out["state"] == "approved"
        execution = out["execution"]
        assert execution.get("outcome") == "succeeded"
        claims = [dict(r) for r in db.claims_for(rec["id"], None)]
        # the endpoint: probe status reached the claim ledger with evidence
        assert any(c["kind"] == "probe_status" for c in claims)
        assert all(c.get("evidence_id") for c in claims)
