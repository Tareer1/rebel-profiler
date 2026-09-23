"""Tests for the rp-mcp server: the operator surface as MCP stdio JSON-RPC.

The real hermes-agent consumes this server (``mcp_servers:`` entry), so the
contract under test is the MCP wire protocol: initialize handshake,
tools/list over the operator registry, tools/call with the same validation
as every other caller, and one-case pinning.
"""

from __future__ import annotations

import json

import pytest

from rebel_profiler.llm.hermes_mcp import McpServer, _schemas


def _feed(server: McpServer, *messages: dict) -> list[dict]:
    lines = [json.dumps(m) for m in messages]
    out: list[dict] = []
    original = server._out
    server._out = _Collector(out)
    server.serve(lines)
    server._out = original
    return out


class _Collector:
    def __init__(self, sink: list) -> None:
        self._sink = sink

    def write(self, text: str) -> int:
        for line in text.strip().splitlines():
            self._sink.append(json.loads(line))
        return len(text)

    def flush(self) -> None:
        return None


@pytest.fixture()
def ws(tmp_path):
    from rebel_profiler.cli.context import AppContext

    ctx = AppContext(data_dir=tmp_path, queue_on_approval_refusal=True)
    rec = ctx.create_case("mcp case", "from tests")
    return ctx, rec


def _server_for(ws, monkeypatch) -> McpServer:
    ctx, rec = ws
    server = McpServer(rec["id"], data_dir=ctx.data_dir)
    original = server._workspace

    def workspace():
        # reuse the fixture's ctx so the test shares its temp workspace
        if server._db is None:
            server._db = ctx.open_case(rec["id"])
        return ctx, server._db

    server._workspace = workspace
    return server


class TestProtocol:
    def test_initialize_handshake(self, ws, monkeypatch):
        server = _server_for(ws, monkeypatch)
        out = _feed(server, {"jsonrpc": "2.0", "id": 1,
                             "method": "initialize", "params": {}})
        assert out[0]["result"]["serverInfo"]["name"] == "rebel-profiler"
        assert "protocolVersion" in out[0]["result"]

    def test_unknown_method_is_protocol_error(self, ws, monkeypatch):
        server = _server_for(ws, monkeypatch)
        out = _feed(server, {"jsonrpc": "2.0", "id": 2,
                             "method": "resources/list", "params": {}})
        assert out[0]["error"]["code"] == -32601

    def test_malformed_json_gets_parse_error(self, ws, monkeypatch):
        server = _server_for(ws, monkeypatch)
        out = _feed(server, {"jsonrpc": "2.0", "id": 3,
                             "method": "ping", "params": {}})
        server._out = server._out  # noop; feed handles dicts only
        # raw malformed line through serve() directly
        import io

        buf = io.StringIO()
        server._out = buf
        server.serve(["{not json"])
        rows = [json.loads(l) for l in buf.getvalue().splitlines()]
        assert rows[0]["error"]["code"] == -32700


class TestTools:
    def test_schemas_come_from_the_operator_registry(self):
        tools = _schemas()
        names = {t["name"] for t in tools}
        assert "rp_system_status" in names
        assert "rp_approval_list" in names
        assert "rp_approval_decide" in names
        assert "rp_probe_suggest" in names
        # required params survive the translation
        decide = next(t for t in tools if t["name"] == "rp_approval_decide")
        assert set(decide["inputSchema"]["required"]) == {"approval_id", "decision"}

    def test_tools_list_over_the_wire(self, ws, monkeypatch):
        server = _server_for(ws, monkeypatch)
        out = _feed(server, {"jsonrpc": "2.0", "id": 4,
                             "method": "tools/list", "params": {}})
        names = [t["name"] for t in out[0]["result"]["tools"]]
        assert "rp_claims_list" in names

    def test_call_executes_the_real_tool(self, ws, monkeypatch):
        ctx, rec = ws
        server = _server_for(ws, monkeypatch)
        out = _feed(server, {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                             "params": {"name": "rp_system_status",
                                        "arguments": {}}})
        row = out[0]["result"]
        assert row["isError"] is False
        payload = json.loads(row["content"][0]["text"])
        assert payload["case"]["id"] == rec["id"]

    def test_call_rejects_non_rp_tools(self, ws, monkeypatch):
        server = _server_for(ws, monkeypatch)
        out = _feed(server, {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                             "params": {"name": "terminal_exec",
                                        "arguments": {"cmd": "rm -rf /"}}})
        assert out[0]["error"]["code"] == -32602

    def test_approval_flow_over_mcp(self, ws, monkeypatch):
        ctx, rec = ws
        server = _server_for(ws, monkeypatch)
        out = _feed(server,
                    {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                     "params": {"name": "rp_scope_add",
                                "arguments": {"value": "127.0.0.1"}}},
                    {"jsonrpc": "2.0", "id": 8, "method": "tools/call",
                     "params": {"name": "rp_probe_suggest",
                                "arguments": {"url": "http://127.0.0.1:9/x"}}},
                    {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                     "params": {"name": "rp_approval_list",
                                "arguments": {}}})
        json.loads(out[0]["result"]["content"][0]["text"])   # scope_add ok
        queued = json.loads(out[1]["result"]["content"][0]["text"])
        assert queued.get("queued_for_approval") is True
        listing = json.loads(out[2]["result"]["content"][0]["text"])
        assert listing["count"] == 1
        assert listing["approvals"][0]["action"] == "probe"
