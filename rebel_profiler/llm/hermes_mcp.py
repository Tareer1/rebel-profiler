"""rp-mcp — Rebel Profiler's operator surface as an MCP stdio server.

The real hermes-agent (Nous Research) keeps its own persona and tools, so
prompting it to "be our planning module" fights its training. The supported
direction is the opposite one: hermes-agent connects to Rebel Profiler as an
MCP client, and the operator tools become tools on ITS side — the model calls
``rp_*`` tools natively, and every call still lands in
:func:`rebel_profiler.llm.operator_tools.execute` (the same validation, the
same broker gates, the same evidence law).

Wiring (once, in ~/.hermes/config.yaml):

    mcp_servers:
      rebel-profiler:
        command: /path/to/rp-mcp
        args: ["--case", "<case-id>"]

Transport: stdio only, JSON-RPC 2.0, one request per line. Methods:
``initialize``, ``tools/list``, ``tools/call`` (plus ``ping``). Scope is
pinned at startup: the server talks to exactly ONE case, so a confused
client cannot wander across the workspace.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "rebel-profiler", "version": "1.7.0"}

# The tool surface hermes-agent gets. Deliberately the operator plane —
# claims/approvals/probe/browser/reports — not a shell, not raw adapters.
_MCP_TOOLS = (
    "case_status", "system_status", "claims_list", "case_search",
    "report_generate", "surface_map", "surface_build", "fusion_report",
    "evidence_verify", "audit_verify", "knowledge_search", "glossary",
    "hunt_run", "hunt_triage", "probe_suggest", "approval_list",
    "approval_decide", "browser_grab", "scope_show", "scope_add",
    "collect", "cwe_lookup", "cwe_search", "cwe_blind_spots",
    "anomalies",
)


def _schemas():
    from .operator_tools import OPERATOR_TOOLS

    tools = []
    for name in _MCP_TOOLS:
        spec = OPERATOR_TOOLS.get(name)
        if spec is None:
            continue
        properties = {
            key: {"type": "string", "description": desc}
            for key, desc in spec.parameters.items()
        }
        tools.append({
            "name": f"rp_{name}",
            "description": spec.description,
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": list(spec.required),
            },
        })
    return tools


class McpServer:
    """One case, one workspace, stdio JSON-RPC."""

    def __init__(self, case_id: str, *, data_dir: Path | None = None,
                 out=None) -> None:
        self.case_id = case_id
        self._data_dir = data_dir
        self._out = out or sys.stdout
        self._ctx = None
        self._db = None

    # -- workspace lazily opened so `tools/list` works without a live case ---
    def _workspace(self):
        if self._ctx is None:
            from ..cli.context import AppContext

            # queue_on_approval_refusal mirrors the real CLI entrypoint: a
            # headless approval-gated action (probe) must land in the durable
            # queue, not vanish as a bare "cancelled" result.
            self._ctx = AppContext(
                queue_on_approval_refusal=True,
                **({"data_dir": self._data_dir} if self._data_dir else {}))
        case = self._ctx.find_case(self.case_id)   # raises UsageError on unknown
        if self._db is None:
            self._db = self._ctx.open_case(case["id"])
        return self._ctx, self._db

    # -- framing ---------------------------------------------------------------
    def _send(self, payload: dict) -> None:
        self._out.write(json.dumps(payload, sort_keys=True) + "\n")
        self._out.flush()

    def _result(self, req_id, result: dict) -> None:
        self._send({"jsonrpc": "2.0", "id": req_id, "result": result})

    def _error(self, req_id, code: int, message: str) -> None:
        self._send({"jsonrpc": "2.0", "id": req_id,
                    "error": {"code": code, "message": message}})

    # -- handlers ------------------------------------------------------------
    def _handle(self, msg: dict) -> None:
        method = str(msg.get("method", ""))
        req_id = msg.get("id")
        params = msg.get("params") or {}
        if method == "initialize":
            self._result(req_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            })
        elif method == "notifications/initialized":
            pass   # notification: no response
        elif method == "ping":
            self._result(req_id, {})
        elif method == "tools/list":
            self._result(req_id, {"tools": _schemas()})
        elif method == "tools/call":
            self._tools_call(req_id, params)
        else:
            self._error(req_id, -32601, f"method not found: {method}")

    def _tools_call(self, req_id, params: dict) -> None:
        name = str(params.get("name", ""))
        arguments = params.get("arguments") or {}
        if not name.startswith("rp_"):
            self._error(req_id, -32602,
                        f"unknown tool '{name}' — rp-mcp exposes rp_* tools only")
            return
        tool = name[3:]
        try:
            ctx, db = self._workspace()
            from .operator_tools import execute as execute_tool

            payload = execute_tool(ctx, db, self.case_id, tool,
                                   dict(arguments))
        except Exception as exc:  # noqa: BLE001 — structured tool error
            payload = {"error": True, "message": f"{type(exc).__name__}: {exc}"}
        text = json.dumps(payload, sort_keys=True, default=str)
        if len(text) > 8000:
            # Truncating JSON mid-string leaves the client an unparseable
            # fragment — cut INSIDE a valid envelope instead, with the note
            # telling the model how to get the rest (narrower arguments).
            text = json.dumps({
                "truncated": True,
                "note": "payload exceeded the transport cap — re-call with "
                        "narrower arguments (subject filter, smaller limit)",
                "preview": text[:7200],
            }, sort_keys=True)
        self._result(req_id, {
            "content": [{"type": "text", "text": text}],
            "isError": bool(payload.get("error")),
        })

    # -- loop ------------------------------------------------------------------
    def serve(self, lines) -> int:
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self._send({"jsonrpc": "2.0", "id": None,
                            "error": {"code": -32700, "message": "parse error"}})
                continue
            if not isinstance(msg, dict):
                self._error(None, -32600, "invalid request envelope")
                continue
            self._handle(msg)
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rp-mcp",
        description="Rebel Profiler operator tools as an MCP stdio server "
                    "(for the hermes-agent integration)")
    parser.add_argument("--case", required=True, help="the single case id to serve")
    parser.add_argument("--data-dir", default="",
                        help="workspace root (default: the standard data dir)")
    args = parser.parse_args(argv)
    data_dir = Path(args.data_dir) if args.data_dir else None
    server = McpServer(args.case, data_dir=data_dir)
    return server.serve(sys.stdin)


if __name__ == "__main__":
    sys.exit(main())
