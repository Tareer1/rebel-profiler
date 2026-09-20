"""Operator tools for the Hermes agent: run the workspace by tool call.

The Hermes loop used to see only the adapter registry (dns-lookup, whois,
port-scan …). That made the model a great collector but a powerless
operator: it could not create a case, authorize a target, generate the
report, verify the evidence chain, or look at a page through the browser
bridge — the operator had to drop back to shell commands for all of that.

This module closes that gap. Each *operator tool* is a small, named,
schema-described function over the same machinery the CLI uses — the
AppContext workspace, the per-case Database, the evidence/audit verifiers,
the fusion/surface engines, the knowledge base and the browser-bridge job
store. No new privileges, no new gates bypassed: whatever the CLI would
refuse, the tool refuses too (an ACTIVE case is still required for
collection, the scope engine still decides, the bridge still token-gates).

Law of the surface:

  * a tool does ONE obvious thing, returns a bounded JSON payload;
  * results are DATA for the model — redaction/truncation still applies
    downstream in the Hermes loop;
  * every failure is a structured ``{"error": True, "message", "fix"}``
    dict, never a traceback.

Public surface:

  * :data:`OPERATOR_TOOLS`       — name → :class:`ToolSpec` registry
  * :func:`operator_schemas`     — Hermes/OpenAI-style tool schemas
  * :func:`validate_arguments`   — param validation against a spec
  * :func:`execute`              — dispatch one validated call
"""

from __future__ import annotations

import json
import socket
import time
from typing import Any, Callable

from ..core.errors import RPError
from ..core.redact import redact

# Payload discipline: tool results re-enter the prompt, so they stay bounded.
_VALUE_MAX = 400          # any single string value
_LIST_MAX = 40            # any list length
_RESULT_MAX = 4000        # whole-payload cap when serialized

BROWSER_WAIT_S = 90       # how long browser_grab waits for the extension
BROWSER_POLL_S = 3

Handler = Callable[..., dict]


class ToolSpec:
    """One operator tool: schema + handler."""

    def __init__(self, name: str, description: str,
                 parameters: dict[str, str], required: tuple[str, ...],
                 handler: Handler) -> None:
        self.name = name
        self.description = description
        self.parameters = parameters
        self.required = required
        self.handler = handler

    def schema(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        key: {"type": "string", "description": desc}
                        for key, desc in self.parameters.items()
                    },
                    "required": list(self.required),
                },
            },
        }


OPERATOR_TOOLS: dict[str, ToolSpec] = {}


def operator_tool(name: str, description: str,
                  parameters: dict[str, str] | None = None,
                  required: tuple[str, ...] = ()):
    """Register an operator tool handler:

    ``fn(ctx, db, case_id, args, scope_engine=None) -> dict``.
    """
    def deco(fn: Handler) -> Handler:
        OPERATOR_TOOLS[name] = ToolSpec(
            name, description, dict(parameters or {}), required, fn)
        return fn
    return deco


def operator_schemas() -> list[dict]:
    """All operator tool schemas, stable order (registry insertion order)."""
    return [spec.schema() for spec in OPERATOR_TOOLS.values()]


def validate_arguments(spec: ToolSpec, arguments: dict) -> tuple[dict, dict | None]:
    """Validate a model-supplied argument dict against the spec.

    Returns ``(args, None)`` on success or ``({}, error_payload)``. Unknown
    params are rejected (the no-guessing rule the adapters follow too);
    missing required params produce an actionable error for the model.
    """
    args = {}
    allowed = ", ".join(spec.parameters) or "(none)"
    unknown = sorted(set(arguments) - set(spec.parameters))
    if unknown:
        return {}, {"error": True, "message":
                    f"tool '{spec.name}' got undeclared params {unknown}",
                    "fix": f"Allowed params: {allowed}"}
    missing = [r for r in spec.required
               if not str(arguments.get(r, "") or "").strip()]
    if missing:
        return {}, {"error": True, "message":
                    f"tool '{spec.name}' is missing required param(s) {missing}",
                    "fix": f"Params: {json.dumps(spec.parameters)}"}
    for key in spec.parameters:
        if key in arguments and arguments[key] is not None:
            args[key] = arguments[key]
    return args, None


def execute(ctx, db, case_id: str, name: str, arguments: dict,
            scope_engine=None) -> dict:
    """Validate + run one operator tool call; every failure is structured."""
    spec = OPERATOR_TOOLS.get(name)
    if spec is None:
        return {"error": True, "message": f"unknown operator tool '{name}'",
                "fix": f"Known: {', '.join(sorted(OPERATOR_TOOLS))}"}
    args, err = validate_arguments(spec, arguments)
    if err is not None:
        return err
    try:
        payload = spec.handler(ctx, db, case_id, args, scope_engine)
    except RPError as exc:
        return {"error": True, "action": name, "message": exc.message,
                "fix": getattr(exc, "action", "")}
    except Exception as exc:  # noqa: BLE001 — the model gets data, not tracebacks
        return {"error": True, "action": name,
                "message": f"{type(exc).__name__}: {exc}",
                "fix": "Rephrase the request; if it persists, run 'rebel-profiler doctor'."}
    payload["action"] = name
    payload["error"] = False
    return _bound(payload)


# ---------------------------------------------------------------------------
# payload bounding

def _bound(value: Any, _depth: int = 0) -> Any:
    if isinstance(value, str):
        text = redact(value)
        return text[:_VALUE_MAX] + ("…" if len(text) > _VALUE_MAX else "")
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        out = [_bound(v, _depth + 1) for v in value[:_LIST_MAX]]
        if len(value) > _LIST_MAX:
            out.append(f"(+{len(value) - _LIST_MAX} more — truncated)")
        return out
    if isinstance(value, dict):
        return {str(k)[:64]: _bound(v, _depth + 1) for k, v in list(value.items())[:60]}
    return str(value)[:_VALUE_MAX]


def _serialized_size(payload) -> int:
    try:
        return len(json.dumps(payload, default=str))
    except (TypeError, ValueError):
        return _RESULT_MAX + 1


# ---------------------------------------------------------------------------
# case + scope management

@operator_tool(
    "case_list",
    "List every case in the workspace with id, name and status.",
)
def _case_list(ctx, db, case_id, args, scope_engine=None):
    cases = ctx.list_cases()
    active = next((c["id"] for c in reversed(cases)
                   if c.get("status") == "active"), None)
    return {"cases": [{"id": c["id"], "name": c["name"], "status": c["status"]}
                      for c in cases],
            "active_case": active or ""}


@operator_tool(
    "case_create",
    "Create a new case workspace (starts as draft; authorize targets with scope_add).",
    parameters={"name": "short case name", "description": "one-line description"},
    required=("name",),
)
def _case_create(ctx, db, case_id, args, scope_engine=None):
    rec = ctx.create_case(str(args["name"]).strip(),
                          str(args.get("description", "")).strip())
    return {"case": rec, "next":
            "Add authorized targets with scope_add, which also activates the case."}


@operator_tool(
    "scope_show",
    "Show the current case's scope entries (authorized + excluded targets).",
)
def _scope_show(ctx, db, case_id, args, scope_engine=None):
    return {"case": case_id, "entries": [dict(r) for r in db.scope_entries(case_id)]}


@operator_tool(
    "scope_add",
    "Authorize a target for this case (adds an include entry) and ACTIVATE the case "
    "so scope enforcement goes live. This is the gate for all collection.",
    parameters={"value": "target to authorize, e.g. example.com or *.example.com",
                "exclude": "'true' to add as an exclusion instead"},
    required=("value",),
)
def _scope_add(ctx, db, case_id, args, scope_engine=None):
    value = str(args["value"]).strip()
    exclude = str(args.get("exclude", "")).strip().lower() in {"true", "yes", "1"}
    db.add_scope_entry(case_id, value, excluded=exclude, note="authorized via hermes")
    rec = ctx.set_case_status(case_id, "active") if not exclude else None
    if rec is not None:
        # The broker holds ONE live engine for the whole session: an in-chat
        # authorization must mutate that same engine, or every later call in
        # this session stays gated on the stale snapshot.
        _refresh_live_scope(db, case_id, scope_engine)
    return {
        "added": value, "excluded": exclude, "case": case_id,
        "case_status": rec["status"] if rec else "unchanged (exclusion entry)",
        "entries": [dict(r) for r in db.scope_entries(case_id)],
    }


@operator_tool(
    "case_activate",
    "Activate the current case (scope enforcement goes live).",
)
def _case_activate(ctx, db, case_id, args, scope_engine=None):
    rec = ctx.set_case_status(case_id, "active")
    _refresh_live_scope(db, case_id, scope_engine)
    return {"case": rec["id"], "status": rec["status"]}


# ---------------------------------------------------------------------------
# intel reading + analysis

@operator_tool(
    "claims_list",
    "List the claims collected so far in this case (optionally for one subject).",
    parameters={"subject": "optional subject filter, e.g. a hostname"},
)
def _claims_list(ctx, db, case_id, args, scope_engine=None):
    subject = str(args.get("subject", "")).strip() or None
    rows = [dict(r) for r in db.claims_for(case_id, subject)]
    return {"case": case_id, "count": len(rows), "claims": rows}


@operator_tool(
    "report_generate",
    "Generate the case report from collected claims + evidence.",
)
def _report_generate(ctx, db, case_id, args, scope_engine=None):
    from ..intel import ClaimLedger, SourceRegistry, generate_report

    ledger = ClaimLedger.load_from_db(db, case_id, SourceRegistry())
    report = generate_report(ledger, case_id)
    return {"case": case_id, "report": report.render_human(),
            "data": report.as_dict()}


@operator_tool(
    "evidence_verify",
    "Verify the evidence hash chain for this case (tamper check).",
)
def _evidence_verify(ctx, db, case_id, args, scope_engine=None):
    from ..evidence.store import EvidenceStore

    store = EvidenceStore(db, blobs_dir=ctx.case_dir(case_id) / "blobs")
    return store.verify_case(case_id)


@operator_tool(
    "audit_verify",
    "Verify the tamper-evident audit chain for this case.",
)
def _audit_verify(ctx, db, case_id, args, scope_engine=None):
    from ..evidence.audit import AuditChain

    return AuditChain(db).verify(case_id)


@operator_tool(
    "surface_map",
    "Per-host exposure summary built from collected claims (hosts, ports, products, lateral hints).",
)
def _surface_map(ctx, db, case_id, args, scope_engine=None):
    from ..intel import ClaimLedger, ExposureMapper, SourceRegistry

    ledger = ClaimLedger.load_from_db(db, case_id, SourceRegistry())
    return ExposureMapper(ledger, case_id).summary()


@operator_tool(
    "surface_build",
    "Build + persist the relationship graph from the case's claims.",
)
def _surface_build(ctx, db, case_id, args, scope_engine=None):
    from ..intel import ClaimLedger, RelationshipGraphStore, SourceRegistry

    ledger = ClaimLedger.load_from_db(db, case_id, SourceRegistry())
    return RelationshipGraphStore(ledger, case_id, db).build()


@operator_tool(
    "fusion_report",
    "Cross-domain fusion: subject profiles, corroborated values and conflicts.",
    parameters={"subject": "optional single subject to fuse"},
)
def _fusion_report(ctx, db, case_id, args, scope_engine=None):
    from ..intel import ClaimLedger, FusionEngine, SourceRegistry

    ledger = ClaimLedger.load_from_db(db, case_id, SourceRegistry())
    engine = FusionEngine(ledger, case_id)
    subject = str(args.get("subject", "")).strip().lower()
    if subject:
        profiles = engine.fuse()
        profile = profiles.get(subject)
        return ({"subject": subject, "profile": profile.as_dict()} if profile
                else {"subject": subject, "profile": None,
                      "note": "no fused profile — collect claims first"})
    return engine.report()


@operator_tool(
    "case_search",
    "Full-text search over this case's claims and observations.",
    parameters={"terms": "space-separated search terms"},
    required=("terms",),
)
def _case_search(ctx, db, case_id, args, scope_engine=None):
    terms = " ".join(str(args["terms"]).split())
    rows = db.search_docs(case_id, terms)
    return {"case": case_id, "query": terms, "count": len(rows), "results": rows}


# ---------------------------------------------------------------------------
# knowledge + browser + status

@operator_tool(
    "knowledge_search",
    "Search the built-in security knowledge base (domains, techniques, tools).",
    parameters={"query": "search keywords"},
    required=("query",),
)
def _knowledge_search(ctx, db, case_id, args, scope_engine=None):
    from ..knowledge import search as kb_search

    results = kb_search(" ".join(str(args["query"]).split()))
    return {"query": args["query"],
            "matches": [{"domain": d.key, "topic": t.key, "title": t.title}
                        for d, t in results]}


@operator_tool(
    "glossary",
    "Look up a term in the canonical glossary.",
    parameters={"term": "term to define"},
    required=("term",),
)
def _glossary(ctx, db, case_id, args, scope_engine=None):
    from ..knowledge import lookup, search_terms

    term = str(args["term"]).strip()
    definition = lookup(term)
    if definition is not None:
        return {"term": term, "definition": definition}
    matches = [{"term": n, "definition": d} for n, d in search_terms(term)]
    return {"term": term, "definition": None, "matches": matches}


@operator_tool(
    "browser_grab",
    "View one in-scope page through the operator's browser (the localhost bridge + "
    "extension). Submit the job, then wait for the extension's result. Pass "
    "job_id instead of url to read the result of a previously submitted job.",
    parameters={"url": "http(s) URL inside the case scope",
                "extract": "comma list: title,text,links,headers,forms,cookies,meta",
                "job_id": "optional: read a previous job's result instead of submitting"},
)
def _browser_grab(ctx, db, case_id, args, scope_engine=None):
    from ..browser import BrowserJobStore

    store = BrowserJobStore(ctx.data_dir / "queue")
    prior = str(args.get("job_id", "")).strip()
    if prior:
        result = store.load_result(prior)
        return ({"job_id": prior, "result": result} if result is not None
                else {"job_id": prior, "state": "pending",
                      "note": "no result yet — the extension may still be working"})
    url = str(args.get("url", "")).strip()
    if not url:
        return {"error": True, "message": "browser_grab needs url (or job_id)",
                "fix": "Pass the http(s) URL to view, or a job_id to poll."}
    extract = [e for e in str(args.get("extract", "title,text,links")).split(",") if e]
    envelope = store.submit(case_id=case_id, url=url, extract=extract,
                            requested_by="hermes-agent",
                            reason="requested in hermes chat")
    job_id = envelope["job_id"]
    deadline = time.time() + BROWSER_WAIT_S
    while time.time() < deadline:
        result = store.load_result(job_id)
        if result is not None:
            return {"job_id": job_id, "result": result}
        time.sleep(BROWSER_POLL_S)
    return {"job_id": job_id, "state": "pending",
            "note": (f"no result after {BROWSER_WAIT_S}s — is the bridge running "
                     "('rp bridge') and the extension polling? poll it in chat "
                     f"with browser_grab job_id={job_id}")}


@operator_tool(
    "system_status",
    "One-glance status: case + scope size, claim/evidence counts, chain integrity, "
    "and whether the browser bridge port is live.",
)
def _system_status(ctx, db, case_id, args, scope_engine=None):
    from ..evidence.audit import AuditChain
    from ..evidence.store import EvidenceStore

    store = EvidenceStore(db, blobs_dir=ctx.case_dir(case_id) / "blobs")
    ev = store.verify_case(case_id)
    audit = AuditChain(db).verify(case_id)
    rec = next((c for c in ctx.list_cases() if c["id"] == case_id), {})
    return {
        "case": {"id": case_id, "name": rec.get("name", ""),
                 "status": rec.get("status", "")},
        "scope_entries": len(db.scope_entries(case_id)),
        "claims": len(db.claims_for(case_id, None)),
        "evidence_records": ev.get("records", 0),
        "evidence_chain_ok": ev.get("chain_ok", False),
        "audit_chain_ok": audit.get("chain_ok", False),
        "bridge": _bridge_state(),
    }


def _refresh_live_scope(db, case_id: str, scope_engine) -> None:
    """Re-register this case's scope into the broker's LIVE engine.

    ``ctx.scope_engine()`` builds a snapshot; the broker keeps one engine
    instance for the whole session, so an in-chat authorization must mutate
    that same instance or every later gated call this session still sees the
    stale state. Missing engine (test doubles) → nothing to refresh.
    """
    if scope_engine is None:
        return
    from datetime import datetime, timezone

    from ..security.scope import Scope, ScopeStatus

    row = db.get_case(case_id)
    if row is None:
        return
    scope = Scope(case_id=case_id, status=ScopeStatus(str(row["status"])))
    for entry in db.scope_entries(case_id):
        expires = entry["expires_at"]
        scope.add(
            entry["value"],
            excluded=bool(entry["excluded"]),
            expires_at=None if expires is None
            else datetime.fromtimestamp(float(expires), tz=timezone.utc),
            note=entry["note"],
        )
    scope_engine.register(scope)


def _bridge_state() -> dict:
    """Cheap liveness probe of the localhost browser bridge (no token needed)."""
    try:
        with socket.create_connection(("127.0.0.1", 8765), timeout=0.5):
            return {"host": "127.0.0.1:8765", "up": True}
    except OSError:
        return {"host": "127.0.0.1:8765", "up": False,
                "note": "start it with 'rp bridge'"}
