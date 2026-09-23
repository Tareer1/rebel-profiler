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
    "attack_plan",
    "Rank concrete attack strategies for this case from its own collected "
    "evidence: what to try, where, why, which action verifies it. No "
    "payloads dispatch here — read-only planning over the ledger.",
)
def _attack_plan(ctx, db, case_id, args, scope_engine=None):
    from ..intel.claims import ClaimLedger
    from ..intel.offense import attack_plan

    ledger = ClaimLedger.load_from_db(db, case_id)
    return attack_plan(case_id, ledger)


@operator_tool(
    "payload_build",
    "Build a benign impact-marker payload (xss/sqli/ssti/redirect/idor/...) "
    "for an in-scope target URL. Marker proves the condition; nothing "
    "destructive. Returns the built payload; deploy via rp_probe with "
    "operator approval.",
    parameters={
        "payload_class": ("reflected_xss|sqli_error|sqli_timing|ssti|"
                          "cmdi_echo|open_redirect|idor_pivot|traversal"),
        "target": "in-scope http(s) URL",
        "param": "parameter to inject into (default q)",
    },
    required=("payload_class", "target"),
)
def _payload_build(ctx, db, case_id, args, scope_engine=None):
    from urllib.parse import urlsplit

    from ..intel.offense import build_payload

    target = str(args.get("target", "")).strip()
    host = (urlsplit(target).hostname or "").lower()
    if scope_engine is not None and host:
        status = scope_engine.evaluate(case_id, host)
        if status != "in_scope":
            return {"error": True, "message": f"target out of scope: {host}",
                    "fix": "Pick a target the case scope authorizes."}
    return build_payload(str(args.get("payload_class", "")), target,
                         str(args.get("param", "") or ""))


@operator_tool(
    "payload_deploy",
    "Deliver a built payload through the approval-gated probe. The model "
    "CANNOT approve: the operator's explicit decision text decides. "
    "decision='yes' dispatches; 'no' aborts; 'custom' edits the payload text.",
    parameters={
        "payload_class": "same classes as payload_build",
        "target": "in-scope http(s) URL",
        "param": "parameter to inject into (default q)",
        "decision": "yes | no | custom",
        "custom_payload": "payload text when decision=custom",
    },
    required=("payload_class", "target", "decision"),
)
def _payload_deploy(ctx, db, case_id, args, scope_engine=None):
    from urllib.parse import urlsplit

    from ..intel.offense import build_payload, deploy_payload

    decision = str(args.get("decision", "")).strip().lower()
    if decision not in {"yes", "no", "custom"}:
        return {"error": True,
                "message": f"decision must be yes|no|custom, got '{decision}'",
                "fix": "Ask the operator for an explicit yes/no/custom."}
    target = str(args.get("target", "")).strip()
    host = (urlsplit(target).hostname or "").lower()
    if scope_engine is not None and host:
        status = scope_engine.evaluate(case_id, host)
        if status != "in_scope":
            return {"error": True, "message": f"target out of scope: {host}",
                    "fix": "Pick a target the case scope authorizes."}
    built = build_payload(str(args.get("payload_class", "")), target,
                          str(args.get("param", "") or ""))
    if decision == "no":
        return {"approved": False, "dispatched": False,
                "note": "operator declined — nothing was sent"}
    if decision == "custom":
        custom = str(args.get("custom_payload", "") or "").strip()
        if not custom:
            return {"error": True, "message": "decision=custom needs custom_payload",
                    "fix": "Ask the operator for the edited payload text."}
        built["payload"] = custom[:400]
    deployment = deploy_payload(case_id, built, approved=True,
                                requested_by="operator")
    from ..execution import ActionRequest, ExecutionBroker

    broker = ExecutionBroker(
        db, scope_engine=scope_engine,
        evidence=__import__("rebel_profiler.evidence.store", fromlist=["EvidenceStore"]).EvidenceStore(
            db, blobs_dir=ctx.case_dir(case_id) / "blobs"),
    )
    request = ActionRequest(
        case_id=case_id, capability="vuln_validation", action="probe",
        target=deployment["request"]["target"],
        params=dict(deployment["request"]["params"]),
        requested_by="operator",
        reason=deployment["request"]["reason"],
    )
    result = broker.execute(request)
    hit = built.get("marker", "") and built["marker"] in (result.stdout or "")
    return {
        "approved": True, "dispatched": True,
        "outcome": result.outcome, "task_id": result.task_id,
        "evidence_id": result.evidence_id,
        "marker_found_in_response": bool(hit),
        "detect": built.get("detect", ""),
    }


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


# ---------------------------------------------------------------------------
# hunt → triage → probe: the bounty-hunt workflow as operator tools.
# Hermes can run the hunt and triage itself; the probe is always a
# suggestion the operator approves — the PoC stays human-owned.

@operator_tool(
    "hunt_run",
    "Run the autonomous JS-surface hunt on one in-scope seed URL (case must "
    "be active). Mines scripts for endpoints, secrets and cloud hosts, folds "
    "in Wayback history, ranks everything, registers evidence + claims. "
    "Follow with hunt_triage.",
    parameters={
        "url": "seed page URL, must be inside the case scope",
        "max_scripts": "optional cap on scripts to mine (1-50, default 25)",
        "no_wayback": '"yes" to skip Wayback history fold-in',
    },
    required=("url",),
)
def _hunt_run(ctx, db, case_id, args, scope_engine=None):
    from ..core.errors import RPError, UsageError
    from ..evidence.store import EvidenceStore
    from ..intel.claims import ClaimLedger
    from ..intel.collection import CollectionPipeline
    from ..intel.hunt import JsHunter
    from ..intel.sources import SourceRegistry

    row = db.get_case(case_id)
    if row is None:
        raise UsageError(f"case {case_id} not found",
                         action="list cases with case_list")
    if str(row["status"]) != "active":
        raise UsageError(
            f"case {case_id} is '{row['status']}', not active",
            reason="the hunter only runs inside an ACTIVE case",
            action="activate it first: case_activate")

    url = str(args["url"]).strip()
    if not url.lower().startswith(("http://", "https://")):
        raise UsageError(
            f"seed '{url}' is not an http(s) URL",
            reason="the hunter fetches one seed page, not a bare host",
            action="pass a full URL like https://host/page")
    try:
        max_scripts = int(args.get("max_scripts", 25))
    except (TypeError, ValueError):
        max_scripts = 25
    max_scripts = max(1, min(max_scripts, 50))

    evidence = EvidenceStore(db, blobs_dir=ctx.case_dir(case_id) / "blobs")
    hunter = JsHunter(case_id, scope_engine=scope_engine
                      if scope_engine is not None else ctx.scope_engine(),
                      evidence=evidence, max_scripts=max_scripts)
    report = hunter.hunt(url, include_wayback=str(
        args.get("no_wayback", "")).strip().lower() not in ("yes", "true", "1"))

    # Assessable items also become ledger claims, exactly like the CLI.
    claim_map = {"secret": "js_secret_candidate", "endpoint": "js_endpoint",
                 "cloud": "js_cloud_host"}
    ledger = ClaimLedger(SourceRegistry())
    pipeline = CollectionPipeline(ledger, evidence, SourceRegistry(), db=db)
    now = time.time()
    claimed = 0
    for item in report["items"]:
        kind = claim_map.get(item["category"])
        if kind is None:
            continue
        value = item["value"][:250]
        if item["category"] == "endpoint" and item["value"].startswith("/"):
            value = f"{url.rstrip('/')} {item['value']}"[:250]
        try:
            claim = ledger.add(
                case_id,
                subject=item["origin"].split("#")[0]
                if item["origin"].startswith("http") else url,
                kind=kind if item["category"] != "secret"
                else f"js_secret:{item['kind']}",
                value=value, source="js.static", method="js-hunt",
                observed_at=now, evidence_id=report.get("evidence_id"),
                notes=f"P{item['priority']} hunt item",
            )
            pipeline._persist([claim], case_id)
            claimed += 1
        except Exception:
            continue

    stats = dict(report["stats"])
    stats["claims_added"] = claimed
    top = []
    for item in report["items"][:8]:
        top.append({
            "priority": item["priority"], "category": item["category"],
            "value": item["value"][:120],
            "suggestion": item["suggestion"][:160],
        })
    return {
        "seed": report["seed"],
        "evidence_id": report.get("evidence_id"),
        "stats": stats,
        "top_items": top,
        "next": "call hunt_triage for the ranked probe-ready queue",
    }


@operator_tool(
    "hunt_triage",
    "Rank the case's collected claims into a probe-ready triage queue "
    "(secrets first, then exposed storage, then API paths). Every candidate "
    "carries its full provenance chain and the exact next probe request.",
    parameters={"limit": "optional max candidates (1-20, default 10)",
                "subject": "optional single subject to triage"},
)
def _hunt_triage(ctx, db, case_id, args, scope_engine=None):
    from ..intel.claims import ClaimLedger
    from ..intel.sources import SourceRegistry
    from ..intel.triage import triage

    try:
        limit = int(args.get("limit", 10))
    except (TypeError, ValueError):
        limit = 10
    limit = max(1, min(limit, 20))
    ledger = ClaimLedger.load_from_db(db, case_id, SourceRegistry())
    return triage(case_id, ledger, limit=limit,
                  subject=args.get("subject") or None)


@operator_tool(
    "probe_suggest",
    "Turn one triage candidate into a queued probe request (approval-gated: "
    "high-risk capability, durable queue, audit trail). Do NOT call this "
    "without naming an exact target URL from hunt_triage output.",
    parameters={
        "url": "exact probe target from hunt_triage's probe_url",
        "method": "optional HTTP method (default GET)",
        "data": "optional request body", "header": "optional extra header",
    },
    required=("url",),
)
def _probe_suggest(ctx, db, case_id, args, scope_engine=None):
    from ..core.errors import RPError, UsageError
    from ..execution import ActionRequest

    url = str(args["url"]).strip()
    if not url.lower().startswith(("http://", "https://")):
        raise UsageError(
            f"probe target '{url}' is not an http(s) URL",
            action="pass the probe_url exactly as hunt_triage listed it")
    try:
        probe_adapter = ctx.broker(db).adapters.get("probe")
        if probe_adapter is None:
            raise UsageError("probe adapter is not registered",
                             action="run 'rebel-profiler doctor'")
        request = ActionRequest(
            case_id=case_id,
            capability=probe_adapter.capability_class,
            action="probe", target=url,
            params={k: str(args[k]) for k in ("method", "data", "header")
                    if args.get(k)},
            requested_by="hermes-agent",
            reason="triage candidate from hunt workflow",
        )
        result = ctx.broker(db).execute(request)
    except RPError:
        raise
    result_payload = result.as_dict()
    # A high-risk request in a headless session becomes a DURABLE queue
    # entry; the broker's ExecutionResult says "cancelled" — surface the
    # queue truth instead so the model (and operator) see the real state.
    from ..security.approvals import ApprovalQueue

    queued = [a for a in ApprovalQueue(db).list(case_id)
              if a.get("task_id") == result.task_id]
    if queued:
        result_payload["queued_for_approval"] = True
        result_payload["approval_id"] = queued[0]["id"]
        result_payload["approval_state"] = queued[0]["state"]
    result_payload["next"] = (
        "if queued_for_approval, the operator decides via the approval "
        "queue (probe_execute runs it only once APPROVED); never retry "
        "automatically")
    return result_payload


@operator_tool(
    "probe_execute",
    "Execute an APPROVED probe by its approval id (the operator decides; "
    "this only runs a request the approval queue already cleared).",
    parameters={"approval_id": "id from the approval queue"},
    required=("approval_id",),
)
def _probe_execute(ctx, db, case_id, args, scope_engine=None):
    from ..core.errors import UsageError
    from ..security.approvals import ApprovalQueue

    approval_id = str(args["approval_id"]).strip()
    queue = ApprovalQueue(db)
    try:
        rec = queue.get(approval_id)
    except UsageError:
        return {"error": False, "action": "probe_execute",
                "approval_id": approval_id, "found": False,
                "note": "no such approval — check the queue listing"}
    result = ctx.broker(db).execute_approved(
        approval_id, decided_by=ctx.actor)
    payload = result.as_dict()
    payload["claims"] = _ingest_result_claims(ctx, db, case_id, result)
    return payload


def _ingest_result_claims(ctx, db, case_id: str, result) -> list:
    """Parse one succeeded broker result into claims (the collect pipeline).

    Execution alone stops at evidence; the endpoint is the claim ledger.
    Failure-tolerant by design: a parser miss degrades to an empty list and
    the evidence stays registered regardless.
    """
    if getattr(result, "outcome", "") != "succeeded":
        return []
    try:
        from ..intel.claims import ClaimLedger
        from ..intel.collection import CollectionPipeline
        from ..intel.sources import SourceRegistry

        pipeline = CollectionPipeline(
            ClaimLedger(SourceRegistry()),
            ctx.evidence_store(db, case_id),
            ctx.broker(db).adapters, db=db,
        )
        collection = pipeline.ingest(
            case_id, action=result.action, target=result.target,
            stdout=result.stdout, stderr=result.stderr,
            returncode=result.returncode or 1, task_id=result.task_id,
            evidence_id=result.evidence_id, params={},
        )
        return collection.get("claims", [])
    except Exception:
        return []


@operator_tool(
    "approval_list",
    "List this case's approval-queue entries (pending/approved/denied). "
    "Pending high-risk actions (e.g. probe) wait here for the operator; "
    "report them and ask whether to continue or move on — never decide "
    "for the operator.",
    parameters={"state": "optional filter: pending (default), approved, denied, or all"},
)
def _approval_list(ctx, db, case_id, args, scope_engine=None):
    from ..security.approvals import ApprovalQueue

    state = str(args.get("state", "")).strip().lower() or "pending"
    if state not in {"pending", "approved", "denied", "cancelled", "all"}:
        state = "pending"
    rows = ApprovalQueue(db).list(case_id, None if state == "all" else state)
    return {"case": case_id, "state": state, "count": len(rows),
            "approvals": [dict(r) for r in rows],
            "next": ("pending entries await the OPERATOR's decision — summarize "
                     "them and ask whether to keep waiting, work something else, "
                     "or wrap up; an approval is granted via the CLI 'approval "
                     "decide' (or the GUI), never by the model")}


@operator_tool(
    "approval_decide",
    "Record the OPERATOR's decision on one approval and, when approved, "
    "execute the action now (approve+run to the evidence endpoint in one "
    "step). Only call this AFTER the operator explicitly chose approve or "
    "deny in the conversation; the model must never decide by itself.",
    parameters={"approval_id": "id from approval_list",
                "decision": "the operator's explicit choice: approve or deny"},
    required=("approval_id", "decision"),
)
def _approval_decide(ctx, db, case_id, args, scope_engine=None):
    from ..core.errors import UsageError
    from ..security.approvals import ApprovalQueue

    approval_id = str(args["approval_id"]).strip()
    decision = str(args["decision"]).strip().lower()
    if decision not in {"approve", "deny"}:
        raise UsageError(
            f"decision '{decision}' is not approve/deny",
            reason="the model must never manufacture the operator's decision",
            action="Ask the operator for an explicit approve or deny.")
    queue = ApprovalQueue(db)
    try:
        rec = queue.get(approval_id)
    except UsageError as exc:
        raise UsageError(
            f"no approval '{approval_id}' in this case",
            action="List the queue with approval_list first.") from exc
    decided = queue.decide(approval_id, decision, decided_by=ctx.actor)
    payload = {"approval_id": approval_id, "decision": decision,
               "state": decided.get("state", decision + "d"),
               "action": decided.get("action", ""),
               "target": decided.get("target", "")}
    if decision != "approve":
        payload["next"] = ("denied — nothing executes; the audit trail "
                           "records the denial")
        return payload
    result = ctx.broker(db).execute_approved(approval_id, decided_by=ctx.actor)
    payload["execution"] = result.as_dict()
    payload["claims"] = _ingest_result_claims(ctx, db, case_id, result)
    payload["next"] = ("executed — claims and evidence are in the ledger; "
                       "read them with claims_list")
    return payload
