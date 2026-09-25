"""Rebel Profiler command-line interface.

See ``rebel-profiler --help``. Output modes: human (default), JSON
(``--output json``), JSONL (``--output jsonl``) and CSV (``--output csv``)
per the CLI contract (PDF 3). Every error exits with a documented exit code
and a structured what/why/next-action message.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
from pathlib import Path

from ..core.config import get as _cfg_get
from ..core.errors import EXIT_SUCCESS, EXIT_USAGE, RPError, UsageError
from ..evidence.audit import AuditChain
from ..intel.claims import ClaimLedger
from ..intel.sources import SourceRegistry
from . import theme
from .context import AppContext

GLOBAL_FLAGS = [
    argparse.ArgumentParser(add_help=False),  # placeholder replaced in build_parser
]


# ---------------------------------------------------------------------------
# Output rendering


def emit(payload, mode: str) -> None:
    # For tabular modes, unwrap the human/data envelope to the data itself.
    if mode in {"jsonl", "csv"} and isinstance(payload, dict) and "data" in payload:
        payload = payload["data"]
    if mode == "json":
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    elif mode == "jsonl":
        if isinstance(payload, list):
            for item in payload:
                print(json.dumps(item, sort_keys=True, default=str))
        else:
            print(json.dumps(payload, sort_keys=True, default=str))
    elif mode == "csv":
        buf = io.StringIO()
        rows = payload if isinstance(payload, list) else [payload]
        flat = [_flatten(r) for r in rows]
        if not flat:
            return
        writer = csv.DictWriter(buf, fieldnames=sorted({k for r in flat for k in r}))
        writer.writeheader()
        for r in flat:
            writer.writerow(r)
        print(buf.getvalue().rstrip("\n"))
    else:
        _emit_human(payload)


def _flatten(value, prefix: str = "") -> dict:
    out: dict = {}
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, dict):
                out.update(_flatten(v, f"{prefix}{k}."))
            else:
                out[f"{prefix}{k}"] = v
    else:
        out[prefix.rstrip(".")] = value
    return out


def _humanize_rows(rows: list[dict]) -> list[dict]:
    """Render copy of data rows for the human table: epochs → ISO time.

    The underlying payload is never mutated — JSON/JSONL/CSV stay raw.
    """
    import datetime

    out: list[dict] = []
    for r in rows:
        row = dict(r)
        for k, v in r.items():
            if k.endswith("_at") or k.endswith("_time"):
                try:
                    row[k] = datetime.datetime.fromtimestamp(
                        float(v)).strftime("%Y-%m-%d %H:%M:%S")
                except (TypeError, ValueError, OSError, OverflowError):
                    pass
        out.append(row)
    return out


def _emit_human(payload) -> None:
    if isinstance(payload, dict) and "human" in payload:
        data = payload.get("data")
        rows = data if isinstance(data, list) and data and all(isinstance(d, dict) for d in data) else None
        print(theme.panel(payload["human"], _humanize_rows(rows) if rows else rows))
    elif isinstance(payload, list):
        for item in payload:
            _emit_human(item)
    else:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))


def _print_table(rows: list[dict]) -> None:
    """Kept for callers that print a bare table; themed like the panel."""
    rendered = theme.table(rows)
    if rendered:
        print(rendered)


# ---------------------------------------------------------------------------
# Command implementations


def cmd_case(ctx: AppContext, args: argparse.Namespace) -> int:
    if args.case_command == "create":
        rec = ctx.create_case(args.name, args.description or "")
        emit({"human": f"Created case {rec['id']} ({rec['status']})\n"
                       f"Next: rebel-profiler case scope add {rec['id']} <target>",
              "data": rec}, args.output)
        return EXIT_SUCCESS
    if args.case_command == "list":
        cases = ctx.list_cases()
        emit({"human": f"{len(cases)} case(s)", "data": [
            {"id": c["id"], "name": c["name"], "status": c["status"]} for c in cases]}, args.output)
        return EXIT_SUCCESS
    if args.case_command == "show":
        rec = ctx.find_case(args.case_id)
        db = ctx.open_case(rec["id"])
        try:
            scope = [dict(r) for r in db.scope_entries(rec["id"])]
        finally:
            db.close()
        emit({"human": f"Case {rec['id']}: {rec['name']} [{rec['status']}]",
              "data": {**rec, "scope": scope}}, args.output)
        return EXIT_SUCCESS
    if args.case_command == "activate":
        rec = ctx.set_case_status(args.case_id, "active")
        emit({"human": f"Case {rec['id']} activated — scope enforcement is now live.", "data": rec}, args.output)
        return EXIT_SUCCESS
    if args.case_command == "close":
        rec = ctx.set_case_status(args.case_id, "closed")
        emit({"human": f"Case {rec['id']} closed. Execution is blocked for closed cases.", "data": rec}, args.output)
        return EXIT_SUCCESS
    if args.case_command == "scope":
        rec = ctx.find_case(args.case_id)
        db = ctx.open_case(rec["id"])
        try:
            if args.scope_command == "add":
                db.add_scope_entry(rec["id"], args.value, excluded=args.exclude, note=args.note or "")
                status = "exclusion" if args.exclude else "include"
                emit({"human": f"Added {status} entry '{args.value}' to case {rec['id']}.",
                      "data": {"value": args.value, "excluded": args.exclude}}, args.output)
            else:  # show
                entries = [dict(r) for r in db.scope_entries(rec["id"])]
                emit({"human": f"{len(entries)} scope entries in {rec['id']}", "data": entries}, args.output)
        finally:
            db.close()
        return EXIT_SUCCESS
    raise UsageError(f"Unknown case subcommand '{args.case_command}'")


def cmd_scope_check(ctx: AppContext, args: argparse.Namespace) -> int:
    engine = ctx.scope_engine()
    status = engine.evaluate(args.case_id, args.target)
    allowed = status == "in_scope"
    emit({"human": f"{args.target}: {status}",
          "data": {"target": args.target, "status": status, "in_scope": allowed}}, args.output)
    return EXIT_SUCCESS if allowed else 5


def cmd_plan(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..execution import ActionRequest, ExecutionBroker

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        broker = ExecutionBroker(db, scope_engine=ctx.scope_engine())
        request = ActionRequest(
            case_id=rec["id"], capability=args.capability, action=args.action,
            target=args.target, params=_params(args.param), reason=args.reason or "",
        )
        gate = broker.plan(request)
        argv = broker.adapters.get(args.action).build_argv(request)
        data = {
            "case": rec["id"],
            "action": args.action,
            "target": request.target,
            "argv": argv,
            "risk": gate.decision.risk.level,
            "policy_outcome": gate.decision.outcome.value,
            "reasons": list(gate.decision.reasons),
            "would_execute": gate.decision.allowed,
        }
        human = [
            f"Plan for {args.action} on {request.target}:",
            f"  command : {' '.join(argv)}",
            f"  risk    : {gate.decision.risk.level}",
            f"  policy  : {gate.decision.outcome.value}",
        ]
        for reason in gate.decision.reasons:
            human.append(f"    - {reason}")
        if not gate.decision.allowed:
            human.append("  result  : DENIED — execution would be blocked")
        emit({"human": "\n".join(human), "data": data}, args.output)
        return EXIT_SUCCESS if gate.decision.allowed else 4
    finally:
        db.close()


def _collect_result(ctx, db, rec, result, params) -> dict:
    """Feed one broker ExecutionResult through the intel pipeline."""
    from ..evidence.store import EvidenceStore
    from ..intel import ClaimLedger, CollectionPipeline, SourceRegistry

    evidence = EvidenceStore(db, blobs_dir=ctx.case_dir(rec["id"]) / "blobs")
    pipeline = CollectionPipeline(
        ClaimLedger(SourceRegistry()), evidence, db=db,
    )
    return pipeline.ingest(
        rec["id"],
        action=result.action, target=result.target,
        stdout=result.stdout, stderr=result.stderr,
        returncode=result.returncode or 1,
        task_id=result.task_id, evidence_id=result.evidence_id,
        params=params,
    )


def cmd_run(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..execution import ActionRequest

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        broker = ctx.broker(db)
        request = ActionRequest(
            case_id=rec["id"], capability=args.capability, action=args.action,
            target=args.target, params=_params(args.param), reason=args.reason or "",
        )
        result = broker.execute(request, dry_run=args.dry_run)
        collection = None
        if args.collect and result.outcome == "succeeded":
            collection = _collect_result(ctx, db, rec, result, request.params)
        data = result.as_dict()
        if collection is not None:
            data["collection"] = {
                "claims_emitted": collection["claims_emitted"],
                "clean": collection["clean"],
                "injection_findings": collection["injection_findings"],
            }
        human = [
            f"{result.action} on {result.target}: {result.outcome}",
            f"  task     : {result.task_id}",
            f"  risk     : {result.decision.risk.level}",
            f"  policy   : {result.decision.outcome.value}",
        ]
        if result.evidence_id:
            human.append(f"  evidence : {result.evidence_id}")
        if collection is not None:
            human.append(f"  claims   : {len(collection['claims_emitted'])} emitted"
                         f" ({'clean' if collection['clean'] else 'INJECTION FINDINGS — see intel scan'})")
        if result.stdout:
            first = result.stdout.splitlines()[0] if result.stdout.splitlines() else ""
            human.append(f"  output   : {first}")
        emit({"human": "\n".join(human), "data": data}, args.output)
        return EXIT_SUCCESS if result.outcome in {"succeeded", "dry_run"} else 1
    finally:
        db.close()


def cmd_intel_collect(ctx: AppContext, args: argparse.Namespace) -> int:
    """One-shot: plan+execute+collect through the broker (six gates intact)."""
    from ..execution import ActionRequest

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        broker = ctx.broker(db)
        request = ActionRequest(
            case_id=rec["id"],
            capability=broker.adapters.get(args.action).capability_class
            if broker.adapters.get(args.action) else "discovery",
            action=args.action, target=args.target,
            params=_params(args.param), reason=args.reason or "",
        )
        result = broker.execute(request)
        if result.outcome != "succeeded":
            data = result.as_dict()
            emit({"human": f"{result.action} on {result.target}: {result.outcome}",
                  "data": data}, args.output)
            return 1
        collection = _collect_result(ctx, db, rec, result, request.params)
        human = [
            f"collected {result.action} on {result.target}:",
            f"  evidence : {collection['evidence_id']}",
            f"  claims   : {len(collection['claims_emitted'])}",
            f"  clean    : {collection['clean']}",
        ]
        for claim in collection["claims"]:
            human.append(f"    - [{claim['kind']}] {claim['value']}"
                         f"  (conf={claim['confidence']:.2f}, src={claim['source']})")
        emit({"human": "\n".join(human), "data": collection}, args.output)
        return EXIT_SUCCESS
    finally:
        db.close()


def cmd_report(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..intel import ClaimLedger, generate_report

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        ledger = ClaimLedger.load_from_db(db, rec["id"])
        report = generate_report(ledger, rec["id"])
        emit({"human": report.render_human(), "data": report.as_dict()}, args.output)
        return EXIT_SUCCESS
    finally:
        db.close()


def cmd_adapters(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..execution import AdapterRegistry

    registry = AdapterRegistry()
    rows = [
        {"action": a.name, "binary": a.binary, "capability": a.capability_class}
        for a in registry.list()
    ]
    emit({"human": f"{len(rows)} registered adapter(s):", "data": rows}, args.output)
    return EXIT_SUCCESS


def cmd_knowledge(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..knowledge import (
        deep_planner_context,
        find_domain,
        find_playbook,
        find_technique,
        glossary_context,
        list_domains,
        lookup,
        planner_context,
        playbooks_context,
        search,
        search_terms,
        techniques_context,
        techniques_for_domain,
        tools_for_domain,
    )

    if args.knowledge_command == "domains":
        rows = [
            {"no": str(d["number"]), "key": d["key"], "title": d["title"], "topics": str(d["topics"])}
            for d in list_domains()
        ]
        emit({"human": f"{len(rows)} knowledge domains:", "data": rows}, args.output)
        return EXIT_SUCCESS
    if args.knowledge_command == "domain":
        d = find_domain(args.key)
        if d is None:
            raise RPError(f"Unknown domain '{args.key}'",
                          action="List domains with: rebel-profiler knowledge domains")
        rows = [
            {"key": t.key, "title": t.title, "capability": t.capability_class,
             "summary": t.summary, "defensive": t.defensive}
            for t in d.topics
        ]
        emit({"human": f"Domain {d.number}: {d.title}\n{d.objective}", "data": rows}, args.output)
        return EXIT_SUCCESS
    if args.knowledge_command == "search":
        results = search(" ".join(args.terms))
        rows = [{"domain": d.key, "topic": t.key, "title": t.title} for d, t in results]
        emit({"human": f"{len(rows)} matching topic(s):", "data": rows}, args.output)
        return EXIT_SUCCESS
    if args.knowledge_command == "tools":
        tools = tools_for_domain(args.key)
        rows = [
            {"action": t.name, "binary": t.binary, "gates": ",".join(t.gates) or "-", "summary": t.summary}
            for t in tools
        ]
        emit({"human": f"{len(rows)} tool(s) mapped to domain '{args.key}':", "data": rows}, args.output)
        return EXIT_SUCCESS
    if args.knowledge_command == "techniques":
        if args.key:
            if args.technique:
                found = find_technique(args.technique)
                if found is None:
                    raise RPError(f"Unknown technique '{args.technique}'",
                                  action="List techniques with: rebel-profiler knowledge techniques <domain>")
                domain, t = found
                data = {"domain": domain, "key": t.key, "name": t.name,
                        "capability_class": t.capability_class,
                        "kali_tools": list(t.kali_tools),
                        "countermeasure": t.countermeasure, "notes": t.notes}
                human = f"{t.name} [{domain}]\n  tools: {', '.join(t.kali_tools) or '-'}\n  defense: {t.countermeasure}"
                emit({"human": human, "data": data}, args.output)
            else:
                techniques = techniques_for_domain(args.key)
                if not techniques:
                    raise RPError(f"Unknown domain '{args.key}'",
                                  action="List domains with: rebel-profiler knowledge domains")
                rows = [
                    {"key": t.key, "name": t.name, "capability": t.capability_class,
                     "tools": ", ".join(t.kali_tools) or "-"}
                    for t in techniques
                ]
                emit({"human": f"{len(rows)} technique(s) in '{args.key}':", "data": rows}, args.output)
        else:
            ctx_data = techniques_context()
            total = sum(len(d["techniques"]) for d in ctx_data["domains"])
            emit({"human": f"{total} techniques across {len(ctx_data['domains'])} domains (use --json for full matrix)",
                  "data": None}, args.output)
        return EXIT_SUCCESS
    if args.knowledge_command == "playbook":
        if args.key:
            pb = find_playbook(args.key)
            if pb is None:
                raise RPError(f"Unknown playbook '{args.key}'",
                              action="List playbooks with: rebel-profiler knowledge playbook")
            rows = [
                {"step": str(s.order), "title": s.title, "capability": s.capability_class,
                 "action": s.action_hint or "-", "description": s.description}
                for s in pb.steps
            ]
            emit({"human": f"Playbook: {pb.title}\n{pb.objective}", "data": rows}, args.output)
        else:
            pbs = playbooks_context()["playbooks"]
            rows = [{"key": p["key"], "title": p["title"], "steps": str(len(p["steps"]))} for p in pbs]
            emit({"human": f"{len(rows)} playbooks:", "data": rows}, args.output)
        return EXIT_SUCCESS
    if args.knowledge_command == "glossary":
        if args.term:
            definition = lookup(args.term)
            if definition is None:
                matches = search_terms(args.term)
                if not matches:
                    raise RPError(f"No glossary entry for '{args.term}'",
                                  action="Browse all terms with: rebel-profiler knowledge glossary")
                rows = [{"term": n, "definition": d} for n, d in matches]
                emit({"human": f"{len(rows)} matching term(s):", "data": rows}, args.output)
            else:
                emit({"human": f"{args.term}: {definition}",
                      "data": {"term": args.term, "definition": definition}}, args.output)
        else:
            terms = glossary_context()["terms"]
            emit({"human": f"{len(terms)} glossary terms:",
                  "data": [{"term": t["term"], "definition": t["definition"]} for t in terms]}, args.output)
        return EXIT_SUCCESS
    if args.knowledge_command == "planner-context":
        emit(planner_context(args.domains), args.output)
        return EXIT_SUCCESS
    if args.knowledge_command == "actions":
        from ..knowledge import action_guides_context, find_action_guide
        from ..knowledge.action_guides import coverage_report

        if args.key:
            guide = find_action_guide(args.key)
            if guide is None:
                raise RPError(f"No action guide for '{args.key}'",
                              action="List covered actions with: "
                                     "rebel-profiler knowledge actions")
            emit({"human": f"{guide.action} [{guide.capability_class}]\n"
                           f"when: {'; '.join(guide.when)}\n"
                           f"target: {guide.target_shape} (e.g. {guide.target_example})\n"
                           f"example: {guide.example}\n"
                           f"claims: {', '.join(guide.output_claims) or '-'}\n"
                           f"next: {' -> '.join(guide.next_steps) or '-'}",
                  "data": {"example": guide.example,
                           "target_shape": guide.target_shape,
                           "params": [{"name": n, "meaning": m}
                                      for n, m in guide.params]},
                  }, args.output)
        else:
            bundle = action_guides_context()
            cov = coverage_report()
            emit({"human": f"action guides: {bundle['covered']}/{bundle['total']} "
                           f"covered (complete={cov['complete']})",
                  "data": bundle}, args.output)
        return EXIT_SUCCESS
    if args.knowledge_command == "deep-context":
        emit(deep_planner_context(args.domains), args.output)
        return EXIT_SUCCESS
    raise UsageError(f"Unknown knowledge subcommand '{args.knowledge_command}'")


def cmd_intel(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..intel import SourceRegistry, source_contract  # noqa: F401

    if args.intel_command == "collect":
        return cmd_intel_collect(ctx, args)
    if args.intel_command == "crawl":
        return _cmd_intel_crawl(ctx, args)
    if args.intel_command == "hunt":
        return _cmd_intel_hunt(ctx, args)
    if args.intel_command == "attack-plan":
        return _cmd_intel_attack_plan(ctx, args)
    if args.intel_command == "vuln-coverage":
        return _cmd_intel_vuln_coverage(ctx, args)
    if args.intel_command == "playbook":
        return _cmd_intel_playbook(ctx, args)
    if args.intel_command == "payload":
        return _cmd_intel_payload(ctx, args)
    if args.intel_command == "fusion":
        return _cmd_intel_fusion(ctx, args)
    if args.intel_command == "sources":
        registry = SourceRegistry()
        if args.key:
            from ..intel import score_source

            src = registry.require(args.key)
            score = score_source(src)
            emit({"human": f"Source {src.key} [{src.grade}] kind={src.kind}\n"
                           f"  score: {score['composite']} (rel={score['reliability']},"
                           f" fresh={score['freshness']}, indep={score['independence']})",
                  "data": score}, args.output)
            return EXIT_SUCCESS
        rows = [
            {"source": s.key, "kind": s.kind, "grade": s.grade,
             "independence": str(s.independence), "operator": s.operator}
            for s in registry.list()
        ]
        contract = source_contract()
        emit({"human": f"{len(rows)} registered source(s) — scoring v{contract['scoring_version']}"
                       f" (weights: reliability={contract['weights']['reliability']},"
                       f" freshness={contract['weights']['freshness']},"
                       f" independence={contract['weights']['independence']})",
              "data": rows}, args.output)
        return EXIT_SUCCESS
    if args.intel_command == "claims":
        rec = ctx.find_case(args.case_id)
        db = ctx.open_case(rec["id"])
        try:
            rows = [dict(r) for r in db.claims_for(rec["id"], args.subject or None)]
        finally:
            db.close()
        label = f" for {args.subject}" if args.subject else ""
        emit({"human": f"{len(rows)} claim(s){label} in case {rec['id']}", "data": rows}, args.output)
        return EXIT_SUCCESS
    if args.intel_command == "sanitize":
        from ..intel import injection_report
        if args.stdin or args.text is None:
            text = sys.stdin.read()
            source = "stdin"
        else:
            text = args.text
            source = "arg"
        report = injection_report(text, source=source)
        human = (
            f"clean: {report['clean']}  highest_severity: {report['highest_severity'] or '-'}"
            + ("" if report["clean"] else "\n  " + "\n  ".join(
                f"{f['rule']} [{f['severity']}]: …{f['excerpt']}…" for f in report["findings"]))
        )
        emit({"human": human, "data": {k: v for k, v in report.items() if k != "sanitized"}}, args.output)
        return EXIT_SUCCESS
    raise UsageError(f"Unknown intel subcommand '{args.intel_command}'")


def cmd_evidence(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..evidence.store import EvidenceStore
    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        store = EvidenceStore(db, blobs_dir=ctx.case_dir(rec["id"]) / "blobs")
        if args.evidence_command == "list":
            records = store.list_records(rec["id"])
            rows = [
                {"id": r.id, "kind": r.kind, "sha256": r.sha256[:16] + "…", "size": str(r.size),
                 "source": r.source, "note": r.note}
                for r in records
            ]
            emit({"human": f"{len(rows)} evidence record(s) in {rec['id']}", "data": rows}, args.output)
            return EXIT_SUCCESS
        if args.evidence_command == "verify":
            report = store.verify_case(rec["id"])
            ok = report["chain_ok"]
            human = (
                f"evidence verify {rec['id']}: {'OK' if ok else 'FAILED'}"
                f" ({report['records']} record(s))"
                + ("" if ok else "\n  " + "\n  ".join(report["problems"]))
            )
            emit({"human": human, "data": report}, args.output)
            return EXIT_SUCCESS if ok else 11
        raise UsageError(f"Unknown evidence subcommand '{args.evidence_command}'")
    finally:
        db.close()


def cmd_audit(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..evidence.audit import AuditChain

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        chain = AuditChain(db)
        if args.audit_command == "show":
            events = chain.events(rec["id"])
            rows = [
                {"seq": str(e.seq), "at": f"{e.at:.0f}", "actor": e.actor, "action": e.action,
                 "subject": e.subject, "hash": e.hash[:12] + "…"}
                for e in events
            ]
            emit({"human": f"{len(rows)} audit event(s) in {rec['id']}", "data": rows}, args.output)
            return EXIT_SUCCESS
        if args.audit_command == "verify":
            report = chain.verify(rec["id"])
            ok = report["chain_ok"]
            human = (
                f"audit verify {rec['id']}: {'OK' if ok else 'FAILED'}"
                f" ({report['events']} event(s))"
                + ("" if ok else "\n  " + "\n  ".join(report["problems"]))
            )
            emit({"human": human, "data": report}, args.output)
            return EXIT_SUCCESS if ok else 11
        raise UsageError(f"Unknown audit subcommand '{args.audit_command}'")
    finally:
        db.close()


def _parse_plan(plan_text: str) -> list:
    """Parse 'action:target[:k=v,k=v];...' into Proposals.

    This is the deterministic stand-in for the LLM planner: same Proposal
    objects an LLM-backed planner would emit.
    """
    from ..agent import Proposal

    proposals: list[Proposal] = []
    for chunk in filter(None, plan_text.split(";")):
        parts = chunk.strip().split(":", 2)
        if not parts or not parts[0].strip():
            continue
        action = parts[0].strip()
        target = parts[1].strip() if len(parts) > 1 else ""
        params: dict = {}
        if len(parts) > 2 and parts[2].strip():
            for pair in parts[2].split(","):
                key, _, value = pair.strip().partition("=")
                params[key.strip()] = _coerce_param(value.strip())
        if not target:
            raise UsageError(
                f"Plan step '{action}' has no target",
                action="Use action:target[:params] format.",
            )
        proposals.append(Proposal(action=action, target=target, params=params))
    return proposals


def _coerce_param(value: str):
    low = value.lower()
    if low in {"true", "false"}:
        return low == "true"
    try:
        return int(value)
    except ValueError:
        return value


def cmd_agent(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..agent import run_session

    if args.agent_command == "auto":
        return cmd_agent_auto(ctx, args)
    if args.agent_command == "chat":
        return cmd_agent_chat(ctx, args)
    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        if getattr(args, "llm", ""):
            planner = _make_llm_planner(args.llm, ctx.broker(db).adapters)
        elif getattr(args, "coverage", False):
            planner = _make_coverage_planner(rec["id"], db)
        else:
            planner = _make_planner(args.plan)
        session = run_session(
            rec["id"], args.goal, planner, ctx=ctx, db=db,
            max_actions=args.max_actions,
        )
        steps = session["steps"]
        ok = sum(1 for s in steps if s["outcome"] == "succeeded")
        human = [
            f"agent session: {len(steps)} step(s), {ok} succeeded",
            f"  goal     : {args.goal}",
        ]
        for s in steps:
            claim_note = f", {len(s['claims'])} claims" if s["claims"] else ""
            human.append(f"  [{s['seq']}] {s['outcome']:>9}  {s['action']} {s['target']}"
                         f"{claim_note}" + (f" — {s['note']}" if s["note"] else ""))
        human.append("")
        human.append(session["report_human"])
        emit({"human": "\n".join(human), "data": session}, args.output)
        return EXIT_SUCCESS if ok else 1
    finally:
        db.close()


def _cmd_intel_vuln_coverage(ctx: AppContext, args: argparse.Namespace) -> int:
    """Vulnerability-class coverage matrix for this case's evidence."""
    from ..intel.claims import ClaimLedger
    from ..intel.vulncov import coverage_for_case, coverage_plan

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        ledger = ClaimLedger.load_from_db(db, rec["id"])
        report = coverage_for_case(ledger, rec["id"])
        plan = (coverage_plan(ledger, rec["id"], max_actions=args.max_plan)
                if args.plan else None)
    finally:
        db.close()
    if plan is not None:
        human = [f"Coverage plan — case {rec['id']}: "
                 f"{len(plan['proposals'])} proposal(s) from blind spots",
                 f"  plan     : {plan['plan_text'] or '(nothing to propose)'}"]
        for p in plan["proposals"]:
            human.append(f"  → {p['action']} {p['target']}  ({p['reason']})")
        for s in plan["skipped"][:6]:
            human.append(f"  skip {s['class']}/{s['action']}: {s['why']}")
        human.append("  execution still passes the six gates — use "
                     "agent run <case> --coverage to dispatch")
        emit({"human": "\n".join(human), "data": plan}, args.output)
        return EXIT_SUCCESS
    human = [f"Vulnerability coverage — case {rec['id']}: "
             f"{report['covered']} covered, {report['available']} available, "
             f"{report['no_adapter']} without adapter (of {report['total']})"]
    mark = {"covered": "[x]", "available": "[ ]", "no-adapter": "[!]"}
    for row in report["classes"]:
        human.append(f"  {mark[row['status']]} {row['class']:<18} "
                     f"{row['cwe']:<9} {row['title']}")
        if row["status"] == "available":
            human.append(f"        run: intel collect {' / '.join(row['detect_actions'][:3])}")
    emit({"human": "\n".join(human), "data": report}, args.output)
    return EXIT_SUCCESS


def _cmd_intel_attack_plan(ctx: AppContext, args: argparse.Namespace) -> int:
    """Ranked, evidence-driven offensive strategies from the case ledger."""
    from ..intel.offense import attack_plan

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        from ..intel.claims import ClaimLedger

        ledger = ClaimLedger.load_from_db(db, rec["id"])
        plan = attack_plan(rec["id"], ledger)
    finally:
        db.close()
    if args.save_payloads:
        import json as _json
        out = ctx.case_dir(rec["id"]) / "attack_plan.json"
        out.write_text(_json.dumps(plan, indent=2, sort_keys=True) + "\n")
    human = [f"Attack plan — case {rec['id']} "
             f"({plan['claims_read']} claims, {plan['subjects']} subject(s))"]
    for s in plan["strategies"]:
        human.append(f"  #{s['rank']} [{s['severity_hint']:>9}] {s['title']}")
        human.append(f"      where  : {s['where']}")
        human.append(f"      why    : {s['why']}")
        human.append(f"      action : {s['action']} {s['params'] or ''}")
        if s["payload_class"]:
            human.append(f"      payload: {s['payload_class']} "
                         "(intel payload build → deploy)")
    if not plan["strategies"]:
        human.append("  (no evidence yet — run intel collect / intel crawl first)")
    emit({"human": "\n".join(human), "data": plan}, args.output)
    return EXIT_SUCCESS


def _cmd_intel_playbook(ctx: AppContext, args: argparse.Namespace) -> int:
    """Hunt playbooks: reviewed multi-step recipes, expanded into gated plans."""
    from ..intel.playbooks import expand_playbook, get_playbook, load_playbooks

    if args.playbook_command == "list":
        pbs = load_playbooks(ctx.data_dir)
        rows = [{"name": p.name, "version": p.version, "source": p.source,
                 "steps": len(p.steps), "description": p.description}
                for p in pbs]
        emit({"human": f"{len(rows)} playbook(s) — "
                       f"run one: intel playbook run <name> <case-id> <target>",
              "data": rows}, args.output)
        return EXIT_SUCCESS
    if args.playbook_command == "show":
        pb = get_playbook(args.playbook_name, ctx.data_dir)
        d = pb.as_dict()
        human = [f"{pb.name} v{pb.version} ({pb.source}) — {pb.description}"]
        for s in pb.steps:
            human.append(f"  {s.rank}. {s.action} {s.params or ''}")
            human.append(f"     why: {s.why}")
        emit({"human": "\n".join(human), "data": d}, args.output)
        return EXIT_SUCCESS
    # run: validate → expand → execute each entry through the same collect
    # pipeline (six gates, evidence, claims). A failed/skipped step is
    # reported and the run continues to the next — the recipe is the plan,
    # the gates stay the law.
    pb = get_playbook(args.playbook_name, ctx.data_dir)
    rec = ctx.find_case(args.case_id)
    overrides = {k: v for k, v in (args.param or [])}
    expansion = expand_playbook(pb, args.target)
    if overrides:
        # operator overrides (e.g. scheme=http) win over the recipe's params,
        # merged into every step whose adapter declares the key
        from ..execution.broker import AdapterRegistry
        registry = AdapterRegistry()
        for entry in expansion["entries"]:
            adapter = registry.get(entry["action"])
            allowed = set(adapter.allowed_params) if adapter else set()
            for k, v in overrides.items():
                if k in allowed:
                    entry["params"][k] = v
    if not expansion["entries"]:
        raise UsageError(
            f"Playbook '{pb.name}' has no executable steps",
            reason="every step failed registry validation",
            action="intel playbook show " + pb.name)
    ran, failed = [], []
    for entry in expansion["entries"]:
        args.action = entry["action"]
        args.target = entry["target"]
        # -p uses append+nargs=2 → a list of [key, value] PAIRS, not flat
        args.param = [[k, v] for k, v in entry["params"].items()]
        args.reason = f"playbook:{pb.name}#{entry['rank']} — {entry['why']}"
        result = cmd_intel_collect(ctx, args)
        (ran if result == 0 else failed).append(
            f"#{entry['rank']} {entry['action']}")
    human = [f"Playbook {pb.name} v{pb.version} on {args.target}: "
             f"{len(ran)} step(s) ran, {len(failed)} failed/skipped"]
    for line in ran:
        human.append(f"  ✓ {line}")
    for line in failed:
        human.append(f"  ✗ {line}")
    emit({"human": "\n".join(human),
          "data": {"playbook": pb.name, "ran": ran, "failed": failed}},
         args.output)
    return EXIT_SUCCESS if not failed else 1


def _cmd_intel_payload(ctx: AppContext, args: argparse.Namespace) -> int:
    """Payload workbench: build / classes / deploy (approval-gated)."""
    from ..intel.offense import build_payload, deploy_payload, payload_classes

    if args.payload_command == "classes":
        rows = [{"payload_class": c} for c in payload_classes()]
        emit({"human": "payload classes: " + ", ".join(payload_classes()),
              "data": rows}, args.output)
        return EXIT_SUCCESS
    if args.payload_command == "build":
        rec = ctx.find_case(args.case_id)
        target = args.target or _plan_first_target(rec["id"], ctx)
        if not target:
            raise RPError("No target for the payload",
                          action="Pass --target with an in-scope URL, or run "
                                 "recon so the case has live hosts.")
        built = build_payload(args.payload_class, target, args.param or "")
        human = [f"Payload [{built['payload_class']}] marker={built['marker']}",
                 f"  target  : {built['target']}",
                 f"  param   : {built['param']}",
                 f"  payload : {built['payload'][:80]}",
                 f"  detect  : {built['detect']}",
                 "  deploy  : intel payload deploy <case> --payload-class "
                 f"{built['payload_class']} --approve  (operator yes/no)"]
        emit({"human": "\n".join(human), "data": built}, args.output)
        return EXIT_SUCCESS
    if args.payload_command == "deploy":
        rec = ctx.find_case(args.case_id)
        target = args.target or _plan_first_target(rec["id"], ctx)
        if not target:
            raise RPError("No target for the payload",
                          action="Pass --target with an in-scope URL.")
        built = build_payload(args.payload_class, target, args.param or "")
        if not args.approve:
            draft = deploy_payload(rec["id"], built, approved=False)
            emit({"human": "DRAFT — nothing dispatched. Re-run with --approve "
                           "to send the operator yes/no decision through.",
                  "data": draft}, args.output)
            return 4
        built["payload"] = args.custom_payload or built["payload"]
        deployment = deploy_payload(rec["id"], built, approved=True)
        from ..execution import ActionRequest, ExecutionBroker

        db = ctx.open_case(rec["id"])
        try:
            broker = ctx.broker(db)
            request = ActionRequest(
                case_id=rec["id"], capability="vuln_validation",
                action="probe", target=deployment["request"]["target"],
                params=dict(deployment["request"]["params"]),
                requested_by=args.actor or "operator",
                reason=deployment["request"]["reason"],
            )
            result = broker.execute(request)
            collection = None
            if result.outcome == "succeeded":
                collection = _collect_result(ctx, db, rec, result,
                                             request.params)
        finally:
            db.close()
        data = result.as_dict()
        if collection:
            data["collection"] = {"claims_emitted": collection["claims_emitted"],
                                  "clean": collection["clean"]}
        marker = built.get("marker", "")
        hit = marker and marker in (result.stdout or "")
        emit({"human": f"probe {result.outcome} — marker {'FOUND in response' if hit else 'not found in response body'}"
                       f"\n  task: {result.task_id}  evidence: {result.evidence_id}",
              "data": data}, args.output)
        return EXIT_SUCCESS if result.outcome == "succeeded" else 1
    raise UsageError(f"Unknown payload subcommand")


def _plan_first_target(case_id: str, ctx) -> str:
    """First live-URL claim for the case, or empty — a convenience default."""
    import re as _re

    db = ctx.open_case(case_id)
    try:
        for row in db.claims_for(case_id, None):
            value = str(row.get("value", ""))
            if row.get("kind") in {"wayback_url", "js_endpoint"} \
                    and _re.match(r"^https?://", value):
                return value
        return ""
    finally:
        db.close()


def _cmd_intel_hunt(ctx: AppContext, args: argparse.Namespace) -> int:
    """Autonomous JS hunt: harvest scripts, mine, rank, one triage queue.

    P1/P2 items also become claims in the ledger (js_endpoint, js_secret:*,
    js_cloud_host) so `bounty assess` and `report` see them — the hunt is a
    collection action, not just a printout.
    """
    from ..evidence.store import EvidenceStore
    from ..intel.claims import ClaimLedger
    from ..intel.collection import CollectionPipeline
    from ..intel.hunt import JsHunter
    from ..intel.sources import SourceRegistry

    rec = ctx.find_case(args.case_id)
    if rec["status"] != "active":
        raise UsageError(
            f"Case {rec['id']} is '{rec['status']}', not active",
            reason="The hunter only runs inside an ACTIVE case.",
            action=f"rebel-profiler case activate {rec['id']}")
    db = ctx.open_case(rec["id"])
    try:
        evidence = EvidenceStore(db, blobs_dir=ctx.case_dir(rec["id"]) / "blobs")
        hunter = JsHunter(
            rec["id"], scope_engine=ctx.scope_engine(),
            evidence=evidence,
            max_scripts=max(1, min(args.max_scripts, 50)),
        )
        report = hunter.hunt(args.url, include_wayback=not args.no_wayback)

        # Ledger claims for the assessable categories (P1 secrets, P2
        # endpoints/cloud hosts). Historical P3 URLs stay hunt-only — they
        # are archive artifacts, not observations of the live target.
        claim_map = {"secret": "js_secret_candidate", "endpoint": "js_endpoint",
                     "cloud": "js_cloud_host"}
        pipeline = CollectionPipeline(
            ClaimLedger(SourceRegistry()), evidence, SourceRegistry(), db=db)
        now = __import__("time").time()
        claimed = 0
        for item in report["items"]:
            kind = claim_map.get(item["category"])
            if kind is None:
                continue
            value = item["value"][:250]
            if item["category"] == "endpoint" and item["value"].startswith("/"):
                value = f"{args.url.rstrip('/')} {item['value']}"[:250]
            try:
                claim = pipeline.ledger.add(
                    rec["id"], subject=item["origin"].split("#")[0]
                    if item["origin"].startswith("http") else args.url,
                    kind=kind if item["category"] != "secret"
                    else f"js_secret:{item['kind']}",
                    value=value,
                    source="js.static", method="js-hunt", observed_at=now,
                    evidence_id=report.get("evidence_id"),
                    notes=f"P{item['priority']} hunt item",
                )
                pipeline._persist([claim], rec["id"])
                claimed += 1
            except Exception:
                continue   # a bad claim never kills the hunt report

        stats = report["stats"]
        stats["claims_added"] = claimed
        lines = [
            f"js hunt on {report['seed']} — "
            f"{stats.get('scripts_mined', 0)} script(s) mined, "
            f"{stats.get('p1', 0)} P1 / {stats.get('p2', 0)} P2 / "
            f"{stats.get('p3', 0)} P3 item(s), {claimed} claim(s)",
            f"  evidence : {report.get('evidence_id')}",
        ]
        for item in report["items"][:20]:
            lines.append(
                f"  [P{item['priority']}][{item['category']}] "
                f"{item['value'][:80]}")
            lines.append(f"        ↳ {item['suggestion'][:90]}")
        if not report["items"]:
            lines.append("  (no items — the page ships no exploitable surface)")
        emit({"human": "\n".join(lines), "data": report}, args.output)
        return EXIT_SUCCESS if report["items"] else EXIT_SUCCESS
    finally:
        db.close()


def _cmd_intel_crawl(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..evidence.store import EvidenceStore
    from ..intel import ClaimLedger, ScopeEnforcedWebAuditor, SourceRegistry

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        scope_engine = ctx.scope_engine()
        auditor = ScopeEnforcedWebAuditor(
            rec["id"],
            scope_engine=scope_engine,
            ledger=ClaimLedger(SourceRegistry()),
            evidence=EvidenceStore(db, blobs_dir=ctx.case_dir(rec["id"]) / "blobs"),
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            # Persist the findings: without this the audit's claims die with
            # the in-memory ledger, so `report`, `surface build`, `intel
            # fusion` and `bounty assess` would never see them.
            db=db,
        )
        report = auditor.crawl(args.urls)
        stats = report["stats"]
        human = [
            f"web audit for {rec['id']}: {stats['pages_audited']} page(s) audited, "
            f"{stats['findings']} finding(s), {stats['pages_blocked_or_errored']} skipped",
        ]
        for page in report["pages"]:
            if page["kind"] != "audited":
                human.append(f"  [{page['kind']}] {page['url']}" +
                             (f" — {page['note']}" if page["note"] else ""))
                continue
            human.append(f"  {page['url']} (status {page['status']})")
            for check in page["checks"]:
                mark = {"pass": "+", "finding": "!"}.get(check["status"], "?")
                human.append(f"    [{mark}] {check['check']}: {check['detail']}")
        emit({"human": "\n".join(human), "data": report}, args.output)
        return EXIT_SUCCESS if stats["pages_audited"] else 1
    finally:
        db.close()


def _cmd_intel_fusion(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..intel import ClaimLedger, FusionEngine

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        engine = FusionEngine(ClaimLedger.load_from_db(db, rec["id"]), rec["id"])
        if args.subject:
            profiles = engine.fuse()
            profile = profiles.get(args.subject.strip().lower())
            if profile is None:
                emit({"human": f"No fused profile for '{args.subject}' — collect claims first.",
                      "data": {}}, args.output)
                return EXIT_SUCCESS
            human = [f"Fused profile: {profile.subject}",
                     f"  domains : {', '.join(sorted(profile.domains_seen))}"]
            for attribute, attr in sorted(profile.attributes.items()):
                for entry in attr.values:
                    support = "+".join(entry["sources"])
                    mark = " (corroborated)" if entry["corroborated"] else ""
                    human.append(f"  {attribute:12} = {entry['value'][:60]}"
                                 f"  [conf={entry['confidence']:.2f} via {support}]{mark}")
            for conflict in profile.conflicts:
                human.append(f"  ! conflict {conflict.attribute}:"
                             f" '{conflict.winner_value}' beats '{conflict.loser_value}'")
            emit({"human": "\n".join(human), "data": profile.as_dict()}, args.output)
            return EXIT_SUCCESS
        report = engine.report()
        stats = report["stats"]
        human = [
            f"fusion report for {rec['id']}: {stats['subjects']} subject(s), "
            f"{stats['fused_values']} fused value(s), "
            f"{stats['cross_domain_subjects']} cross-domain, "
            f"{stats['conflicts']} conflict(s)",
        ]
        for subject, profile in report["subjects"].items():
            domains = ", ".join(profile["domains"])
            human.append(f"  {subject}  [{domains}]")
        for conflict in report["conflicts"]:
            human.append(
                f"  ! {conflict['subject']} {conflict['attribute']}:",
            )
            human.append(
                f"      '{conflict['winner']['value']}' ({', '.join(conflict['winner']['sources'])})"
                f" beats '{conflict['loser']['value']}' ({', '.join(conflict['loser']['sources'])})"
            )
        emit({"human": "\n".join(human), "data": report}, args.output)
        return EXIT_SUCCESS
    finally:
        db.close()


def cmd_surface(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..intel import ClaimLedger, ExposureMapper

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        ledger = ClaimLedger.load_from_db(db, rec["id"])
        mapper = ExposureMapper(ledger, rec["id"])
        if args.surface_command == "map":
            graph = mapper.build_graph()
            nodes = graph.nodes()
            if not nodes:
                emit({"human": f"Surface is empty for {rec['id']} — collect discovery data first "
                               f"(e.g. intel collect … port-scan).", "data": graph.as_dict()},
                     args.output)
                return EXIT_SUCCESS
            rows = []
            for node in nodes:
                rels = ", ".join(
                    f"-{e.relation}→ {graph.node(e.dst).label if graph.node(e.dst) else '?'}"
                    for e in graph.edges() if e.src == node.node_id
                ) or "-"
                rows.append({"node": node.node_id, "confidence": f"{node.confidence:.2f}",
                             "edges": rels})
            emit({"human": f"Surface graph for {rec['id']}: {len(nodes)} node(s)",
                  "data": rows}, args.output)
            return EXIT_SUCCESS
        if args.surface_command == "exposure":
            summary = mapper.summary()
            rows = []
            for host in summary["hosts"]:
                rows.append({
                    "host": host["host"],
                    "ips": ",".join(host["ips"]) or "-",
                    "open_ports": ",".join(host["open_ports"]) or "-",
                    "products": ",".join(
                        f"{p}:{'/'.join(labels)}"
                        for p, labels in host["products"].items()
                    ) or "-",
                    "lateral_hints": ",".join(
                        f"{p}→{','.join(peers)}" for p, peers in host["lateral_hints"].items()
                    ) or "-",
                })
            stats = summary["stats"]
            emit({"human": f"Exposure map for {rec['id']}: {stats['hosts']} host(s), "
                           f"{stats['distinct_open_ports']} distinct open port(s)",
                  "data": rows}, args.output)
            return EXIT_SUCCESS
        if args.surface_command == "build":
            from ..intel import RelationshipGraphStore

            store = RelationshipGraphStore(ledger, rec["id"], db)
            stats = store.build()
            emit({"human": f"Relationship graph built for {rec['id']}: "
                           f"{stats['nodes']} node(s), {stats['edges']} edge(s)",
                  "data": stats}, args.output)
            return EXIT_SUCCESS
        if args.surface_command == "show":
            from ..intel import RelationshipGraphStore

            store = RelationshipGraphStore(ledger, rec["id"], db)
            graph = store.as_dict()
            rows = [
                {"node": n["node_id"], "kind": n["kind"], "label": n["label"],
                 "confidence": f"{n['confidence']:.2f}"}
                for n in graph["nodes"]
            ]
            edge_rows = [{"src": e["src"], "relation": e["relation"], "dst": e["dst"]}
                         for e in graph["edges"]]
            human_lines = [f"Persisted graph for {rec['id']}: {len(rows)} node(s), "
                           f"{len(edge_rows)} edge(s)"]
            human_lines += [f"  {r['node']} ({r['kind']}, conf={r['confidence']})" for r in rows]
            human_lines += [f"    -{e['relation']}→ {e['dst']}" for e in edge_rows]
            emit({"human": "\n".join(human_lines),
                  "data": {"nodes": rows, "edges": edge_rows}}, args.output)
            return EXIT_SUCCESS
        if args.surface_command == "paths":
            from ..intel import RelationshipGraphStore

            store = RelationshipGraphStore(ledger, rec["id"], db)
            found = store.paths(args.src, args.dst)
            rows = [{"path": " → ".join(p)} for p in found]
            emit({"human": (f"{len(found)} path(s) from {args.src} to {args.dst}"
                            if found else f"No path from {args.src} to {args.dst}"),
                  "data": rows}, args.output)
            return EXIT_SUCCESS if found else 1
        if args.surface_command == "related":
            from ..intel import RelationshipGraphStore

            store = RelationshipGraphStore(ledger, rec["id"], db)
            peers = store.related(args.node)
            rows = [{"node_id": p["node_id"], "shared": ",".join(p["shared"])}
                    for p in peers]
            emit({"human": f"{len(rows)} node(s) related to {args.node}",
                  "data": rows}, args.output)
            return EXIT_SUCCESS
        raise UsageError(f"Unknown surface subcommand '{args.surface_command}'")
    finally:
        db.close()


def _make_coverage_planner(case_id: str, db):
    """Coverage-driven planner: vuln-coverage blind spots become proposals.

    Reads the case ledger once, hands the planner a bounded plan of the
    un-probed classes; the proposals then flow through the SAME validation
    (unknown action/param = rejection) and the broker's six gates as every
    other planner path. Nothing here decides — the gates do.
    """
    from ..agent import Proposal
    from ..intel.claims import ClaimLedger
    from ..intel.vulncov import coverage_plan

    ledger = ClaimLedger.load_from_db(db, case_id)
    plan = coverage_plan(ledger, case_id)
    proposals = [
        Proposal(action=p["action"], target=p["target"],
                 params=dict(p["params"]), reason=p["reason"])
        for p in plan["proposals"]
    ]
    if not proposals:
        raise UsageError(
            "Coverage planner found nothing to propose",
            reason="Every available class is already covered, or the case "
                   "has no subjects to target.",
            action="Run recon first (agent run <case> '<goal>') or check "
                   "intel vuln-coverage.",
        )

    def coverage_planner(view):
        return proposals

    return coverage_planner


def _make_planner(plan_text: str):
    """Return the planner callable — deterministic today, LLM tomorrow."""
    if plan_text.strip():
        proposals = _parse_plan(plan_text)
        return lambda view: proposals

    def auto_planner(view):
        """Heuristic passive-first plan: DNS → whois → CT on the goal's domain."""
        import re as _re

        from ..intel.normalize import canonical_domain

        # find the first domain-looking token in the goal
        candidates = _re.findall(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+",
            view.goal,
        )
        if not candidates:
            raise UsageError(
                "No domain found in goal for the auto planner",
                reason="The heuristic planner needs a domain in the goal text.",
                action="Include a domain (e.g. 'map example.com') or pass --plan.",
            )
        domain = canonical_domain(candidates[0])
        plan = [
            _proposal("passive-dns", domain, {"record_type": "A"}),
            _proposal("passive-dns", domain, {"record_type": "MX"}),
            _proposal("passive-dns", domain, {"record_type": "NS"}),
            _proposal("whois-lookup", domain),
            _proposal("cert-transparency", domain),
        ]
        return [p for p in plan if p is not None]

    return auto_planner


def _proposal(action: str, target: str, params: dict | None = None):
    from ..agent import Proposal

    return Proposal(action=action, target=target, params=params or {},
                    reason="auto passive-first plan")


def cmd_member(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..security.rbac import MemberManager, RoleEngine

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        roles = RoleEngine(db)
        manager = MemberManager(db, audit=__import__("rebel_profiler.evidence.audit", fromlist=["AuditChain"]).AuditChain(db), actor=ctx.actor)
        if args.member_command == "add":
            if ctx.rbac_enabled:
                roles.require(rec["id"], ctx.actor, "manage_members")
            manager.add(rec["id"], args.subject, args.role, actor=ctx.actor)
            emit({"human": f"Member '{args.subject}' is now '{args.role}' on {rec['id']}.",
                  "data": {"subject": args.subject, "role": args.role}}, args.output)
        elif args.member_command == "remove":
            if ctx.rbac_enabled:
                roles.require(rec["id"], ctx.actor, "manage_members")
            manager.remove(rec["id"], args.subject, actor=ctx.actor)
            emit({"human": f"Member '{args.subject}' removed from {rec['id']}.",
                  "data": {"subject": args.subject}}, args.output)
        else:  # list
            rows = manager.list(rec["id"])
            mode = "multi-user (RBAC enforced)" if rows else "single-operator (implicit operator)"
            emit({"human": f"{len(rows)} member(s) on {rec['id']} — {mode}", "data": rows}, args.output)
    finally:
        db.close()
    return EXIT_SUCCESS


def cmd_approval(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..security.approvals import ApprovalQueue
    from ..security.rbac import RoleEngine

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        queue = ApprovalQueue(db, AuditChain(db))
        if args.approval_command == "list":
            rows = queue.list(rec["id"], args.state)
            emit({"human": f"{len(rows)} approval(s) in {rec['id']}", "data": rows}, args.output)
            return EXIT_SUCCESS
        if args.approval_command == "decide":
            if ctx.rbac_enabled:
                RoleEngine(db).require(rec["id"], ctx.actor, "approve")
            record = queue.decide(args.approval_id, args.decision, decided_by=ctx.actor)
            emit({"human": f"Approval {args.approval_id} → {record['state']} (by {ctx.actor}).",
                  "data": record}, args.output)
            return EXIT_SUCCESS
        if args.approval_command == "run":
            if ctx.rbac_enabled:
                RoleEngine(db).require(rec["id"], ctx.actor, "approve")
            from ..execution.broker import ExecutionBroker

            broker = ctx.broker(db)
            result = broker.execute_approved(args.approval_id, decided_by=ctx.actor)
            emit({"human": f"Approved action executed: {result.action} on {result.target} → {result.outcome}",
                  "data": result.as_dict()}, args.output)
            return EXIT_SUCCESS if result.outcome == "succeeded" else 1
        raise UsageError(f"Unknown approval subcommand '{args.approval_command}'")
    finally:
        db.close()


def cmd_hypothesis(ctx: AppContext, args: argparse.Namespace) -> int:
    import json as _json

    from ..evidence.audit import AuditChain as _A

    from ..intel import ClaimLedger, SourceRegistry
    from ..intel.hypotheses import HypothesisEngine, HypothesisError, render_human

    # `evaluate <hyp-id>` carries no case_id: the hypothesis id resolves the
    # case through the workspace index (regression: the shared handler read
    # args.case_id for every subcommand and crashed with an AttributeError).
    if args.hypothesis_command == "evaluate":
        for rec in ctx.list_cases():
            db = ctx.open_case(rec["id"])
            try:
                engine = HypothesisEngine(
                    db, ClaimLedger.load_from_db(db, rec["id"], SourceRegistry()))
                try:
                    hyp = engine.evaluate(args.hypothesis_id)
                except HypothesisError:
                    continue   # not in this case — keep looking
                emit({"human": f"{hyp.id} → {hyp.status}\n" + render_human([hyp]),
                      "data": hyp.as_dict()}, args.output)
                return EXIT_SUCCESS
            finally:
                db.close()
        raise UsageError(
            f"Hypothesis '{args.hypothesis_id}' not found in any case",
            action="List hypotheses with: rebel-profiler hypothesis list <case-id>")
    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        engine = HypothesisEngine(db, ClaimLedger.load_from_db(db, rec["id"], SourceRegistry()))
        if args.hypothesis_command == "add":
            try:
                criteria = _json.loads(args.criteria)
            except _json.JSONDecodeError as exc:
                # A raw traceback here violated the every-error-is-structured
                # contract; invalid criteria input is ordinary usage error.
                raise UsageError(
                    "--criteria is not valid JSON",
                    reason=f"JSON decode failed: {exc}",
                    action=('Pass a JSON list, e.g. --criteria \'[{"kind": '
                            '"exists", "subject": "h1", "claim_kind": '
                            '"ip"}]\''),
                ) from exc
            hyp = engine.add(rec["id"], args.statement, criteria, rationale=args.rationale or "")
            emit({"human": f"Hypothesis {hyp.id} recorded ({len(hyp.criteria)} criteria).",
                  "data": hyp.as_dict()}, args.output)
        else:  # list
            hyps = engine.list(rec["id"])
            emit({"human": render_human(hyps), "data": [h.as_dict() for h in hyps]}, args.output)
        return EXIT_SUCCESS
    finally:
        db.close()


def _read_text_arg(path: str | None, *, stdin_ok: bool = False) -> str:
    """Read a path argument to text. '-' (or None with stdin_ok) reads stdin.

    Replaces the deprecated argparse.FileType: a missing file becomes a
    structured UsageError instead of an interpreter-level failure.
    """
    if path in (None, "-"):
        if stdin_ok:
            return sys.stdin.read()
        raise UsageError("No input file provided",
                         action="Pass a file path as the argument.")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        raise UsageError(f"Cannot read file: {path}", reason=str(exc),
                         action="Check the path exists and is readable.")


def cmd_workflow(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..evidence.audit import AuditChain
    from ..execution.workflow import WorkflowRunner, parse_workflow

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        runner = WorkflowRunner(db, ctx.broker(db), AuditChain(db))
        if args.workflow_command == "create":
            spec = parse_workflow(_read_text_arg(args.dsl_file))
            started = runner.start(rec["id"], spec)
            emit({"human": f"Workflow '{started['name']}' created: {started['workflow_id']} "
                           f"({started['steps']} steps)", "data": started}, args.output)
        elif args.workflow_command == "run":
            if args.dsl_file is not None:
                spec = parse_workflow(_read_text_arg(args.dsl_file))
                started = runner.start(rec["id"], spec)
                status = runner.resume(rec["id"], started["workflow_id"])
            else:
                status = runner.resume(rec["id"], args.workflow_id)
            emit({"human": f"Workflow {status['workflow_id']}: {status['state']} "
                           f"({status['progress']} steps done)", "data": status}, args.output)
            return EXIT_SUCCESS if status["state"] in {"completed", "paused"} else 1
        elif args.workflow_command == "approve":
            decision = runner.approve_gate(rec["id"], args.workflow_id, args.step_key,
                                           decided_by=ctx.actor, approve=not args.deny)
            emit({"human": f"Gate '{args.step_key}' {'approved' if decision['approved'] else 'denied'}"
                           f" by {ctx.actor}.", "data": decision}, args.output)
        else:  # status
            status = runner.status(rec["id"], args.workflow_id)
            lines = [f"Workflow {status['workflow_id']} '{status['name']}': {status['state']}"
                     f" ({status['progress']})"]
            for step in status["steps"]:
                lines.append(f"  {step['step']:20} {step['kind']:10} {step['state']}")
            emit({"human": "\n".join(lines), "data": status}, args.output)
        return EXIT_SUCCESS
    finally:
        db.close()


def cmd_schedule(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..evidence.audit import AuditChain
    from ..execution.scheduler import Scheduler

    if args.schedule_command == "tick":
        # A tick is a global scheduler pass: schedules live in per-case
        # databases, so sweep every active case in the workspace.
        report = {"now": 0.0, "evaluated": 0, "results": []}
        for case_rec in ctx.list_cases():
            if case_rec.get("status") != "active":
                continue
            case_db = ctx.open_case(case_rec["id"])
            try:
                scheduler = Scheduler(case_db, ctx.broker(case_db), AuditChain(case_db))
                case_report = scheduler.tick()
            finally:
                case_db.close()
            report["now"] = case_report["now"]
            report["evaluated"] += case_report["evaluated"]
            report["results"].extend(case_report["results"])
        emit({"human": f"Scheduler tick: {report['evaluated']} schedule(s) evaluated",
              "data": report}, args.output)
        return EXIT_SUCCESS

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        scheduler = Scheduler(db, ctx.broker(db), AuditChain(db))
        if args.schedule_command == "add":
            record = scheduler.schedule(
                rec["id"], action=args.action or "", target=args.target or "",
                params=_params(args.param),
                not_before=args.not_before, not_after=args.not_after,
                cron=args.cron or "", workflow_spec=args.workflow_spec or "",
            )
            emit({"human": f"Schedule {record['schedule_id']} active"
                           f" (window: {record['not_before']} → {record['not_after']})",
                  "data": record}, args.output)
        elif args.schedule_command == "pause":
            db.set_schedule_state(args.schedule_id, "paused")
            emit({"human": f"Schedule {args.schedule_id} paused.", "data": {"id": args.schedule_id}}, args.output)
        else:  # list
            rows = [dict(r) for r in db.schedules_for(rec["id"], args.state)]
            emit({"human": f"{len(rows)} schedule(s) in {rec['id']}", "data": rows}, args.output)
        return EXIT_SUCCESS
    finally:
        db.close()


def cmd_search(ctx: AppContext, args: argparse.Namespace) -> int:
    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        if args.search_command == "rebuild":
            count = db.rebuild_search_index(rec["id"])
            emit({"human": f"Search index rebuilt: {count} document(s).", "data": {"docs": count}}, args.output)
        else:
            results = db.search_docs(rec["id"], " ".join(args.terms))
            emit({"human": f"{len(results)} result(s) for '{' '.join(args.terms)}':",
                  "data": results}, args.output)
        return EXIT_SUCCESS
    finally:
        db.close()


def cmd_credential(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..security.credentials import CredentialBroker
    from ..security.rbac import RoleEngine

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        roles = RoleEngine(db) if ctx.rbac_enabled else None
        broker = CredentialBroker(db, AuditChain(db))
        if args.credential_command == "store":
            import getpass

            secret = args.secret or getpass.getpass(f"Secret for '{args.name}': ")
            record = broker.store(rec["id"], name=args.name, secret=secret,
                                  scopes=args.scope or [], notes=args.note or "",
                                  actor=ctx.actor)
            emit({"human": f"Credential '{record['name']}' stored (encrypted, audit-chained).",
                  "data": record}, args.output)
        elif args.credential_command == "use":
            if roles:
                roles.require(rec["id"], ctx.actor, "manage_credentials")
            secret = broker.use(rec["id"], args.name, purpose=args.purpose,
                                actor=ctx.actor)
            emit({"human": "secret delivered to caller (not printed)" + (f": {secret}" if args.show else ""),
                  "data": {"name": args.name, "purpose": args.purpose,
                           "delivered": True, "redacted": not args.show}}, args.output)
        elif args.credential_command == "delete":
            if roles:
                roles.require(rec["id"], ctx.actor, "manage_credentials")
            broker.delete(rec["id"], args.name, actor=ctx.actor)
            emit({"human": f"Credential '{args.name}' deleted.", "data": {"name": args.name}}, args.output)
        else:  # list
            rows = broker.list(rec["id"])
            emit({"human": f"{len(rows)} credential(s) — metadata only:", "data": rows}, args.output)
        return EXIT_SUCCESS
    finally:
        db.close()


def cmd_plugin(ctx: AppContext, args: argparse.Namespace) -> int:
    import os

    from ..core.plugins import load_plugin, sign_manifest

    if args.plugin_command == "sign":
        secret = os.environ.get("RP_PLUGIN_SECRET", "")
        if not secret:
            raise UsageError("Set RP_PLUGIN_SECRET to sign plugin manifests")
        signature = sign_manifest(args.plugin_dir / "plugin.toml", secret)
        (args.plugin_dir / "signature").write_text(signature + "\n")
        emit({"human": f"Manifest signed: {args.plugin_dir / 'signature'}",
              "data": {"plugin_dir": str(args.plugin_dir)}}, args.output)
        return EXIT_SUCCESS
    permissions = [p.strip() for p in args.grant.split(",") if p.strip()]
    handle = load_plugin(args.plugin_dir, secret=os.environ.get("RP_PLUGIN_SECRET", ""),
                         granted=permissions, allow_unsigned=args.allow_unsigned)
    rows = [handle.as_dict()]
    emit({"human": f"Plugin '{handle.manifest.name}' loaded with trust '{handle.trust}'"
                   f" ({len(handle.adapters)} adapter(s))",
          "data": rows}, args.output)
    return EXIT_SUCCESS


def cmd_events(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..core.events import list_events, list_webhooks, register_webhook

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        if args.events_command == "register":
            import os

            hook = register_webhook(db, rec["id"], url=args.url,
                                    secret=args.secret or os.urandom(24).hex(),
                                    events=[e for e in args.events.split(",") if e])
            emit({"human": f"Webhook {hook['id']} registered for {hook['events']}",
                  "data": hook}, args.output)
        elif args.events_command == "webhooks":
            hooks = list_webhooks(db, rec["id"])
            emit({"human": f"{len(hooks)} webhook(s) registered", "data": hooks}, args.output)
        else:  # show
            events = list_events(db, rec["id"], limit=args.limit)
            emit({"human": f"{len(events)} recent event(s)", "data": events}, args.output)
        return EXIT_SUCCESS
    finally:
        db.close()


def cmd_serve(ctx: AppContext, args: argparse.Namespace) -> int:
    import hashlib
    import os

    from ..core.events import ApiGateway

    rec = ctx.find_case(args.case_id)
    token = os.environ.get("RP_API_TOKEN", "") or args.token or ""
    if token and len(token) != 64:
        token = hashlib.sha256(token.encode()).hexdigest()
    gateway = ApiGateway(ctx.open_case(rec["id"]), rec["id"], token=token)

    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class ApiHandler(BaseHTTPRequestHandler):
        def _json(self, code, data):
            body = json.dumps(data, sort_keys=True, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            code, data = gateway.handle(self.command, self.path,
                                        self.headers.get("Authorization", ""))
            self._json(code, data)

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer((args.bind, args.port), ApiHandler)
    emit({"human": f"API gateway on http://{args.bind}:{args.port} for {rec['id']}"
                   f" ({'token-gated' if token else 'NO TOKEN — disabled)'})",
          "data": {"bind": args.bind, "port": args.port}}, "human")
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return EXIT_SUCCESS


def cmd_ops(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..core import ops

    if args.ops_command == "backup":
        rec = ctx.find_case(args.case_id)
        record = ops.backup_case(ctx.case_dir(rec["id"]), Path(args.out))
        emit({"human": f"Backup written: {record['backup']} ({record['members']} members,"
                       f" sha256 {record['sha256'][:16]}…)", "data": record}, args.output)
        return EXIT_SUCCESS
    if args.ops_command == "restore":
        record = ops.restore_case(Path(args.backup), Path(args.dest))
        emit({"human": f"Restored {record['restored']} member(s) into {record['dest']}",
              "data": record}, args.output)
        return EXIT_SUCCESS
    if args.ops_command == "package":
        import rebel_profiler

        root = Path(rebel_profiler.__file__).parent
        record = ops.package_zipapp(root, Path(args.out))
        emit({"human": f"Zipapp: {record['zipapp']} (sha256 {record['sha256'][:16]}…)",
              "data": record}, args.output)
        return EXIT_SUCCESS
    if args.ops_command == "update":
        import rebel_profiler

        record = ops.update_zipapp(
            Path(args.target), expect_version=rebel_profiler.__version__)
        if record.get("updated"):
            human = (f"Updated → v{record['version']} "
                     f"(sha256 {record['sha256'][:16]}…, "
                     f"{record['size']} bytes) at {record['target']}")
        else:
            human = f"No update: {record.get('reason', 'already current')} " \
                    f"(v{record.get('version', '?')})"
        emit({"human": human, "data": record}, args.output)
        return EXIT_SUCCESS
    if args.ops_command == "check":
        rec = ctx.find_case(args.case_id)
        db = ctx.open_case(rec["id"])
        try:
            report = ops.check_and_repair(db, rec["id"], repair=args.repair)
        finally:
            db.close()
        lines = [f"self-check {rec['id']}: {'healthy' if report['healthy'] else 'PROBLEMS'}"]
        lines += [f"  ! {p}" for p in report["problems"]]
        lines += [f"  ✓ {r}" for r in report["repaired"]]
        lines += [f"  → operator: {p}" for p in report["needs_operator"]]
        emit({"human": "\n".join(lines), "data": report}, args.output)
        return EXIT_SUCCESS if report["healthy"] else 1
    raise UsageError(f"Unknown ops subcommand '{args.ops_command}'")


def cmd_worker(ctx: AppContext, args: argparse.Namespace) -> int:
    from ..execution.worker import JobPlane, WorkerDaemon

    # config is a plain dict — read it through core.config.get (the earlier
    # isinstance(..., callable) probe here was a TypeError waiting to fire).
    from ..core.config import get as _get

    queue_dir = Path(_get(ctx.config, "paths.queue_dir", "") or (ctx.data_dir / "queue"))
    plane = JobPlane(queue_dir)
    if args.worker_command == "submit":
        rec = ctx.find_case(args.case_id)
        envelope = plane.submit(case_id=rec["id"], action=args.action,
                                target=args.target, params=_params(args.param),
                                requested_by="operator", reason=args.reason or "")
        emit({"human": f"Job {envelope['job_id']} submitted (SYN sent, seq={envelope['seq']})",
              "data": envelope}, args.output)
        return EXIT_SUCCESS
    if args.worker_command == "status":
        st = plane.status(args.job_id)
        emit({"human": f"Job {args.job_id}: {st['state']} ({st['phase']})",
              "data": st}, args.output)
        return EXIT_SUCCESS
    if args.worker_command == "list":
        jobs = plane.list_jobs()
        emit({"human": f"{len(jobs)} job(s) in queue", "data": jobs}, args.output)
        return EXIT_SUCCESS
    if args.worker_command == "run":
        rec = ctx.find_case(args.case_id)
        db = ctx.open_case(rec["id"])
        try:
            from ..evidence.audit import AuditChain
            from ..intel import ClaimLedger, CollectionPipeline, SourceRegistry

            def collect(case_id, result, params):
                pipeline = CollectionPipeline(
                    ClaimLedger.load_from_db(db, case_id, SourceRegistry()),
                    ctx.evidence_store(db, case_id), SourceRegistry(), db=db)
                return pipeline.ingest(
                    case_id, action=result.action, target=result.target,
                    stdout=result.stdout, stderr=result.stderr,
                    returncode=result.returncode or 1, task_id=result.task_id,
                    evidence_id=result.evidence_id, params=params)

            daemon = WorkerDaemon(queue_dir, broker=ctx.broker(db), audit=AuditChain(db),
                                  interval=args.interval, max_runs=args.max_runs,
                                  collect=collect)
            daemon.run_forever(once=args.once)
            emit({"human": "worker pass complete", "data": {"once": args.once}}, args.output)
        finally:
            db.close()
        return EXIT_SUCCESS
    raise UsageError(f"Unknown worker subcommand '{args.worker_command}'")


def cmd_browser(ctx: AppContext, args: argparse.Namespace) -> int:
    import os

    from ..browser import BrowserBridge, BrowserJobStore

    if args.browser_command == "result":
        # Result files live in the workspace queue — no case lookup needed
        # (and the result subcommand takes a job_id, not a case_id).
        store = BrowserJobStore(ctx.data_dir / "queue")
        result = store.load_result(args.job_id)
        if result is None:
            emit({"human": f"No result yet for {args.job_id} (extension may still be working).",
                  "data": {"job_id": args.job_id, "state": "pending"}}, args.output)
            return 1
        emit({"human": f"Job {args.job_id}: {result.get('state')}"
                       + (f" — {result.get('error', '')}" if result.get("error") else ""),
              "data": result}, args.output)
        return EXIT_SUCCESS if result.get("state") == "done" else 1
    rec = ctx.find_case(args.case_id)
    if args.browser_command == "submit":
        store = BrowserJobStore(ctx.data_dir / "queue")
        actions = None
        if args.actions:
            try:
                actions = json.loads(args.actions)
            except json.JSONDecodeError as exc:
                raise UsageError(f"--actions is not valid JSON: {exc}")
        envelope = store.submit(case_id=rec["id"], url=args.url,
                                extract=[e for e in args.extract.split(",") if e],
                                actions=actions, approved=args.approved,
                                requested_by="operator", reason=args.reason or "")
        kind = "interact" if actions else "extract"
        emit({"human": f"Browser {kind} job {envelope['job_id']} submitted for {args.url}"
                       + (" [APPROVED]" if args.approved else ""),
              "data": envelope}, args.output)
        return EXIT_SUCCESS
    if args.browser_command == "serve":
        db = ctx.open_case(rec["id"])
        try:
            bridge = BrowserBridge(
                rec["id"], queue_dir=ctx.data_dir / "queue",
                scope_engine=ctx.scope_engine(),
                evidence=ctx.evidence_store(db, rec["id"]),
                audit=AuditChain(db), token=os.environ.get("RP_BROWSER_TOKEN", ""))
            from ..browser import serve_browser_bridge

            emit({"human": f"Browser bridge on 127.0.0.1:{args.port} for {rec['id']}",
                  "data": {"port": args.port}}, "human")
            serve_browser_bridge(bridge, port=args.port, once=args.once)
        finally:
            db.close()
        return EXIT_SUCCESS
    raise UsageError(f"Unknown browser subcommand '{args.browser_command}'")


def cmd_agent_auto(ctx: AppContext, args: argparse.Namespace) -> int:
    """The Autonomous Engineer: LLM plans, repairs and forges its own tools."""
    from ..llm.autonomous import AutonomousEngineer

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        engineer = AutonomousEngineer(
            rec["id"], args.goal, ctx=ctx, db=db,
            model=getattr(args, "llm", ""),
            max_actions=args.max_actions,
            max_repair_attempts=args.max_repair_attempts,
        )
        report = engineer.run()
        emit({"human": report["report_human"], "data": report}, args.output)
        return EXIT_SUCCESS
    finally:
        db.close()


def cmd_agent_chat(ctx: AppContext, args: argparse.Namespace) -> int:
    """The Hermes agent: ChatML tool-calling loop (one <tool_call> per turn)."""
    if not str(getattr(args, "goal", "") or "").strip():
        return _cmd_agent_chat_repl(ctx, args)
    from ..llm.inference import ModelPlane
    from ..llm.planner import _plane_from_env
    from ..llm.budget import resolve_limits
    from ..llm.hermes import HermesAgentLoop, render_human

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        prefer = os.environ.get("RP_LLM__ENGINE", "").strip().lower()
        plane = ModelPlane(
            limits=resolve_limits(tier=_llm_tier_arg(args)),
            prefer_engine=prefer if prefer in {"tiny", "airllm", "external", "gguf", "native", "hermes"} else None)
        try:
            if plane.engine is None:
                plane.select_engine(_hermes_model_pin(ctx, args))
            loop = HermesAgentLoop(
                rec["id"], args.goal, plane=plane,
                broker=ctx.broker(db), evidence=ctx.evidence_store(db, rec["id"]),
                db=db, max_turns=args.max_turns, ctx=ctx,
            )
            report = loop.run()
        finally:
            plane.unload()   # the CLI process never stays heavy
        emit({"human": render_human(report), "data": report}, args.output)
        return EXIT_SUCCESS
    finally:
        db.close()


def _hermes_model_pin(ctx, args) -> str:
    """Model pin for Hermes: --llm flag > RP_LLM__MODEL > config profile."""
    return (str(getattr(args, "llm", "") or "")
            or os.environ.get("RP_LLM__MODEL", "").strip()
            or str(_cfg_get(ctx.config, "llm.model", "") or ""))


def _llm_tier_arg(args) -> str | None:
    """Explicit --tier pin on an LLM-backed command (None = auto-fit)."""
    return getattr(args, "tier", None)


def _hermes_repl_plane(args) -> "ModelPlane":
    """Resolve the ModelPlane for the interactive Hermes REPL."""
    from ..llm.budget import resolve_limits
    from ..llm.inference import ModelPlane

    prefer = os.environ.get("RP_LLM__ENGINE", "").strip().lower()
    return ModelPlane(
        limits=resolve_limits(tier=_llm_tier_arg(args)),
        prefer_engine=prefer if prefer in {"tiny", "airllm", "external", "gguf", "native", "hermes"} else None)


def _cmd_agent_chat_repl(ctx: AppContext, args: argparse.Namespace,
                         plane=None) -> int:
    """`agent chat` entry: resolve the case, then run the shared Hermes REPL."""
    return _hermes_repl(ctx, ctx.find_case(args.case_id), args, plane=plane)


def _hermes_repl(ctx: AppContext, case_rec: dict, args: argparse.Namespace,
                 plane=None, seed: str = "") -> int:
    """The Hermes shell (cloned from the Hermes agent CLI): banner, slash
    commands, and one gated agent loop per plain-language line.

    ``seed`` runs first (a query on a real TTY opens the session and
    submits itself as the first turn), then the prompt keeps accepting
    lines.
    """
    from ..llm.hermes_shell import run_repl

    if seed:
        try:
            args.goal_seed = seed
        except AttributeError:
            pass
    return run_repl(ctx, case_rec, args, plane or _hermes_repl_plane(args))


def _resolve_session_case(ctx: AppContext, want: str = "") -> dict:
    """Pick the case a front-door session works on — zero ceremony.

    Explicit --case wins; otherwise the newest ACTIVE case, else the newest
    case of any status (the model can scope + activate it by chat); else a
    fresh case is created so the very first chat just works.
    """
    if str(want or "").strip():
        return ctx.find_case(str(want).strip())
    cases = ctx.list_cases()
    for rec in reversed(cases):
        if rec.get("status") == "active":
            return rec
    if cases:
        return cases[-1]
    return ctx.create_case("Hermes Session", "created by the hermes front door")


def cmd_hermes(ctx: AppContext, args: argparse.Namespace, plane=None) -> int:
    """The Hermes front door: ONE command, plain language in, LLM answers out.

    No case-id ceremony: the case is picked (or created) automatically, and
    the model holds the operator tool surface — case + scope + reports +
    verification + surface + fusion + browser + knowledge — alongside the
    gated adapter registry. Everything the old CLI did by subcommand maze is
    now reachable by asking.
    """
    case_rec = _resolve_session_case(ctx, getattr(args, "case", ""))
    goal_raw = getattr(args, "goal", "") or ""
    goal = " ".join(goal_raw) if isinstance(goal_raw, list) else str(goal_raw)
    goal = goal.strip()
    if not goal:
        return _hermes_repl(ctx, case_rec, args, plane=plane)
    # Hermes-agent CLI semantics: a query on a real TTY seeds an interactive
    # session; piped/oneshot answers once and exits.
    if not getattr(args, "oneshot", False) and sys.stdin.isatty():
        return _hermes_repl(ctx, case_rec, args, plane=plane, seed=goal)

    from ..llm.budget import resolve_limits
    from ..llm.hermes import HermesAgentLoop, render_human
    from ..llm.inference import ModelPlane
    from ..llm.planner import _plane_from_env

    db = ctx.open_case(case_rec["id"])
    prefer = os.environ.get("RP_LLM__ENGINE", "").strip().lower()
    plane = plane or ModelPlane(
        limits=resolve_limits(tier=_llm_tier_arg(args)),
        prefer_engine=prefer if prefer in {"tiny", "airllm", "external", "gguf", "native", "hermes"} else None)
    try:
        if plane.engine is None:
            plane.select_engine(_hermes_model_pin(ctx, args))
        loop = HermesAgentLoop(
            case_rec["id"], goal, plane=plane,
            broker=ctx.broker(db), evidence=ctx.evidence_store(db, case_rec["id"]),
            db=db, max_turns=args.max_turns, ctx=ctx,
        )
        report = loop.run()
    finally:
        plane.unload()   # the CLI process never stays heavy
        db.close()
    emit({"human": render_human(report), "data": report}, args.output)
    return EXIT_SUCCESS


def cmd_agent_work(ctx: AppContext, args: argparse.Namespace) -> int:
    """The self-repair agent loop: work list → error log → revise → ask user."""
    from ..agent.repair import SelfRepairSession, render_session_human

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        audit = AuditChain(db)
        session = SelfRepairSession(
            rec["id"], args.goal, broker=ctx.broker(db),
            ledger=ClaimLedger(SourceRegistry()),
            evidence=ctx.evidence_store(db, rec["id"]), db=db, audit=audit,
            max_actions=args.max_actions,
            max_repair_attempts=args.max_repair_attempts,
        )
        if getattr(args, "llm", "") or _cfg_get(ctx.config, "llm.model", ""):
            planner = _make_llm_planner(getattr(args, "llm", ""),
                                        ctx.broker(db).adapters,
                                        config=ctx.config)
        else:
            planner = _make_planner(args.plan)
        reviser = _make_reviser(args.plan)
        report = session.run(planner, reviser=reviser)
        emit({"human": render_session_human(report), "data": report}, args.output)
        # Exit 0 even when blocked: the session awaits the operator by design.
        return EXIT_SUCCESS
    finally:
        db.close()


def _make_reviser(plan_text: str):
    """Deterministic reviser for --plan sessions; LLM reviser plugs in later."""
    def reviser(feedback):
        return None   # deterministic reviser gives up after first failure
    return reviser


def _make_llm_planner(model: str, registry, *, config=None):
    """Build the LLM planner (AirLLM-mode) wired to the live adapter registry.

    The plane unloads after the session — the CLI process never stays heavy.
    A config profile's [llm] model applies when no --llm flag is given, so a
    --config-file job pins its model without repeating it on every command.
    """
    from ..agent import PlannerView
    from ..llm import LlmPlanner

    if not model and config is not None:
        model = str(_cfg_get(config, "llm.model", "") or "")
    base = LlmPlanner(model=model or None, registry=registry)

    def llm_planner(view: PlannerView):
        try:
            return base(view)
        finally:
            base.plane.unload()   # unload even when the planner raises

    return llm_planner


def cmd_forge(ctx: AppContext, args: argparse.Namespace) -> int:
    """Feature Forge: the LLM extends the tool with self-written adapters."""
    from ..agent.forge import FeatureForge

    forge = FeatureForge(ctx.data_dir, audit=None)
    if args.forge_command == "propose":
        source = _read_text_arg(args.source_file, stdin_ok=True)
        if not source.strip():
            raise UsageError(
                "No adapter source provided",
                action="Pass a .py file or pipe source via stdin.")
        test_cases = []
        if args.test_cases:
            try:
                test_cases = json.loads(args.test_cases)
            except json.JSONDecodeError as exc:
                raise UsageError(f"--test-cases is not valid JSON: {exc}")
        result = forge.propose(source, author=args.author or ctx.actor,
                               test_cases=test_cases)
        if result.accepted:
            human = [f"ACCEPTED: module {result.module_name}"
                     f" ({', '.join(result.adapters)})",
                     "  static gate: clean; sandbox test: passed",
                     "  adapters are now registerable (see forge list)"]
        else:
            human = ["REJECTED — the safety gate blocked this code:"]
            for f in result.findings:
                human.append(f"  [{f.rule}] {f.message}")
            human.append("  Fix the findings and re-propose.")
        emit({"human": "\n".join(human), "data": result.as_dict()}, args.output)
        return EXIT_SUCCESS if result.accepted else 1
    if args.forge_command == "list":
        rows = forge.list_modules()
        emit({"human": f"{len(rows)} forged module(s):", "data": rows}, args.output)
        return EXIT_SUCCESS
    if args.forge_command == "register":
        from ..execution import AdapterRegistry

        registry = AdapterRegistry()
        registered = forge.register_into(registry)
        emit({"human": f"{len(registered)} forged adapter(s) registered: "
                       f"{', '.join(registered)}",
              "data": {"adapters": registered}}, args.output)
        return EXIT_SUCCESS
    raise UsageError(f"Unknown forge subcommand '{args.forge_command}'")


def cmd_system(ctx: AppContext, args: argparse.Namespace) -> int:
    """Privileged system jobs: whitelisted templates + approval gate."""
    from ..execution.system_jobs import SystemJobDaemon, SystemJobStore

    queue_dir = ctx.data_dir / "queue"
    store = SystemJobStore(queue_dir)
    if args.system_command == "submit":
        rec = ctx.find_case(args.case_id)
        envelope = store.submit(case_id=rec["id"], job_type=args.job_type,
                                params=_params(args.param),
                                requested_by=ctx.actor, reason=args.reason or "")
        emit({"human": f"System job {envelope['job_id']} submitted"
                       f" ({args.job_type}, sudo={envelope['params']['sudo']})",
              "data": envelope}, args.output)
        return EXIT_SUCCESS
    if args.system_command == "run":
        rec = ctx.find_case(args.case_id)
        db = ctx.open_case(rec["id"])
        try:
            daemon = SystemJobDaemon(queue_dir, db=db, audit=AuditChain(db),
                                     max_runs=args.max_runs)
            handled = daemon.poll_once()
            emit({"human": f"{len(handled)} system job(s) processed:",
                  "data": handled}, args.output)
        finally:
            db.close()
        return EXIT_SUCCESS
    if args.system_command == "templates":
        from ..execution.system_jobs import SYSTEM_JOB_TEMPLATES

        rows = [{"job_type": t.key, "sudo": str(t.use_sudo),
                 "description": t.description,
                 "params": ", ".join(t.params) or "-"}
                for t in SYSTEM_JOB_TEMPLATES.values()]
        emit({"human": f"{len(rows)} whitelisted system job type(s):",
              "data": rows}, args.output)
        return EXIT_SUCCESS
    raise UsageError(f"Unknown system subcommand '{args.system_command}'")


def cmd_detection(ctx: AppContext, args: argparse.Namespace) -> int:
    """Detection engineering: benign test artifacts + IoC/YARA rules."""
    from ..intel.detection import ARTIFACT_KINDS, DetectionLab

    # `kinds` is a static catalog — it needs no case, so it must not demand
    # one (regression: the shared handler read args.case_id for every
    # subcommand and crashed with a raw AttributeError on `detection kinds`).
    if args.detection_command == "kinds":
        rows = [{"kind": k, "risk": v[0], "description": v[1]}
                for k, v in sorted(ARTIFACT_KINDS.items())]
        emit({"human": "Available benign artifact kinds:", "data": rows}, args.output)
        return EXIT_SUCCESS

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        lab = DetectionLab(rec["id"], case_dir=ctx.case_dir(rec["id"]),
                           evidence=ctx.evidence_store(db, rec["id"]),
                           audit=AuditChain(db))
        if args.detection_command == "generate":
            iocs = {}
            for pair in args.ioc or []:
                key, _, value = pair.partition("=")
                iocs.setdefault(key.strip(), []).append(value.strip())
            record = lab.generate(args.kind, name=args.name,
                                  ioc_text=args.text or "", iocs=iocs or None,
                                  canary_note=args.note or "")
            human = [f"Generated {args.kind}: {record['path']}",
                     f"  sha256 : {record['sha256'][:24]}…",
                     f"  risk   : {record['risk']}  evidence: {record['evidence_id']}"]
            if record.get("iocs"):
                for bucket, values in record["iocs"].items():
                    human.append(f"  {bucket}: {', '.join(values[:8])}")
            emit({"human": "\n".join(human), "data": record}, args.output)
        else:  # list
            rows = lab.list_artifacts()
            emit({"human": f"{len(rows)} artifact(s) in the detections folder:",
                  "data": rows}, args.output)
        return EXIT_SUCCESS
    finally:
        db.close()


def cmd_complaint(ctx: AppContext, args: argparse.Namespace) -> int:
    """Law-enforcement complaint packages (FIA CCW / IC3 / CERT)."""
    from ..intel.complaint import ComplaintPackageBuilder, render_complaint_human

    rec = ctx.find_case(args.case_id)
    db = ctx.open_case(rec["id"])
    try:
        builder = ComplaintPackageBuilder(
            rec["id"], case_dir=ctx.case_dir(rec["id"]), db=db,
            evidence=ctx.evidence_store(db, rec["id"]), audit=AuditChain(db))
        if args.complaint_command == "build":
            record = builder.build(
                agency=args.agency, incident_type=args.incident_type,
                narrative=args.narrative or "",
                complainant=args.complainant or "",
                subject_targets=[t for t in args.targets.split(",") if t])
            package = json.loads(Path(record["path"]).read_text())
            emit({"human": render_complaint_human(record, package),
                  "data": record}, args.output)
        else:  # list
            rows = builder.list_packages()
            emit({"human": f"{len(rows)} complaint package(s):", "data": rows}, args.output)
        return EXIT_SUCCESS
    finally:
        db.close()


def _llm_script(ctx: AppContext, args: argparse.Namespace) -> int:
    """Script plane: the LLM writes a code file; the daemon executes it."""
    from ..llm.codescript import (
        default_script_dir,
        list_scripts,
        load_script_result,
        submit_script,
    )

    def _script_dir() -> Path:
        return Path(getattr(args, "script_dir", "") or default_script_dir(ctx.data_dir))

    if args.script_command == "submit":
        source = ""
        if getattr(args, "file", None):
            source = Path(args.file).read_text()
        elif args.source:
            source = args.source
        else:
            import sys as _sys

            source = _sys.stdin.read() if not _sys.stdin.isatty() else ""
        payload = json.loads(args.payload) if args.payload else {}
        envelope = submit_script(
            source, script_dir=_script_dir(), payload=payload,
            name=args.name or "", requested_by="operator",
            timeout_s=args.timeout)
        emit({"human": (f"Script {envelope['script_id']} submitted (stored, not "
                        "executed — the daemon gates it, then runs it)"),
              "data": envelope}, args.output)
        return EXIT_SUCCESS

    if args.script_command == "result":
        result = load_script_result(args.script_id, script_dir=_script_dir())
        if result is None:
            emit({"human": f"Script {args.script_id}: no result yet (daemon "
                           "still gating/executing?)",
                  "data": {"script_id": args.script_id, "state": "pending"}}, args.output)
            return EXIT_SUCCESS
        if result.get("state") == "done":
            human = (f"Script {args.script_id}: done in {result.get('elapsed_s', '?')}s\n"
                     f"result: {json.dumps(result.get('result'), default=str)[:2000]}")
        else:
            human = (f"Script {args.script_id}: {result.get('state')} — "
                     f"{result.get('error', '')}\nfix: {result.get('fix', '')}")
        emit({"human": human, "data": result}, args.output)
        return EXIT_SUCCESS

    if args.script_command == "list":
        rows = list_scripts(_script_dir())
        emit({"human": f"{len(rows)} script(s) in the queue", "data": rows}, args.output)
        return EXIT_SUCCESS

    if args.script_command == "author":
        from ..llm.codegen import author_script

        payload = json.loads(args.payload) if args.payload else {}
        envelope = author_script(
            args.goal, script_dir=_script_dir(), payload=payload,
            name=args.name, model=args.model or None)
        engine = envelope.get("generator", {}).get("engine", "?")
        emit({"human": (f"The {engine} engine wrote script {envelope['script_id']} "
                        f"({len(envelope['source'].splitlines())} lines) for: "
                        f"{args.goal}\n"
                        "Stored, NOT executed. The daemon gates it, then runs it:"
                        f"\n  rebel-profiler llm script run --once "
                        f"--script-dir {_script_dir()}"
                        f"\n  rebel-profiler llm script result "
                        f"{envelope['script_id']} --script-dir {_script_dir()}"),
              "data": envelope}, args.output)
        return EXIT_SUCCESS

    if args.script_command == "retry":
        from ..llm.codegen import retry_script

        envelope = retry_script(args.script_id, script_dir=_script_dir(),
                                model=args.model or None)
        emit({"human": (f"Re-authored script {envelope['script_id']} from the failure "
                        f"of {args.script_id} ({envelope['fixed_from']['state']}).\n"
                        f"  was: {envelope['fixed_from']['error'][:200]}\n"
                        "Stored, NOT executed — run the daemon to gate and run it."),
              "data": envelope}, args.output)
        return EXIT_SUCCESS

    if args.script_command == "run":
        from ..llm.codescript import ScriptDaemon

        daemon = ScriptDaemon(
            _script_dir(), interval=args.interval,
            data_dir=ctx.data_dir, max_runs=args.max_runs)
        if args.once:
            handled = daemon.poll_once()
            emit({"human": f"one pass: {len(handled)} script(s) handled",
                  "data": handled}, args.output)
            return EXIT_SUCCESS
        emit({"human": f"script daemon polling {_script_dir()} every "
                       f"{args.interval}s (Ctrl-C to stop)",
              "data": {"script_dir": str(_script_dir()), "interval": args.interval}},
             args.output)
        daemon.run_forever()
        return EXIT_SUCCESS

    raise UsageError(f"Unknown llm script command '{args.script_command}'")


def cmd_llm(ctx: AppContext, args: argparse.Namespace) -> int:
    """AirLLM-mode: hardware budget, engines, generation, planner, daemon."""
    from ..llm import (
        LlmDaemon,
        ModelPlane,
        default_queue_dir,
        load_result,
        read_budget,
        recommend,
        resolve_limits,
        submit_job,
    )

    def _queue_dir() -> Path:
        return Path(getattr(args, "queue_dir", "") or default_queue_dir(ctx.data_dir))

    def _limits():
        # Job profile ([llm] section of --config-file) pins tier/model caps;
        # live RP_LLM__* env still wins; explicit --tier wins over both.
        return resolve_limits(tier=getattr(args, "tier", None) or None,
                              config=ctx.config)

    def _model() -> str:
        # Model precedence: --model flag > RP_LLM__MODEL env > config profile
        # [llm] model > default.
        return (str(getattr(args, "model", "") or "")
                or os.environ.get("RP_LLM__MODEL", "").strip()
                or str(_cfg_get(ctx.config, "llm.model", "") or "")
                or "Qwen/Qwen3-4B")

    if args.llm_command == "status":
        budget = read_budget()
        limits = _limits()
        plane = ModelPlane(limits=limits)
        try:
            import importlib.util

            airllm_ok = importlib.util.find_spec("airllm") is not None
        except Exception:
            airllm_ok = False
        from ..llm.hermes_agent import engine_env_status as _hermes_env

        hermes_env = _hermes_env()
        payload = {
            "budget": budget,
            "recommended_tier": recommend(budget),
            "tier": limits.tier,
            "limits": {
                "max_rss_mb": limits.max_rss_mb,
                "max_context_tokens": limits.max_context_tokens,
                "max_new_tokens": limits.max_new_tokens,
                "max_model_b": limits.max_model_b,
                "require_compression": limits.require_compression,
                "allow_gpu": limits.allow_gpu,
            },
            "airllm_installed": airllm_ok,
            "llama_cpp_installed": _module_present("llama_cpp"),
            "torch_installed": _module_present("torch"),
            "hermes_agent": hermes_env,
            "local_models": _local_model_counts(),
            "engine": plane.engine_kind or "none",
            "model": "",
            "loaded": False,
            "device": "",
        }
        if args.load_engine:
            engine = plane.select_engine(args.load_engine)
            payload["engine"] = plane.engine_kind
            payload["model"] = getattr(engine, "model_id", "")
            payload["loaded"] = bool(engine.loaded)
            payload["device"] = getattr(engine, "last_device", "")
            payload["fallback_reason"] = plane.fallback_reason
            plane.unload()
        emit({"human": (
            f"llm status: tier={payload['tier']} "
            f"(recommended {payload['recommended_tier']})  "
            f"ram={budget['total_ram_mb']}MB  cpu_only={budget['cpu_only']}  "
            f"airllm={'yes' if airllm_ok else 'no (tiny engine fallback)'}  "
            f"hermes-agent={'yes (' + hermes_env['version'] + ')' if hermes_env['installed'] else 'not installed (RP_LLM__ENGINE=hermes unavailable)'}"
        ), "data": payload}, args.output)
        return EXIT_SUCCESS

    if args.llm_command == "models":
        from ..llm.catalog import suggest_models

        budget = read_budget()
        models = suggest_models(budget["total_ram_mb"], cpu_only=budget["cpu_only"])
        # On-disk checkpoints surface first: the local engines run those with
        # NO download and NO airllm install (the local-first rule).
        local = []
        try:
            from ..llm.native import discover_local_models

            local = discover_local_models()
        except Exception:
            local = []
        gguf = []
        try:
            from ..llm.gguf import discover_local_gguf

            gguf = discover_local_gguf()
        except Exception:
            gguf = []
        emit({"human": f"{sum(1 for m in models if m['fits'])} model(s) fit this machine "
                       f"({budget['total_ram_mb']}MB RAM); "
                       f"{len(gguf)} GGUF + {len(local)} HF checkpoint(s) on disk\n"
                       "local checkpoints with their run command: "
                       "rebel-profiler llm local",
              "data": {"local_gguf": gguf, "local": local, "catalog": models}},
             args.output)
        return EXIT_SUCCESS

    if args.llm_command in {"local", "setup"}:
        from ..llm.setup import (local_models, render_local, render_setup,
                                 setup_plan)

        limits = _limits()
        if args.llm_command == "local":
            payload = local_models(limits=limits)
            emit({"human": render_local(payload), "data": payload}, args.output)
            return EXIT_SUCCESS
        plan = setup_plan(engine=getattr(args, "engine", None), limits=limits)
        emit({"human": render_setup(plan), "data": plan}, args.output)
        return EXIT_SUCCESS

    if args.llm_command == "prepare":
        # AirLLM layer-shards: bake a LOCAL checkpoint into per-layer shard
        # files (optionally 4/8-bit quantized), optionally reclaiming the
        # original disk after verification. Never touches the network.
        from ..llm.native import prepare_layer_shards

        manifest = prepare_layer_shards(
            args.model, args.out, bits=args.bits,
            delete_original=args.delete_original)
        total_mb = sum(s["bytes"] for s in manifest["shards"]) // (1024 * 1024)
        emit({"human": (f"prepared {len(manifest['shards'])} layer shard(s) "
                        f"({total_mb}MB, bits={manifest['bits']}) at {args.out}"
                        + (" — originals deleted after verification"
                           if args.delete_original else "")),
              "data": manifest}, args.output)
        return EXIT_SUCCESS

    if args.llm_command == "script":
        return _llm_script(ctx, args)

    if args.llm_command == "generate":
        limits = _limits()
        plane = ModelPlane(limits=limits, prefer_engine=args.engine)
        try:
            requested = _model()
            if getattr(args, "local", False):
                requested, _why = _best_local_model(limits)
            engine = plane.select_engine(requested, compression=args.compression)
            result = plane.generate(args.prompt, max_new_tokens=args.max_tokens)
            payload = result.as_dict()
            payload["engine_kind"] = plane.engine_kind
            payload["fallback_reason"] = plane.fallback_reason
            human = (f"[{payload['engine_kind']}/{payload['device'] or '-'}] "
                     f"{payload['input_tokens']} in → {payload['output_tokens']} out "
                     f"in {payload['elapsed_s']}s\n{result.text}")
            if plane.fallback_reason and plane.engine_kind == "tiny":
                human += f"\n(note: {plane.fallback_reason})"
            emit({"human": human, "data": payload}, args.output)
            return EXIT_SUCCESS
        finally:
            plane.unload()

    if args.llm_command == "plan":
        from ..agent import PlannerView
        from ..llm import LlmPlanner

        rec = ctx.find_case(args.case_id)
        db = ctx.open_case(rec["id"])
        try:
            planner = LlmPlanner(model=args.model or None,
                                 registry=ctx.broker(db).adapters,
                                 max_new_tokens=args.max_tokens)
            view = PlannerView(rec["id"], args.goal, ctx.broker(db).adapters)
            proposals = planner(view)
            data = [ {"action": p.action, "target": p.target,
                      "params": p.params, "reason": p.reason,
                      "capability": p.capability} for p in proposals ]
            engine = planner.plane.engine_kind
            emit({"human": f"planned {len(data)} step(s) via the {engine} engine:\n" +
                           "\n".join(f"  [{i + 1}] {d['action']} {d['target']}"
                                     f" {d['params'] or ''}" for i, d in enumerate(data)),
                  "data": {"engine": engine, "proposals": data}}, args.output)
            return EXIT_SUCCESS
        finally:
            planner.plane.unload()
            db.close()

    if args.llm_command == "submit":
        envelope = submit_job(
            args.prompt, queue_dir=_queue_dir(), model=args.model or "",
            max_new_tokens=args.max_tokens, compression=args.compression,
            requested_by="operator",
        )
        emit({"human": f"LLM job {envelope['job_id']} submitted (SYN sent, seq={envelope['seq']})",
              "data": envelope}, args.output)
        return EXIT_SUCCESS

    if args.llm_command == "data":
        # Case data reaches the model ONLY through the checksummed job file
        # and the bounded, redacted data pack — never direct DB access.
        rec = ctx.find_case(args.case_id)
        envelope = submit_job(
            queue_dir=_queue_dir(), kind="data", case_id=rec["id"],
            question=args.question, generate=not args.pack_only,
            model=args.model or "", max_new_tokens=args.max_tokens,
            requested_by="operator",
        )
        emit({"human": f"Data job {envelope['job_id']} submitted for case "
                       f"{rec['id']} (SYN sent; daemon builds the pack"
                       + (", then analyzes" if not args.pack_only else "") + ")",
              "data": envelope}, args.output)
        return EXIT_SUCCESS

    if args.llm_command == "result":
        result = load_result(args.job_id, queue_dir=_queue_dir())
        if result is None:
            emit({"human": f"Job {args.job_id}: no result yet (daemon still working?)",
                  "data": {"job_id": args.job_id, "state": "pending"}}, args.output)
            return EXIT_SUCCESS
        if result.get("state") == "done":
            gen = result.get("generation", {})
            human = (f"Job {args.job_id}: done in {gen.get('elapsed_s', '?')}s "
                     f"({gen.get('engine', '?')}/{gen.get('device', '-')})\n"
                     f"{gen.get('text', '')}")
        else:
            human = (f"Job {args.job_id}: {result.get('state')} — "
                     f"{result.get('error', '')} ({result.get('fix', '')})")
        emit({"human": human, "data": result}, args.output)
        return EXIT_SUCCESS

    if args.llm_command == "daemon":
        daemon = LlmDaemon(
            _queue_dir(), interval=args.interval, model=args.model or "",
            prefer_engine=args.engine, max_runs=args.max_runs,
            db_factory=lambda case_id: ctx.open_case(case_id),
            config=ctx.config,
        )
        if args.once:
            handled = daemon.poll_once()
            emit({"human": f"one pass: {len(handled)} job(s) handled", "data": handled},
                 args.output)
            return EXIT_SUCCESS
        emit({"human": f"llm daemon polling {_queue_dir()} every {args.interval}s "
                       "(Ctrl-C to stop; the model unloads after every job)",
              "data": {"queue_dir": str(_queue_dir()), "interval": args.interval}},
             args.output)
        daemon.run_forever()
        return EXIT_SUCCESS

    raise UsageError(f"Unknown llm command '{args.llm_command}'")


def _case_program(db, case_id: str) -> str:
    """Recover the bug-bounty program handle recorded at scope-import time."""
    try:
        entries = [dict(r) for r in db.scope_entries(case_id)]
    except Exception:
        return ""
    for entry in entries:
        note = str(entry.get("note") or "")
        if "bug-bounty program scope (" in note:
            inside = note.split("bug-bounty program scope (", 1)[1]
            return inside.split(")", 1)[0].strip()
    return ""


def cmd_bounty(ctx: AppContext, args: argparse.Namespace) -> int:
    """Authorized bug-bounty workflow: program scope → checks → report.

    Scope is the authorization. Importing a program's published scope writes
    ordinary scope entries, so every check that follows is gated by the same
    fail-closed engine as the rest of the tool — nothing here is special-cased
    or exempt.
    """
    from ..intel.bounty import assess
    from ..intel.program import parse_scope_file

    if args.bounty_command == "fetch":
        rec = ctx.find_case(args.case_id)
        db = ctx.open_case(rec["id"])
        try:
            creds = _h1_credentials(ctx, db, rec["id"], args)
            if creds is None:
                raise UsageError(
                    "No HackerOne API credentials found",
                    reason="bounty fetch uses the authenticated Hacker API — it "
                           "never scrapes and never runs without credentials.",
                    action="Store them once: rebel-profiler credential store "
                           f"{rec['id']} hackerone-api-identity --scope bounty-fetch "
                           "… (and hackerone-api-token), or export H1_API_USERNAME / "
                           "H1_API_TOKEN.",
                )
            identity, token = creds
            from ..intel.h1_fetch import fetch_program_document

            try:
                doc = fetch_program_document(args.handle, identity, token)
            except (RuntimeError, ValueError) as exc:
                raise UsageError(str(exc), action="Check the handle and "
                                                  "credentials, then retry.") from exc
            _import_scope_document(ctx, db, rec, doc, args.program or args.handle,
                                   activate=args.activate)
            human = [
                f"Fetched HackerOne program '{doc['program_name']}' ({args.handle})",
                f"  in-scope   : {len(doc['includes'])}",
                f"  exclusions : {len(doc['excludes'])}",
                f"  skipped    : {len(doc['skipped'])}",
                f"  source     : {doc['program_url']}",
            ]
            emit({"human": "\n".join(human), "data": {
                "case": rec["id"], "program": args.handle,
                "includes": len(doc["includes"]),
                "excludes": len(doc["excludes"]),
                "skipped": len(doc["skipped"]),
                "activated": args.activate}}, args.output)
            return EXIT_SUCCESS
        finally:
            db.close()

    if args.bounty_command == "hunt":
        return _cmd_bounty_hunt(ctx, args)

    if args.bounty_command == "import":
        rec = ctx.find_case(args.case_id)
        db = ctx.open_case(rec["id"])
        try:
            try:
                doc = parse_scope_file(args.file, program=args.program)
            except (ValueError, OSError) as exc:
                raise UsageError(
                    f"Could not parse the scope document: {exc}",
                    reason="Accepted inputs are HackerOne-style JSON/CSV exports "
                           "or a plain one-target-per-line list.",
                    action="Pass a scope export, or a text file listing in-scope "
                           "targets (use '!target' lines for exclusions).",
                ) from exc

            source_note = doc["authorization_source"]
            added_in = added_out = 0
            for entry in doc["includes"]:
                note = " | ".join(x for x in (source_note, entry["note"]) if x)
                db.add_scope_entry(rec["id"], entry["value"], excluded=False, note=note)
                added_in += 1
            for entry in doc["excludes"]:
                note = " | ".join(x for x in (f"EXCLUDED | {source_note}",
                                              entry["note"]) if x)
                db.add_scope_entry(rec["id"], entry["value"], excluded=True, note=note)
                added_out += 1

            activated = False
            if args.activate:
                ctx.set_case_status(rec["id"], "active")
                activated = True

            human = [
                f"Imported program scope into case {rec['id']}"
                + (f" ({args.program})" if args.program else ""),
                f"  in-scope   : {added_in}",
                f"  exclusions : {added_out}",
                f"  skipped    : {len(doc['skipped'])}",
            ]
            for row in doc["skipped"][:8]:
                human.append(f"    - {row['asset'] or '(blank)'} — {row['reason']}")
            human.append("")
            if activated:
                human.append("Case is ACTIVE — scope enforcement is live.")
            else:
                human.append("Case is NOT active yet. Review the scope, then run:")
                human.append(f"  rebel-profiler case activate {rec['id']}")
            human.append(f"  rebel-profiler bounty run {rec['id']} --execute")
            emit({"human": "\n".join(human), "data": {
                "case": rec["id"], "program": args.program,
                "includes": added_in, "excludes": added_out,
                "skipped": doc["skipped"], "activated": activated}},
                args.output)
            return EXIT_SUCCESS
        finally:
            db.close()

    if args.bounty_command in {"assess", "report"}:
        from ..intel import ClaimLedger

        rec = ctx.find_case(args.case_id)
        db = ctx.open_case(rec["id"])
        try:
            ledger = ClaimLedger.load_from_db(db, rec["id"])
            report = assess(ledger, rec["id"], program=_case_program(db, rec["id"]))
            data = report.as_dict()
            fmt = getattr(args, "report_format", "") or ""
            if fmt == "sarif":
                from ..intel.report_export import to_sarif

                print(to_sarif(data))
                return EXIT_SUCCESS if report.findings else 1
            if fmt == "markdown":
                from ..intel.report_export import to_markdown

                print(to_markdown(data))
                return EXIT_SUCCESS if report.findings else 1
            emit({"human": report.render_human(), "data": data},
                 args.output)
            return EXIT_SUCCESS if report.findings else 1
        finally:
            db.close()

    if args.bounty_command == "run":
        from ..evidence.store import EvidenceStore
        from ..intel import ClaimLedger, ScopeEnforcedWebAuditor, SourceRegistry
        from ..intel.bounty_session import seed_url, split_asset

        rec = ctx.find_case(args.case_id)
        db = ctx.open_case(rec["id"])
        try:
            entries = [dict(r) for r in db.scope_entries(rec["id"])]
            includes = [str(e["value"]) for e in entries if not e.get("excluded")]
            if not includes:
                raise UsageError(
                    f"Case {rec['id']} has no in-scope assets",
                    reason="The check chain has nothing authorized to run against.",
                    action=f"rebel-profiler bounty import {rec['id']} <scope-file>",
                )
            assets = includes[: max(1, args.max_assets)]
            scope_engine = ctx.scope_engine()

            seeds: list[str] = []
            skipped: list[dict] = []
            for asset in assets:
                if "/" in asset and "://" not in asset:
                    skipped.append({
                        "asset": asset,
                        "reason": "network range — web audit does not apply; use "
                                  f"'intel collect {rec['id']} port-scan <host>'"})
                    continue
                target = split_asset(asset)
                if target is None:
                    skipped.append({"asset": asset, "reason": "not a web host"})
                    continue
                host, port = target
                status = scope_engine.evaluate(rec["id"], host)
                if status != "in_scope":
                    skipped.append({"asset": asset, "reason": status})
                    continue
                seeds.append(seed_url(args.scheme, host, port))

            plan = {
                "case": rec["id"],
                "case_status": rec["status"],
                "check_family": "scope-enforced web audit "
                                "(headers, cookie flags, cleartext forms, TLS posture)",
                "seeds": seeds,
                "skipped": skipped,
                "executed": False,
            }

            if not args.execute:
                human = [
                    f"PLAN ONLY — {len(seeds)} in-scope asset(s) would be audited "
                    f"in case {rec['id']}:",
                ]
                for seed in seeds:
                    human.append(f"  - {seed}")
                for row in skipped:
                    human.append(f"  (skip) {row['asset']} — {row['reason']}")
                human.append("")
                human.append("Nothing ran. Re-run with --execute to dispatch, or use "
                             "'intel crawl' for a single URL.")
                emit({"human": "\n".join(human), "data": plan}, args.output)
                return EXIT_SUCCESS

            if rec["status"] != "active":
                raise UsageError(
                    f"Case {rec['id']} is '{rec['status']}', not active",
                    reason="Scope enforcement only authorizes targets in an ACTIVE case.",
                    action=f"rebel-profiler case activate {rec['id']}",
                )
            if not seeds:
                raise UsageError(
                    "No seed survived the scope check",
                    reason="Every imported asset was out of scope or unusable.",
                    action="Review the imported scope with 'case scope show'.",
                )

            auditor = ScopeEnforcedWebAuditor(
                rec["id"], scope_engine=scope_engine,
                ledger=ClaimLedger(SourceRegistry()),
                evidence=EvidenceStore(db, blobs_dir=ctx.case_dir(rec["id"]) / "blobs"),
                max_pages=max(5, min(4 * len(seeds), 50)), max_depth=1,
                db=db,   # findings must reach the claim ledger, not just memory
            )
            report = auditor.crawl(seeds)
            plan.update({"executed": True, "audit": report})
            stats = report["stats"]
            human = [
                f"Audited {stats['pages_audited']} page(s) across "
                f"{len(seeds)} in-scope asset(s): {stats['findings']} finding(s)",
            ]
            for row in skipped:
                human.append(f"  (skip) {row['asset']} — {row['reason']}")
            human.append("")
            human.append("Every finding above is hash-chained evidence. "
                         "Next: rebel-profiler bounty assess " f"{rec['id']}")
            emit({"human": "\n".join(human), "data": plan}, args.output)
            return EXIT_SUCCESS if stats["pages_audited"] else 1
        finally:
            db.close()

    if args.bounty_command == "auto":
        # Imported here, not at module scope: other branches of this function
        # import the same names locally, which makes them function-locals.
        from ..evidence.audit import AuditChain as _AuditChain
        from ..intel.bounty_session import BountySession
        from ..intel.claims import ClaimLedger as _ClaimLedger
        from ..intel.sources import SourceRegistry as _SourceRegistry
        from ..llm.codescript import default_script_dir

        rec = ctx.find_case(args.case_id)
        db = ctx.open_case(rec["id"])
        try:
            def _on_stage(record: dict) -> None:
                if args.verbose:
                    detail = record.get("detail", "")
                    print(f"  [{record.get('status', '?')}] {record['stage']}"
                          + (f" — {detail}" if detail else ""),
                          file=sys.stderr)

            session = BountySession(
                rec["id"], goal=args.goal, db=db,
                scope_engine=ctx.scope_engine(),
                case_dir=ctx.case_dir(rec["id"]), case_status=rec["status"],
                ledger=_ClaimLedger(_SourceRegistry()),
                evidence=ctx.evidence_store(db, rec["id"]),
                audit=_AuditChain(db),
                max_assets=args.max_assets, max_pages=args.max_pages,
                max_scripts=0 if args.no_author else args.max_scripts,
                max_repair_rounds=args.max_repair_rounds,
                scheme=args.scheme, model=args.model or None,
                tier=args.tier,
                script_dir=Path(getattr(args, "script_dir", "")
                                or default_script_dir(ctx.data_dir)),
                author_scripts=not args.no_author,
                on_stage=_on_stage,
            )
            result = session.run()
            findings = (result.report or {}).get("findings") or []
            if getattr(args, "save", False):
                out_dir = ctx.case_dir(rec["id"]) / "reports"
                out_dir.mkdir(parents=True, exist_ok=True)
                path = out_dir / f"bounty-{result.case_id}.json"
                path.write_text(json.dumps(result.as_dict(), indent=2,
                                           sort_keys=True, default=str) + "\n")
                result.stats["report_path"] = str(path)
            emit({"human": result.render_human(), "data": result.as_dict()},
                 args.output)
            return EXIT_SUCCESS if findings else 1
        finally:
            db.close()

    raise UsageError(f"Unknown bounty command '{args.bounty_command}'")


def _h1_credentials(ctx: AppContext, db, case_id: str, args) -> tuple[str, str] | None:
    """H1 credentials: flags > env > the case credential broker (audited)."""
    import os

    identity = str(getattr(args, "api_identity", "") or "").strip() \
        or os.environ.get("H1_API_USERNAME", "").strip()
    token = str(getattr(args, "api_token", "") or "").strip() \
        or os.environ.get("H1_API_TOKEN", "").strip()
    if identity and token:
        return identity, token
    try:
        from ..security.credentials import CredentialBroker

        broker = CredentialBroker(db, AuditChain(db))
        identity = identity or str(broker.use(case_id, "hackerone-api-identity",
                                              purpose="bounty-fetch",
                                              actor=ctx.actor) or "")
        token = token or str(broker.use(case_id, "hackerone-api-token",
                                        purpose="bounty-fetch",
                                        actor=ctx.actor) or "")
    except Exception:
        return None
    if identity and token:
        return identity, token
    return None


def _import_scope_document(ctx: AppContext, db, rec: dict, doc: dict,
                           program: str, *, activate: bool) -> None:
    """Write a parsed scope document into the case (shared by import/fetch/hunt)."""
    source_note = doc["authorization_source"]
    for entry in doc["includes"]:
        note = " | ".join(x for x in (source_note, entry["note"]) if x)
        db.add_scope_entry(rec["id"], entry["value"], excluded=False, note=note)
    for entry in doc["excludes"]:
        note = " | ".join(x for x in (f"EXCLUDED | {source_note}", entry["note"]) if x)
        db.add_scope_entry(rec["id"], entry["value"], excluded=True, note=note)
    if activate:
        ctx.set_case_status(rec["id"], "active")


def _cmd_bounty_hunt(ctx: AppContext, args: argparse.Namespace) -> int:
    """``bounty hunt <handle>`` — the whole chain, no questions asked.

    fetch scope → create/reuse case → import + activate → the full
    BountySession chain (recon/audit/assess/author/repair) → report.
    Every stage still passes its own gates; zero-questions applies to the
    OPERATOR, never to the policy engine.
    """
    from ..core.errors import RPError as _RPError
    from ..evidence.audit import AuditChain as _AuditChain
    from ..intel.bounty_session import BountySession
    from ..intel.claims import ClaimLedger as _ClaimLedger
    from ..intel.sources import SourceRegistry as _SourceRegistry
    from ..llm.codescript import default_script_dir

    def _stage(record: dict) -> None:
        if args.verbose:
            detail = record.get("detail", "")
            print(f"  [{record.get('status', '?')}] {record['stage']}"
                  + (f" — {detail}" if detail else ""), file=sys.stderr)

    # Stage 0: credentials BEFORE any case mutation — fail closed, early.
    # Exception: a reused case whose scope is already in the ledger is an
    # authorization fact on disk (imported via `bounty import`/`fetch` or
    # scope-added by the operator) — re-fetching adds nothing, so the run
    # proceeds from the stored scope and the H1 gate simply doesn't apply.
    # A FRESH case has no such fact, so without credentials it fails closed.
    probe_case = ctx.find_case(args.case_id) if args.case_id else None
    have_stored_scope = False
    if probe_case is not None:
        db0 = ctx.open_case(probe_case["id"])
        try:
            have_stored_scope = bool(db0.scope_entries(probe_case["id"]))
            if not have_stored_scope:
                creds = _h1_credentials(ctx, db0, probe_case["id"], args)
                if creds is None and not (
                        os.environ.get("H1_API_USERNAME")
                        and os.environ.get("H1_API_TOKEN")):
                    raise UsageError(
                        "No HackerOne API credentials found",
                        reason="bounty hunt fetches the live program scope; "
                               "without credentials it cannot know what is "
                               "authorized.",
                        action="Store them once in any case: rebel-profiler "
                               "credential store <case-id> hackerone-api-identity "
                               "--scope bounty-fetch …, or export H1_API_USERNAME / "
                               "H1_API_TOKEN. (A case that already has scope "
                               "entries skips the fetch entirely.)",
                    )
        finally:
            db0.close()
    else:
        # fresh case: no stored authorization fact exists yet, so the fetch
        # is unavoidable and the credential gate applies right here, before
        # any case is created.
        has_flag_creds = (str(getattr(args, "api_identity", "") or "").strip()
                          and str(getattr(args, "api_token", "") or "").strip())
        if not has_flag_creds and not (os.environ.get("H1_API_USERNAME")
                                       and os.environ.get("H1_API_TOKEN")):
            raise UsageError(
                "No HackerOne API credentials found",
                reason="bounty hunt fetches the live program scope; without "
                       "credentials it cannot know what is authorized.",
                action="Store them once in any case: rebel-profiler credential "
                       "store <case-id> hackerone-api-identity --scope bounty-fetch "
                       "…, or export H1_API_USERNAME / H1_API_TOKEN.",
            )

    # Stage 1: case — fresh or reused
    if args.case_id:
        rec = ctx.find_case(args.case_id)
    else:
        name = f"H1 {args.handle} — auto hunt"
        rec = ctx.create_case(name, f"program: https://hackerone.com/{args.handle}")
        db = ctx.open_case(rec["id"])
        try:
            creds = _h1_credentials(ctx, db, rec["id"], args)
        finally:
            db.close()

    db = ctx.open_case(rec["id"])
    try:
        if have_stored_scope:
            # Authorization already on file for this case — skip the fetch
            # (and the credential requirement with it) and run from the
            # stored scope.
            _stage({"stage": "scope", "status": "ok",
                    "detail": "reusing the case's stored scope (fetch skipped)"})
            ctx.set_case_status(rec["id"], "active")
            rec = ctx.find_case(rec["id"])
        else:
            from ..intel.h1_fetch import fetch_program_document

            if creds is None:   # reuse without stored scope and no creds
                raise UsageError(
                    "No HackerOne API credentials found",
                    reason="this case has no stored scope, so bounty hunt must "
                           "fetch the live program scope to authorize targets.",
                    action="Store credentials: rebel-profiler credential store "
                           "<case-id> hackerone-api-identity --scope bounty-fetch "
                           "…, or export H1_API_USERNAME / H1_API_TOKEN.",
                )
            identity, token = creds
            try:
                doc = fetch_program_document(args.handle, identity, token)
            except (RuntimeError, ValueError) as exc:
                raise UsageError(
                    f"HackerOne fetch failed: {exc}",
                    action="Check the program handle and API credentials.") from exc
            _import_scope_document(ctx, db, rec, doc, args.handle, activate=True)
            rec = ctx.find_case(rec["id"])   # refresh status after activation

        session = BountySession(
            rec["id"],
            goal=(f"HackerOne program {args.handle}: stay strictly inside the "
                  "imported scope, enumerate and audit every in-scope asset, "
                  "assess what was observed, and produce a report with real "
                  "results — no demos."),
            db=db, scope_engine=ctx.scope_engine(),
            case_dir=ctx.case_dir(rec["id"]), case_status=rec["status"],
            ledger=_ClaimLedger(_SourceRegistry()),
            evidence=ctx.evidence_store(db, rec["id"]),
            audit=_AuditChain(db),
            max_assets=max(1, args.max_assets), max_pages=args.max_pages,
            max_scripts=0 if args.no_author else args.max_scripts,
            max_repair_rounds=2, scheme=args.scheme, model="",
            tier=args.tier,
            script_dir=default_script_dir(ctx.data_dir),
            author_scripts=not args.no_author,
            on_stage=_stage,
        )
        result = session.run()
        findings = (result.report or {}).get("findings") or []
        if args.save:
            out_dir = ctx.case_dir(rec["id"]) / "reports"
            out_dir.mkdir(parents=True, exist_ok=True)
            path = out_dir / f"hunt-{args.handle}-{rec['id']}.json"
            path.write_text(json.dumps(result.as_dict(), indent=2,
                                       sort_keys=True, default=str) + "\n")
            result.stats["report_path"] = str(path)
        emit({"human": result.render_human(), "data": result.as_dict()},
             args.output)
        return EXIT_SUCCESS if findings else 1
    except _RPError:
        raise
    finally:
        db.close()


def cmd_doctor(ctx: AppContext, args: argparse.Namespace) -> int:
    import shutil

    from ..core.config import PROTECTED_SECURITY_KEYS
    from ..knowledge import list_domains

    checks: list[dict] = []
    checks.append({"check": "config", "ok": "yes", "detail": f"data_dir={ctx.data_dir}"})
    checks.append({"check": "workspace index", "ok": "yes", "detail": str(ctx.index_path)})
    domains = list_domains()
    checks.append({"check": "knowledge domains",
                   "ok": "yes" if len(domains) >= 15 else "no",
                   "detail": f"{len(domains)} domains, "
                             f"{sum(d['topics'] for d in domains)} topics loaded"})
    for b in ("nmap", "dig", "whois", "curl"):
        found = shutil.which(b) is not None
        checks.append({"check": f"tool: {b}", "ok": "yes" if found else "no",
                       "detail": "available" if found else "not installed (adapters will refuse)"})
    hunter_missing = [b for b in ("subfinder", "httpx", "katana", "gau", "arjun",
                                  "nuclei", "amass", "ffuf", "whatweb", "wafw00f")
                      if shutil.which(b) is None]
    # Advisory, not gating: the adapters degrade gracefully when a binary is
    # absent (the plan skips the step and says so), so a slim box must still
    # pass doctor — same philosophy as the optional LLM engines below.
    checks.append({
        "check": "hunter toolset",
        "ok": "yes",
        "detail": ("all 10 hunter binaries available" if not hunter_missing
                   else f"optional, missing: {', '.join(hunter_missing)} "
                        "(sudo apt install " + " ".join(hunter_missing) + ")"),
    })
    # Optional LLM engines are informational: the deterministic tiny engine
    # always exists, so a missing optional dependency is never a failure.
    for module, label in (("llama_cpp", "llm engine: gguf (llama-cpp-python)"),
                          ("torch", "llm engine: native (torch)"),
                          ("airllm", "llm engine: airllm")):
        checks.append({
            "check": label, "ok": "yes",
            "detail": "installed" if _module_present(module) else
                      "not installed (optional — 'llm setup' prints the command)"})
    local = _local_model_counts()
    checks.append({"check": "llm local models", "ok": "yes",
                   "detail": f"{local['gguf']} GGUF + {local['hf']} HF "
                             "checkpoint(s) on disk"})
    for section, key in PROTECTED_SECURITY_KEYS:
        checks.append({"check": f"protected: {section}.{key}", "ok": "yes", "detail": "enforced"})
    ok = all(c["ok"] == "yes" for c in checks)
    verdict = (f"doctor: ALL CHECKS PASSED {theme.GREEN}{theme.GLYPHS['ok']}{theme.RESET}"
               if ok else
               f"doctor: ISSUES FOUND {theme.YELLOW}{theme.GLYPHS['warn']}{theme.RESET} "
               "(see table)")
    emit({"human": f"{theme.CYAN}{theme.GLYPHS['shield']} {verdict}{theme.RESET}",
          "data": checks}, args.output)
    return EXIT_SUCCESS if ok else 1


def _llm_tiers():
    from ..llm.budget import BUDGET_TIERS

    return BUDGET_TIERS


def _module_present(module: str) -> bool:
    try:
        import importlib.util

        return importlib.util.find_spec(module) is not None
    except Exception:
        return False


def _local_model_counts() -> dict:
    counts = {"gguf": 0, "hf": 0}
    try:
        from ..llm.gguf import discover_local_gguf

        counts["gguf"] = len(discover_local_gguf())
    except Exception:
        pass
    try:
        from ..llm.native import discover_local_models

        counts["hf"] = len(discover_local_models())
    except Exception:
        pass
    return counts


def _best_local_model(limits) -> tuple[str, str]:
    """Pick the best-fitting LOCAL checkpoint for --local (no download, ever)."""
    from ..llm.budget import BUDGET_TIERS
    from ..llm.setup import local_models

    payload = local_models(limits=limits)
    for engine in ("gguf", "hf"):
        fitting = [r for r in payload.get(engine) or [] if r.get("fits")]
        if fitting:
            row = fitting[0]
            return (row["path"] if engine == "gguf" else row["model"],
                    f"best local {engine} checkpoint that fits tier '{limits.tier}'")
    # Nothing fits THIS tier. That is not necessarily "no model": the verdict
    # now includes peak RSS, so a checkpoint can be right-sized for a wider
    # tier while being too heavy for the default one. Say which tier fits.
    narrower: list[str] = []
    for row in (payload.get("gguf") or []):
        if row.get("needs_tier") and row["needs_tier"] != limits.tier:
            narrower.append(
                f"'{row['name']}' needs tier '{row['needs_tier']}'")
    raise UsageError(
        "No local checkpoint fits this tier",
        reason="--local never downloads and never exceeds the hardware budget.",
        action=("Run 'rebel-profiler llm local' to see what is on disk, or "
                "re-run with a wider tier: "
                + ("; ".join(narrower[:3]) if narrower
                   else "check the tier caps with 'llm status'")),
    )


def _params(pairs: list[list[str]] | None) -> dict:
    result: dict = {}
    for pair in pairs or []:
        key, value = pair[0], pair[1]
        low = value.strip().lower()
        if low in {"true", "false"}:
            result[key] = low == "true"
        else:
            try:
                result[key] = int(value)
            except ValueError:
                result[key] = value
    return result


# ---------------------------------------------------------------------------
# Parser


def _package_version() -> str:
    import rebel_profiler

    return getattr(rebel_profiler, "__version__", "?")


def build_parser() -> argparse.ArgumentParser:
    # Root-level flags carry the defaults; subparser copies use SUPPRESS so
    # they never clobber values given before the subcommand.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--output", "-o", choices=["human", "json", "jsonl", "csv"], default="human")
    common.add_argument("--yes", "-y", action="store_true", help="assume yes for confirmations")
    common.add_argument("--actor", default=None, help="acting subject for RBAC (default: RP_ACTOR env or 'operator')")
    common.add_argument("--rbac", action="store_true", help="enforce case membership roles for this command")
    common.add_argument("--config-file", default=None, metavar="PATH",
                        help="TOML profile pinning model/tier/etc for recurring jobs "
                             "(merged between local config and environment)")
    common.add_argument("--data-dir", default=None, help=argparse.SUPPRESS)

    sub_common = argparse.ArgumentParser(add_help=False)
    sub_common.add_argument("--output", "-o", choices=["human", "json", "jsonl", "csv"], default=argparse.SUPPRESS)
    sub_common.add_argument("--yes", "-y", action="store_true", default=argparse.SUPPRESS)
    sub_common.add_argument("--actor", default=argparse.SUPPRESS)
    sub_common.add_argument("--rbac", action="store_true", default=argparse.SUPPRESS)
    sub_common.add_argument("--privileged", action="store_true", default=argparse.SUPPRESS,
                            help="allow the RF tools (airmon-ng/airodump-ng) to run via sudo -n — "
                                 "Kali wireless workflows need root; the argv whitelist is unchanged")
    sub_common.add_argument("--config-file", default=argparse.SUPPRESS)
    sub_common.add_argument("--data-dir", default=argparse.SUPPRESS, help=argparse.SUPPRESS)

    parser = argparse.ArgumentParser(
        prog="rebel-profiler",
        parents=[common],
        description="Kali Linux cybersecurity intelligence & authorized security operations framework.",
    )
    parser.add_argument("--version", action="version",
                        version=f"rebel-profiler {_package_version()}")
    subs = parser.add_subparsers(dest="group")

    # case
    p_case = subs.add_parser("case", parents=[sub_common], help="case workspace lifecycle")
    case_subs = p_case.add_subparsers(dest="case_command", required=True)
    p_create = case_subs.add_parser("create", parents=[sub_common], help="create a new case")
    p_create.add_argument("name")
    p_create.add_argument("description", nargs="?")
    case_subs.add_parser("list", parents=[sub_common], help="list cases")
    p_show = case_subs.add_parser("show", parents=[sub_common], help="show case detail")
    p_show.add_argument("case_id")
    p_act = case_subs.add_parser("activate", parents=[sub_common], help="activate scope enforcement")
    p_act.add_argument("case_id")
    p_close = case_subs.add_parser("close", parents=[sub_common], help="close a case")
    p_close.add_argument("case_id")
    p_scope = case_subs.add_parser("scope", parents=[sub_common], help="manage case scope")
    scope_subs = p_scope.add_subparsers(dest="scope_command", required=True)
    p_sa = scope_subs.add_parser("add", parents=[sub_common], help="add scope entry")
    p_sa.add_argument("case_id")
    p_sa.add_argument("value")
    p_sa.add_argument("--exclude", action="store_true", help="add as exclusion")
    p_sa.add_argument("--note", default="")
    p_ss = scope_subs.add_parser("show", parents=[sub_common], help="show scope entries")
    p_ss.add_argument("case_id")

    # scope check
    p_check = subs.add_parser("scope-check", parents=[sub_common], help="evaluate a target against case scope")
    p_check.add_argument("case_id")
    p_check.add_argument("target")

    # plan
    p_plan = subs.add_parser("plan", parents=[sub_common], help="plan an action without executing")
    p_plan.add_argument("case_id")
    p_plan.add_argument("action")
    p_plan.add_argument("target")
    p_plan.add_argument("-p", "--param", action="append", nargs=2, metavar=("KEY", "VALUE"), default=[])
    p_plan.add_argument("--reason", default="")
    p_plan.add_argument("--capability", default="discovery")

    # run
    p_run = subs.add_parser("run", parents=[sub_common], help="execute a structured action through the broker")
    p_run.add_argument("case_id")
    p_run.add_argument("action")
    p_run.add_argument("target")
    p_run.add_argument("-p", "--param", action="append", nargs=2, metavar=("KEY", "VALUE"), default=[])
    p_run.add_argument("--reason", default="")
    p_run.add_argument("--capability", default="discovery")
    p_run.add_argument("--dry-run", action="store_true")
    p_run.add_argument("--collect", action="store_true",
                       help="feed the result through the intel collection pipeline")

    # adapters
    subs.add_parser("adapters", parents=[sub_common], help="list registered tool adapters")

    # knowledge
    p_know = subs.add_parser("knowledge", parents=[sub_common], help="structured security knowledge base")
    know_subs = p_know.add_subparsers(dest="knowledge_command", required=True)
    know_subs.add_parser("domains", parents=[sub_common], help="list knowledge domains")
    p_kd = know_subs.add_parser("domain", parents=[sub_common], help="show one domain's topics")
    p_kd.add_argument("key")
    p_ks = know_subs.add_parser("search", parents=[sub_common], help="search topics by keyword")
    p_ks.add_argument("terms", nargs="+")
    p_kt = know_subs.add_parser("tools", parents=[sub_common], help="Kali tools mapped to a domain")
    p_kt.add_argument("key")
    p_kp = know_subs.add_parser("planner-context", parents=[sub_common], help="machine-readable planner context")
    p_kp.add_argument("domains", nargs="*")
    p_ktech = know_subs.add_parser("techniques", parents=[sub_common], help="techniques per domain (how + defended how)")
    p_ktech.add_argument("key", nargs="?", default="")
    p_ktech.add_argument("--technique", default="", help="show one technique in detail")
    p_kact = know_subs.add_parser("actions", parents=[sub_common], help="executable action guides: when/how/example/output/next for every action")
    p_kact.add_argument("key", nargs="?", default="", help="one action name for its full guide")
    p_kpb = know_subs.add_parser("playbook", parents=[sub_common], help="authorized step-ordered playbooks")
    p_kpb.add_argument("key", nargs="?", default="")
    p_kgl = know_subs.add_parser("glossary", parents=[sub_common], help="canonical term definitions")
    p_kgl.add_argument("term", nargs="?", default="")
    p_kdeep = know_subs.add_parser("deep-context", parents=[sub_common], help="complete planner bundle: domains+tools+techniques+playbooks+glossary")
    p_kdeep.add_argument("domains", nargs="*")

    # report
    p_rep = subs.add_parser("report", parents=[sub_common], help="generate the case report from claims + evidence")
    p_rep.add_argument("case_id")

    # surface — attack-surface graph + exposure map
    p_surf = subs.add_parser("surface", parents=[sub_common], help="attack-surface graph & exposure map from collected claims")
    surf_subs = p_surf.add_subparsers(dest="surface_command", required=True)
    p_smap = surf_subs.add_parser("map", parents=[sub_common], help="show the surface graph (host→ip→port→service)")
    p_smap.add_argument("case_id")
    p_sexpo = surf_subs.add_parser("exposure", parents=[sub_common], help="per-host exposure summary with lateral hints")
    p_sexpo.add_argument("case_id")
    p_sbuild = surf_subs.add_parser("build", parents=[sub_common], help="rebuild + persist the relationship graph from claims (PDF 8/10)")
    p_sbuild.add_argument("case_id")
    p_sshow = surf_subs.add_parser("show", parents=[sub_common], help="show the persisted relationship graph")
    p_sshow.add_argument("case_id")
    p_spaths = surf_subs.add_parser("paths", parents=[sub_common], help="paths between two persisted nodes")
    p_spaths.add_argument("case_id")
    p_spaths.add_argument("src")
    p_spaths.add_argument("dst")
    p_srel = surf_subs.add_parser("related", parents=[sub_common], help="nodes sharing neighbors with the given node")
    p_srel.add_argument("case_id")
    p_srel.add_argument("node")

    # intel
    p_intel = subs.add_parser("intel", parents=[sub_common], help="intelligence layer: sources, claims, sanitization")
    intel_subs = p_intel.add_subparsers(dest="intel_command", required=True)
    p_isrc = intel_subs.add_parser("sources", parents=[sub_common], help="list scored intelligence sources")
    p_isrc.add_argument("key", nargs="?", default="", help="score one source (with default freshness)")
    p_iclaim = intel_subs.add_parser("claims", parents=[sub_common], help="list claims for a case (optionally one subject)")
    p_iclaim.add_argument("case_id")
    p_iclaim.add_argument("subject", nargs="?", default="")
    p_isan = intel_subs.add_parser("sanitize", parents=[sub_common], help="scan untrusted text for injection patterns")
    p_isan.add_argument("text", nargs="?")
    p_isan.add_argument("--stdin", action="store_true", help="read text from stdin")
    p_icollect = intel_subs.add_parser("collect", parents=[sub_common], help="plan+run+collect one action into claims (six gates still apply)")
    p_icollect.add_argument("case_id")
    p_icollect.add_argument("action")
    p_icollect.add_argument("target")
    p_icollect.add_argument("-p", "--param", action="append", nargs=2, metavar=("KEY", "VALUE"), default=[])
    p_icollect.add_argument("--reason", default="")
    p_icrawl = intel_subs.add_parser("crawl", parents=[sub_common], help="scope-enforced web audit: headers, cookies/session, forms, TLS (PDF 7)")
    p_icrawl.add_argument("case_id")
    p_icrawl.add_argument("urls", nargs="+", help="seed http(s) URLs inside the case scope")
    p_icrawl.add_argument("--max-pages", type=int, default=20)
    p_icrawl.add_argument("--max-depth", type=int, default=2)
    p_ifuse = intel_subs.add_parser("fusion", parents=[sub_common], help="cross-domain fusion report: subject profiles + conflicts (PDF 9)")
    p_ifuse.add_argument("case_id")
    p_ifuse.add_argument("subject", nargs="?", default="", help="one subject's fused profile")
    p_ihunt = intel_subs.add_parser("hunt", parents=[sub_common], help="autonomous JS surface hunt: harvest scripts from a page, mine endpoints/keys/cloud hosts, rank a triage queue")
    p_ihunt.add_argument("case_id")
    p_ihunt.add_argument("url", help="seed page (must be in scope)")
    p_ihunt.add_argument("--max-scripts", type=int, default=25)
    p_ihunt.add_argument("--no-wayback", action="store_true",
                         help="skip Wayback history fold-in")
    p_iap = intel_subs.add_parser("attack-plan", parents=[sub_common],
                                  help="ranked attack strategies from THIS case's evidence — every step names an executable action")
    p_iap.add_argument("case_id")
    p_iap.add_argument("--save-payloads", action="store_true",
                       help="write attack_plan.json into the case directory")
    p_ivc = intel_subs.add_parser("vuln-coverage", parents=[sub_common],
                                  help="vulnerability-class coverage matrix: what this case has probed vs blind spots")
    p_ivc.add_argument("case_id")
    p_ivc.add_argument("--plan", action="store_true",
                       help="turn blind spots into a concrete gated action plan")
    p_ivc.add_argument("--max-plan", type=int, default=8,
                       help="cap on planned actions (default 8)")
    p_ipb = intel_subs.add_parser("playbook", parents=[sub_common],
                                  help="hunt playbooks: reviewed multi-step recipes expanded into gated plans")
    ipb_subs = p_ipb.add_subparsers(dest="playbook_command", required=True)
    p_ipbl = ipb_subs.add_parser("list", parents=[sub_common], help="list builtin + operator playbooks")
    p_ipbs = ipb_subs.add_parser("show", parents=[sub_common], help="show one playbook's steps")
    p_ipbs.add_argument("playbook_name")
    p_ipbr = ipb_subs.add_parser("run", parents=[sub_common],
                                 help="run a playbook against one target in an active case (every step passes the six gates)")
    p_ipbr.add_argument("playbook_name")
    p_ipbr.add_argument("case_id")
    p_ipbr.add_argument("target")
    p_ipbr.add_argument("-p", "--param", action="append", nargs=2,
                        metavar=("KEY", "VALUE"), default=[],
                        help="params merged into every step that declares the key")
    p_ipay = intel_subs.add_parser("payload", parents=[sub_common],
                                   help="payload workbench: build benign impact-markers, deploy them through the approval-gated probe")
    ipay_subs = p_ipay.add_subparsers(dest="payload_command", required=True)
    ipay_subs.add_parser("classes", parents=[sub_common],
                         help="list payload classes")
    p_ipb = ipay_subs.add_parser("build", parents=[sub_common],
                                 help="build one benign impact-marker payload for an in-scope target")
    p_ipb.add_argument("case_id")
    p_ipb.add_argument("payload_class", help=f"one of: reflected_xss, sqli_error, sqli_timing, ssti, cmdi_echo, open_redirect, idor_pivot, traversal")
    p_ipb.add_argument("--target", default="", help="in-scope URL (default: first live-URL claim in the case)")
    p_ipb.add_argument("--param", default="", help="parameter to inject into (default q)")
    p_ipd = ipay_subs.add_parser("deploy", parents=[sub_common],
                                 help="deploy a payload through the approval-gated probe (yes/no/custom flow)")
    p_ipd.add_argument("case_id")
    p_ipd.add_argument("payload_class")
    p_ipd.add_argument("--target", default="", help="in-scope URL (default: first live-URL claim)")
    p_ipd.add_argument("--param", default="", help="parameter to inject into (default q)")
    p_ipd.add_argument("--approve", action="store_true",
                       help="OPERATOR YES: dispatch the probe (without it only a draft is shown)")
    p_ipd.add_argument("--custom-payload", default="", help="operator-edited payload text (custom flow)")

    # evidence
    p_ev = subs.add_parser("evidence", parents=[sub_common], help="evidence ledger operations")
    ev_subs = p_ev.add_subparsers(dest="evidence_command", required=True)
    p_evl = ev_subs.add_parser("list", parents=[sub_common], help="list evidence records")
    p_evl.add_argument("case_id")
    p_evv = ev_subs.add_parser("verify", parents=[sub_common], help="verify hashes and chain linkage for a case")
    p_evv.add_argument("case_id")

    # audit
    p_au = subs.add_parser("audit", parents=[sub_common], help="tamper-evident audit chain operations")
    au_subs = p_au.add_subparsers(dest="audit_command", required=True)
    p_aus = au_subs.add_parser("show", parents=[sub_common], help="show audit events")
    p_aus.add_argument("case_id")
    p_auv = au_subs.add_parser("verify", parents=[sub_common], help="verify audit chain integrity")
    p_auv.add_argument("case_id")

    # member (RBAC)
    p_mem = subs.add_parser("member", parents=[sub_common], help="case membership: owner/operator/viewer (PDF 11)")
    mem_subs = p_mem.add_subparsers(dest="member_command", required=True)
    p_madd = mem_subs.add_parser("add", parents=[sub_common], help="add/update a member")
    p_madd.add_argument("case_id")
    p_madd.add_argument("subject")
    p_madd.add_argument("role", choices=["owner", "operator", "viewer"])
    p_mrm = mem_subs.add_parser("remove", parents=[sub_common], help="remove a member")
    p_mrm.add_argument("case_id")
    p_mrm.add_argument("subject")
    p_mls = mem_subs.add_parser("list", parents=[sub_common], help="list members")
    p_mls.add_argument("case_id")

    # approval queue
    p_appr = subs.add_parser("approval", parents=[sub_common], help="durable approval queue (headless ALLOW_WITH_APPROVAL)")
    appr_subs = p_appr.add_subparsers(dest="approval_command", required=True)
    p_apl = appr_subs.add_parser("list", parents=[sub_common], help="list approvals")
    p_apl.add_argument("case_id")
    p_apl.add_argument("--state", default="pending", choices=["pending", "approved", "denied", "cancelled", "all"])
    p_apd = appr_subs.add_parser("decide", parents=[sub_common], help="approve/deny one queued request")
    p_apd.add_argument("case_id")
    p_apd.add_argument("approval_id")
    p_apd.add_argument("decision", choices=["approve", "deny", "cancel"])
    p_apr = appr_subs.add_parser("run", parents=[sub_common], help="execute an approved request (re-validates all gates)")
    p_apr.add_argument("case_id")
    p_apr.add_argument("approval_id")

    # hypotheses
    p_hyp = subs.add_parser("hypothesis", parents=[sub_common], help="hypothesis-driven investigation (PDF 4/11)")
    hyp_subs = p_hyp.add_subparsers(dest="hypothesis_command", required=True)
    p_hadd = hyp_subs.add_parser("add", parents=[sub_common], help="state a testable hypothesis")
    p_hadd.add_argument("case_id")
    p_hadd.add_argument("statement")
    p_hadd.add_argument("--criteria", required=True, help="JSON list of criteria, e.g. '[{\"kind\":\"exists\",\"subject\":\"h1\",\"claim_kind\":\"ip\"}]'")
    p_hadd.add_argument("--rationale", default="")
    p_heval = hyp_subs.add_parser("evaluate", parents=[sub_common], help="evaluate one hypothesis against the ledger")
    p_heval.add_argument("hypothesis_id")
    p_hlist = hyp_subs.add_parser("list", parents=[sub_common], help="list hypotheses")
    p_hlist.add_argument("case_id")

    # workflows
    p_wf = subs.add_parser("workflow", parents=[sub_common], help="workflow DSL + DAG runner with approval gates (PDF 14)")
    wf_subs = p_wf.add_subparsers(dest="workflow_command", required=True)
    p_wfc = wf_subs.add_parser("create", parents=[sub_common], help="create from a DSL file (checkpoint only)")
    p_wfc.add_argument("case_id")
    p_wfc.add_argument("dsl_file", type=str)
    p_wfr = wf_subs.add_parser("run", parents=[sub_common], help="run/resume a workflow (resumable checkpoints)")
    p_wfr.add_argument("case_id")
    p_wfr.add_argument("workflow_id", nargs="?")
    p_wfr.add_argument("--dsl-file", type=str, default=None)
    p_wfa = wf_subs.add_parser("approve", parents=[sub_common], help="decide an approval-gate step")
    p_wfa.add_argument("case_id")
    p_wfa.add_argument("workflow_id")
    p_wfa.add_argument("step_key")
    p_wfa.add_argument("--deny", action="store_true")
    p_wfs = wf_subs.add_parser("status", parents=[sub_common], help="show workflow + step states")
    p_wfs.add_argument("case_id")
    p_wfs.add_argument("workflow_id")

    # scheduler
    p_sched = subs.add_parser("schedule", parents=[sub_common], help="schedules with authorization windows (PDF 14)")
    sched_subs = p_sched.add_subparsers(dest="schedule_command", required=True)
    p_scadd = sched_subs.add_parser("add", parents=[sub_common], help="schedule an action or workflow")
    p_scadd.add_argument("case_id")
    p_scadd.add_argument("--action", default="")
    p_scadd.add_argument("--target", default="")
    p_scadd.add_argument("-p", "--param", action="append", nargs=2, metavar=("KEY", "VALUE"), default=[])
    p_scadd.add_argument("--not-before", type=float, default=None, help="epoch seconds; window opens")
    p_scadd.add_argument("--not-after", type=float, default=None, help="epoch seconds; window closes")
    p_scadd.add_argument("--cron", default="", help="only 'interval=<minutes>' is offered")
    p_scadd.add_argument("--workflow-spec", default="", help="workflow DSL text to run in-window")
    p_sctick = sched_subs.add_parser("tick", parents=[sub_common], help="run one scheduler pass")
    p_sclist = sched_subs.add_parser("list", parents=[sub_common], help="list schedules")
    p_sclist.add_argument("case_id")
    p_sclist.add_argument("--state", default=None, choices=["active", "paused", "expired", "cancelled", "all"])
    p_scpause = sched_subs.add_parser("pause", parents=[sub_common], help="pause one schedule")
    p_scpause.add_argument("schedule_id")

    # search
    p_search = subs.add_parser("search", parents=[sub_common], help="full-text search over the case (FTS5)")
    search_subs = p_search.add_subparsers(dest="search_command", required=True)
    p_srq = search_subs.add_parser("query", parents=[sub_common], help="search claims + observations")
    p_srq.add_argument("case_id")
    p_srq.add_argument("terms", nargs="+")
    p_srb = search_subs.add_parser("rebuild", parents=[sub_common], help="rebuild the search index from claims")
    p_srb.add_argument("case_id")

    # credentials
    p_cred = subs.add_parser("credential", parents=[sub_common], help="encrypted, scoped credential broker (PDF 17)")
    cred_subs = p_cred.add_subparsers(dest="credential_command", required=True)
    p_crcs = cred_subs.add_parser("store", parents=[sub_common], help="store a secret (encrypted at rest)")
    p_crcs.add_argument("case_id")
    p_crcs.add_argument("name")
    p_crcs.add_argument("--secret", default="", help="omit to be prompted")
    p_crcs.add_argument("--scope", action="append", help="purpose scope, repeatable")
    p_crcs.add_argument("--note", default="")
    p_crcu = cred_subs.add_parser("use", parents=[sub_common], help="scoped access (audited, not printed)")
    p_crcu.add_argument("case_id")
    p_crcu.add_argument("name")
    p_crcu.add_argument("--purpose", required=True)
    p_crcu.add_argument("--show", action="store_true", help="print (loudly audited)")
    p_crdl = cred_subs.add_parser("delete", parents=[sub_common], help="delete a credential")
    p_crdl.add_argument("case_id")
    p_crdl.add_argument("name")
    p_crls = cred_subs.add_parser("list", parents=[sub_common], help="list credentials (metadata only)")
    p_crls.add_argument("case_id")

    # plugins
    p_plug = subs.add_parser("plugin", parents=[sub_common], help="plugin SDK: sign/validate/load (PDF 15)")
    plug_subs = p_plug.add_subparsers(dest="plugin_command", required=True)
    p_plsg = plug_subs.add_parser("sign", parents=[sub_common], help="HMAC-sign a plugin manifest")
    p_plsg.add_argument("plugin_dir", type=Path)
    p_plld = plug_subs.add_parser("load", parents=[sub_common], help="validate + load a plugin")
    p_plld.add_argument("plugin_dir", type=Path)
    p_plld.add_argument("--grant", default="", help="comma-separated granted permissions")
    p_plld.add_argument("--allow-unsigned", action="store_true")

    # events / webhooks
    p_ev2 = subs.add_parser("events", parents=[sub_common], help="structured events + webhooks")
    ev2_subs = p_ev2.add_subparsers(dest="events_command", required=True)
    p_evsh = ev2_subs.add_parser("show", parents=[sub_common], help="recent events")
    p_evsh.add_argument("case_id")
    p_evsh.add_argument("--limit", type=int, default=50)
    p_evwh = ev2_subs.add_parser("register", parents=[sub_common], help="register a signed webhook")
    p_evwh.add_argument("case_id")
    p_evwh.add_argument("url")
    p_evwh.add_argument("--secret", default="")
    p_evwh.add_argument("--events", default="*", help="comma-separated event types or '*'")
    p_evls = ev2_subs.add_parser("webhooks", parents=[sub_common], help="list webhooks")
    p_evls.add_argument("case_id")

    # api gateway
    p_serve = subs.add_parser("serve", parents=[sub_common], help="read-only API gateway for one case")
    p_serve.add_argument("case_id")
    p_serve.add_argument("--bind", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8766)
    p_serve.add_argument("--token", default="", help="API secret (hashed); RP_API_TOKEN env wins")

    # ops
    p_ops = subs.add_parser("ops", parents=[sub_common], help="backup/restore/package/self-check (PDF 18/20)")
    ops_subs = p_ops.add_subparsers(dest="ops_command", required=True)
    p_opb = ops_subs.add_parser("backup", parents=[sub_common], help="manifest-verified case backup (zip)")
    p_opb.add_argument("case_id")
    p_opb.add_argument("out")
    p_opr = ops_subs.add_parser("restore", parents=[sub_common], help="restore a verified backup")
    p_opr.add_argument("backup")
    p_opr.add_argument("dest")
    p_opp = ops_subs.add_parser("package", parents=[sub_common], help="build an offline .pyz zipapp")
    p_opp.add_argument("out")
    p_opc = ops_subs.add_parser("check", parents=[sub_common], help="self-check + deterministic repair (PDF 20)")
    p_opc.add_argument("case_id")
    p_opc.add_argument("--repair", action="store_true", help="rebuild rebuildable views")
    p_opu = ops_subs.add_parser("update", parents=[sub_common],
                                help="self-update the installed zipapp from the latest release (sha256-verified)")
    p_opu.add_argument("--target", default="~/.local/share/rebel-profiler/rebel-profiler.pyz",
                       help="path to the installed .pyz (default: the --zipapp install location)")

    # worker (file-based job plane)
    p_wrk = subs.add_parser("worker", parents=[sub_common], help="file-based job plane: 3-way handshake with the daemon")
    wrk_subs = p_wrk.add_subparsers(dest="worker_command", required=True)
    p_wsub = wrk_subs.add_parser("submit", parents=[sub_common], help="write a SYN job file")
    p_wsub.add_argument("case_id")
    p_wsub.add_argument("action")
    p_wsub.add_argument("target")
    p_wsub.add_argument("-p", "--param", action="append", nargs=2, metavar=("KEY", "VALUE"), default=[])
    p_wsub.add_argument("--reason", default="")
    p_wst = wrk_subs.add_parser("status", parents=[sub_common], help="handshake status of one job")
    p_wst.add_argument("job_id")
    wrk_subs.add_parser("list", parents=[sub_common], help="list jobs in the queue")
    p_wrun = wrk_subs.add_parser("run", parents=[sub_common], help="run the daemon (poll loop)")
    p_wrun.add_argument("case_id")
    p_wrun.add_argument("--interval", type=float, default=5.0, help="poll seconds (default 5)")
    p_wrun.add_argument("--max-runs", type=int, default=None)
    p_wrun.add_argument("--once", action="store_true", help="single pass (tests/CI)")

    # browser bridge
    p_brw = subs.add_parser("browser", parents=[sub_common], help="browser bridge: LLM uses the operator's browser via the extension")
    brw_subs = p_brw.add_subparsers(dest="browser_command", required=True)
    p_brsub = brw_subs.add_parser("submit", parents=[sub_common], help="submit a browser job (extract or interact)")
    p_brsub.add_argument("case_id")
    p_brsub.add_argument("url")
    p_brsub.add_argument("--extract", default="title,links", help="comma list: title,text,links,headers,forms,cookies,meta")
    p_brsub.add_argument("--actions", default="", help="JSON interaction script: [{\"op\":\"click\",\"selector\":\"#login\"}]")
    p_brsub.add_argument("--approved", action="store_true", help="operator approval for submit/navigate ops (required)")
    p_brsub.add_argument("--reason", default="")
    p_brrst = brw_subs.add_parser("result", parents=[sub_common], help="read one job's result/error log")
    p_brrst.add_argument("job_id")
    p_brsrv = brw_subs.add_parser("serve", parents=[sub_common], help="run the localhost bridge for the extension")
    p_brsrv.add_argument("case_id")
    p_brsrv.add_argument("--port", type=int, default=8765)
    p_brsrv.add_argument("--once", action="store_true")

    # agent work (self-repair loop)
    p_awork = subs.add_parser("agent", parents=[sub_common], help="agent sessions")
    agent_subs = p_awork.add_subparsers(dest="agent_command", required=True)
    p_arun = agent_subs.add_parser("run", parents=[sub_common], help="run one agent session")
    p_arun.add_argument("case_id")
    p_arun.add_argument("goal")
    p_arun.add_argument("--plan", default="", help="deterministic plan: action:target[:k=v,k=v];... (LLM planner plugs here)")
    p_arun.add_argument("--max-actions", type=int, default=12)
    p_arun.add_argument("--llm", default="", metavar="MODEL",
                        help="use the LLM planner (AirLLM-mode) with this model")
    p_arun.add_argument("--coverage", action="store_true",
                        help="coverage-driven planner: audit the vuln-coverage blind spots for this case")
    p_aauto = agent_subs.add_parser("auto", parents=[sub_common],
                                    help="Autonomous Engineer: plan → execute → repair → forge missing tools (LLM self-sufficient)")
    p_aauto.add_argument("case_id")
    p_aauto.add_argument("goal")
    p_aauto.add_argument("--llm", default="", metavar="MODEL",
                         help="model for planning/repair (AirLLM local by default; RP_LLM__ENGINE=external for a provider)")
    p_aauto.add_argument("--max-actions", type=int, default=12)
    p_aauto.add_argument("--max-repair-attempts", type=int, default=2)
    p_achat = agent_subs.add_parser("chat", parents=[sub_common],
                                    help="Hermes agent: interactive ChatML chat (no goal → live REPL), or one loop with a goal")
    p_achat.add_argument("case_id")
    p_achat.add_argument("goal", nargs="?", default="",
                         help="omit for the interactive Hermes chat")
    p_achat.add_argument("--max-turns", type=int, default=8,
                         help="bounded agentic turns per message (default 8)")
    p_achat.add_argument("--llm", default="", metavar="MODEL",
                         help="pin the model (default: config profile / engine default)")
    p_achat.add_argument("--tier", default=None, choices=list(_llm_tiers()),
                         help="budget tier for the LLM plane (default: hardware-fit)")
    p_awrk = agent_subs.add_parser("work", parents=[sub_common], help="self-repair session: work list → error log → revise → asks you")
    p_awrk.add_argument("case_id")
    p_awrk.add_argument("goal")
    p_awrk.add_argument("--plan", default="", help="deterministic plan (LLM planner plugs here)")
    p_awrk.add_argument("--max-actions", type=int, default=12)
    p_awrk.add_argument("--llm", default="", metavar="MODEL",
                        help="use the LLM planner (AirLLM-mode) with this model")
    p_awrk.add_argument("--max-repair-attempts", type=int, default=2)

    # hermes — the ONE front door: plain language in, everything by tool call
    p_her = subs.add_parser("hermes", parents=[sub_common],
                            help="the front door: chat with Hermes in plain language — "
                                 "cases, scope, recon, reports, browser, everything by "
                                 "prompting (no case-id ceremony)")
    p_her.add_argument("goal", nargs="*", default="",
                       help="the goal in plain words — quotes optional; "
                            "omit entirely for the interactive chat REPL")
    p_her.add_argument("--max-turns", type=int, default=8,
                       help="bounded agentic turns per message (default 8)")
    p_her.add_argument("--llm", "--model", dest="llm", default="", metavar="MODEL",
                       help="pin the model (default: config profile / engine default)")
    p_her.add_argument("--tier", default=None, choices=list(_llm_tiers()),
                       help="budget tier for the LLM plane (default: hardware-fit)")
    p_her.add_argument("--case", default="",
                       help="case id (default: newest ACTIVE case, else newest, "
                            "else a fresh one is created)")
    p_her.add_argument("--oneshot", action="store_true",
                       help="answer the goal and exit even on a TTY")

    # forge — LLM self-extension
    p_forge = subs.add_parser("forge", parents=[sub_common], help="Feature Forge: the LLM writes its own adapters (gated)")
    forge_subs = p_forge.add_subparsers(dest="forge_command", required=True)
    p_fprop = forge_subs.add_parser("propose", parents=[sub_common], help="submit adapter source through the safety gates")
    p_fprop.add_argument("source_file", nargs="?", type=str, default=None)
    p_fprop.add_argument("--author", default="")
    p_fprop.add_argument("--test-cases", default="", help="JSON list of {target, params} sandbox cases")
    forge_subs.add_parser("list", parents=[sub_common], help="list forged modules")
    p_freg = forge_subs.add_parser("register", parents=[sub_common], help="register forged adapters into the live registry")

    # system — privileged jobs
    p_sys = subs.add_parser("system", parents=[sub_common], help="privileged system jobs (whitelisted, approval-gated sudo)")
    sys_subs = p_sys.add_subparsers(dest="system_command", required=True)
    p_sysub = sys_subs.add_parser("submit", parents=[sub_common], help="submit a whitelisted system job")
    p_sysub.add_argument("case_id")
    p_sysub.add_argument("job_type")
    p_sysub.add_argument("-p", "--param", action="append", nargs=2, metavar=("KEY", "VALUE"), default=[])
    p_sysub.add_argument("--reason", default="")
    p_syrun = sys_subs.add_parser("run", parents=[sub_common], help="run the system-job daemon pass")
    p_syrun.add_argument("case_id")
    p_syrun.add_argument("--max-runs", type=int, default=None)
    sys_subs.add_parser("templates", parents=[sub_common], help="list whitelisted job templates")

    # detection — benign artifacts + IoC/YARA
    p_det = subs.add_parser("detection", parents=[sub_common], help="detection engineering: EICAR/canary/IoC/YARA (benign only)")
    det_subs = p_det.add_subparsers(dest="detection_command", required=True)
    p_detg = det_subs.add_parser("generate", parents=[sub_common], help="generate one benign artifact or ruleset")
    p_detg.add_argument("case_id")
    p_detg.add_argument("kind")
    p_detg.add_argument("--name", required=True)
    p_detg.add_argument("--text", default="", help="free text to extract IoCs from")
    p_detg.add_argument("--ioc", action="append", help="explicit IoC as kind=value (repeatable)")
    p_detg.add_argument("--note", default="")
    p_detk = det_subs.add_parser("kinds", parents=[sub_common], help="list artifact kinds (no case needed)")
    p_detl = det_subs.add_parser("list", parents=[sub_common], help="list generated artifacts")
    p_detl.add_argument("case_id")

    # complaint — law-enforcement packages
    p_comp = subs.add_parser("complaint", parents=[sub_common], help="FIA/IC3/CERT complaint package with verified evidence")
    comp_subs = p_comp.add_subparsers(dest="complaint_command", required=True)
    p_comb = comp_subs.add_parser("build", parents=[sub_common], help="build the complaint bundle")
    p_comb.add_argument("case_id")
    p_comb.add_argument("--agency", default="generic_cert",
                        choices=["fia_ccw", "ic3", "cert_in", "generic_cert"])
    p_comb.add_argument("--incident-type", default="other",
                        choices=["phishing", "ransomware", "beaconing_c2", "account_takeover",
                                 "data_theft", "scam_fraud", "impersonation",
                                 "malware_distribution", "other"])
    p_comb.add_argument("--narrative", default="")
    p_comb.add_argument("--complainant", default="")
    p_comb.add_argument("--targets", default="", help="comma-separated subject targets")
    p_coml = comp_subs.add_parser("list", parents=[sub_common], help="list built packages")
    p_coml.add_argument("case_id")

    # llm — AirLLM-mode low-memory inference plane
    p_llm = subs.add_parser("llm", parents=[sub_common],
                            help="AirLLM-mode: 70B-class models on low-end hardware")
    llm_subs = p_llm.add_subparsers(dest="llm_command", required=True)
    p_lstat = llm_subs.add_parser("status", parents=[sub_common],
                                  help="hardware budget, tier, caps and engine state")
    p_lstat.add_argument("--tier", default=None, choices=list(_llm_tiers()))
    p_lstat.add_argument("--load-engine", default="", metavar="MODEL",
                         help="actually select+load this model, then unload")
    llm_subs.add_parser("models", parents=[sub_common],
                        help="models that fit this machine (AirLLM-mode sizes)")
    llm_subs.add_parser("local", parents=[sub_common],
                        help="checkpoints already on this machine (GGUF + HF cache) "
                             "with the exact command to run each")
    p_lsetup = llm_subs.add_parser("setup", parents=[sub_common],
                                   help="hardware-aware setup: what to install for each "
                                        "engine, with copy-paste commands")
    p_lsetup.add_argument("--engine", default=None,
                          choices=["airllm", "gguf", "native", "external", "hermes"])
    p_lsetup.add_argument("--tier", default=None, choices=list(_llm_tiers()))
    p_lgen = llm_subs.add_parser("generate", parents=[sub_common],
                                 help="one bounded generation (engine loads and unloads)")
    p_lgen.add_argument("prompt")
    p_lgen.add_argument("--model", default="",
                        help="model id (default: RP_LLM__MODEL / config / Qwen/Qwen3-4B)")
    p_lgen.add_argument("--max-tokens", type=int, default=None)
    p_lgen.add_argument("--tier", default=None, choices=list(_llm_tiers()))
    p_lgen.add_argument("--engine", default=None,
                        choices=["airllm", "gguf", "native", "tiny", "external", "hermes"])
    p_lgen.add_argument("--compression", default="", choices=["", "4bit", "8bit"])
    p_lgen.add_argument("--local", action="store_true",
                        help="use the best LOCAL checkpoint that fits this tier "
                             "(GGUF or HF cache) instead of the model default")
    p_lplan = llm_subs.add_parser("plan", parents=[sub_common],
                                  help="LLM planner: goal → validated proposals (dry)")
    p_lplan.add_argument("case_id")
    p_lplan.add_argument("goal")
    p_lplan.add_argument("--model", default="")
    p_lplan.add_argument("--max-tokens", type=int, default=None)
    p_lsub = llm_subs.add_parser("submit", parents=[sub_common],
                                 help="write a SYN llm job file (daemon generates)")
    p_lsub.add_argument("prompt")
    p_lsub.add_argument("--model", default="")
    p_lsub.add_argument("--max-tokens", type=int, default=None)
    p_lsub.add_argument("--compression", default="", choices=["", "4bit", "8bit"])
    p_lsub.add_argument("--queue-dir", default="")
    p_ldata = llm_subs.add_parser("data", parents=[sub_common],
                                  help="case analysis via data pack job (LLM never touches the DB)")
    p_ldata.add_argument("case_id")
    p_ldata.add_argument("question")
    p_ldata.add_argument("--model", default="")
    p_ldata.add_argument("--max-tokens", type=int, default=None)
    p_ldata.add_argument("--pack-only", action="store_true",
                         help="return the bounded data pack without model analysis")
    p_ldata.add_argument("--queue-dir", default="")
    p_lres = llm_subs.add_parser("result", parents=[sub_common],
                                 help="read one llm job's result (ACK)")
    p_lres.add_argument("job_id")
    p_lres.add_argument("--queue-dir", default="")
    p_ldaemon = llm_subs.add_parser("daemon", parents=[sub_common],
                                    help="resident generator: claim → generate → unload")
    p_ldaemon.add_argument("--model", default="")
    p_ldaemon.add_argument("--interval", type=float, default=5.0)
    p_ldaemon.add_argument("--engine", default=None,
                           choices=["airllm", "gguf", "native", "tiny", "external"])
    p_ldaemon.add_argument("--max-runs", type=int, default=None)
    p_ldaemon.add_argument("--once", action="store_true", help="single pass (tests/CI)")
    p_ldaemon.add_argument("--queue-dir", default="")

    # llm prepare — AirLLM layer-shard bake (optionally 4/8-bit quantized)
    p_lprep = llm_subs.add_parser("prepare", parents=[sub_common],
                                  help="bake a LOCAL checkpoint into per-layer shards "
                                       "(optionally 4/8-bit quantized; --delete-original "
                                       "reclaims disk after verification)")
    p_lprep.add_argument("model", help="repo id already in the HF cache, or a local path")
    p_lprep.add_argument("out", help="output shards directory")
    p_lprep.add_argument("--bits", type=int, default=0, choices=[0, 4, 8])
    p_lprep.add_argument("--delete-original", action="store_true")

    # llm script — the LLM writes a code file, the daemon executes it
    p_lscript = llm_subs.add_parser("script", parents=[sub_common],
                                    help="script plane: LLM-written code file, gated "
                                         "and sandbox-executed by the daemon")
    script_subs = p_lscript.add_subparsers(dest="script_command", required=True)
    p_lscsub = script_subs.add_parser("submit", parents=[sub_common],
                                      help="submit a script file (stored, NOT executed here)")
    p_lscsub.add_argument("--file", default="", help="path to the .py script")
    p_lscsub.add_argument("--source", default="", help="inline Python source")
    p_lscsub.add_argument("--payload", default="", help="JSON data passed to run(payload)")
    p_lscsub.add_argument("--name", default="")
    p_lscsub.add_argument("--timeout", type=float, default=60.0)
    p_lscsub.add_argument("--script-dir", default="")
    p_lscres = script_subs.add_parser("result", parents=[sub_common],
                                      help="read one script's actual result")
    p_lscres.add_argument("script_id")
    p_lscres.add_argument("--script-dir", default="")
    p_lsclist = script_subs.add_parser("list", parents=[sub_common], help="list scripts + states")
    p_lsclist.add_argument("--script-dir", default="")
    p_lscrun = script_subs.add_parser("run", parents=[sub_common],
                                      help="run the script daemon (gates → sandbox → result)")
    p_lscrun.add_argument("--interval", type=float, default=5.0)
    p_lscrun.add_argument("--max-runs", type=int, default=None)
    p_lscrun.add_argument("--once", action="store_true", help="single pass (tests/CI)")
    p_lscrun.add_argument("--script-dir", default="")
    p_lscauth = script_subs.add_parser("author", parents=[sub_common],
                                       help="the LLM writes a script for a goal, then "
                                            "submits it through the static gate")
    p_lscauth.add_argument("goal", help="what the script should compute")
    p_lscauth.add_argument("--payload", default="", help="JSON data for run(payload)")
    p_lscauth.add_argument("--name", default="")
    p_lscauth.add_argument("--model", default="")
    p_lscauth.add_argument("--script-dir", default="")
    p_lscretry = script_subs.add_parser("retry", parents=[sub_common],
                                        help="feed a failed script's error + fix hint back "
                                             "to the LLM and re-submit the corrected source")
    p_lscretry.add_argument("script_id")
    p_lscretry.add_argument("--model", default="")
    p_lscretry.add_argument("--script-dir", default="")

    # bounty — authorized bug-bounty workflow (program scope → checks → report)
    p_bounty = subs.add_parser("bounty", parents=[sub_common],
                               help="authorized bug-bounty workflow: import a program's "
                                    "published scope, run in-scope checks, report")
    bounty_subs = p_bounty.add_subparsers(dest="bounty_command", required=True)
    p_bimp = bounty_subs.add_parser("import", parents=[sub_common],
                                    help="import a program's scope document into a case "
                                         "(HackerOne CSV/JSON, or a plain target list)")
    p_bimp.add_argument("case_id")
    p_bimp.add_argument("file", help="scope export: HackerOne CSV/JSON or plain list")
    p_bimp.add_argument("--program", default="", help="program handle/name (recorded as "
                                                       "the authorization source)")
    p_bimp.add_argument("--activate", action="store_true",
                        help="activate the case right away (default: leave it for review)")
    p_bfetch = bounty_subs.add_parser("fetch", parents=[sub_common],
                                      help="fetch a HackerOne program's structured scope "
                                           "directly (API credentials via the credential "
                                           "broker, env, or flags) and import it into a case")
    p_bfetch.add_argument("case_id")
    p_bfetch.add_argument("handle", help="program handle, e.g. 'github' for "
                                          "hackerone.com/github")
    p_bfetch.add_argument("--api-identity", default="", help="H1 API identity "
                            "(default: credential broker / H1_API_USERNAME)")
    p_bfetch.add_argument("--api-token", default="", help="H1 API token "
                          "(default: credential broker / H1_API_TOKEN)")
    p_bfetch.add_argument("--activate", action="store_true",
                          help="activate the case right after import")
    p_bassess = bounty_subs.add_parser("assess", parents=[sub_common],
                                    help="triage collected evidence into reportable "
                                         "findings with severity, CWE and reproduction")
    p_bassess.add_argument("case_id")
    # the exporter formats ride a SEPARATE flag (--fmt) because argparse does
    # not allow a subparser to widen the parent's -o choices in place
    p_breport = bounty_subs.add_parser("report", parents=[sub_common],
                                       help="final submission-ready report (real evidence only; --fmt sarif|markdown for exporters)")
    p_breport.add_argument("case_id")
    p_breport.add_argument("--fmt", dest="report_format", default="",
                           choices=["sarif", "markdown"],
                           help="export format: sarif = SARIF 2.1.0 (code scanning), markdown = disclosure draft")
    p_brun = bounty_subs.add_parser("run", parents=[sub_common],
                                    help="run the authorized check chain over every "
                                         "in-scope asset, then assess")
    p_brun.add_argument("case_id")
    p_brun.add_argument("--execute", action="store_true",
                        help="actually dispatch (default: show the plan only)")
    p_brun.add_argument("--max-assets", type=int, default=25)
    p_brun.add_argument("--scheme", default="https", choices=["https", "http"])
    p_bauto = bounty_subs.add_parser(
        "auto", parents=[sub_common],
        help="one stated goal in, an evidenced report out: scope → recon → assess → "
             "LLM-authored scripts → execute → repair → report")
    p_bauto.add_argument("case_id")
    p_bauto.add_argument("goal", help="plain-language goal, e.g. \"this scope came from "
                                       "HackerOne — find what you can, test it, and give "
                                       "me a report with real results, no demos\"")
    p_bauto.add_argument("--max-assets", type=int, default=25)
    p_bauto.add_argument("--max-pages", type=int, default=25)
    p_bauto.add_argument("--max-scripts", type=int, default=3,
                         help="cap on LLM-authored scripts (default 3)")
    p_bauto.add_argument("--max-repair-rounds", type=int, default=2,
                         help="how many times a failing script goes back to the model")
    p_bauto.add_argument("--no-author", action="store_true",
                         help="skip LLM script authoring (deterministic audit + report only)")
    p_bauto.add_argument("--scheme", default="https", choices=["https", "http"])
    p_bauto.add_argument("--model", default="", help="model id for authoring")
    p_bauto.add_argument("--tier", default=None, choices=list(_llm_tiers()),
                         help="budget tier for authoring (a big local GGUF may "
                              "need a wider tier than the default)")
    p_bauto.add_argument("--script-dir", default="",
                         help="script queue directory (default: workspace llm_scripts)")
    p_bauto.add_argument("--save", action="store_true",
                         help="also write the full session JSON into the case's reports/")
    p_bauto.add_argument("--verbose", action="store_true",
                         help="stream each stage as it runs (stderr)")
    p_bhunt = bounty_subs.add_parser(
        "hunt", parents=[sub_common],
        help="THE front door: HackerOne handle in, an evidenced bounty report out. "
             "Fetches the program scope, authorizes it, runs the full recon/audit "
             "chain, assesses and reports — no questions asked, everything gated.")
    p_bhunt.add_argument("handle", help="program handle (hackerone.com/<handle>)")
    p_bhunt.add_argument("--case", dest="case_id", default="",
                         help="existing case to reuse (default: a fresh one is created)")
    p_bhunt.add_argument("--api-identity", default="",
                         help="H1 API identity (default: broker / H1_API_USERNAME)")
    p_bhunt.add_argument("--api-token", default="",
                         help="H1 API token (default: broker / H1_API_TOKEN)")
    p_bhunt.add_argument("--max-assets", type=int, default=15)
    p_bhunt.add_argument("--max-pages", type=int, default=25)
    p_bhunt.add_argument("--max-scripts", type=int, default=0,
                         help="cap on LLM-authored scripts (0 = deterministic chain)")
    p_bhunt.add_argument("--scheme", default="https", choices=["https", "http"])
    p_bhunt.add_argument("--tier", default=None, choices=list(_llm_tiers()))
    p_bhunt.add_argument("--no-author", action="store_true",
                         help="skip LLM script authoring (deterministic audit + report)")
    p_bhunt.add_argument("--save", action="store_true",
                         help="write the session JSON into the case's reports/")
    p_bhunt.add_argument("--verbose", action="store_true", help="stream stages to stderr")

    # doctor
    subs.add_parser("doctor", parents=[sub_common], help="environment and configuration health check")

    # shell — the sci-fi unicode interactive console
    subs.add_parser("shell", parents=[sub_common], help="interactive sci-fi console over the same CLI (unicode prompt, :plan/:cover/:tools)")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "group", None):
        parser.print_help()
        return EXIT_USAGE
    try:
        ctx = AppContext(
            data_dir=args.data_dir, assume_yes=args.yes,
            actor=getattr(args, "actor", None),
            rbac_enabled=getattr(args, "rbac", False),
            queue_on_approval_refusal=True,
            profile_path=getattr(args, "config_file", None),
            privileged_runner=bool(getattr(args, "privileged", False)),
        )
    except RPError as exc:
        # A bad --config-file must fail like every other error: structured,
        # with a fix hint — never a traceback.
        if getattr(args, "output", "human") == "human":
            print(theme.error_frame(exc.title, exc.message, exc.reason,
                                    exc.action, exc.exit_code), file=sys.stderr)
        else:
            print(json.dumps({"error": {"title": exc.title, "message": exc.message,
                                        "reason": exc.reason, "action": exc.action,
                                        "exit_code": exc.exit_code}}, indent=2),
                  file=sys.stderr)
        return exc.exit_code
    try:
        handlers = {
            "case": cmd_case,
            "llm": cmd_llm,
            "scope-check": cmd_scope_check,
            "plan": cmd_plan,
            "run": cmd_run,
            "adapters": cmd_adapters,
            "knowledge": cmd_knowledge,
            "intel": cmd_intel,
            "evidence": cmd_evidence,
            "audit": cmd_audit,
            "report": cmd_report,
            "agent": cmd_agent,
            "hermes": cmd_hermes,
            "surface": cmd_surface,
            "member": cmd_member,
            "approval": cmd_approval,
            "hypothesis": cmd_hypothesis,
            "workflow": cmd_workflow,
            "schedule": cmd_schedule,
            "search": cmd_search,
            "credential": cmd_credential,
            "plugin": cmd_plugin,
            "events": cmd_events,
            "serve": cmd_serve,
            "ops": cmd_ops,
            "worker": cmd_worker,
            "browser": cmd_browser,
            "forge": cmd_forge,
            "system": cmd_system,
            "detection": cmd_detection,
            "complaint": cmd_complaint,
            "bounty": cmd_bounty,
            "doctor": cmd_doctor,
        }
        if args.group == "shell":
            from .shell import run_shell

            return run_shell(ctx)
        return handlers[args.group](ctx, args)
    except RPError as exc:
        if getattr(args, "output", "human") == "human":
            print(theme.error_frame(exc.title, exc.message, exc.reason,
                                    exc.action, exc.exit_code), file=sys.stderr)
        else:
            print(json.dumps({"error": {"title": exc.title, "message": exc.message,
                                        "reason": exc.reason, "action": exc.action,
                                        "exit_code": exc.exit_code}}, indent=2), file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 10


if __name__ == "__main__":
    sys.exit(main())
