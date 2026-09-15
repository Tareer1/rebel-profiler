"""Bounty session: one stated goal in, a scoped and evidenced report out.

The operator states the goal in plain language — for example *"this scope came
from HackerOne: find what you can, test it, and give me a report with real
results, no demos"* — and this orchestrator runs the whole chain:

    SCOPE    read the case's authorized assets (imported from the program)
    RECON    scope-enforced web audit of every in-scope asset
    ASSESS   triage the collected evidence into reportable findings
    AUTHOR   the LLM decides which scripts the goal still needs, writes them
             and queues them (stored, never executed at submission time)
    EXECUTE  the script plane's static gate + sandbox runs them and records the
             real outcome — return value, stdout, timings, or a real failure
    REPAIR   failures and gate rejections go back to the model, bounded
    REPORT   severity + CWE + reproduction + remediation, evidence-backed

Nothing here widens authority. The case must be **ACTIVE**, every asset is
re-validated against the live scope before it is touched, scripts reach exactly
what the static gate allows (no network, no filesystem, no process access), and
no finding is reported without hash-chained evidence behind it.

When no real engine is available the session says so and skips authoring rather
than failing or faking it: the deterministic audit and the report still run.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from ..core.errors import UsageError

# Bounds. A session is always finite, and never unbounded in files or rounds.
MAX_STATE_FINDINGS = 40
MAX_PAYLOAD_BYTES = 200_000
DEFAULT_MAX_SCRIPTS = 3
DEFAULT_MAX_REPAIR_ROUNDS = 2

def split_asset(asset: str) -> tuple[str, int | None] | None:
    """Split one scope asset into ``(host, port)`` the way scope matching sees it.

    The scope engine and the web auditor both match on **hostname**
    (``ScopeEnforcedWebAuditor`` authorizes ``urlsplit(url).hostname``), so the
    port is kept aside instead of being glued into the value being authorized.
    Doing the split here keeps the session's own validation and the seeds it
    builds in the same shape: a ``host:port`` asset is authorized as ``host``
    and seeded *with* its port, rather than failing to match anything and being
    skipped as out of scope.

    Returns ``None`` when the value cannot be a web host at all.
    """
    value = (asset or "").strip()
    if not value:
        return None
    host, port = value, None
    if "://" in value:
        try:
            parsed = urlsplit(value)
            # `.port` raises on a malformed port, so it belongs inside the try.
            host, port = parsed.hostname or "", parsed.port
        except ValueError:
            return None
    elif value.startswith("[") and "]" in value:       # [v6]:port or [v6]
        end = value.index("]")
        host, tail = value[1:end], value[end + 1:]
        if tail.startswith(":") and tail[1:].isdigit():
            port = int(tail[1:])
    elif value.count(":") == 1:                        # host:port (v6 has more)
        name, _, tail = value.partition(":")
        if tail.isdigit():
            host, port = name, int(tail)
    if host.startswith("*."):
        host = host[2:]
    host = host.strip().strip("[]").lower().rstrip(".")
    return (host, port) if host else None


def seed_url(scheme: str, host: str, port: int | None) -> str:
    """The audit URL for one authorized host (IPv6 literals re-bracketed)."""
    literal = f"[{host}]" if ":" in host else host
    return f"{scheme}://{literal}{f':{port}' if port else ''}/"


@dataclass
class BountySessionResult:
    """Everything the session did, in the order it did it."""

    case_id: str
    goal: str
    started_at: float
    finished_at: float = 0.0
    assets: list[str] = field(default_factory=list)
    skipped_assets: list[dict] = field(default_factory=list)
    stages: list[dict] = field(default_factory=list)
    audit: dict | None = None
    scripts: list[dict] = field(default_factory=list)
    authoring: dict = field(default_factory=dict)
    report: dict | None = None
    stats: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "schema_version": 1,
            "case_id": self.case_id,
            "goal": self.goal,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "stages": self.stages,
            "assets": self.assets,
            "skipped_assets": self.skipped_assets,
            "audit": self.audit,
            "authoring": self.authoring,
            "scripts": self.scripts,
            "report": self.report,
            "stats": self.stats,
        }

    def render_human(self) -> str:
        duration = (self.finished_at or time.time()) - self.started_at
        lines = [
            f"Bounty session — case {self.case_id}",
            f"goal      : {self.goal}",
            f"elapsed   : {duration:.1f}s",
            "",
            "Stages:",
        ]
        for stage in self.stages:
            mark = {"done": "+", "skipped": "-", "failed": "!"}.get(
                stage.get("status", ""), "?")
            detail = stage.get("detail", "")
            lines.append(f"  [{mark}] {stage['stage']:<8} {stage.get('status', '')}"
                         + (f" — {detail}" if detail else ""))
        lines.append("")
        lines.append(f"Assets: {len(self.assets)} audited, "
                     f"{len(self.skipped_assets)} skipped")
        for row in self.skipped_assets:
            lines.append(f"  (skip) {row['asset']} — {row['reason']}")
        if self.audit:
            stats = self.audit.get("stats", {})
            lines.append(f"  pages: {stats.get('pages_audited', 0)} audited, "
                         f"{stats.get('findings', 0)} check(s) fired, "
                         f"{stats.get('pages_blocked_or_errored', 0)} unreachable")
        lines.append("")
        scripts = self.scripts
        if scripts:
            lines.append(f"Scripts: {len(scripts)} authored, "
                         f"{sum(1 for s in scripts if s.get('state') == 'done')} "
                         "finished")
            for script in scripts:
                state = script.get("state", "pending")
                lines.append(f"  [{state}] {script.get('name', script.get('script_id'))}")
                if state == "done":
                    rendered = str(script.get("result", ""))[:200]
                    lines.append(f"        result: {rendered}")
                else:
                    lines.append(f"        error : {str(script.get('error', ''))[:200]}")
                    rounds = script.get("repair_rounds", 0)
                    lines.append(f"        repair rounds: {rounds}")
        elif self.authoring.get("available") is False:
            lines.append(f"No scripts: {self.authoring.get('reason', '')}")
        else:
            lines.append("No scripts were needed for this goal.")
        lines.append("")
        report = self.report or {}
        findings = report.get("findings") or []
        lines.append(f"Findings: {len(findings)}")
        for finding in findings:
            lines.append(f"  [{str(finding.get('severity', '')).upper()}] "
                         f"{finding.get('title', '')} — {finding.get('asset', '')}")
            lines.append(f"        cwe: {finding.get('cwe', '-')}  "
                         f"repro: {finding.get('reproduce', '-')}")
            lines.append(f"        evidence: "
                         f"{(finding.get('evidence_ids') or ['-'])[0]}")
        if not findings:
            lines.append("  (nothing reportable from the evidence collected)")
        lines.append("")
        lines.append(f"Verify the evidence: rebel-profiler evidence verify {self.case_id}")
        lines.append("Advisory severities — the program's own taxonomy governs payout.")
        return "\n".join(lines)


class BountySession:
    """Runs the whole authorized chain for one goal."""

    def __init__(self, case_id: str, *, goal: str, db, scope_engine, case_dir,
                 case_status: str, ledger, evidence, audit=None,
                 max_assets: int = 25, max_pages: int = 25,
                 max_scripts: int = DEFAULT_MAX_SCRIPTS,
                 max_repair_rounds: int = DEFAULT_MAX_REPAIR_ROUNDS,
                 scheme: str = "https", model: str | None = None,
                 tier: str | None = None,
                 script_dir: Path | str | None = None,
                 author_scripts: bool = True,
                 on_stage=None) -> None:
        self.case_id = case_id
        self.goal = goal or ""
        self.db = db
        self.scope_engine = scope_engine
        self.case_dir = Path(case_dir)
        self.case_status = case_status
        self.ledger = ledger
        self.evidence = evidence
        self.audit = audit
        self.max_assets = max(1, max_assets)
        self.max_pages = max(1, max_pages)
        self.max_scripts = max(0, max_scripts)
        self.max_repair_rounds = max(0, max_repair_rounds)
        self.scheme = scheme if scheme in {"http", "https"} else "https"
        self.model = model
        self.tier = tier
        self.script_dir = Path(script_dir) if script_dir else (
            self.case_dir / "llm_scripts")
        self.author_scripts = author_scripts
        self.on_stage = on_stage
        self.result = BountySessionResult(case_id=case_id, goal=self.goal,
                                          started_at=time.time())

    # -- reporting helpers ----------------------------------------------------

    def _stage(self, stage: str, status: str, detail: str = "", **extra) -> None:
        record = {"stage": stage, "status": status, "detail": detail, **extra}
        self.result.stages.append(record)
        if self.on_stage is not None:
            try:
                self.on_stage(record)
            except Exception:
                pass

    def _reload_ledger(self):
        from .claims import ClaimLedger

        return ClaimLedger.load_from_db(self.db, self.case_id)

    # -- the chain ------------------------------------------------------------

    def run(self) -> BountySessionResult:
        self._resolve_assets()
        self._recon()
        self._assess()
        self._author()
        self._execute()
        self._repair()
        self._report()
        self.result.finished_at = time.time()
        return self.result

    # SCOPE -------------------------------------------------------------------

    def _resolve_assets(self) -> None:
        entries = [dict(row) for row in self.db.scope_entries(self.case_id)]
        includes = [str(e["value"]) for e in entries if not e.get("excluded")]
        if not includes:
            raise UsageError(
                f"Case {self.case_id} has no in-scope assets",
                reason="A session only ever touches what the case authorizes.",
                action=f"rebel-profiler bounty import {self.case_id} <scope-file>")
        if self.case_status != "active":
            raise UsageError(
                f"Case {self.case_id} is '{self.case_status}', not active",
                reason="Scope enforcement only authorizes targets in an ACTIVE "
                       "case — activating it is the authorization step.",
                action=f"rebel-profiler case activate {self.case_id}")

        seeds: list[str] = []
        skipped: list[dict] = []
        for asset in includes[: self.max_assets]:
            if "/" in asset and "://" not in asset:
                skipped.append({
                    "asset": asset,
                    "reason": "network range — web audit does not apply; use "
                              f"'intel collect {self.case_id} port-scan <host>'"})
                continue
            target = split_asset(asset)
            if target is None:
                skipped.append({"asset": asset,
                                "reason": "not a web host"})
                continue
            host, port = target
            status = self.scope_engine.evaluate(self.case_id, host)
            if status != "in_scope":
                skipped.append({"asset": asset, "reason": status})
                continue
            seeds.append(seed_url(self.scheme, host, port))

        self.result.assets = seeds
        self.result.skipped_assets = skipped
        if len(includes) > self.max_assets:
            skipped.append({"asset": f"(+{len(includes) - self.max_assets} more)",
                            "reason": f"beyond --max-assets {self.max_assets}"})
        if not seeds:
            raise UsageError(
                "No in-scope asset survived validation",
                reason="Every imported asset was out of scope or not web-auditable.",
                action=f"rebel-profiler case scope show {self.case_id}")
        self._stage("scope", "done",
                    f"{len(seeds)} asset(s) authorized, {len(skipped)} skipped")

    # RECON -------------------------------------------------------------------

    def _recon(self) -> None:
        from .claims import ClaimLedger
        from .sources import SourceRegistry
        from .web import ScopeEnforcedWebAuditor

        auditor = ScopeEnforcedWebAuditor(
            self.case_id, scope_engine=self.scope_engine,
            ledger=ClaimLedger(SourceRegistry()), evidence=self.evidence,
            max_pages=self.max_pages, max_depth=1,
            # Findings must reach the ledger, not just memory: the assessment
            # and the report both read it back from the case database.
            db=self.db,
        )
        try:
            report = auditor.crawl(self.result.assets)
        except Exception as exc:      # scope refusals and transport errors alike
            self._stage("recon", "failed", f"{type(exc).__name__}: {exc}")
            raise
        self.result.audit = report
        stats = report.get("stats", {})
        self._stage("recon", "done",
                    f"{stats.get('pages_audited', 0)} page(s), "
                    f"{stats.get('findings', 0)} check(s) fired")

    # ASSESS ------------------------------------------------------------------

    def _assess(self, *, stage: bool = True) -> dict:
        """Triage the ledger. Re-run before the report without re-staging."""
        from .bounty import assess

        ledger = self._reload_ledger()
        report = assess(ledger, self.case_id, program=self._program())
        self.result.report = report.as_dict()
        if stage:
            self._stage("assess", "done",
                        f"{len(report.findings)} reportable, "
                        f"{len(report.unmapped)} unmapped observation(s)")
        return self.result.report or {}

    # AUTHOR ------------------------------------------------------------------

    def _session_state(self) -> dict:
        report = self.result.report or {}
        stats = (self.result.audit or {}).get("stats", {})
        state = {
            "goal": self.goal,
            "assets": self.result.assets[:20],
            "skipped_assets": self.result.skipped_assets[:10],
            "audit_stats": stats,
            "report_stats": report.get("stats", {}),
            "findings": [
                {"asset": f.get("asset"), "title": f.get("title"),
                 "severity": f.get("severity"), "cwe": f.get("cwe"),
                 "detail": f.get("detail")}
                for f in (report.get("findings") or [])[:MAX_STATE_FINDINGS]
            ],
            "unmapped_observations": (report.get("unmapped_observations") or [])[:20],
        }
        return state

    def _author(self) -> None:
        if not self.author_scripts or self.max_scripts == 0:
            self.result.authoring = {"available": False,
                                     "reason": "authoring disabled for this run"}
            self._stage("author", "skipped", "disabled (--no-author)")
            return
        from ..core.errors import DependencyUnavailableError
        from ..llm import codegen

        state = self._session_state()
        plane = None
        try:
            try:
                plan = codegen.plan_scripts(self.goal, state=state,
                                            model=self.model,
                                            max_scripts=self.max_scripts)
            except DependencyUnavailableError as exc:
                # Honest degradation: the deterministic half of the session has
                # already run, so we record why authoring was skipped.
                self.result.authoring = {"available": False,
                                         "reason": exc.message,
                                         "action": exc.action}
                self._stage("author", "skipped", exc.message)
                return

            self.result.authoring = {"available": True,
                                     "engine": plan.get("engine", ""),
                                     "model": plan.get("model", ""),
                                     "dropped": plan.get("dropped", 0),
                                     "note": plan.get("note", "")}
            specs = plan.get("scripts") or []
            if not specs:
                self._stage("author", "done", "the model judged no script necessary")
                return

            # One plane for the whole session: weights load once, not per script.
            plane = codegen._plane_from_env(tier=self.tier)
            payload_common = self._script_payload(state)
            for spec in specs:
                payload = dict(spec.get("payload") or {})
                payload.update(payload_common)
                envelope = codegen.author_script(
                    spec["goal"], script_dir=self.script_dir, payload=payload,
                    name=spec["goal"][:48], model=self.model, plane=plane,
                    case_id=self.case_id, requested_by="agent")
                self.result.scripts.append({
                    "script_id": envelope["script_id"],
                    "name": envelope.get("name", ""),
                    "goal": spec["goal"],
                    "state": "pending",
                    "generator": envelope.get("generator", {}),
                    "lines": len(str(envelope.get("source", "")).splitlines()),
                })
            self._stage("author", "done",
                        f"{len(self.result.scripts)} script(s) written and queued "
                        f"via the {plan.get('engine', '?')} engine")
        finally:
            if plane is not None:
                plane.unload()

    def _script_payload(self, state: dict) -> dict:
        """The evidence-backed data a script may compute over."""
        data = {
            "case_state": state,
            "findings": state.get("findings", []),
            "assets": state.get("assets", []),
        }
        if len(json.dumps(data, default=str)) > MAX_PAYLOAD_BYTES:
            data["case_state"]["findings"] = data["findings"][:10]
        return data

    # EXECUTE -----------------------------------------------------------------

    def _poll_scripts(self) -> list[dict]:
        from ..llm.codescript import REJECT_SUFFIX, ScriptRunner, load_script_result

        runner = ScriptRunner(self.script_dir,
                              data_dir=self.script_dir.parent,
                              audit=self.audit, evidence=self.evidence)
        handled = runner.poll_once()
        for entry in self.result.scripts:
            result = load_script_result(entry["script_id"],
                                        script_dir=self.script_dir)
            if result is None:
                # A script the static gate refused never produces a result
                # file — only a rejection. Report that, don't leave it
                # looking like it is still pending.
                reject = self.script_dir / f"{entry['script_id']}{REJECT_SUFFIX}"
                if reject.exists():
                    try:
                        payload = json.loads(reject.read_text())
                    except (OSError, json.JSONDecodeError):
                        payload = {}
                    entry["state"] = "rejected"
                    entry["error"] = str(
                        payload.get("error", "rejected by the static gate"))[:500]
                    entry["fix"] = "; ".join(
                        str(f) for f in (payload.get("findings") or [])[:6])[:300]
                continue
            entry["state"] = result.get("state", "unknown")
            if result.get("state") == "done":
                entry["result"] = result.get("result")
                entry["stdout"] = (result.get("stdout") or "")[:2000]
                entry["elapsed_s"] = result.get("elapsed_s")
            else:
                entry["error"] = str(result.get("error", ""))[:500]
                entry["fix"] = str(result.get("fix", ""))[:300]
        return handled

    def _execute(self) -> None:
        if not self.result.scripts:
            self._stage("execute", "skipped", "no scripts to run")
            return
        handled = self._poll_scripts()
        done = sum(1 for s in self.result.scripts if s.get("state") == "done")
        self._stage("execute", "done",
                    f"{done}/{len(self.result.scripts)} script(s) produced a real "
                    f"result ({len(handled)} handled by the gate)")

    # REPAIR ------------------------------------------------------------------

    def _repair(self) -> None:
        if not self.result.scripts:
            self._stage("repair", "skipped", "no scripts to run")
            return
        pending = [s for s in self.result.scripts if s.get("state") != "done"]
        if not pending:
            self._stage("repair", "skipped", "every script succeeded")
            return
        if self.max_repair_rounds == 0:
            self._stage("repair", "skipped", "repair disabled")
            return
        from ..core.errors import RPError
        from ..llm import codegen

        plane = None
        try:
            plane = codegen._plane_from_env(tier=self.tier)
            for entry in pending:
                entry["repair_rounds"] = 0
                for _round in range(self.max_repair_rounds):
                    try:
                        envelope = codegen.retry_script(
                            entry["script_id"], script_dir=self.script_dir,
                            goal=self.goal, model=self.model, plane=plane,
                            case_id=self.case_id, requested_by="agent")
                    except RPError as exc:
                        entry.setdefault("repair_notes", []).append(exc.message)
                        break
                    entry["repair_rounds"] += 1
                    fixed = {
                        "script_id": envelope["script_id"],
                        "name": envelope.get("name", ""),
                        "goal": f"repair of {entry['script_id']}",
                        "state": "pending",
                        "parent_script_id": entry["script_id"],
                        "generator": envelope.get("generator", {}),
                    }
                    self.result.scripts.append(fixed)
                    self._poll_scripts()
                    if fixed.get("state") == "done":
                        entry["repaired_by"] = fixed["script_id"]
                        break
        finally:
            if plane is not None:
                plane.unload()

        repaired = sum(1 for s in self.result.scripts if s.get("repaired_by"))
        still = sum(1 for s in self.result.scripts
                    if s.get("state") != "done" and not s.get("parent_script_id"))
        self._stage("repair", "done",
                    f"{repaired} repaired, {still} still failing")

    # REPORT ------------------------------------------------------------------

    def _report(self) -> None:
        # Re-assess: the authored scripts may have added evidence since the
        # authoring step. No second stage line — `report` summarises it.
        report = self._assess(stage=False)
        stats = report.get("stats", {})
        self.result.stats = {
            "assets": len(self.result.assets),
            "pages_audited": (self.result.audit or {}).get("stats", {}).get(
                "pages_audited", 0),
            "findings": stats.get("findings", 0),
            "by_severity": stats.get("by_severity", {}),
            "scripts_authored": len(self.result.scripts),
            "scripts_succeeded": sum(1 for s in self.result.scripts
                                     if s.get("state") == "done"),
            "authoring_available": self.result.authoring.get("available", False),
        }
        self._stage("report", "done",
                    f"{stats.get('findings', 0)} finding(s) across "
                    f"{stats.get('assets', 0)} asset(s)")

    # helpers -----------------------------------------------------------------

    def _program(self) -> str:
        try:
            rows = [dict(r) for r in self.db.scope_entries(self.case_id)]
        except Exception:
            return ""
        for row in rows:
            note = str(row.get("note") or "")
            if "bug-bounty program scope (" in note:
                return note.split("bug-bounty program scope (", 1)[1].split(")", 1)[0].strip()
        return ""
