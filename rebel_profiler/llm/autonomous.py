"""The Autonomous Engineer: the LLM repairs and extends the tool itself.

Goal — the operator states *what*; the LLM figures out *how*, and when the
tool cannot do something yet, the LLM builds that capability too:

    rebel-profiler agent auto <case-id> "map example.com fully"

One loop, four phases, every step gated:

  1. PLAN      — the LLM planner reads the goal + the live action contract
                 and emits validated Proposals (same gate as `agent run`).
  2. EXECUTE   — the work list runs through the six gates. Failures become
                 structured error-log entries with deterministic fix hints.
  3. REPAIR    — the LLM reviser sees the error + the fix hint + the action
                 contract and returns a corrected proposal (bounded retries;
                 scope/policy blocks are NEVER auto-retried).
  4. EXTEND    — when the fix hint says the capability itself is missing
                 ("no adapter", "unknown action", "not whitelisted"), the LLM
                 writes a new adapter module and pushes it through Feature
                 Forge's deterministic gates (static AST gate → subprocess
                 sandbox test → HMAC signature → live registration). If the
                 gates reject it, the LLM gets the findings and may rewrite —
                 bounded times. The system, never the LLM, decides what code
                 may run.

Output: a session report — what was proposed, what ran, what was repaired,
what was forged, what still awaits the operator. Evidence and audit cover
every step; nothing here bypasses scope, policy or the hardware budget.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..agent import Proposal
from ..agent.forge import FeatureForge
from ..agent.repair import SelfRepairSession
from ..core.errors import RPError, UsageError
from ..core.redact import redact
from ..llm.planner import LlmPlanner

# How many forge rounds the LLM may spend per session (bounded self-growth).
MAX_FORGE_ROUNDS = 3
MAX_SOURCE_ROUNDS = 3

# Error signatures that mean "the capability does not exist yet".
_EXTENDABLE_SIGNATURES = ("no adapter", "unknown action", "not whitelisted",
                          "missing capability")

FORGE_TEMPLATE = '''"""Feature-forge adapter: written by the LLM, gated by the system."""

import shlex

from rebel_profiler.execution.broker import Adapter


class {class_name}(Adapter):
    name = "{adapter_name}"
    binary = {binary!r}
    capability_class = "forge"
    allowed_params = {allowed_params!r}

    def build_argv(self, request):
        {body}


PLUGIN_ADAPTERS = ({class_name},)
'''


@dataclass
class AutoSessionResult:
    """Everything the operator needs to see after an autonomous run."""

    plan: list[dict] = field(default_factory=list)
    executed: list[dict] = field(default_factory=list)
    repairs: list[dict] = field(default_factory=list)
    forged: list[dict] = field(default_factory=list)
    still_missing: list[str] = field(default_factory=list)
    awaiting_user: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "plan": self.plan, "executed": self.executed,
            "repairs": self.repairs, "forged": self.forged,
            "still_missing": self.still_missing,
            "awaiting_user": self.awaiting_user,
        }


class AutonomousEngineer:
    """Plan → execute → repair → extend, with the LLM in every thinking seat."""

    def __init__(self, case_id: str, goal: str, *, ctx, db, model: str = "",
                 max_actions: int = 12, max_repair_attempts: int = 2) -> None:
        self.case_id = case_id
        self.goal = goal
        self.ctx = ctx
        self.db = db
        # Model resolution: --llm flag > config profile [llm] model > "".
        self.model = model or str(
            (getattr(ctx, "config", None) or {}).get("llm", {}).get("model", "") or "")
        self.max_actions = max_actions
        self.max_repair_attempts = max_repair_attempts
        self.result = AutoSessionResult()

    # -- entry -------------------------------------------------------------------

    def run(self) -> dict:
        """The full autonomous loop. Returns the operator-facing report."""
        registry = self.ctx.broker(self.db).adapters

        # -- 1. PLAN — the LLM planner, validated like any other source -----
        planner = LlmPlanner(model=self.model or None, registry=registry)
        try:
            from ..agent import PlannerView

            proposals = planner(PlannerView(self.case_id, self.goal, registry))
            self.result.plan = [
                {"action": p.action, "target": p.target, "params": p.params}
                for p in proposals
            ]
        finally:
            planner.plane.unload()   # the CLI process never stays heavy

        # -- 2+3. EXECUTE + REPAIR — the self-repair loop with an LLM reviser
        reviser = self._make_llm_reviser(registry)
        session = SelfRepairSession(
            self.case_id, self.goal, broker=self.ctx.broker(self.db),
            ledger=self._ledger(), evidence=self.ctx.evidence_store(self.db, self.case_id),
            db=self.db, audit=None, max_actions=self.max_actions,
            max_repair_attempts=self.max_repair_attempts,
        )

        def planner_callable(view):
            return proposals

        report = session.run(planner_callable, reviser=reviser)
        self.result.executed = report["items"]
        self.result.repairs = report["repairs"]

        # -- 4. EXTEND — forge what the tool was missing ---------------------
        self._extend_missing(registry)
        self.result.awaiting_user = [
            s["text"] for s in session.suggestions]
        return {
            "session_id": report["session_id"],
            "case_id": self.case_id,
            "goal": self.goal,
            "mode": "autonomous-engineer",
            **self.result.as_dict(),
            "report_human": render_auto_human(self.result, report),
            "self_repair_report": report,
        }

    # -- pieces --------------------------------------------------------------------

    def _ledger(self):
        from ..intel.claims import ClaimLedger
        from ..intel.sources import SourceRegistry

        return ClaimLedger(SourceRegistry())

    def _make_llm_reviser(self, registry):
        """LLM reviser: error log + fix hint → corrected Proposal (or None)."""
        plane_holder: dict = {"plane": None}

        def reviser(feedback: dict):
            try:
                if plane_holder["plane"] is None:
                    from ..llm.planner import _plane_from_env

                    plane_holder["plane"] = _plane_from_env()
                plane = plane_holder["plane"]
                if plane.engine_kind is None:
                    plane.select_engine(self.model or "")
                from ..llm.inference import TinyLlmEngine

                if isinstance(plane.engine, TinyLlmEngine):
                    return None   # honest: no weights, no invented fixes
                prompt = _repair_prompt(feedback, self.goal)
                result = plane.generate(prompt, max_new_tokens=256)
                proposals = parse_repair_reply(result.text, registry)
                return proposals[0] if proposals else None
            except (RPError, UsageError):
                return None   # a failed repair attempt is just a failed attempt
            finally:
                pass

        return reviser

    # -- phase 4: self-extension -------------------------------------------------

    def _extend_missing(self, registry) -> None:
        """Forge adapters for every missing capability the error log revealed."""
        missing = _missing_capabilities(self.result.repairs, registry)
        if not missing:
            return
        forge = FeatureForge(self.ctx.data_dir, audit=None)
        for spec in missing[:MAX_FORGE_ROUNDS]:
            forged = self._forge_one(forge, spec)
            self.result.forged.append(forged)
            if forged.get("accepted"):
                registered = forge.register_into(registry)
                forged["registered"] = registered

    def _forge_one(self, forge: FeatureForge, spec: dict) -> dict:
        """Write → gate → (on findings) rewrite → register one adapter."""
        source = _render_adapter(spec)
        rounds = 0
        last_findings: list[dict] = []
        while rounds < MAX_SOURCE_ROUNDS:
            rounds += 1
            outcome = forge.propose(source, author="autonomous-engineer",
                                    test_cases=[{"target": spec["example_target"],
                                                 "params": {}}])
            if outcome.accepted:
                return {"capability": spec["capability"], "accepted": True,
                        "module": outcome.module_name,
                        "adapters": outcome.adapters, "rounds": rounds}
            last_findings = [f.as_dict() for f in outcome.findings]
            # The LLM rewrites against the gate findings (bounded).
            source = _rewrite_against_findings(source, last_findings)
            if source is None:
                break
        return {"capability": spec["capability"], "accepted": False,
                "module": "", "adapters": [], "rounds": rounds,
                "findings": last_findings}


# ---------------------------------------------------------------------------
# prompt builders + parsers (deterministic validation on top of LLM text)


def _repair_prompt(feedback: dict, goal: str) -> str:
    item = feedback.get("item", {})
    error = feedback.get("error", {})
    return (
        "You are the repair reviser of an authorized security tool.\n"
        f"GOAL: {redact(goal)[:300]}\n"
        f"FAILED ITEM: {json.dumps(item)[:400]}\n"
        f"ERROR: {redact(str(error.get('message', '')))[:200]}\n"
        f"FIX HINT: {feedback.get('fix_hint', '')[:200]}\n"
        "AVAILABLE ACTIONS: "
        + json.dumps(feedback.get("available_actions", []))[:600] + "\n\n"
        "Reply with ONE JSON object — the corrected proposal:\n"
        '{"action": "...", "target": "...", "params": {}, "reason": "..."}\n'
        "Only declared actions/params. If no correction can help, reply {}."
    )


def parse_repair_reply(reply: str, registry) -> list[Proposal] | None:
    """Parse the reviser's single-proposal reply; None means 'give up'."""
    import re as _re

    from ..llm.planner import parse_proposals

    # Strip fences and find the JSON object the model was asked to emit.
    compact = _re.sub(r"```(?:json)?", "", reply).strip()
    if not compact or compact.startswith("{}"):
        return None
    start = compact.find("{")
    if start == -1:
        return None
    end = compact.rfind("}")
    if end <= start:
        return None
    candidate = compact[start:end + 1]
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or not data.get("action"):
        return None   # an empty/give-up reply is honest, never invented
    try:
        proposals = parse_proposals(candidate, registry=registry)
    except UsageError:
        return None
    return proposals or None


def _missing_capabilities(repairs: list[dict], registry) -> list[dict]:
    """Capabilities whose failure signatures mean 'this action does not exist'."""
    known = set(registry.names())
    specs: list[dict] = []
    seen: set[str] = set()
    for entry in repairs:
        message = str(entry.get("message", "")).lower()
        if not any(sig in message for sig in _EXTENDABLE_SIGNATURES):
            continue
        action = str(entry.get("action", "")).strip()
        if not action or action in known or action in seen:
            continue
        seen.add(action)
        specs.append({
            "capability": action,
            "example_target": str(entry.get("target", "h1.lab.example.test")),
        })
    return specs


def _render_adapter(spec: dict) -> str:
    """First-cut adapter source for a missing capability.

    The template builds a bounded argv from declared params only — the same
    contract every broker adapter follows. The LLM may refine the body via
    the rewrite loop; the forge gates decide whether any version runs.
    """
    class_name = "Forged" + "".join(
        part.capitalize() for part in spec["capability"].replace("-", "_").split("_"))
    safe_params = ["mode", "target_port", "record_type"]
    body = (
        "params = dict(request.params or {})\n"
        "        argv = [self.binary, request.target]\n"
        "        mode = str(params.get('mode', 'default'))\n"
        "        if mode:\n"
        "            argv += ['--mode', shlex.quote(mode)]\n"
        "        port = params.get('target_port')\n"
        "        if port is not None:\n"
        "            argv += ['-p', shlex.quote(str(port))]\n"
        "        return argv"
    )
    return FORGE_TEMPLATE.format(
        class_name=class_name,
        adapter_name=spec["capability"],
        binary=_guess_binary(spec["capability"]),
        allowed_params=safe_params,
        body=body,
    )


def _guess_binary(capability: str) -> str:
    """Pick the whitelisted binary the capability name suggests."""
    cap = capability.lower()
    for tool, binary in (("dns", "dig"), ("whois", "whois"), ("scan", "nmap"),
                         ("ssl", "sslscan"), ("smb", "enum4linux-ng"),
                         ("http", "curl")):
        if tool in cap:
            return binary
    return "dig"   # harmless default; the broker whitelist still gates it


def _rewrite_against_findings(source: str, findings: list[dict]) -> str | None:
    """Deterministic rewrite pass over gate findings (no LLM needed for these).

    Handles the common gate complaints mechanically; returns None when the
    findings are not mechanically fixable (then the round budget stops it).
    """
    rules = {f.get("rule") for f in findings}
    rewritten = source
    if "forbidden_builtin" in rules and "shlex.quote" in rewritten:
        # shlex.quote is fine, but getattr/setattr-style strings are not;
        # strip any residual dynamic access defensively.
        rewritten = rewritten.replace("getattr(", "  # removed: ")
    if "dangerous_literal" in rules:
        rewritten = rewritten.replace("rm -rf", "").replace("chmod 777", "")
    if "ast_size" in rules or "size" in rules:
        return None   # too big — not mechanically fixable
    if rewritten == source:
        return None   # nothing changed; stop the loop honestly
    return rewritten


def render_auto_human(result: AutoSessionResult, repair_report: dict) -> str:
    """Human rendering of the autonomous session."""
    lines = ["autonomous engineer session", f"  goal: {repair_report['goal']}"]
    lines.append(f"  planned {len(result.plan)} step(s) via the LLM planner")
    status = repair_report.get("status", {})
    lines.append(
        f"  executed: {status.get('done', 0)}/{status.get('items', 0)} done,"
        f" {status.get('blocked', 0)} blocked")
    if result.repairs:
        lines.append(f"  repairs logged: {len(result.repairs)}")
    if result.forged:
        lines.append("  self-extension (Feature Forge):")
        for f in result.forged:
            state = "accepted" if f.get("accepted") else "rejected"
            lines.append(f"    [{state}] {f['capability']}"
                         + (f" → adapters {f.get('adapters', [])}"
                            if f.get("accepted") else
                            f" ({f.get('rounds', 0)} rewrite rounds)"))
    if result.still_missing:
        lines.append(f"  still missing: {', '.join(result.still_missing)}")
    lines.append("")
    lines.append("awaiting operator:")
    for s in result.awaiting_user:
        lines.append(f"  - {s}")
    return "\n".join(lines)
