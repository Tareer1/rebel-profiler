"""LLM planner: the airllm-backed planner that plugs into the agent harness.

The agent plane accepts any callable ``view -> list[Proposal]``; this module
is the real-LLM implementation of that contract:

  * :func:`build_plan_prompt` — renders the :class:`PlannerView` (goal,
    available actions, rules) into a bounded, redacted prompt.
  * :func:`parse_proposals` — deterministic, defensive parsing of the model's
    reply into :class:`~rebel_profiler.agent.Proposal` objects. Parse
    discipline matches the collection parsers: malformed output yields a
    structured error, never a guess and never an invented action.
  * :class:`LlmPlanner` — one class wiring ModelPlane → prompt → proposals.
    When the machine cannot load weights the tiny engine answers, the parse
    fails honestly, and the caller gets a structured error with the
    ``--plan`` escape hatch — no hallucinated proposals, ever.

The harness stays identical: ``session.run(LlmPlanner(plane))`` replaces the
deterministic planner without any change in gates, evidence or audit.
"""

from __future__ import annotations

import json
import os
import re

from ..agent import Proposal
from ..core.errors import DependencyUnavailableError, UsageError
from ..core.redact import redact
from .inference import ModelPlane, TinyLlmEngine
from .budget import resolve_limits

# Bounded prompt/output — the budget guard caps context, these cap style.
PROMPT_GOAL_MAX_CHARS = 600
REPLY_SNIPPET_MAX = 240

_JSON_FENCE = re.compile(r"```(?:json)?\s*(\[.*?\]|\{.*?\})\s*```", re.DOTALL)


def build_plan_prompt(view) -> str:
    """Render a PlannerView into the planner prompt.

    The goal is redacted before it can reach any model (secrets never leak),
    and the available-action contract is emitted verbatim from the live
    adapter registry — the model cannot propose what is not printed.
    """
    goal = redact(str(view.goal))[:PROMPT_GOAL_MAX_CHARS]
    contract = json.dumps(view.available_actions(), indent=2, sort_keys=True)
    return (
        "You are the planner of Rebel Profiler, an authorized security-"
        "operations framework. You PROPOSE actions; the broker decides.\n\n"
        "RULES (non-negotiable):\n"
        "1. Propose ONLY actions from available_actions with ONLY their "
        "allowed_params.\n"
        "2. Prefer passive actions first; escalate only when the goal needs it.\n"
        "3. Every proposal still passes scope + policy gates; denials are feedback.\n"
        "4. Respond with ONLY a JSON array of proposals — no prose, no fences "
        "other than the example below.\n\n"
        f"GOAL: {goal}\n\n"
        "AVAILABLE ACTIONS (the only executable contract):\n"
        f"{contract}\n\n"
        "OUTPUT FORMAT — one JSON array, one object per step, in execution order:\n"
        '```json\n'
        '[{"action": "passive-dns", "target": "lab.example.test", '
        '"params": {"record_type": "A"}, "reason": "resolve A records"}]\n'
        "```\n"
    )


def _extract_json_array(text: str) -> str:
    """Pull the JSON array (or single object) out of a model reply."""
    fences = list(_JSON_FENCE.finditer(text))
    if fences:
        return fences[-1].group(1)
    start = text.find("[")
    if start != -1:
        depth = 0
        for idx in range(start, len(text)):
            if text[idx] == "[":
                depth += 1
            elif text[idx] == "]":
                depth -= 1
                if depth == 0:
                    return text[start: idx + 1]
    return text


def parse_proposals(reply: str, registry=None) -> list[Proposal]:
    """Parse a model reply into Proposals — defensively, never inventing.

    Validation (hard, structured errors — the no-fake-adapter rule applies to
    LLM output too):

    * the reply must contain a JSON array (or a single object),
    * every entry must carry a known ``action`` (when *registry* is given),
    * every param must be declared by that adapter's ``allowed_params``,
    * ``target`` must be a non-empty string.
    """
    snippet = redact(reply.strip()[:REPLY_SNIPPET_MAX])
    raw = _extract_json_array(reply)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UsageError(
            "LLM planner reply is not parsable as proposals",
            reason=f"JSON decode failed ({exc}); reply snippet: {snippet!r}",
            action="Re-run with a stronger model, or pass an explicit "
                   "--plan 'action:target[:k=v,k=v];...'.",
        ) from exc
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not data:
        raise UsageError(
            "LLM planner proposed nothing",
            reason=f"Expected a JSON array of proposals; got: {snippet!r}",
            action="Re-run, or pass --plan to skip the model.",
        )
    proposals: list[Proposal] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise UsageError(
                f"Proposal #{i + 1} is not a JSON object",
                reason=f"Got: {redact(str(item))[:120]!r}",
                action='Each proposal needs {"action", "target", "params", "reason"}.',
            )
        action = str(item.get("action", "")).strip()
        target = str(item.get("target", "")).strip()
        if not action or not target:
            raise UsageError(
                f"Proposal #{i + 1} is missing action or target",
                action="Every proposal needs a non-empty action and target.",
            )
        params = item.get("params") or {}
        if not isinstance(params, dict):
            raise UsageError(
                f"Proposal #{i + 1} params must be an object",
                action='Use {"key": "value"} pairs from allowed_params only.',
            )
        adapter = registry.get(action) if registry is not None else True
        if not adapter:
            raise UsageError(
                f"LLM proposed unknown action '{action}'",
                reason="The no-fake-adapter policy applies to LLM planners too.",
                action="Re-run, or pass --plan with actions from "
                       "'rebel-profiler adapters'.",
            )
        if registry is not None:
            unknown = set(params) - set(adapter.allowed_params)
            if unknown:
                raise UsageError(
                    f"LLM proposed undeclared params {sorted(unknown)} for '{action}'",
                    action=f"Allowed params: {', '.join(adapter.allowed_params)}",
                )
        proposals.append(Proposal(
            action=action, target=target, params=params,
            capability=str(item.get("capability", "") or ""),
            reason=redact(str(item.get("reason", "")))[:200],
        ))
    return proposals


class LlmPlanner:
    """Callable planner: PlannerView → prompt → model → validated Proposals.

    Engine selection is delegated to the ModelPlane (airllm when loadable,
    tiny otherwise, with the fallback reason recorded). When only the tiny
    engine is available the parse will fail honestly — that is the contract:
    no hallucinated proposals, ever.
    """

    def __init__(self, plane: ModelPlane | None = None, *,
                 model: str | None = None, registry=None,
                 max_new_tokens: int | None = None) -> None:
        self.plane = plane or _plane_from_env()
        self.model = model or os.environ.get("RP_LLM__MODEL", "")
        self.registry = registry
        self.max_new_tokens = max_new_tokens
        self.last_prompt = ""
        self.last_result = None

    def __call__(self, view):
        prompt = build_plan_prompt(view)
        self.last_prompt = prompt
        # Always ensure an engine exists: with no model pinned (e.g. the model
        # came from a config profile, not the CLI) select_engine falls back to
        # the tier default — never generate with no engine loaded.
        self.plane.select_engine(self.model or "")
        # Instruct checkpoints (Qwen2.5, Llama, …) degenerate on raw
        # instruction text; send the plan request through the engine's own
        # chat template so the model sees its trained role structure.
        result = self.plane.chat_generate(
            "You are the planner of Rebel Profiler. Follow the request "
            "exactly and reply with the requested JSON only.", prompt,
            max_new_tokens=self.max_new_tokens)
        self.last_result = result
        if isinstance(self.plane.engine, TinyLlmEngine):
            raise DependencyUnavailableError(
                "The LLM planner needs real weights; only the tiny engine loaded",
                reason=self.plane.fallback_reason,
                action="pip install 'rebel-profiler[airllm]' and pull a model, "
                       "or run the agent with --plan for the deterministic path.",
            )
        return parse_proposals(result.text, registry=self.registry)


def _plane_from_env() -> ModelPlane:
    limits = resolve_limits()
    prefer = os.environ.get("RP_LLM__ENGINE", "").strip().lower()
    return ModelPlane(limits=limits,
                      prefer_engine=prefer if prefer in {"tiny", "airllm", "external", "gguf", "native", "hermes"} else None)
