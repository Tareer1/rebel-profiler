"""Script authoring: the LLM writes a code file for a goal, then fixes it.

The script plane already executes gated code (``codescript``); this module is
the *authoring* half of that loop:

    llm script author "<goal>"   →  model writes run(payload)
                                 →  syntax check
                                 →  submitted (stored, NOT executed)
                                 →  daemon: static gate → sandbox → result

    llm script retry <script_id> →  failure + fix hint go back to the model
                                 →  corrected source re-submitted

Two laws hold throughout:

* **The model writes data, not authority.** Generated source is just a script
  file; it passes the same deterministic static gate and sandbox as anything a
  human submits. Nothing here can widen what a script may reach.
* **No real engine, no authoring.** With only the tiny engine loaded the model
  cannot write code, so the call fails with a structured error naming the
  install command — it never submits a placeholder and calls it a script.
"""

from __future__ import annotations

import json
import re
import time

from ..core.errors import DependencyUnavailableError, UsageError
from ..core.redact import redact
from .codescript import (
    REJECT_SUFFIX,
    RESULT_SUFFIX,
    SCRIPT_SUFFIX,
    load_script_result,
    submit_script,
)
from .inference import ModelPlane, TinyLlmEngine

GOAL_MAX_CHARS = 800
PREVIOUS_MAX_CHARS = 6_000
ERROR_MAX_CHARS = 600
STATE_MAX_CHARS = 4_000

_PY_FENCE = re.compile(r"```(?:python|py)?\s*\n(.*?)```", re.DOTALL)
_ANY_FENCE = re.compile(r"```[a-zA-Z]*\s*\n(.*?)```", re.DOTALL)
_NONE_REPLY = re.compile(r"(?i)^none\s*[.!]?$")

CONTRACT = """\
The script must:
1. define exactly one entry point:  def run(payload):
2. take `payload` (a plain dict) and return a JSON-serializable value,
3. use only the Python standard library, and NEVER import or use os, sys
   (except nothing), subprocess, socket, shutil, glob, pathlib, ctypes,
   importlib, pickle, marshal, eval, exec, compile, open, __import__,
   input, or any network/process/filesystem access,
4. be deterministic and finish quickly (hard timeout enforced),
5. raise a clear ValueError with a helpful message on bad input instead of
   returning a wrong value.
"""

EXAMPLE = """\
```python
def run(payload):
    nums = payload.get("nums", [])
    if not isinstance(nums, list):
        raise ValueError("payload['nums'] must be a list of numbers")
    return {"count": len(nums), "sum": sum(nums), "max": max(nums, default=0)}
```
"""


def build_author_prompt(goal: str, *, payload_keys: list[str] | None = None) -> str:
    keys = ", ".join(sorted(payload_keys or [])) or "(none provided)"
    return (
        "You write small, safe Python scripts for Rebel Profiler, an authorized "
        "security-operations framework.\n\n"
        f"TASK:\n{redact(str(goal))[:GOAL_MAX_CHARS]}\n\n"
        f"payload keys available at runtime: {keys}\n\n"
        "RULES (enforced mechanically — a violation is rejected, not patched):\n"
        f"{CONTRACT}\n"
        "OUTPUT: only one ```python fenced block containing the whole script. "
        "No prose, no explanation.\n\n"
        f"EXAMPLE:\n{EXAMPLE}"
    )


def build_repair_prompt(goal: str, source: str, *, error: str, fix: str,
                        payload_keys: list[str] | None = None) -> str:
    keys = ", ".join(sorted(payload_keys or [])) or "(none provided)"
    return (
        "You are fixing a Python script that failed in Rebel Profiler's "
        "sandboxed script plane.\n\n"
        f"ORIGINAL TASK:\n{redact(str(goal))[:GOAL_MAX_CHARS]}\n\n"
        f"payload keys: {keys}\n\n"
        f"FAILED SCRIPT:\n```python\n{source[:PREVIOUS_MAX_CHARS]}\n```\n\n"
        f"FAILURE:\n{redact(str(error))[:ERROR_MAX_CHARS]}\n\n"
        f"FIX HINT FROM THE TOOL:\n{redact(str(fix))[:ERROR_MAX_CHARS]}\n\n"
        "Rewrite the script so it succeeds, keeping the SAME entry point "
        "contract. If the failure is a rejected import or builtin, use a "
        "different, allowed standard-library approach; if no allowed approach "
        "can do the job, return a script that raises a clear ValueError "
        "explaining what is unavailable.\n\n"
        f"RULES:\n{CONTRACT}\n"
        "OUTPUT: only one ```python fenced block containing the complete fixed "
        "script. No prose.\n\n"
        f"EXAMPLE:\n{EXAMPLE}"
    )


def _extract_json_array(text: str) -> str:
    """Pull one JSON array out of a model reply (bounded, defensive)."""
    for match in reversed(list(_ANY_FENCE.finditer(text))):
        body = match.group(1).strip()
        if body.startswith("["):
            return body
    start = text.find("[")
    if start == -1:
        return text
    depth = 0
    for idx in range(start, len(text)):
        if text[idx] == "[":
            depth += 1
        elif text[idx] == "]":
            depth -= 1
            if depth == 0:
                return text[start: idx + 1]
    return text


def build_script_plan_prompt(goal: str, *, state, max_scripts: int = 3) -> str:
    """Ask the model which (if any) scripts this goal actually needs.

    The state handed over is already-collected, evidence-backed case data. The
    model is told plainly what a script *cannot* do here (no network, no
    filesystem, no process access) so it proposes computation, not scanning.
    """
    rendered = json.dumps(state, indent=2, sort_keys=True, default=str)
    return (
        "You are the operator of Rebel Profiler, an authorized security-\n"
        "operations framework, working a bug-bounty case. You decide what \n"
        "analysis is missing; the system decides whether code may run.\n\n"
        f"GOAL:\n{redact(str(goal))[:GOAL_MAX_CHARS]}\n\n"
        f"CURRENT STATE (collected, evidence-backed):\n"
        f"{rendered[:STATE_MAX_CHARS]}\n\n"
        "Decide whether small Python scripts would add ANALYSIS the framework "
        "cannot already do: correlating, diffing, parsing, scoring, "
        "summarising, cross-referencing the data above.\n\n"
        "A script runs sandboxed with NO network, NO filesystem and NO process "
        "access, so it cannot scan, fetch or exploit anything — propose only "
        "computation over the payload.\n\n"
        f"If no script is needed, reply exactly: NONE\n"
        "Otherwise reply with ONLY a JSON array of at most "
        f"{max_scripts} object(s):\n"
        '```json\n'
        '[{"goal": "<what the script computes>", "payload": {"<key>": "<value>"}}]\n'
        "```\n"
        "Each goal must be achievable from its payload alone using only the "
        "Python standard library. No prose."
    )


def parse_script_plan(reply: str, *, max_scripts: int = 3) -> dict:
    """Parse a script plan defensively; malformed output is a structured error.

    Entries missing a usable ``goal`` are dropped and counted rather than
    guessed at — the same parse discipline as every other external input.
    """
    text = (reply or "").strip()
    if not text:
        raise UsageError(
            "The model returned nothing for the script plan",
            action="Re-run, or pass --no-author to skip script authoring.")
    if _NONE_REPLY.match(text):
        return {"scripts": [], "dropped": 0,
                "note": "the model judged no script necessary"}
    raw = _extract_json_array(text)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UsageError(
            "The model's script plan is not parsable JSON",
            reason=f"{exc}; snippet: {redact(text[:200])!r}",
            action="Re-run, or pass --no-author to skip script authoring.",
        ) from exc
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise UsageError(
            "The model's script plan is not a JSON array",
            reason=f"snippet: {redact(text[:200])!r}",
            action="Re-run, or pass --no-author to skip script authoring.")
    scripts: list[dict] = []
    dropped = 0
    for item in data:
        if not isinstance(item, dict):
            dropped += 1
            continue
        goal = str(item.get("goal", "")).strip()
        payload = item.get("payload")
        if not goal or not isinstance(payload or {}, dict):
            dropped += 1
            continue
        scripts.append({"goal": redact(goal)[:GOAL_MAX_CHARS],
                        "payload": payload or {}})
    extra = max(0, len(scripts) - max_scripts)
    return {"scripts": scripts[:max_scripts], "dropped": dropped + extra}


def plan_scripts(goal: str, *, state, model: str | None = None,
                 plane: ModelPlane | None = None,
                 max_scripts: int = 3) -> dict:
    """Model-decided script plan for a session goal."""
    prompt = build_script_plan_prompt(goal, state=state, max_scripts=max_scripts)
    result = _generate(prompt, model=model, plane=plane)
    plan = parse_script_plan(result.text, max_scripts=max_scripts)
    plan["engine"] = result.engine
    plan["model"] = result.model
    return plan


def extract_python(reply: str) -> str:
    """Pull the script source out of a model reply (defensive, bounded)."""
    if not reply or not reply.strip():
        raise UsageError(
            "The model returned nothing",
            action="Re-run, or submit the script yourself with "
                   "'llm script submit --file'.")
    fences = list(_PY_FENCE.finditer(reply))
    if fences:
        source = fences[-1].group(1)
    elif "def run(" in reply:
        source = reply
    else:
        raise UsageError(
            "The model reply contained no Python script",
            reason=f"Reply snippet: {redact(reply[:200])!r}",
            action="Re-run with a stronger model, or write the script yourself.",
        )
    return source.strip() + "\n"


def syntax_check(source: str) -> None:
    """Fail fast on code that cannot even parse (the gate checks safety)."""
    try:
        compile(source, "<llm-script>", "exec")
    except SyntaxError as exc:
        raise UsageError(
            f"The generated script has a syntax error (line {exc.lineno})",
            reason=redact(str(exc.msg))[:200],
            action="Re-run 'llm script author', or fix and submit with "
                   "'llm script submit --file'.",
        ) from exc


def _ensure_engine(plane: ModelPlane, model: str | None) -> None:
    """Load an engine once and reuse it across a session.

    Selecting on every call would reload the weights for each generated
    script, so a batch of scripts would pay the load cost N times. Reselect
    only when nothing is loaded yet, or when an explicit different model was
    requested.
    """
    current = getattr(plane.engine, "model_id", "") or ""
    if plane.engine is None or (model and current and current != model):
        plane.select_engine(model or "")


def _generate(prompt: str, *, model: str | None, plane: ModelPlane | None,
              max_new_tokens: int | None = None):
    """One bounded generation through the LLM plane, then unload the model."""
    own = plane is None
    plane = plane or _plane_from_env()
    try:
        _ensure_engine(plane, model)
        if isinstance(plane.engine, TinyLlmEngine):
            raise DependencyUnavailableError(
                "Writing a script needs real weights; only the tiny engine loaded",
                reason=plane.fallback_reason,
                action="pip install llama-cpp-python (GGUF) or "
                       "'rebel-profiler[airllm]' (HF models), then re-run.",
            )
        # Instruct checkpoints degenerate on raw instruction text; route the
        # authoring request through the engine's own chat template.
        return plane.chat_generate(
            "You write exact, minimal Python for Rebel Profiler script jobs. "
            "Reply with the requested code only.", prompt,
            max_new_tokens=max_new_tokens)
    finally:
        if own:
            plane.unload()


def author_script(goal: str, *, script_dir, payload: dict | None = None,
                  name: str = "", model: str | None = None,
                  plane: ModelPlane | None = None, case_id: str = "",
                  requested_by: str = "llm") -> dict:
    """Goal → model-written script → submitted through the gated queue."""
    payload = payload or {}
    prompt = build_author_prompt(goal, payload_keys=list(payload))
    result = _generate(prompt, model=model, plane=plane)
    source = extract_python(result.text)
    syntax_check(source)
    envelope = submit_script(
        source, script_dir=script_dir, payload=payload,
        name=name or goal.strip()[:48] or "llm-authored",
        requested_by=requested_by, case_id=case_id)
    envelope["source"] = source
    envelope["generator"] = {"engine": result.engine, "model": result.model}
    return envelope


def load_failure(script_id: str, *, script_dir) -> dict:
    """Read a failed or rejected script's error + the source that produced it."""
    from pathlib import Path

    script_dir = Path(script_dir)
    source_path = script_dir / f"{script_id}{SCRIPT_SUFFIX}"
    source = source_path.read_text() if source_path.exists() else ""
    result = load_script_result(script_id, script_dir=script_dir)
    if result is not None:
        if result.get("state") == "done":
            raise UsageError(
                f"Script {script_id} already succeeded",
                reason="The script plane never re-runs a script that finished.",
                action="Submit a new goal instead, or copy the source and edit it.",
            )
        return {"error": str(result.get("error", "")),
                "fix": str(result.get("fix", "")), "source": source,
                "state": result.get("state", "")}
    reject_path = script_dir / f"{script_id}{REJECT_SUFFIX}"
    if reject_path.exists():
        try:
            payload = json.loads(reject_path.read_text())
        except (OSError, json.JSONDecodeError):
            payload = {}
        findings = payload.get("findings") or []
        return {"error": str(payload.get("error", "rejected by the static gate")),
                "fix": "; ".join(str(f) for f in findings[:6]),
                "source": source, "state": "rejected"}
    raise UsageError(
        f"Script {script_id} has no result yet",
        reason=f"No result or rejection file in {script_dir}.",
        action="Run the daemon first: 'llm script run --once', then retry.",
    )


def retry_script(script_id: str, *, script_dir, goal: str = "",
                 model: str | None = None, plane: ModelPlane | None = None,
                 case_id: str = "", requested_by: str = "llm") -> dict:
    """Feed a failure back to the model and submit the corrected script."""
    failure = load_failure(script_id, script_dir=script_dir)
    prompt = build_repair_prompt(
        goal or f"script {script_id}", failure["source"],
        error=failure["error"], fix=failure["fix"])
    result = _generate(prompt, model=model, plane=plane)
    source = extract_python(result.text)
    syntax_check(source)
    envelope = submit_script(
        source, script_dir=script_dir, name=f"fix-{script_id}",
        requested_by=requested_by, case_id=case_id)
    envelope["parent_script_id"] = script_id
    envelope["fixed_from"] = {"error": failure["error"], "fix": failure["fix"],
                              "state": failure["state"]}
    envelope["source"] = source
    envelope["generator"] = {"engine": result.engine, "model": result.model}
    envelope["authored_at"] = time.time()
    return envelope


def _plane_from_env(*, tier: str | None = None) -> ModelPlane:
    """Build the session's model plane from the environment.

    ``tier`` is an explicit operator pin (``bounty auto --tier``) — it wins
    over RP_LLM__TIER because it names the machine the operator says they have.
    """
    from .budget import resolve_limits
    import os

    limits = resolve_limits(tier=tier or None)
    prefer = os.environ.get("RP_LLM__ENGINE", "").strip().lower()
    return ModelPlane(
        limits=limits,
        prefer_engine=prefer if prefer in {"tiny", "airllm", "external", "gguf", "native", "hermes"} else None)
