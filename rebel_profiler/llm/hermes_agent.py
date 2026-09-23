"""The REAL Hermes agent as an engine: Nous Research's installed hermes-agent.

Rebel Profiler's ``hermes`` front door has always *mimicked* the Hermes-agent
pattern (ChatML, ``<tool_call>`` discipline). This engine closes the loop: the
operator's actual hermes-agent installation (``~/.hermes/hermes-agent``, the
Nous Research self-improving agent) becomes one of the ModelPlane engines, so
the local GGUF can be swapped for a frontier-grade agent brain with:

    RP_LLM__ENGINE=hermes  rebel-profiler hermes "map the scope"

Contract — the same law every engine obeys, enforced mechanically:

  * **subprocess only**: the installed ``hermes`` binary is invoked as
    ``hermes -z <prompt> --toolsets safe`` (``-z`` = oneshot: prompt in, final
    answer text out). No API key handling, no SDK, no embedding of foreign
    code — the tool talks to a binary the operator installed and controls.
  * **``--toolsets safe``**: the child agent runs with the ``safe`` toolset
    only (``web_search, web_extract, vision_analyze, image_generate``). Its
    terminal/file toolsets are never enabled, so the no-raw-shell law holds
    *mechanically*, not on the honor system.
  * **binary allow-list**: the child is resolved from ``RP_HERMES_BIN`` or
    well-known install paths; an arbitrary ``model`` string is never executed.
  * **redacted both ways**: outbound prompts pass :func:`redact`, replies are
    redacted again on arrival — secrets never reach the remote provider
    behind the child, and never re-enter this process unredacted.
  * **bounded**: per-call timeout (``RP_HERMES_TIMEOUT_S``, default 240s),
    context ceiling via the tier limits, structured failures with fix hints.
  * **never decides**: the child only produces text; the same deterministic
    validation gates (tool-call parsing, scope, policy, risk) still apply
    before anything executes.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time

from ..core.errors import DependencyUnavailableError
from ..core.redact import redact
from .budget import BudgetGuard, Limits
from .inference import GenerationResult

DEFAULT_TIMEOUT_S = 240.0
DEFAULT_BIN = "hermes"

# The child agent's reach: `safe` is hermes-agent's curated toolset without
# terminal/file access. Overridable for operators who know what they are
# doing — but never empty, so a bare invocation cannot silently run with the
# full CLI toolset (which includes a terminal).
SAFE_TOOLSET = "safe"
_TOOLSET_ENV = "RP_HERMES_TOOLSETS"

# The child runs its OWN agent loop (persona, memory, its own tool list), so
# a bare relay of our planning prompt makes it answer as "the assistant with
# vision_analyze/web_… tools" and ignore our tool contract entirely. The
# preamble re-tasks it as a deterministic planning module: it does NOT call
# its own tools, it replies in OUR protocol (one <tool_call> JSON or prose).
# The safe toolset stays as defense-in-depth for the case the child ignores
# the preamble — but with a strong instruct model the preamble is what lands.
_INTERPRETER_PREAMBLE = (
    "[SYSTEM] You are the planning module of an automated harness. The text "
    "after this line is a structured planning request. Ignore any other "
    "persona, memory or tool list you were configured with: do NOT use your "
    "own tools for this reply — nothing you call yourself reaches the "
    "harness. Respond with EITHER exactly one tool call in the format the "
    "request specifies (<tool_call>{\"name\": …, \"arguments\": {…}}"
    "</tool_call>) OR a short plain-prose final answer. Never both, nothing "
    "else.\n\n--- planning request follows ---\n\n")

# Well-known install locations, tried in order when `hermes` is not on PATH.
_KNOWN_BINS = (
    "/home/rebel/.local/bin/hermes",
    os.path.expanduser("~/.local/bin/hermes"),
    os.path.expanduser("~/.hermes/hermes-agent/hermes"),
)

def resolve_hermes_agent_bin(environ: dict | None = None) -> str:
    """Locate the installed hermes-agent CLI, or return ``""``.

    Order: ``RP_HERMES_BIN`` → PATH → well-known install paths. Never
    guesses: an empty result means "not installed", and callers must fail
    structurally instead of trying anything else.
    """
    env = dict(environ) if environ is not None else dict(os.environ)
    pinned = env.get("RP_HERMES_BIN", "").strip()
    if pinned:
        return pinned
    found = shutil.which(DEFAULT_BIN)
    if found:
        return found
    for candidate in _KNOWN_BINS:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


def hermes_agent_version(bin_path: str, timeout_s: float = 30.0) -> str:
    """One-line version string of the installed agent (empty when unknown)."""
    try:
        proc = subprocess.run(
            [bin_path, "--version"], capture_output=True, text=True,
            timeout=timeout_s, shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    first = (proc.stdout or "").strip().splitlines()
    return first[0].strip() if first else ""


class HermesAgentEngine:
    """The operator's installed hermes-agent, one bounded oneshot per call.

    ``kind = "hermes"`` — a remote-brain-class engine that stays local-first:
    the child process runs on this machine and talks to whichever provider
    the operator configured *in hermes-agent* (Nous Portal by default).
    Rebel Profiler never sees or stores those credentials.
    """

    kind = "hermes"

    def __init__(self, model: str = "", *, limits: Limits,
                 bin_path: str = "", timeout_s: float | None = None,
                 toolsets: str = "", **_options) -> None:
        self.model_id = model or "hermes-agent (operator install)"
        self.limits = limits
        self.guard = BudgetGuard(limits)
        self.loaded = False
        self.compressed = False
        self.last_device = "subprocess"
        self.bin_path = bin_path or resolve_hermes_agent_bin()
        env = os.environ
        try:
            self.timeout_s = float(
                timeout_s if timeout_s is not None
                else env.get("RP_HERMES_TIMEOUT_S", "") or DEFAULT_TIMEOUT_S)
        except (TypeError, ValueError):
            self.timeout_s = DEFAULT_TIMEOUT_S
        self.toolsets = (toolsets or env.get(_TOOLSET_ENV, "") or SAFE_TOOLSET)

    # -- lifecycle -------------------------------------------------------------

    def load(self) -> None:
        self.guard.check_rss()
        if not self.bin_path:
            raise DependencyUnavailableError(
                "The hermes-agent CLI is not installed",
                reason="RP_HERMES_BIN is not set, 'hermes' is not on PATH, "
                       "and the well-known install paths are empty.",
                action="Install the Nous Research hermes-agent (it provides "
                       "the 'hermes' command), or set RP_HERMES_BIN=/path/to/hermes. "
                       "Drop the RP_LLM__ENGINE=hermes pin to use a local engine.",
            )
        self.loaded = True

    def unload(self) -> None:
        self.loaded = False

    # -- generation ------------------------------------------------------------

    def generate(self, prompt: str, *, max_new_tokens: int | None = None,
                 temperature: float = 0.2) -> GenerationResult:
        del temperature, max_new_tokens  # the child owns its own decoding
        self.load()
        self.guard.check_rss()
        started = time.time()
        text = self._oneshot(redact(_INTERPRETER_PREAMBLE + prompt))
        text = redact(text)
        self.guard.check_rss()
        return GenerationResult(
            text=text, engine="hermes", model=self.model_id,
            input_tokens=len(prompt.split()),
            output_tokens=max(1, len(text) // 4),
            elapsed_s=time.time() - started,
            peak_rss_mb=self.guard.peak_rss_mb,
            truncated=False, device="subprocess",
        )

    # -- transport ---------------------------------------------------------------

    def _argv(self, prompt: str) -> list[str]:
        argv = [self.bin_path, "-z", prompt, "--toolsets", self.toolsets]
        model = str(os.environ.get("RP_HERMES_MODEL", "") or "").strip()
        if model:
            argv += ["--model", model]
        return argv

    def _oneshot(self, prompt: str) -> str:
        argv = self._argv(prompt)
        env = dict(os.environ)
        env["RP_ACTOR"] = env.get("RP_ACTOR", "hermes-agent")
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=self.timeout_s, shell=False, env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise DependencyUnavailableError(
                f"hermes-agent oneshot exceeded {self.timeout_s:.0f}s",
                reason="The child run was killed at the timeout — a slow "
                       "provider or an oversized prompt.",
                action="Raise RP_HERMES_TIMEOUT_S, shorten the goal, or drop "
                       "back to a local engine (unset RP_LLM__ENGINE=hermes).",
            ) from exc
        except OSError as exc:
            raise DependencyUnavailableError(
                "Could not execute the hermes-agent binary",
                reason=f"{type(exc).__name__}: {exc}",
                action="Check RP_HERMES_BIN points at the installed agent "
                       "and is executable.",
            ) from exc
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            raise DependencyUnavailableError(
                f"hermes-agent exited {proc.returncode}",
                reason=redact(detail[:400]) or "no stderr output captured",
                action="Run the same prompt with 'hermes -z …' directly to "
                       "see the agent's own error output.",
            )
        return proc.stdout.strip()


def engine_env_status(environ: dict | None = None) -> dict:
    """Cheap readiness probe for `llm status` / `llm setup` tables."""
    env = dict(environ) if environ is not None else dict(os.environ)
    bin_path = resolve_hermes_agent_bin(env)
    return {
        "engine": "hermes",
        "installed": bool(bin_path),
        "bin": bin_path,
        "version": hermes_agent_version(bin_path) if bin_path else "",
        "toolsets": env.get(_TOOLSET_ENV, "") or SAFE_TOOLSET,
        "timeout_s": env.get("RP_HERMES_TIMEOUT_S", "") or DEFAULT_TIMEOUT_S,
    }
