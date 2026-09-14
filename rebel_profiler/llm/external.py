"""Opt-in external AI-provider engine (the ONLY remote path in the tool).

Rebel Profiler is local-first: the default engine is AirLLM (on-device,
layer-wise streaming) and the honest fallback is the tiny engine. A remote
provider is used *only* when the operator explicitly pins it:

    RP_LLM__ENGINE=external  RP_LLM__API_KEY=…  rebel-profiler llm generate …

Contract (mechanical, not prompt-enforced):

  * no API key configured  → :class:`ModelBudgetError` — never a silent
    network call, never a silent fallback to some other engine,
  * the key is read from the environment (or RP_LLM__API_KEY_FILE), never
    stored in config files, never logged, never echoed,
  * outbound payloads pass through :func:`redact` first — secrets never
    leave the machine even when the operator chooses a remote brain,
  * one HTTP call per generation, bounded timeout, structured errors with
    fix hints; responses are redacted before they enter the process,
  * any OpenAI-compatible /chat/completions endpoint works (OpenAI, Groq,
    Together, OpenRouter, llama.cpp server, vLLM, Ollama's compat layer…)
    via RP_LLM__API_BASE.

This engine never decides anything: it produces text that the same
deterministic validation gates (planner parsing, policy, scope) still apply.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from ..core.errors import RPError
from ..core.redact import redact
from .budget import BudgetGuard, Limits
from .inference import GenerationResult

DEFAULT_TIMEOUT_S = 120.0
DEFAULT_API_BASE = "https://api.openai.com/v1"


class ExternalEngineError(RPError):
    exit_code = 7
    title = "External AI provider unavailable"


def resolve_api_key(environ: dict | None = None) -> str:
    """Read the provider key from the env or a key file — never from config."""
    import os

    env = dict(environ) if environ is not None else dict(os.environ)
    key = env.get("RP_LLM__API_KEY", "").strip()
    if key:
        return key
    key_file = env.get("RP_LLM__API_KEY_FILE", "").strip()
    if key_file:
        try:
            from pathlib import Path

            return Path(key_file).read_text().strip()
        except OSError:
            return ""
    return ""


class ExternalEngine:
    """OpenAI-compatible chat engine — opt-in, redacted, bounded."""

    kind = "external"

    def __init__(self, model: str, *, limits: Limits,
                 api_key: str = "", api_base: str = "",
                 timeout_s: float = DEFAULT_TIMEOUT_S, **_options) -> None:
        self.model_id = model
        self.limits = limits
        self.guard = BudgetGuard(limits)
        self.loaded = False
        self.compressed = False
        self.last_device = "remote"
        self.api_key = api_key or resolve_api_key()
        self.api_base = (api_base or _env_or(DEFAULT_API_BASE)).rstrip("/")
        self.timeout_s = timeout_s

    # -- lifecycle -------------------------------------------------------------

    def load(self) -> None:
        if not self.api_key:
            raise _missing_key_error()
        self.loaded = True

    def unload(self) -> None:
        self.loaded = False
        self.api_key = ""   # drop the secret as soon as the engine is idle

    @property
    def loaded(self) -> bool:  # type: ignore[override]
        return self._loaded

    @loaded.setter
    def loaded(self, value: bool) -> None:
        self._loaded = value

    # -- generation ------------------------------------------------------------

    def generate(self, prompt: str, *, max_new_tokens: int | None = None,
                 temperature: float = 0.2) -> GenerationResult:
        self.load()
        self.guard.check_rss()
        started = time.time()
        cap = min(max_new_tokens or self.limits.max_new_tokens,
                  self.limits.max_new_tokens)
        self.guard.check_generate(cap)
        payload = {
            "model": self.model_id,
            "messages": [{"role": "user", "content": redact(prompt)}],
            "max_tokens": cap,
            "temperature": temperature,
        }
        text = self._post(payload)
        text = redact(text)
        self.guard.check_rss()
        return GenerationResult(
            text=text, engine="external", model=self.model_id,
            input_tokens=len(redact(prompt).split()),
            output_tokens=max(1, len(text) // 4),
            elapsed_s=time.time() - started,
            peak_rss_mb=self.guard.peak_rss_mb,
            truncated=False, device="remote",
        )

    # -- transport ----------------------------------------------------------------

    def _post(self, payload: dict) -> str:
        request = urllib.request.Request(
            f"{self.api_base}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise ExternalEngineError(
                f"Provider returned HTTP {exc.code}",
                reason="The endpoint rejected the request (key, model id or "
                       "payload).",
                action="Check RP_LLM__API_KEY / RP_LLM__API_BASE / the model id.",
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ExternalEngineError(
                "Could not reach the AI provider",
                reason=f"{type(exc).__name__}: {exc}",
                action="Check network/DNS, or drop back to the local AirLLM "
                       "engine (remove RP_LLM__ENGINE=external).",
            ) from exc
        except json.JSONDecodeError as exc:
            raise ExternalEngineError(
                "Provider response was not valid JSON",
                reason=str(exc),
                action="Verify RP_LLM__API_BASE points at an OpenAI-compatible "
                       "/v1 endpoint.",
            ) from exc
        try:
            return str(body["choices"][0]["message"]["content"] or "")
        except (KeyError, IndexError, TypeError) as exc:
            raise ExternalEngineError(
                "Provider response has an unexpected shape",
                reason=f"keys: {sorted(body)[:8]}",
                action="Verify the endpoint is OpenAI-compatible (/v1).",
            ) from exc


def _env_or(default: str) -> str:
    import os

    return os.environ.get("RP_LLM__API_BASE", "").strip() or default


def _missing_key_error():
    from .budget import ModelBudgetError

    return ModelBudgetError(
        "No API key configured for the external engine",
        reason="Remote providers are opt-in; the key comes from "
               "RP_LLM__API_KEY (or RP_LLM__API_KEY_FILE).",
        action="Export RP_LLM__API_KEY=… (or drop the pin to stay local: "
               "unset RP_LLM__ENGINE).",
    )
