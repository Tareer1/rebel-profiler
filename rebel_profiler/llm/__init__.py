"""LLM plane: low-memory local inference + planning (AirLLM-mode).

The tool's law — *the LLM reasons, the system decides* — needs a reasoning
engine that does not eat the operator's machine. This plane brings AirLLM's
feature set in-process so even a 70B model runs on low-end hardware:

  * layer-wise streaming   — only one transformer layer is resident at a time
  * 4/8-bit compression    — block-wise weight compression (bitsandbytes)
  * AutoModel              — one line for Llama/Qwen/DeepSeek/Mistral/Phi/…
  * prefetching/profiling  — engine options passed straight through
  * CPU + Apple silicon    — GPU optional, never required
  * hardware budget guard  — RSS ceiling, tier caps, CPU-only placement
  * daemon offloading      — the CLI writes a job file and stays tiny while
                             the resident worker does the heavy lifting;
                             data jobs ship a bounded, redacted case pack
                             instead of any direct database access
  * LLM planner            — validated proposals into the agent harness
  * optional external brain — an OpenAI-compatible provider, opt-in via
                             RP_LLM__ENGINE=external + RP_LLM__API_KEY,
                             redacted payloads; local AirLLM stays default

When the machine cannot (or may not) run weights at all, a deterministic
tiny fallback keeps every downstream contract alive.
"""

from __future__ import annotations

from .budget import (
    BUDGET_TIERS,
    DEFAULT_LIMITS,
    DEFAULT_MODELS,
    BudgetGuard,
    ModelBudgetError,
    read_budget,
    recommend,
    resolve_limits,
)
from .daemon import (
    JobValidationError,
    LlmDaemon,
    default_queue_dir,
    load_result,
    submit_job,
)
from .datapack import build_data_pack, wrap_pack_as_prompt
from .external import ExternalEngine, ExternalEngineError, resolve_api_key
from .inference import AIRLLM_OPTIONS, AirLlmEngine, GenerationResult, ModelPlane, TinyLlmEngine
from .planner import LlmPlanner, build_plan_prompt, parse_proposals

__all__ = [
    "AIRLLM_OPTIONS",
    "AirLlmEngine",
    "BUDGET_TIERS",
    "BudgetGuard",
    "DEFAULT_LIMITS",
    "DEFAULT_MODELS",
    "ExternalEngine",
    "ExternalEngineError",
    "GenerationResult",
    "JobValidationError",
    "LlmDaemon",
    "LlmPlanner",
    "ModelBudgetError",
    "ModelPlane",
    "TinyLlmEngine",
    "build_data_pack",
    "build_plan_prompt",
    "default_queue_dir",
    "load_result",
    "parse_proposals",
    "read_budget",
    "recommend",
    "resolve_api_key",
    "resolve_limits",
    "submit_job",
    "wrap_pack_as_prompt",
]
