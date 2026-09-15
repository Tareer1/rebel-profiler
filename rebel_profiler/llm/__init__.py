"""LLM plane: low-memory local inference + planning (AirLLM-mode).

The tool's law — *the LLM reasons, the system decides* — needs a reasoning
engine that does not eat the operator's machine. This plane brings AirLLM's
feature set in-process so even a 70B model runs on low-end hardware:

  * layer-wise streaming   — only one transformer layer is resident at a time
  * 4/8-bit compression    — native block-wise quantization (CPU-safe) or the
                             bitsandbytes path when CUDA exists
  * AutoModel              — one line for Llama/Qwen/DeepSeek/Mistral/Phi/…
  * prefetching/profiling  — engine options passed straight through
  * CPU + Apple silicon    — GPU optional, never required (MPS + CUDA OK)
  * real tokenizer         — byte-level BPE from tokenizer.json, stdlib-only
  * layer shards           — `llm prepare` bakes per-layer shards (optionally
                             quantized) with --delete-original to reclaim disk
  * script plane           — the LLM writes a code file; the daemon gates it
                             and sandbox-executes it ~5s later; real result
  * hardware budget guard  — RSS ceiling, tier caps, CPU-only placement
  * GGUF / llama.cpp       — single-file quantized checkpoints (llama.cpp,
                             Ollama, LM Studio exports) run in place, with the
                             quant tag read from the filename for the budget
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
from .codescript import (
    ScriptDaemon,
    ScriptRunner,
    default_script_dir,
    list_scripts,
    load_script_result,
    submit_script,
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
from .gguf import (
    GgufEngine,
    discover_local_gguf,
    gguf_params_b,
    parse_quant,
    resolve_local_gguf,
)
from .inference import AIRLLM_OPTIONS, AirLlmEngine, GenerationResult, ModelPlane, TinyLlmEngine
from .native import NativeStreamingEngine, discover_local_models, resolve_local_model
from .planner import LlmPlanner, build_plan_prompt, parse_proposals
from .quant import (
    QTensor,
    QuantError,
    find_shards_dir,
    prepare_model_shards,
    quantize_tensor,
)
from .tokenizer import ApproxTokenizer, BpeTokenizer, load_tokenizer

__all__ = [
    "AIRLLM_OPTIONS",
    "AirLlmEngine",
    "ApproxTokenizer",
    "BUDGET_TIERS",
    "BudgetGuard",
    "BpeTokenizer",
    "DEFAULT_LIMITS",
    "DEFAULT_MODELS",
    "ExternalEngine",
    "ExternalEngineError",
    "GenerationResult",
    "GgufEngine",
    "JobValidationError",
    "LlmDaemon",
    "LlmPlanner",
    "ModelBudgetError",
    "ModelPlane",
    "NativeStreamingEngine",
    "QTensor",
    "QuantError",
    "ScriptDaemon",
    "ScriptRunner",
    "TinyLlmEngine",
    "build_data_pack",
    "build_plan_prompt",
    "default_queue_dir",
    "default_script_dir",
    "discover_local_gguf",
    "discover_local_models",
    "find_shards_dir",
    "gguf_params_b",
    "list_scripts",
    "load_result",
    "load_script_result",
    "load_tokenizer",
    "parse_proposals",
    "parse_quant",
    "prepare_model_shards",
    "quantize_tensor",
    "read_budget",
    "recommend",
    "resolve_api_key",
    "resolve_limits",
    "resolve_local_gguf",
    "resolve_local_model",
    "submit_job",
    "submit_script",
    "wrap_pack_as_prompt",
]
