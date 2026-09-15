"""Setup planner: what this machine needs, and the exact commands to get it.

One function builds the whole story — hardware, tier, which engines are already
installed, which local checkpoints are on disk, and the copy-paste command for
each path. Nothing here installs anything: the operator stays in control of
their own environment.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

from .budget import BUDGET_TIERS, DEFAULT_LIMITS, Limits, read_budget, recommend

# Prebuilt wheel indexes published by the llama-cpp-python project. A bare
# `pip install` compiles from source and needs a toolchain; these avoid that.
GGUF_WHEEL_CPU = "https://abetlen.github.io/llama-cpp-python/whl/cpu"
GGUF_WHEEL_CUDA = "https://abetlen.github.io/llama-cpp-python/whl/cu121"
TORCH_WHEEL_CPU = "https://download.pytorch.org/whl/cpu"


def _installed(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _fits(params_b: float, compressed: bool, limits: Limits) -> bool:
    if params_b > limits.max_model_b:
        return False
    if limits.require_compression and not compressed:
        return False
    return True


# A GGUF is mmapped and dequantized in place, but llama.cpp still holds the
# weights *and* compute/KV buffers resident, so peak RSS lands at roughly
# twice the file size. Verified against a real 8B Q4_K_S load: 4.4GB file,
# ~8.5GB peak RSS. The 2× multiplier is the honest planning number.
GGUF_RSS_MULTIPLIER = 2


def gguf_rss_need_mb(size_gb: float) -> int:
    """Peak resident memory a GGUF load is expected to need (MB)."""
    return int(size_gb * 1024 * GGUF_RSS_MULTIPLIER)


def _gguf_fits(row: dict, limits: Limits) -> bool:
    """Fit verdict for one GGUF row: size class, compression AND resident RAM.

    The RAM check is what keeps the verdict honest: without it an 8B Q4 model
    was announced as fitting the mid tier, then refused at load when the real
    RSS crossed that tier's ceiling.
    """
    if not _fits(row["params_b"], row["compressed"], limits):
        return False
    return gguf_rss_need_mb(row.get("size_gb", 0.0)) <= limits.max_rss_mb


def smallest_fitting_tier(row: dict) -> str | None:
    """The narrowest tier that can carry this checkpoint, or ``None``."""
    for tier in BUDGET_TIERS:
        if _gguf_fits(row, DEFAULT_LIMITS[tier]):
            return tier
    return None


def local_models(*, limits: Limits, roots: list[str | Path] | None = None) -> dict:
    """Local checkpoints (GGUF + HF cache) with a fit verdict and run command."""
    gguf: list[dict] = []
    try:
        from .gguf import discover_local_gguf

        for row in discover_local_gguf(roots=roots):
            row = dict(row)
            row["fits"] = _gguf_fits(row, limits)
            row["needs_tier"] = smallest_fitting_tier(row)
            row["run"] = (f"rebel-profiler llm generate \"<prompt>\" "
                          f"--model {row['path']}")
            gguf.append(row)
    except Exception:
        pass

    hf: list[dict] = []
    try:
        from .native import discover_local_models

        for row in discover_local_models():
            row = dict(row)
            from .catalog import model_params_b

            params = model_params_b(row["model"])
            row["params_b"] = params
            row["fits"] = _fits(params, False, limits)
            row["run"] = (f"rebel-profiler llm generate \"<prompt>\" "
                          f"--model {row['model']}")
            hf.append(row)
    except Exception:
        pass

    return {"gguf": gguf, "hf": hf,
            "total": len(gguf) + len(hf)}


def engine_table() -> list[dict]:
    """Every engine, whether it is ready, and how to enable it."""
    return [
        {
            "engine": "tiny",
            "installed": True,
            "needs": "nothing (stdlib only)",
            "purpose": "Deterministic, no-weights fallback. Keeps every contract "
                       "alive on machines that cannot run a model; never "
                       "hallucinates, proposes nothing.",
            "install": "(built in — nothing to install)",
            "run": "rebel-profiler llm generate \"<prompt>\" --engine tiny",
        },
        {
            "engine": "gguf",
            "installed": _installed("llama_cpp"),
            "needs": "llama-cpp-python",
            "purpose": "Single-file quantized checkpoints (llama.cpp / Ollama / "
                       "LM Studio exports). Runs the file you already have, "
                       "no download, no layer split.",
            "install": f"pip install llama-cpp-python --extra-index-url {GGUF_WHEEL_CPU}",
            "install_gpu": (f"pip install llama-cpp-python "
                            f"--extra-index-url {GGUF_WHEEL_CUDA}"),
            "run": "rebel-profiler llm generate \"<prompt>\" --model /path/to/model.gguf",
        },
        {
            "engine": "native",
            "installed": _installed("torch"),
            "needs": "torch",
            "purpose": "Layer-wise streaming over HF safetensors checkpoints "
                       "already in the local cache — one layer resident at a "
                       "time, no airllm install.",
            "install": f"pip install torch --index-url {TORCH_WHEEL_CPU}",
            "run": "rebel-profiler llm generate \"<prompt>\" --model Qwen/Qwen3-4B",
        },
        {
            "engine": "airllm",
            "installed": _installed("airllm"),
            "needs": "airllm + torch",
            "purpose": "AirLLM-mode layer streaming with AutoModel across "
                       "Llama/Qwen/DeepSeek/Mistral/Phi/Gemma. Optional 4/8-bit "
                       "compression on CUDA machines.",
            "install": "pip install 'rebel-profiler[airllm]'",
            "install_gpu": "pip install 'rebel-profiler[airllm-compression]'",
            "run": "rebel-profiler llm generate \"<prompt>\" --engine airllm --model Qwen/Qwen3-4B",
        },
        {
            "engine": "external",
            "installed": bool(os.environ.get("RP_LLM__API_KEY")),
            "needs": "an API key for any OpenAI-compatible endpoint",
            "purpose": "Remote brain, explicitly opt-in. Without this pin nothing "
                       "ever leaves the machine; payloads and responses are redacted.",
            "install": "export RP_LLM__ENGINE=external RP_LLM__API_KEY=sk-... "
                       "[RP_LLM__API_BASE=https://host/v1]",
            "run": "RP_LLM__ENGINE=external rebel-profiler llm generate \"<prompt>\"",
        },
    ]


def _recommended(engines: list[dict], local: dict) -> str:
    ready = {e["engine"] for e in engines if e["installed"]}
    if local["gguf"] and "gguf" in ready:
        return "gguf"
    if local["hf"] and "native" in ready:
        return "native"
    if "airllm" in ready:
        return "airllm"
    if local["gguf"]:
        return "gguf"
    if "native" in ready:
        return "native"
    return "tiny"


def setup_plan(*, engine: str | None = None, limits: Limits,
               budget: dict | None = None) -> dict:
    """Full setup picture for this machine."""
    budget = budget or read_budget()
    engines = engine_table()
    local = local_models(limits=limits)
    chosen = engine or _recommended(engines, local)

    next_steps: list[str] = []
    entry = next((e for e in engines if e["engine"] == chosen), None)
    if entry is not None and not entry["installed"]:
        install = entry["install"]
        if engine == "gguf" and not budget.get("cpu_only"):
            install = entry.get("install_gpu") or install
        next_steps.append(f"install: {install}")
    if local["gguf"]:
        best = local["gguf"][0]
        next_steps.append(
            f"run your local checkpoint: rebel-profiler llm generate \"<prompt>\" "
            f"--model {best['path']}")
    elif local["hf"]:
        next_steps.append(
            f"run your local checkpoint: rebel-profiler llm generate \"<prompt>\" "
            f"--model {local['hf'][0]['model']}")
    next_steps.append("health check: rebel-profiler llm status")
    next_steps.append("verify the plane end to end: python3 -m pytest tests/ -q")

    return {
        "hardware": budget,
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
        "recommended_engine": chosen,
        "engines": engines,
        "local_models": local,
        "next_steps": next_steps,
    }


def render_setup(plan: dict) -> str:
    hw = plan["hardware"]
    lines = [
        "LLM plane setup",
        f"  hardware   : {hw['total_ram_mb']}MB RAM, {hw['cpu_count']} CPU, "
        f"{'CPU-only' if hw['cpu_only'] else 'GPU available'}"
        + (" (Apple silicon)" if hw.get("apple_silicon") else ""),
        f"  tier       : {plan['tier']} (recommended {plan['recommended_tier']})",
        f"  caps       : model<= {plan['limits']['max_model_b']:g}B, "
        f"ctx<= {plan['limits']['max_context_tokens']}, "
        f"out<= {plan['limits']['max_new_tokens']}, "
        f"rss<= {plan['limits']['max_rss_mb']}MB",
        "",
        "Engines:",
    ]
    for entry in plan["engines"]:
        mark = "ready" if entry["installed"] else "install needed"
        star = " *" if entry["engine"] == plan["recommended_engine"] else "  "
        lines.append(f" {star} {entry['engine']:<9} [{mark:^14}] needs: {entry['needs']}")
        lines.append(f"      {entry['purpose']}")
        if not entry["installed"]:
            lines.append(f"      install: {entry['install']}")
    lines.append("")
    local = plan["local_models"]
    lines.append(f"Local checkpoints: {local['total']} found "
                 f"({len(local['gguf'])} GGUF, {len(local['hf'])} HF cache)")
    if not local["total"]:
        lines.append("  (none — set RP_LLM__GGUF_DIRS or place a checkpoint in "
                     "~/.cache/huggingface)")
    lines.append("")
    lines.append("Next steps:")
    for step in plan["next_steps"]:
        lines.append(f"  - {step}")
    return "\n".join(lines)


def render_local(payload: dict) -> str:
    lines = [f"Local checkpoints: {payload['total']} found"]
    for engine in ("gguf", "hf"):
        rows = payload.get(engine) or []
        if not rows:
            continue
        lines.append("")
        lines.append(f"{engine.upper()} ({len(rows)}):")
        for row in rows:
            name = row.get("name") or row.get("model", "")
            if row.get("fits"):
                fit = "fits"
            else:
                needs = row.get("needs_tier") if "needs_tier" in row else None
                fit = (f"needs tier '{needs}'" if needs
                       else "TOO BIG for this tier")
            extra = f"{row.get('quant', '')} {row.get('params_b', '?')}B".strip()
            lines.append(f"  {name}  [{extra}] {fit}")
            lines.append(f"      run: {row['run']}")
    if not payload["total"]:
        lines.append("")
        lines.append("  Nothing local yet. Put a .gguf in the project or set")
        lines.append("  RP_LLM__GGUF_DIRS=/path/to/models, then re-run this command.")
    return "\n".join(lines)
