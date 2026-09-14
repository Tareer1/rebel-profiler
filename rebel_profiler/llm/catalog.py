"""Model catalog: parameter sizing + tier-aware suggestions.

Sizes are approximate class estimates used for *budget decisions only*
(never for claims or evidence). Unknown ids fall back to a conservative
heuristic so an oversized model is still refused on a small tier.
"""

from __future__ import annotations

import re

from .budget import DEFAULT_MODELS

_PAT_SIZE = re.compile(r"(?i)(\d+(?:\.\d+)?)\s*[bB]\b")


def model_params_b(model_id: str) -> float:
    """Approximate parameter count (billions) for a repo id or local path."""
    name = model_id.rstrip("/").split("/")[-1].lower()
    for key, size in DEFAULT_MODELS.items():
        if key in name.replace("_", "-").replace(" ", "-"):
            return size
    match = _PAT_SIZE.search(name)
    if match:
        return float(match.group(1))
    # Unknown: assume mid-large so tiny tiers refuse rather than swap-die.
    return 32.0


def suggest_models(total_ram_mb: int, *, cpu_only: bool = False) -> list[dict]:
    """Deterministic shortlist for this machine's RAM (AirLLM-mode sizes)."""
    table = [
        ("Qwen/Qwen2.5-0.5B", 0.5, "<2GB", "runs anywhere"),
        ("Qwen/Qwen3-4B", 4.0, "~2GB", "good default on tiny tiers"),
        ("Qwen/Qwen3-8B", 8.0, "~1-2GB", "layer-wise streaming"),
        ("meta-llama/Meta-Llama-3-8B", 8.0, "~2GB", "layer-wise streaming"),
        ("Qwen/Qwen3-32B", 32.0, "~2-3GB", "compressed + streaming"),
        ("mistralai/Mixtral-8x7B-Instruct-v0.1", 47.0, "~1-3GB", "MoE expert streaming"),
        ("meta-llama/Llama-3.3-70B-Instruct", 70.0, "~4GB", "the classic AirLLM demo"),
        ("deepseek-ai/DeepSeek-V3", 671.0, "~12GB", "FP8 + expert streaming"),
    ]
    out = []
    for model_id, size_b, vram, note in table:
        # Layer-wise streaming keeps resident memory tiny; RAM gates which
        # classes are honest: sub-1B runs anywhere ≥2GB, small models need
        # breathing room, everything streams on ≥12GB machines.
        fits = ((size_b <= 0.5 and total_ram_mb >= 2_000)
                or (size_b <= 8.0 and total_ram_mb >= 4_000)
                or total_ram_mb >= 12_000)
        out.append({"model": model_id, "params_b": size_b, "airllm_vram": vram,
                    "note": note, "fits": fits})
    return out
