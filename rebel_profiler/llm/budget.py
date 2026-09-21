"""Hardware budget: what this machine can carry without buckling.

Deterministic, stdlib-only. Reads /proc/meminfo (Linux), sysconf or
/proc-equivalents via :mod:`os` elsewhere, classifies the machine into a
tier and computes hard caps so the LLM plane can never push a low-end box
into swap-death. Env may only *tighten* the caps (RP_LLM__* — the same
layered, tighten-only spirit as core.config).

Tiers
-----
tiny     — < 6 GB RAM or CPU-only low-end: small models, short outputs
low      — 6–12 GB RAM: small/quantized models, modest concurrency
mid      — 12–32 GB RAM: quantized large models via layer streaming
high     — > 32 GB RAM: any model the engine supports
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field, replace
from pathlib import Path

from ..core.errors import RPError

EXIT_MODEL = 15


class ModelBudgetError(RPError):
    exit_code = EXIT_MODEL
    title = "Model budget exceeded"


@dataclass(frozen=True)
class Limits:
    """Hard caps the LLM plane may never exceed. Tighten-only."""

    max_rss_mb: int            # ceiling on resident memory for the plane
    max_context_tokens: int    # per-call input ceiling
    max_new_tokens: int        # per-call generation ceiling
    max_model_b: float         # largest parameter count allowed (billions)
    allow_gpu: bool            # GPU placement permitted at all
    require_compression: bool  # only compressed (4/8-bit) models may load
    tier: str = "mid"


DEFAULT_LIMITS = {
    "tiny": Limits(max_rss_mb=2048, max_context_tokens=1024, max_new_tokens=128,
                   max_model_b=3.0, allow_gpu=True, require_compression=True,
                   tier="tiny"),
    "low": Limits(max_rss_mb=4096, max_context_tokens=2048, max_new_tokens=256,
                  max_model_b=8.0, allow_gpu=True, require_compression=True,
                  tier="low"),
    "mid": Limits(max_rss_mb=10240, max_context_tokens=4096, max_new_tokens=512,
                  max_model_b=70.0, allow_gpu=True, require_compression=False,
                  tier="mid"),
    "high": Limits(max_rss_mb=16384, max_context_tokens=8192, max_new_tokens=1024,
                   max_model_b=700.0, allow_gpu=True, require_compression=False,
                   tier="high"),
}

BUDGET_TIERS = tuple(sorted(DEFAULT_LIMITS))

# Known model size classes (billions of parameters). Engine falls back to a
# conservative heuristic from the repo id when a model is unknown.
DEFAULT_MODELS: dict[str, float] = {
    "qwen2.5-0.5b": 0.5, "qwen2.5-1.5b": 1.5, "qwen3-4b": 4.0,
    "qwen3-8b": 8.0, "qwen3-32b": 32.0, "llama-3-8b": 8.0,
    "llama-3.1-8b": 8.0, "llama-3.3-70b": 70.0, "llama-2-70b": 70.0,
    "mistral-7b": 7.0, "mixtral-8x7b": 47.0, "phi-4": 14.0,
    "gemma-2-9b": 9.0, "deepseek-v3": 671.0, "kimi-k3": 2800.0,
}


def read_budget(meminfo_path: str = "/proc/meminfo") -> dict:
    """Snapshot of the hardware we may use. Deterministic, no psutil."""
    total_mb = _total_ram_mb(meminfo_path)
    available_mb = _available_ram_mb(meminfo_path, total_mb)
    cpu_count = os.cpu_count() or 1
    return {
        "total_ram_mb": total_mb,
        "available_ram_mb": available_mb,
        "cpu_count": cpu_count,
        "cpu_only": not _cuda_available(),
        "apple_silicon": _apple_silicon(),
        "at": time.time(),
    }


def _wider_tier(tier: str) -> str:
    """The next tier up — the only sanctioned way to raise a cap."""
    try:
        index = BUDGET_TIERS.index(tier)
    except ValueError:
        return BUDGET_TIERS[-1]
    return BUDGET_TIERS[min(index + 1, len(BUDGET_TIERS) - 1)]


def recommend(budget: dict | None = None) -> str:
    """Pick the widest tier this hardware can honestly carry."""
    budget = budget or read_budget()
    if budget["cpu_only"] and budget["total_ram_mb"] < 6_000:
        return "tiny"
    if budget["total_ram_mb"] < 6_000:
        return "tiny"
    if budget["total_ram_mb"] < 12_000:
        return "low"
    if budget["total_ram_mb"] < 32_000:
        return "mid"
    return "high"


@dataclass
class BudgetGuard:
    """Tracks the LLM plane's own RSS against a hard ceiling.

    The guard cannot stop the OS from swapping, but it can refuse every
    allocation-heavy call *before* the machine buckles: any operation that
    would push the plane past ``max_rss_mb`` is a structured error, not a
    freeze. Readings are conservative (peak RSS seen since creation).
    """

    limits: Limits
    _peak_rss_mb: float = field(default=0.0, repr=False)
    _base_rss_mb: float = field(default=0.0, repr=False)

    def __post_init__(self) -> None:
        self._base_rss_mb = _current_rss_mb()
        self._peak_rss_mb = self._base_rss_mb

    # -- observation ---------------------------------------------------------

    @property
    def base_rss_mb(self) -> float:
        return self._base_rss_mb

    @property
    def peak_rss_mb(self) -> float:
        return self._peak_rss_mb

    @property
    def current_rss_mb(self) -> float:
        rss = _current_rss_mb()
        self._peak_rss_mb = max(self._peak_rss_mb, rss)
        return rss

    def headroom_mb(self) -> float:
        return max(0.0, self.limits.max_rss_mb - self.current_rss_mb)

    # -- enforcement ---------------------------------------------------------

    def check_context(self, input_tokens: int) -> None:
        if input_tokens > self.limits.max_context_tokens:
            raise ModelBudgetError(
                f"Context {input_tokens} tokens exceeds cap {self.limits.max_context_tokens}",
                reason=f"Tier '{self.limits.tier}' caps input length to protect this machine.",
                action="Shorten the input or raise RP_LLM__MAX_CONTEXT_TOKENS (tighten-only in reverse is refused).",
            )

    def check_model(self, model_b: float, *, compressed: bool,
                    cuda_required: bool = True) -> None:
        if model_b > self.limits.max_model_b:
            raise ModelBudgetError(
                f"Model ~{model_b:g}B exceeds tier cap {self.limits.max_model_b:g}B",
                reason=f"Tier '{self.limits.tier}' cannot carry a model this large without buckling.",
                action="Pick a smaller model or enable compression ('4bit'/'8bit').",
            )
        if self.limits.require_compression and not compressed:
            raise ModelBudgetError(
                "Tier requires compressed weights",
                reason=f"Tier '{self.limits.tier}' only allows 4/8-bit compressed models.",
                action="Pass compression='4bit' (or '8bit') when loading.",
            )
        if compressed and cuda_required and not _cuda_available():
            # AirLLM's block-wise compression quantizes on-device (bnb .cuda());
            # a CPU-only torch cannot even split the layers. Refuse early with
            # an honest fix instead of a mid-load AssertionError. (The native
            # engine's own block-wise quantization is CPU-safe and passes
            # cuda_required=False — same feature, different mechanism.)
            raise ModelBudgetError(
                "Compression requires CUDA",
                reason="AirLLM's 4/8-bit block-wise compression (bitsandbytes) "
                       "quantizes on the GPU; this machine has no usable CUDA.",
                action="Run uncompressed — layer-wise streaming already keeps "
                       "memory tiny — or install a CUDA build of torch.",
            )

    def check_generate(self, max_new_tokens: int) -> None:
        if max_new_tokens > self.limits.max_new_tokens:
            raise ModelBudgetError(
                f"max_new_tokens={max_new_tokens} exceeds cap {self.limits.max_new_tokens}",
                reason=f"Tier '{self.limits.tier}' caps generation length.",
                action="Lower max_new_tokens.",
            )

    def check_rss(self) -> None:
        rss = self.current_rss_mb
        if rss > self.limits.max_rss_mb:
            wider = _wider_tier(self.limits.tier)
            if wider == self.limits.tier:
                # Already the widest tier: the only honest fixes are lighter.
                action = ("This is the widest tier — load a smaller or more "
                          "aggressively quantized checkpoint.")
            else:
                action = ("Run at a wider tier if this machine can carry it "
                          f"(--tier {wider}, or RP_LLM__TIER={wider}). "
                          "RP_LLM__MAX_RSS_MB may only *lower* this ceiling.")
            raise ModelBudgetError(
                f"LLM plane RSS {rss:.0f}MB exceeds ceiling {self.limits.max_rss_mb}MB",
                reason="The plane must never push a low-end machine into swap.",
                action=action,
            )

    def as_dict(self) -> dict:
        return {
            "tier": self.limits.tier,
            "limits": _limits_dict(self.limits),
            "rss_mb": round(self.current_rss_mb, 1),
            "peak_rss_mb": round(self._peak_rss_mb, 1),
            "headroom_mb": round(self.headroom_mb(), 1),
        }


def resolve_limits(*, tier: str | None = None, environ: dict | None = None,
                   budget: dict | None = None,
                   config: dict | None = None) -> Limits:
    """Resolve limits for *tier*, then apply tighten-only overrides.

    Precedence: built-in tier defaults < [llm] section of the resolved config
    (``--config-file`` profile or any layered config) < RP_LLM__* environment
    (tighten-only) < explicit *tier* argument.

    RP_LLM__MAX_RSS_MB / _MAX_CONTEXT_TOKENS / _MAX_NEW_TOKENS /
    _MAX_MODEL_B may only *lower* the caps; RP_LLM__ALLOW_GPU=false and
    RP_LLM__REQUIRE_COMPRESSION=true may only tighten booleans. A config
    profile pinning an env-var-style value behaves exactly like that env var:
    it may tighten the tier caps, never loosen them.
    """
    env = dict(os.environ if environ is None else environ)
    # The [llm] section of a config profile feeds the same tighten-only path:
    # profile values are applied first so live env vars keep precedence.
    profile = (config or {}).get("llm", {})
    if isinstance(profile, dict):
        for key, value in profile.items():
            var = f"RP_LLM__{str(key).upper()}"
            if var not in env and value is not None:
                env[var] = str(value)
    budget = budget or read_budget()
    tier = (tier or env.get("RP_LLM__TIER") or recommend(budget)).lower()
    if tier not in DEFAULT_LIMITS:
        raise ModelBudgetError(
            f"Unknown budget tier '{tier}'",
            action=f"Valid tiers: {', '.join(BUDGET_TIERS)}",
        )
    limits = DEFAULT_LIMITS[tier]

    def _num(name: str, current, smaller_is_tight: bool = True):
        raw = env.get(name)
        if raw is None:
            return current
        try:
            value = float(raw) if isinstance(current, float) else int(raw)
        except ValueError:
            return current
        if smaller_is_tight:
            return min(current, value) if value else current
        return value

    limits = replace(
        limits,
        max_rss_mb=_num("RP_LLM__MAX_RSS_MB", limits.max_rss_mb),
        max_context_tokens=_num("RP_LLM__MAX_CONTEXT_TOKENS", limits.max_context_tokens),
        max_new_tokens=_num("RP_LLM__MAX_NEW_TOKENS", limits.max_new_tokens),
        max_model_b=_num("RP_LLM__MAX_MODEL_B", limits.max_model_b),
        allow_gpu=env.get("RP_LLM__ALLOW_GPU", "true").strip().lower() != "false"
        and limits.allow_gpu,
        require_compression=env.get("RP_LLM__REQUIRE_COMPRESSION", "").strip().lower()
        in {"1", "true", "yes"} or limits.require_compression,
    )
    return limits


# ---------------------------------------------------------------------------
# readers


def _parse_meminfo(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        num = re.match(r"\s*(\d+)", rest)
        if num:
            out[key.strip()] = int(num.group(1))  # kB
    return out


def _total_ram_mb(meminfo_path: str) -> int:
    try:
        info = _parse_meminfo(Path(meminfo_path).read_text())
        if "MemTotal" in info:
            return info["MemTotal"] // 1024
    except OSError:
        pass
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page = os.sysconf("SC_PAGE_SIZE")
        return pages * page // (1024 * 1024)
    except (ValueError, OSError, AttributeError):
        return 4_096  # conservative default


def _available_ram_mb(meminfo_path: str, total_mb: int) -> int:
    try:
        info = _parse_meminfo(Path(meminfo_path).read_text())
        if "MemAvailable" in info:
            return info["MemAvailable"] // 1024
        if "MemFree" in info:
            return info["MemFree"] // 1024
    except OSError:
        pass
    return total_mb


def _current_rss_mb() -> float:
    try:
        with open("/proc/self/statm") as fh:
            pages = int(fh.read().split()[1])
        return pages * os.sysconf("SC_PAGE_SIZE") / (1024 * 1024)
    except (OSError, ValueError, IndexError):
        try:
            import resource

            peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            # macOS reports bytes, Linux reports kB.
            return peak / 1024 if peak < 10_000_000 else peak / (1024 * 1024)
        except Exception:
            return 0.0


def _cuda_available() -> bool:
    try:
        import torch  # noqa: PLC0415 — optional at runtime

        return bool(torch.cuda.is_available())
    except Exception:
        return False


def _apple_silicon() -> bool:
    return os.uname().sysname == "Darwin" and os.uname().machine == "arm64"


def _limits_dict(limits: Limits) -> dict:
    return {
        "max_rss_mb": limits.max_rss_mb,
        "max_context_tokens": limits.max_context_tokens,
        "max_new_tokens": limits.max_new_tokens,
        "max_model_b": limits.max_model_b,
        "allow_gpu": limits.allow_gpu,
        "require_compression": limits.require_compression,
    }
