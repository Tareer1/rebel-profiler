"""Low-memory inference engines: AirLLM-mode + deterministic tiny fallback.

Two engines, one interface:

* :class:`AirLlmEngine` — real generation through the ``airllm`` package with
  its whole low-memory feature set, guarded by the hardware budget:
  layer-wise streaming (one layer resident at a time), 4/8-bit block-wise
  compression, AutoModel across Llama/Qwen/DeepSeek/Mistral/Phi/Gemma/…,
  prefetching, profiling, layer-shards path, ``delete_original`` and
  ``hf_token``. GPU is optional: with ``RP_LLM__ALLOW_GPU=false`` (or no
  CUDA/MPS at all) tensors are placed on CPU; Apple-silicon machines get MPS
  placement automatically.

* :class:`TinyLlmEngine` — a deterministic, stdlib-only fallback that keeps
  every downstream contract (planner → proposals, daemon results, CLI exit
  codes) alive on machines that cannot or may not load weights. It never
  hallucinates: it echoes bounded, labeled text and proposes nothing.

:class:`ModelPlane` owns the lifecycle: exactly one engine loaded at a time,
eager unload (``del`` + gc + optional torch CUDA cache flush), RSS check
before/after every call, and structured errors with fix hints.
"""

from __future__ import annotations

import gc
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from .budget import BudgetGuard, Limits, ModelBudgetError, read_budget

# Params that pass straight through to airllm's AutoModel.from_pretrained.
AIRLLM_OPTIONS = (
    "compression",       # None | '4bit' | '8bit' (block-wise weight compression)
    "profiling_mode",    # True → time-consumption output
    "layer_shards_saving_path",
    "hf_token",          # gated models (meta-llama/*)
    "prefetching",       # overlap loading and compute (AirLLMLlama2)
    "delete_original",   # reclaim checkpoint disk after the layer split
)


@dataclass(frozen=True)
class GenerationResult:
    """One generation: text plus provenance and budget telemetry."""

    text: str
    engine: str                 # airllm | tiny | external
    model: str
    input_tokens: int
    output_tokens: int
    elapsed_s: float
    peak_rss_mb: float
    compressed: bool = False
    truncated: bool = False     # input was capped by the tier context ceiling
    device: str = ""            # cuda | mps | cpu (airllm only)

    def as_dict(self) -> dict:
        return {
            "text": self.text, "engine": self.engine, "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "elapsed_s": round(self.elapsed_s, 2),
            "peak_rss_mb": round(self.peak_rss_mb, 1),
            "compressed": self.compressed, "truncated": self.truncated,
            "device": self.device,
        }


def _require_airllm():
    try:
        import airllm  # noqa: PLC0415 — heavy import, only when needed
    except ImportError as exc:
        from ..core.errors import DependencyUnavailableError

        raise DependencyUnavailableError(
            "The airllm package is not installed",
            reason="AirLLM-mode runs large models layer-by-layer in tiny VRAM; "
                   "it is an optional dependency.",
            action="pip install 'rebel-profiler[airllm]'  (or run "
                   "'rebel-profiler llm status' to fall back to the tiny engine)",
        ) from exc
    return airllm


class AirLlmEngine:
    """AirLLM-backed engine: 70B-class models on small machines."""

    kind = "airllm"

    def __init__(self, model: str, *, limits: Limits, budget: dict | None = None,
                 **options) -> None:
        self.model_id = model
        self.limits = limits
        self.options = {k: v for k, v in options.items() if k in AIRLLM_OPTIONS}
        self.compressed = self.options.get("compression") in {"4bit", "8bit"}
        self._model = None
        self._tokenizer = None
        self.last_device = ""
        self.budget = budget or read_budget()
        self.guard = BudgetGuard(limits)
        self.guard.check_model(model_params_b(model), compressed=self.compressed)

    # -- placement -------------------------------------------------------------

    def _device(self) -> str:
        """Pick the widest placement the budget allows — GPU never required."""
        if not self.limits.allow_gpu:
            return "cpu"
        try:
            import torch  # noqa: PLC0415 — optional at runtime

            if torch.cuda.is_available():
                return "cuda"
            mps = getattr(torch.backends, "mps", None)
            if mps is not None and mps.is_available():
                return "mps"   # Apple silicon
        except Exception:
            pass
        return "cpu"

    # -- lifecycle ------------------------------------------------------------

    def load(self) -> None:
        if self._model is not None:
            return
        self.guard.check_rss()
        airllm = _require_airllm()
        device = self._device()
        try:
            # AirLLM 4.x defaults to cuda:0; pass the placement explicitly so
            # CPU-only and Apple-silicon machines never hit a CUDA assertion.
            self._model = airllm.AutoModel.from_pretrained(
                self.model_id, device=device, **self.options)
            self._tokenizer = self._model.tokenizer
        except Exception as exc:  # structured failure, never a stack-trace dump
            self.unload()
            from ..core.errors import DependencyUnavailableError

            raise DependencyUnavailableError(
                f"AirLLM could not load '{self.model_id}'",
                reason=f"{type(exc).__name__}: {exc}",
                action="Check disk space in the HF cache, the model id, and "
                       "hf_token for gated models.",
            ) from exc

    def unload(self) -> None:
        self._tokenizer = None
        if self._model is not None:
            self._model = None
            gc.collect()
            try:
                import torch  # noqa: PLC0415 — optional

                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
            except Exception:
                pass
        gc.collect()

    @property
    def loaded(self) -> bool:
        return self._model is not None

    # -- generation ---------------------------------------------------------------

    def generate(self, prompt: str, *, max_new_tokens: int | None = None,
                 temperature: float = 0.2) -> GenerationResult:
        del temperature  # airllm generates greedily; temperature is not exposed
        self.load()
        self.guard.check_rss()
        device = self._device()
        started = time.time()
        ids = self._encode(prompt)
        self.guard.check_context(len(ids))
        new_tokens = min(max_new_tokens or self.limits.max_new_tokens,
                         self.limits.max_new_tokens)
        self.guard.check_generate(new_tokens)
        try:
            import torch  # noqa: PLC0415 — engine requires it

            out = self._model.generate(
                torch.tensor([ids], device=device),
                max_new_tokens=new_tokens,
                use_cache=True,
                return_dict_in_generate=True,
            )
            seq = out.sequences[0]
            text = self._tokenizer.decode(seq)
            produced = max(0, len(seq) - len(ids))
        except Exception as exc:
            from ..core.errors import DependencyUnavailableError

            raise DependencyUnavailableError(
                "AirLLM generation failed",
                reason=f"{type(exc).__name__}: {exc}",
                action="Reduce max_new_tokens/context, or re-run with the tiny engine.",
            ) from exc
        self.last_device = device
        self.guard.check_rss()
        return GenerationResult(
            text=text, engine="airllm", model=self.model_id,
            input_tokens=len(ids), output_tokens=produced,
            elapsed_s=time.time() - started,
            peak_rss_mb=self.guard.peak_rss_mb, compressed=self.compressed,
            truncated=len(ids) >= self.limits.max_context_tokens,
            device=device,
        )

    def _encode(self, text: str) -> list[int]:
        try:
            encoded = self._tokenizer(
                [text], return_tensors="pt", return_attention_mask=False,
                truncation=True, max_length=self.limits.max_context_tokens,
                padding=False,
            )
            return list(encoded["input_ids"][0].tolist())
        except TypeError:
            return self._tokenizer.encode(text)[: self.limits.max_context_tokens]


class TinyLlmEngine:
    """Deterministic fallback: no weights, no RAM spike, no hallucination.

    Output is a bounded, clearly-labeled summary of the prompt. It exists so
    low-end boxes, CI and air-gapped operators still get *structured,
    honest* behavior from every LLM-plane entry point.
    """

    kind = "tiny"

    def __init__(self, model: str = "deterministic-tiny", *, limits: Limits,
                 **_options) -> None:
        self.model_id = model
        self.limits = limits
        self.guard = BudgetGuard(limits)
        self.loaded = False
        self.compressed = False
        self.last_device = "cpu"

    def load(self) -> None:
        self.loaded = True

    def unload(self) -> None:
        self.loaded = False

    def generate(self, prompt: str, *, max_new_tokens: int | None = None,
                 temperature: float = 0.2) -> GenerationResult:
        started = time.time()
        cap = min(max_new_tokens or 64, self.limits.max_new_tokens)
        # Deterministic "generation": bounded echo under an explicit label.
        # ~4 chars per token keeps the cap meaningful without a tokenizer.
        budget_chars = max(32, cap * 4)
        body = re.sub(r"\s+", " ", prompt).strip()
        truncated_prompt = len(body) > budget_chars
        text = (
            "[tiny-engine deterministic output]\n"
            + body[:budget_chars]
            + ("…" if truncated_prompt else "")
        )
        self.guard.check_rss()
        return GenerationResult(
            text=text, engine="tiny", model=self.model_id,
            input_tokens=len(prompt.split()), output_tokens=cap,
            elapsed_s=time.time() - started,
            peak_rss_mb=self.guard.peak_rss_mb,
            truncated=truncated_prompt,
            device="cpu",
        )


class ModelPlane:
    """Owns exactly one engine; every call is budget-checked and unloadable.

    The plane is the only object in the process that holds a model. When the
    operator's CLI/agent is done (or hands off to the daemon), ``unload()``
    returns the memory to the machine — the same "LLM goes quiet" rule the
    worker plane applies to jobs.
    """

    def __init__(self, *, limits: Limits, budget: dict | None = None,
                 prefer_engine: str | None = None) -> None:
        self.limits = limits
        self.budget = budget or read_budget()
        self._engine = None
        self._engine_kind: str | None = None
        self._fallback_reason = ""
        self._prefer = prefer_engine

    # -- engine selection -----------------------------------------------------

    @property
    def engine(self):
        return self._engine

    @property
    def engine_kind(self) -> str | None:
        return self._engine_kind

    @property
    def fallback_reason(self) -> str:
        return self._fallback_reason

    def select_engine(self, model: str, **options):
        """Choose airllm when loadable and allowed; tiny otherwise.

        Selection is deterministic given the environment: airllm importable,
        tier rules satisfied, not force-pinned to tiny. Every fallback
        records *why* (``fallback_reason``) — no silent substitution.
        """
        if self._prefer == "tiny":
            self._fallback_reason = "engine=tiny requested (RP_LLM__ENGINE or --engine)"
            engine = self._engine_for("tiny", model, **options)
            engine.load()
            self._engine = engine
            self._engine_kind = "tiny"
            return engine
        if self._prefer == "external":
            # Opt-in remote provider: pinned explicitly, never a silent default.
            engine = self._engine_for("external", model, **options)
            engine.load()
            self._engine = engine
            self._engine_kind = "external"
            self._fallback_reason = "engine=external requested (remote AI provider)"
            return engine
        if self._prefer == "gguf":
            # Explicit GGUF pin: the caller knows the checkpoint is a gguf.
            engine = self._engine_for("gguf", model, **options)
            engine.load()
            self.unload()
            self._engine = engine
            self._engine_kind = "gguf"
            return engine
        # Every failed attempt is kept, in order. Overwriting the reason with
        # the *last* engine's failure hid the real cause: a local GGUF that
        # tripped the budget guard reported only "airllm unavailable", so the
        # operator was told to install a package instead of what actually
        # happened.
        reasons: list[str] = []

        def _adopt(kind: str, engine):
            engine.load()
            self.unload()
            self._engine = engine
            self._engine_kind = kind
            self._fallback_reason = "; ".join(reasons)
            return engine

        try:
            # Local GGUF first when the request names a checkpoint that is
            # already on disk: one file, already quantized, no download and no
            # layer split. Falls through to the HF-dir engines otherwise.
            from .gguf import resolve_local_gguf

            if resolve_local_gguf(model) is not None:
                engine = self._engine_for("gguf", model, **options)
                return _adopt("gguf", engine)
        except Exception as exc:
            self.unload()
            reasons.append(
                f"gguf engine unavailable ({type(exc).__name__}: {exc})")
        try:
            # Native engine first when the checkpoint is ALREADY on disk:
            # no airllm install, no download. Falls through to airllm (which
            # may download) only when the model is not local.
            from .native import resolve_local_model

            if resolve_local_model(model) is not None:
                engine = self._engine_for("native", model, **options)
                return _adopt("native", engine)
        except Exception as exc:
            self.unload()
            reasons.append(
                f"native engine unavailable ({type(exc).__name__}: {exc})")
        try:
            engine = self._engine_for("airllm", model, **options)
            return _adopt("airllm", engine)
        except Exception as exc:
            self.unload()
            reasons.append(
                f"airllm unavailable ({type(exc).__name__}: {exc})")
            self._fallback_reason = (
                "; ".join(reasons)
                + "; fell back to the deterministic tiny engine")
            engine = self._engine_for("tiny", model)
            engine.load()
            self._engine = engine
            self._engine_kind = "tiny"
            return engine

    def _engine_for(self, kind: str, model: str, **options):
        if kind == "tiny":
            engine = TinyLlmEngine(model, limits=self.limits)
        elif kind == "external":
            from .external import ExternalEngine

            engine = ExternalEngine(model, limits=self.limits,
                                    **{k: v for k, v in options.items()
                                       if k in {"api_key", "api_base", "timeout_s"}})
        elif kind == "native":
            from .native import NativeStreamingEngine

            engine = NativeStreamingEngine(model, limits=self.limits,
                                           budget=self.budget)
        elif kind == "gguf":
            from .gguf import GgufEngine

            engine = GgufEngine(model, limits=self.limits, budget=self.budget,
                                **{k: v for k, v in options.items()
                                   if k in {"n_gpu_layers", "n_threads"}})
        else:
            engine = AirLlmEngine(model, limits=self.limits,
                                  budget=self.budget, **options)
        return engine

    # -- lifecycle ------------------------------------------------------------

    def generate(self, prompt: str, *, model: str | None = None, **kwargs) -> GenerationResult:
        if self._engine is None:
            raise ModelBudgetError(
                "No engine loaded",
                action="Call select_engine() or load_tiny() first.",
            )
        if self._engine_kind == "airllm":
            self._engine.guard.check_rss()
        return self._engine.generate(prompt, **kwargs)

    def load_tiny(self) -> TinyLlmEngine:
        self.unload()
        engine = TinyLlmEngine("deterministic-tiny", limits=self.limits)
        engine.load()
        self._engine = engine
        self._engine_kind = "tiny"
        self._fallback_reason = self._fallback_reason or "tiny engine loaded"
        return engine

    def unload(self) -> None:
        if self._engine is not None:
            try:
                self._engine.unload()
            except Exception:
                pass
        self._engine = None
        self._engine_kind = None
        gc.collect()

    def status(self) -> dict:
        engine = self._engine
        guard = engine.guard if engine is not None else None
        model_id = getattr(engine, "model_id", "")
        return {
            "engine": self._engine_kind,
            "model": model_id,
            "model_b": model_params_b(model_id) if model_id else 0.0,
            "loaded": bool(engine is not None and engine.loaded),
            "compressed": bool(getattr(engine, "compressed", False)),
            "device": getattr(engine, "last_device", ""),
            "fallback_reason": self._fallback_reason,
            "limits": {
                "max_rss_mb": self.limits.max_rss_mb,
                "max_context_tokens": self.limits.max_context_tokens,
                "max_new_tokens": self.limits.max_new_tokens,
                "max_model_b": self.limits.max_model_b,
                "require_compression": self.limits.require_compression,
                "allow_gpu": self.limits.allow_gpu,
            },
            "rss": guard.as_dict() if guard else None,
            "budget": self.budget,
        }

    # -- persistence (daemon handoff) -------------------------------------------

    def save_session(self, path: Path) -> dict:
        state = {"kind": self._engine_kind or "none",
                 "model": getattr(self._engine, "model_id", ""),
                 "saved_at": time.time()}
        Path(path).write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
        return state

    @classmethod
    def restore_session(cls, path: Path, *, limits: Limits) -> "ModelPlane":
        state = json.loads(Path(path).read_text())
        plane = cls(limits=limits)
        if state.get("kind") == "tiny":
            plane.load_tiny()
        return plane


def model_params_b(model_id: str) -> float:
    """Import-lazy re-export so inference.py stays the only import many need."""
    from .catalog import model_params_b as _fn

    return _fn(model_id)
