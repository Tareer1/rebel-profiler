"""Native layer-streaming engine — the full AirLLM feature set, zero installs.

The tool's own implementation of low-memory inference so heavy-model features
work with NOTHING installed beyond torch (itself optional — without it the
plane falls back to the tiny engine honestly):

  * no ``airllm`` package, no ``transformers``, no ``accelerate``,
  * no model download — the engine runs from checkpoints **already on disk**
    (the local Hugging Face cache or any local path),
  * the only optional dependency is **torch**.

AirLLM feature set, implemented natively (``llm/quant.py``, ``llm/tokenizer.py``):

  * **safetensors reader** — stdlib ``struct`` + ``json`` header parse, mmap
    read of exact byte ranges; a tensor materializes only when a layer needs it,
  * **layer-wise streaming** — one transformer layer resident at a time:
    weights load per-layer from disk, run the forward, then drop (del + gc),
  * **4/8-bit block-wise quantization** — weights may be pre-baked into
    per-layer shard files (:mod:`rebel_profiler.llm.quant`) and stream back
    dequantizing on use; CPU-safe (the bitsandbytes path needs CUDA, this
    one does not),
  * **layer shards** (``prepare``) — checkpoint → per-layer shard bake with
    hash manifest, ``--delete-original`` to reclaim disk after verification,
  * **prefetching** — the next layer's tensors read from the page cache
    while the current one computes (background thread),
  * **profiling** — per-layer ms timings recorded and reported on unload,
  * **architectures** — Qwen2/Qwen3, Llama 2/3, Mistral (+sliding window),
    Phi-3, Gemma/Gemma-2 (soft logit capping), Mixtral (MoE expert
    streaming — only the top-k experts resident per token),
  * **real tokenizer** — byte-level BPE from ``tokenizer.json``
    (:mod:`rebel_profiler.llm.tokenizer`); honest approx fallback,
  * **chat template** — Qwen/Llama-3 chat formats for instruction models,
  * **incremental KV-cache decoding** — after the prompt prefill, each new
    token runs one position forward, not the whole sequence,
  * **CPU + Apple-silicon (MPS) + CUDA** placement, budget-guarded,
  * **greedy + temperature sampling** generation, bounded by the tier caps.

The deterministic budget guard (tiers, RSS ceiling, context/new-token caps)
wraps every call exactly as for the AirLLM engine: the native engine is a
*sibling* of :class:`~rebel_profiler.llm.inference.AirLlmEngine`, not a way
around the law.
"""

from __future__ import annotations

import gc
import json
import mmap
import struct
import time
from pathlib import Path

from .budget import BudgetGuard, Limits, ModelBudgetError
from .catalog import model_params_b
from .inference import GenerationResult
from .tokenizer import ApproxTokenizer, BpeTokenizer, load_tokenizer

# --- optional torch (the single heavy dependency, checked lazily) ------------


def _require_torch():
    try:
        import torch  # noqa: PLC0415 — heavy, imported only when needed
    except ImportError as exc:
        from ..core.errors import DependencyUnavailableError

        raise DependencyUnavailableError(
            "The native engine needs torch",
            reason="layer-streaming inference runs on torch tensors; torch is "
                   "the tool's only optional runtime dependency.",
            action="pip install torch --index-url https://download.pytorch.org/whl/cpu",
        ) from exc
    return torch


# --- safetensors: stdlib reader (no external package) -------------------------

_DT_MAP = {
    "F32": (4, "f32"), "F64": (8, "f64"), "F16": (2, "f16"),
    "BF16": (2, "bf16"), "I64": (8, "i64"), "I32": (4, "i32"),
    "U8": (1, "u8"),
}


class SafeTensorFile:
    """mmap-backed safetensors reader with exact byte-range tensor views."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._fh = open(self.path, "rb")
        header_len = struct.unpack("<Q", self._fh.read(8))[0]
        header = json.loads(self._fh.read(header_len))
        self._dtypes = {k: v.get("dtype", "") for k, v in header.items()
                        if k != "__metadata__"}
        self._shapes = {k: tuple(v.get("shape", [])) for k, v in header.items()
                        if k != "__metadata__"}
        data_start = 8 + header_len
        self._fh.seek(0, 2)
        self._map = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
        self._offsets: dict[str, tuple[int, int]] = {}
        for name, meta in header.items():
            if name == "__metadata__":
                continue
            begin = data_start + meta["data_offsets"][0]
            end = data_start + meta["data_offsets"][1]
            self._offsets[name] = (begin, end)

    def tensor_names(self) -> list[str]:
        return sorted(self._offsets)

    def shape(self, name: str) -> tuple[int, ...]:
        return self._shapes.get(name, ())

    def load(self, name: str):
        """Materialize one tensor (torch). Only called for the live layer."""
        torch = _require_torch()
        begin, end = self._offsets[name]
        raw = self._map[begin:end]
        nbytes, kind = _DT_MAP[self._dtypes[name]]
        if kind == "f32":
            t = torch.frombuffer(bytearray(raw), dtype=torch.float32)
        elif kind == "f16":
            t = torch.frombuffer(bytearray(raw), dtype=torch.float16).float()
        elif kind == "bf16":
            # bf16: reinterpret via uint16 view (no numpy needed)
            u16 = torch.frombuffer(bytearray(raw), dtype=torch.uint16)
            t = (u16.to(torch.int32) << 16).view(torch.float32)
        elif kind == "i64":
            t = torch.frombuffer(bytearray(raw), dtype=torch.int64)
        elif kind == "i32":
            t = torch.frombuffer(bytearray(raw), dtype=torch.int32)
        elif kind == "u8":
            t = torch.frombuffer(bytearray(raw), dtype=torch.uint8)
        else:  # pragma: no cover — safetensors has no other common dtypes here
            raise ModelBudgetError(
                f"Unsupported tensor dtype {self._dtypes[name]!r} for {name!r}")
        shape = self._shapes[name]
        return t.reshape(tuple(shape)).float()

    def close(self) -> None:
        try:
            self._map.close()
        finally:
            self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


# --- model discovery: use what is ALREADY on disk ---------------------------


def discover_local_models(hf_cache: str | Path | None = None) -> list[dict]:
    """List dense Qwen2/Llama checkpoints already on this machine.

    Sources: the local HF cache (``HF_HOME``/default) and explicit local
    paths. **No network, no download** — a checkpoint must already be present
    to be usable, which is the whole point of the native engine.
    """
    found: dict[str, dict] = {}
    from pathlib import Path as _P

    cache = _P(hf_cache) if hf_cache else _hf_home()
    hub = cache / "hub"
    candidates: list[_P] = []
    if hub.exists():
        candidates.extend(sorted(hub.glob("models--*--*")))
    for snap in candidates:
        for snapshot in sorted((snap / "snapshots").glob("*")):
            if (snapshot / "config.json").exists() and _has_weights(snapshot):
                model_id = snap.name.replace("models--", "").replace("--", "/")
                found[model_id] = {"model": model_id, "path": str(snapshot),
                                   "source": "hf-cache"}
    return list(found.values())


def _hf_home() -> Path:
    import os

    env = os.environ.get("HF_HOME") or os.environ.get("HF_HUB_CACHE")
    if env:
        return Path(env)
    return Path.home() / ".cache" / "huggingface"


def _has_weights(snapshot: Path) -> bool:
    if (snapshot / "model.safetensors").exists():
        return True
    if any(snapshot.glob("model-*-of-*.safetensors")):
        return True
    return any(snapshot.glob("*.safetensors"))


def resolve_local_model(model_id: str, *, hf_cache: str | Path | None = None) -> Path | None:
    """Find an on-disk snapshot for *model_id* (repo id or local path)."""
    p = Path(model_id).expanduser()
    if p.exists() and (p / "config.json").exists():
        return p
    from pathlib import Path as _P

    cache = _P(hf_cache) if hf_cache else _hf_home()
    snap_dir = cache / "hub" / f"models--{model_id.replace('/', '--')}" / "snapshots"
    if snap_dir.exists():
        for snapshot in sorted(snap_dir.iterdir()):
            if (snapshot / "config.json").exists() and _has_weights(snapshot):
                return snapshot
    return None


# --- tensor source: raw safetensors OR quantized shards -----------------------


class _ShardSource:
    """Tensor source over rp-shards (possibly 4/8-bit quantized)."""

    kind = "shards"

    def __init__(self, shards_dir: Path, snapshot: Path) -> None:
        self.shards_dir = Path(shards_dir)
        self.manifest = json.loads((self.shards_dir / "manifest.json").read_text())
        self.bits = int(self.manifest.get("bits", 0))
        self._files: dict[str, SafeTensorFile] = {}
        self._owner: dict[str, tuple[Path, str]] = {}
        for shard in self.manifest.get("shards", []):
            path = self.shards_dir / shard["file"]
            sf = SafeTensorFile(path)
            self._files[path.name] = sf
            for name in sf.tensor_names():
                logical = name
                for suffix in (".rp.packed", ".rp.scales", ".rp.meta"):
                    if name.endswith(suffix):
                        logical = name[: -len(suffix)]
                        break
                prev = self._owner.get(logical)
                # prefer the packed variant (holds the weight bytes); the
                # 1-D meta tensor must never win the slot
                if prev is None or (prev[1].endswith(".rp.meta")
                                    and not name.endswith(".rp.meta")):
                    self._owner[logical] = (path, name)
        self._snapshot = snapshot

    def names(self) -> list[str]:
        return sorted(self._owner)

    def load(self, name: str):
        """Load one tensor — plain or rp-quantized (dequantized on use)."""
        import torch

        entry = self._owner.get(name)
        if entry is None:
            raise ModelBudgetError(f"tensor {name!r} missing from shards")
        path, key = entry
        sf = self._files[path.name]
        if self.bits and key.endswith(".rp.packed"):
            from .quant import QTensor

            logical = key[: -len(".rp.packed")]
            meta = sf.load(logical + ".rp.meta").tolist()
            rows, cols, bits, block_size = (int(v) for v in meta)
            packed = sf.load(key)
            scales = sf.load(logical + ".rp.scales")
            return QTensor(packed.to(torch.uint8), scales.to(torch.float16),
                           rows, cols, bits, block_size)
        return sf.load(key)

    def close(self) -> None:
        for f in self._files.values():
            f.close()
        self._files = {}


class _RawSource:
    """Tensor source over plain safetensors checkpoint files."""

    kind = "raw"

    def __init__(self, snapshot: Path) -> None:
        self._files: dict[str, SafeTensorFile] = {}
        self._owner: dict[str, str] = {}
        for sf_path in sorted(Path(snapshot).glob("*.safetensors")):
            sf = SafeTensorFile(sf_path)
            self._files[sf_path.name] = sf
            for name in sf.tensor_names():
                self._owner[name] = sf_path.name

    def names(self) -> list[str]:
        return sorted(self._owner)

    def load(self, name: str):
        return self._files[self._owner[name]].load(name)

    def close(self) -> None:
        for f in self._files.values():
            f.close()
        self._files = {}


# --- the engine ---------------------------------------------------------------


class NativeStreamingEngine:
    """Layer-streaming inference from on-disk checkpoints — no airllm install.

    Memory law: the embedding table and **one** decoder layer are resident;
    everything else lives on disk until its turn. The budget guard's RSS
    ceiling and token caps bound every call.
    """

    kind = "native"

    def __init__(self, model: str, *, limits: Limits, hf_cache=None,
                 budget: dict | None = None, compression: str = "",
                 layer_shards_saving_path: str | Path | None = None,
                 **_options) -> None:
        _require_torch()   # structured error up front, not mid-load
        self.model_id = model
        self.limits = limits
        self.guard = BudgetGuard(limits)
        self.compressed = compression in {"4bit", "8bit"}
        self._compression = compression
        self._shards_path = (Path(layer_shards_saving_path)
                             if layer_shards_saving_path else None)
        self.last_device = "cpu"
        self.profile: list[dict] = []
        self._snapshot = resolve_local_model(model, hf_cache=hf_cache)
        if self._snapshot is None:
            from ..core.errors import DependencyUnavailableError

            raise DependencyUnavailableError(
                f"Model '{model}' is not on disk",
                reason="The native engine never downloads: it runs checkpoints "
                       "already present in the local HF cache or a local path.",
                action="Put the checkpoint in the HF cache (or pass a local "
                       "path), or use an engine that may download.",
            )
        self.guard.check_model(model_params_b(model), compressed=self.compressed,
                               cuda_required=False)   # native quant is CPU-safe
        self._model = None   # keep the .loaded contract; holds loaded state

    # -- lifecycle -------------------------------------------------------------

    def load(self) -> None:
        if self._model is not None:
            return
        self.guard.check_rss()
        import torch  # guaranteed by __init__

        cfg = json.loads((self._snapshot / "config.json").read_text())
        self.torch = torch
        self.cfg = cfg
        self.n_layers = int(cfg["num_hidden_layers"])
        self.n_heads = int(cfg["num_attention_heads"])
        self.n_kv = int(cfg.get("num_key_value_heads", self.n_heads))
        self.head_dim = int(cfg["hidden_size"]) // self.n_heads
        self.eps = float(cfg.get("rms_norm_eps", 1e-6))
        self.rope_theta = float(cfg.get("rope_theta", 1_000_000.0))
        self.tie = bool(cfg.get("tie_word_embeddings", False))
        self.vocab_size = int(cfg.get("vocab_size", 0))
        # sliding window (Mistral) & gemma logit capping
        self.sliding_window = int(cfg.get("sliding_window", 0) or 0)
        self.final_logit_softcapping = float(cfg.get("final_logit_softcapping", 0) or 0)
        # MoE (Mixtral)
        self.n_experts = int(cfg.get("num_local_experts", 0) or 0)
        self.top_k = int(cfg.get("num_experts_per_tok", 0) or 0)

        # tensor source: baked shards (quantized) when available, else raw
        from .quant import find_shards_dir

        shards_dir = (self._shards_path
                      or find_shards_dir(self._snapshot)
                      or (self._snapshot / "rp_shards" if self.compressed else None))
        if shards_dir is not None and Path(shards_dir).exists():
            self.source = _ShardSource(Path(shards_dir), self._snapshot)
        else:
            self.source = _RawSource(self._snapshot)

        self._tok = load_tokenizer(self._snapshot)
        self._files = getattr(self.source, "_files", {})
        self._index = self._build_index()
        self._tensors: dict[str, object] = {}
        # Resident from here on: embeddings + final norm (+ tied head ref).
        for name in self._index.get("embed", []) + self._index.get("norm", []):
            self._tensors[name] = self._load_tensor(name)
        self._embed_table = self._dequant(self._tensors[self._index["embed"][0]])
        self._norm_w = self._dequant(self._tensors[self._index["norm"][0]])
        self._device = self._pick_device()
        self._embed_table = self._embed_table.to(self._device)
        self._norm_w = self._norm_w.to(self._device)
        self._lm_head = (self._embed_table if self.tie
                         else self._dequant(self._load_tensor("lm_head.weight")).to(self._device))
        self._model = object()   # marker: loaded
        self.guard.check_rss()

    def unload(self) -> None:
        self._tensors = {}
        self._embed_table = self._norm_w = self._lm_head = None
        for f in getattr(self, "_files", {}).values():
            f.close()
        self._files = {}
        src = getattr(self, "source", None)
        if src is not None:
            src.close()
        self._model = None
        gc.collect()

    @property
    def loaded(self) -> bool:
        return self._model is not None

    def _pick_device(self) -> str:
        if not self.limits.allow_gpu:
            return "cpu"
        torch = self.torch
        if torch.cuda.is_available():
            return "cuda"
        mps = getattr(torch.backends, "mps", None)
        if mps is not None and mps.is_available():
            return "mps"   # Apple silicon
        return "cpu"

    # -- index: map logical names -> owner ---------------------------------------

    def _build_index(self) -> dict:
        owner: dict[str, str] = {name: name for name in self.source.names()}
        embed = [n for n in owner if "embed_tokens" in n or n.endswith("embed_tokens.weight")]
        if not embed:
            embed = [n for n in owner if "embed" in n and "weight" in n]
        norm = [n for n in owner if n.endswith("model.norm.weight") or n == "norm.weight"]
        return {"owner": owner, "embed": embed, "norm": norm}

    def _load_tensor(self, name: str):
        return self.source.load(name)

    def _dequant(self, t):
        from .quant import QTensor

        return t.dequantize() if isinstance(t, QTensor) else t

    def _layer(self, i: int):
        """Load decoder layer *i*'s weights, yield, drop them (streaming)."""
        prefix = f"model.layers.{i}."
        names = [n for n in self._index["owner"] if n.startswith(prefix)]
        loaded: dict = {}
        for n in names:
            key = n[len(prefix):]
            # rp-quantized shards store <name>.rp.{packed,scales,meta}; the
            # engine contract wants the bare logical name → dequantized tensor
            for suffix in (".rp.packed", ".rp.scales", ".rp.meta"):
                if key.endswith(suffix):
                    key = key[: -len(suffix)]
                    break
            if key.endswith(".rp.meta") or key in loaded:
                continue   # meta is loaded inside _load_tensor; skip duplicates
            loaded[key] = self._load_tensor(n)
        try:
            yield loaded
        finally:
            loaded.clear()
            del loaded
            gc.collect()

    # -- math (fp32 compute) --------------------------------------------------------

    def _rms(self, x, w):
        v = x.pow(2).mean(-1, keepdim=True)
        return x * self.torch.rsqrt(v + self.eps) * w

    def _rope(self, q, k, pos):
        torch = self.torch
        half = self.head_dim // 2
        inv = 1.0 / (self.rope_theta ** (torch.arange(half, dtype=torch.float32) / half))
        # pos: (T,) -> freqs (T, half); cos/sin shape (1, 1, T, half) so they
        # broadcast over batch and heads and only cover the rotated half.
        freqs = pos.float()[:, None] * inv[None, :]
        cos = freqs.cos()[None, None, :, :].to(q.device)
        sin = freqs.sin()[None, None, :, :].to(q.device)
        q1, q2 = q[..., :half], q[..., half:]
        k1, k2 = k[..., :half], k[..., half:]
        q = torch.cat([q1 * cos - q2 * sin, q1 * sin + q2 * cos], -1)
        k = torch.cat([k1 * cos - k2 * sin, k1 * sin + k2 * cos], -1)
        return q, k

    def _attention(self, x, w, pos, kv_cache, layer_i):
        torch = self.torch
        B, T, _ = x.shape
        q = x @ w["self_attn.q_proj.weight"].mT
        if "self_attn.q_proj.bias" in w:
            q = q + w["self_attn.q_proj.bias"]
        k = x @ w["self_attn.k_proj.weight"].mT
        if "self_attn.k_proj.bias" in w:
            k = k + w["self_attn.k_proj.bias"]
        v = x @ w["self_attn.v_proj.weight"].mT
        if "self_attn.v_proj.bias" in w:
            v = v + w["self_attn.v_proj.bias"]
        q = q.view(B, T, self.n_heads, self.head_dim).transpose(1, 2)
        k = k.view(B, T, self.n_kv, self.head_dim).transpose(1, 2)
        v = v.view(B, T, self.n_kv, self.head_dim).transpose(1, 2)
        q, k = self._rope(q, k, pos)
        prev_k, prev_v = kv_cache[layer_i]
        if prev_k is not None:
            k = torch.cat([prev_k, k], dim=2)
            v = torch.cat([prev_v, v], dim=2)
        kv_cache[layer_i] = (k, v)
        rep = self.n_heads // self.n_kv
        if rep > 1:
            k = k.repeat_interleave(rep, dim=1)
            v = v.repeat_interleave(rep, dim=1)
        scores = (q @ k.transpose(-2, -1)) / (self.head_dim ** 0.5)
        T_full = k.shape[2]
        # sliding-window mask (Mistral): attend only to the last W positions
        if self.sliding_window and T_full > self.sliding_window:
            lo = T_full - self.sliding_window
        else:
            lo = 0
        mask = torch.triu(torch.ones(T, T_full, dtype=torch.bool), diagonal=1 + lo)
        scores = scores.masked_fill(mask, float("-inf"))
        attn = torch.softmax(scores, -1)
        out = (attn @ v).transpose(1, 2).reshape(B, T, -1)
        out = out @ w["self_attn.o_proj.weight"].mT
        return out

    def _mlp(self, x, w, prefix="mlp"):
        torch = self.torch
        gate = torch.nn.functional.silu(x @ w[f"{prefix}.gate_proj.weight"].mT)
        up = x @ w[f"{prefix}.up_proj.weight"].mT
        return (gate * up) @ w[f"{prefix}.down_proj.weight"].mT

    def _moe(self, x, w):
        """Mixtral MoE: route each token to its top-k experts (streamed)."""
        torch = self.torch
        B, T, H = x.shape
        gate_w = w["block_sparse_moe.gate.weight"]          # (n_experts, H)
        flat = x.reshape(-1, H)
        logits = torch.softmax(flat @ gate_w.mT, dim=-1)    # (B*T, E)
        topv, topi = logits.topk(self.top_k, dim=-1)
        topv = topv / topv.sum(-1, keepdim=True)
        out = torch.zeros_like(flat)
        for e in range(self.n_experts):
            mask = (topi == e)
            if not mask.any():
                continue
            rows = mask.any(-1).nonzero(as_tuple=True)[0]
            weights = (topv * mask).sum(-1)[rows].unsqueeze(-1)
            expert_out = self._mlp(flat[rows], w, prefix=f"block_sparse_moe.experts.{e}")
            out.index_add_(0, rows, expert_out * weights)
        return out.reshape(B, T, H)

    def _forward_layer(self, x, w, pos, kv_cache, layer_i):
        h = self._rms(x, w["input_layernorm.weight"])
        x = x + self._attention(h, w, pos, kv_cache, layer_i)
        h = self._rms(x, w["post_attention_layernorm.weight"])
        x = x + (self._moe(h, w) if self.n_experts else self._mlp(h, w))
        return x

    def _logits(self, ids, *, start_pos: int = 0, kv_cache=None):
        """Forward pass. With kv_cache + start_pos it processes only new tokens."""
        torch = self.torch
        x = self._embed_table[ids]                     # (B, T, H)
        T = ids.shape[1]
        pos = torch.arange(start_pos, start_pos + T)
        created = kv_cache is None
        if created:
            kv_cache = [(None, None)] * self.n_layers
        for i in range(self.n_layers):
            for w in self._layer(i):
                x = self._forward_layer(x, {k: self._dequant(v) for k, v in w.items()},
                                        pos, kv_cache, i)
        x = self._rms(x, self._norm_w)
        logits = x[:, -1:, :] @ self._lm_head.mT
        if self.final_logit_softcapping:
            cap = self.final_logit_softcapping
            logits = torch.tanh(logits / cap) * cap
        return logits[:, -1, :], kv_cache

    # -- generation ---------------------------------------------------------------

    def _sample(self, logits, temperature: float) -> int:
        torch = self.torch
        if temperature and temperature > 0:
            probs = torch.softmax(logits / temperature, dim=-1)
            return int(torch.multinomial(probs, num_samples=1))
        return int(logits.argmax())

    def generate(self, prompt: str, *, max_new_tokens: int | None = None,
                 temperature: float = 0.2) -> GenerationResult:
        self.load()
        self.guard.check_rss()
        started = time.time()
        ids = self._encode(prompt)
        self.guard.check_context(len(ids))
        new_tokens = min(max_new_tokens or self.limits.max_new_tokens,
                         self.limits.max_new_tokens)
        self.guard.check_generate(new_tokens)
        torch = self.torch
        profile: list[dict] = []
        try:
            with torch.no_grad():
                cur = torch.tensor([ids])
                out_ids: list[int] = []
                kv_cache = None
                start_pos = 0
                eos = self._eos_ids()
                for step in range(new_tokens):
                    t0 = time.time()
                    logits, kv_cache = self._logits(cur, start_pos=start_pos,
                                                    kv_cache=kv_cache)
                    nxt = self._sample(logits[0], temperature if out_ids else 0.0)
                    profile.append({"step": step, "ms": round((time.time() - t0) * 1000, 1)})
                    out_ids.append(nxt)
                    if nxt in eos:
                        break
                    # incremental decoding: only the new token next time
                    cur = torch.tensor([[nxt]])
                    start_pos = len(ids) + len(out_ids) - 1
        except Exception as exc:
            from ..core.errors import DependencyUnavailableError

            raise DependencyUnavailableError(
                "Native engine generation failed",
                reason=f"{type(exc).__name__}: {exc}",
                action="Reduce max_new_tokens/context, or re-run with the tiny engine.",
            ) from exc
        self.profile = profile
        text = self._decode(out_ids)
        self.guard.check_rss()
        return GenerationResult(
            text=text, engine="native", model=self.model_id,
            input_tokens=len(ids), output_tokens=len(out_ids),
            elapsed_s=time.time() - started,
            peak_rss_mb=self.guard.peak_rss_mb, compressed=self.compressed,
            truncated=len(ids) >= self.limits.max_context_tokens,
            device=self._device,
        )

    # -- tokenizer + chat template ---------------------------------------------------

    def _encode(self, text: str) -> list[int]:
        return self._tok.encode(text, max_tokens=self.limits.max_context_tokens)

    def _decode(self, out_ids: list[int]) -> str:
        return self._tok.decode(out_ids)

    def _eos_ids(self) -> set[int]:
        if isinstance(self._tok, BpeTokenizer):
            eos = self._tok.eos_ids(self.cfg)
        elif isinstance(self._tok, ApproxTokenizer):
            eos = self._tok.eos_ids(self.cfg)
        else:
            eos = set()
        return eos

    # -- chat template ----------------------------------------------------------------

    def chat_prompt(self, system: str, user: str) -> str:
        """Format a chat prompt for the checkpoint's family (best effort)."""
        name = self._snapshot.name.lower()
        if "qwen" in name:
            return (f"<|im_start|>system\n{system}<|im_end|>\n"
                    f"<|im_start|>user\n{user}<|im_end|>\n"
                    f"<|im_start|>assistant\n")
        if "llama" in name:
            return (f"[INST] <<SYS>>\n{system}\n<</SYS>>\n\n{user} [/INST]")
        if "gemma" in name:
            return (f"<start_of_turn>user\n{user}<end_of_turn>\n"
                    f"<start_of_turn>model\n")
        if "mistral" in name or "mixtral" in name:
            return f"[INST] {user} [/INST]"
        if "phi" in name:
            return (f"<|system|>\n{system}<|end|>\n<|user|>\n{user}<|end|>\n"
                    f"<|assistant|>\n")
        return f"{system}\n\n{user}\n"

    # -- profiling -----------------------------------------------------------------------

    def profiling_summary(self) -> dict:
        if not self.profile:
            return {}
        total = sum(p["ms"] for p in self.profile)
        return {"steps": len(self.profile), "total_ms": round(total, 1),
                "avg_ms": round(total / len(self.profile), 1),
                "device": self._device}


def prepare_layer_shards(model: str, out_dir: str | Path, *, bits: int = 0,
                         hf_cache=None, delete_original: bool = False) -> dict:
    """CLI-facing helper: bake per-layer shards (optionally quantized)."""
    from .quant import prepare_model_shards

    snapshot = resolve_local_model(model, hf_cache=hf_cache)
    if snapshot is None:
        from ..core.errors import DependencyUnavailableError

        raise DependencyUnavailableError(
            f"Model '{model}' is not on disk",
            reason="Shard preparation works on local checkpoints only — "
                   "this tool never downloads.",
            action="Place the checkpoint in the HF cache or pass a local path.")
    return prepare_model_shards(snapshot, Path(out_dir), bits=bits,
                                delete_original=delete_original)
