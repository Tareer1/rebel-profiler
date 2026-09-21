"""GGUF engine — run single-file quantized checkpoints through llama.cpp.

GGUF is the format most operators actually have on disk: one file per model
(llama.cpp / Ollama / LM Studio exports), already quantized by the publisher.
It needs no Hugging Face cache layout, no layer split, and no GPU.

This is the tool's third local engine and it obeys exactly the same law as the
other two:

* **local-first** — the engine never downloads. A checkpoint must already be
  on disk (a path, or a file discovered under the usual roots). Nothing here
  reaches the network.
* **budget-guarded** — :class:`~rebel_profiler.llm.budget.BudgetGuard` wraps
  construction, load and every call: tier model-size caps, the RSS ceiling and
  the context/new-token caps all apply. A Q4/Q5/Q8 GGUF counts as *compressed*
  (it genuinely is), so ``require_compression`` tiers accept it.
* **honest fallback** — ``llama-cpp-python`` is optional. Missing it produces a
  structured :class:`DependencyUnavailableError` with the exact install
  command, never a stack trace and never a silent substitution.

Quant tags are read from the filename (``Q4_K_S``, ``Q5_K_M``, ``Q8_0``,
``IQ3_XS``, ``F16``, …) so the engine can report the checkpoint's real weight
format and size class to the budget guard.
"""

from __future__ import annotations

import gc
import mmap
import os
import re
import struct
import time
from pathlib import Path

from .budget import BudgetGuard, Limits, ModelBudgetError
from .inference import GenerationResult

# ---------------------------------------------------------------------------
# quant / size parsing

# Trailing quantization tag on a GGUF filename stem:
#   -Q4_K_S  _Q8_0  .f16  -IQ3_XS  -Q5_K_M
_QUANT_RE = re.compile(
    r"(?i)[-_.](?:iq\d+_[a-z0-9_]+|q\d+_[a-z0-9_]+|q\d+|f16|f32|bf16)$"
)

# Parameter count in the model name: 8B, 1.5B, 70B (not followed by a word char)
_PARAM_RE = re.compile(r"(?i)(\d+(?:\.\d+)?)\s*b(?![a-z0-9_])")


def strip_quant(name: str) -> str:
    """Drop a trailing quantization tag from a GGUF name or stem."""
    return _QUANT_RE.sub("", str(name))


def parse_quant(path: str | Path) -> tuple[str, int, bool]:
    """Return ``(tag, bits_per_weight, is_compressed)`` for a GGUF file.

    Unknown/absent tags are treated as f16-class uncompressed, which is the
    conservative choice: a tier that demands compression will refuse it rather
    than under-report the memory it needs.
    """
    stem = Path(path).stem
    match = _QUANT_RE.search(stem)
    if not match:
        return ("unknown", 16, False)
    tag = match.group(0).lstrip("-._").upper()
    if tag in {"F32"}:
        return (tag, 32, False)
    if tag in {"F16", "BF16"}:
        return (tag, 16, False)
    core = re.match(r"(IQ|Q)(\d+)", tag)
    if core:
        bits = int(core.group(2))
        return (tag, bits, bits < 16)
    return (tag, 16, False)


def gguf_params_b(path: str | Path) -> float:
    """Approximate parameter count (billions) for a GGUF checkpoint.

    Prefers the number in the filename (``…-8B-Q4_K_S.gguf`` → 8.0). When the
    name carries no size, it estimates from the file size and the quant's bits
    per weight — good enough for a budget decision, never used as a claim.
    """
    stem = strip_quant(Path(path).stem)
    match = _PARAM_RE.search(stem)
    if match:
        return float(match.group(1))
    _, bits, _ = parse_quant(path)
    try:
        size = Path(path).stat().st_size
    except OSError:
        return 32.0
    # bytes ≈ params × bits/8  →  params ≈ bytes × 8 / bits
    return round(size * 8 / (max(bits, 1) * 1e9), 1)


# ---------------------------------------------------------------------------
# integrity: a GGUF that cannot hold its own tensors is not a checkpoint

# ggml tensor type -> (bytes per block, elements per block). The header states
# only shapes and a type id, so the table is what turns a declaration into a
# byte count - and a byte count is what says whether the file is long enough
# to hold what it declares.
_GGML_TYPE_BLOCK: dict[int, tuple[int, int]] = {
    0: (4, 1), 1: (2, 1), 2: (18, 32), 3: (20, 32), 6: (22, 32), 7: (24, 32),
    8: (34, 32), 9: (36, 32), 10: (84, 256), 11: (110, 256), 12: (144, 256),
    13: (176, 256), 14: (210, 256), 15: (292, 256), 16: (66, 256),
    17: (74, 256), 18: (98, 256), 19: (50, 256), 20: (18, 32), 21: (110, 256),
    22: (82, 256), 23: (136, 256), 24: (1, 1), 25: (2, 1), 26: (4, 1),
    27: (8, 1), 28: (8, 1), 29: (56, 256), 30: (2, 1),
}

# GGUF metadata value-type ids (the on-disk enum ).
_GGUF_STRING, _GGUF_ARRAY = 8, 9
_GGUF_SCALAR_SIZE = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1,
                     10: 8, 11: 8, 12: 8}


def _gguf_read_string(buf, pos: int) -> tuple[str, int]:
    (length,) = struct.unpack_from("<Q", buf, pos)
    pos += 8
    if length > len(buf) - pos:
        raise ValueError("string runs past the end of the file")
    return bytes(buf[pos:pos + length]).decode("utf-8", "replace"), pos + length


def _gguf_skip_value(buf, pos: int, vtype: int) -> int:
    size = _GGUF_SCALAR_SIZE.get(vtype)
    if size is not None:
        return pos + size
    if vtype == _GGUF_STRING:
        _, pos = _gguf_read_string(buf, pos)
        return pos
    if vtype == _GGUF_ARRAY:
        (elem,) = struct.unpack_from("<I", buf, pos)
        (count,) = struct.unpack_from("<Q", buf, pos + 4)
        pos += 12
        elem_size = _GGUF_SCALAR_SIZE.get(elem)
        if elem_size is not None:
            return pos + elem_size * count
        if elem == _GGUF_STRING:      # tokenizer vocab/merges: the big ones
            for _ in range(count):
                _, pos = _gguf_read_string(buf, pos)
            return pos
        raise ValueError("nested metadata array")
    raise ValueError(f"unknown metadata type {vtype}")


def gguf_integrity(path: str | Path) -> dict:
    """Does the file actually hold the tensors its header declares?

    A truncated download keeps a perfectly valid header - truncation happens
    at the end - so the file lists fine and then dies at load, with the one
    useful sentence ("model is corrupted or incomplete") printed by the C
    library to stderr, where llama-cpp-python never puts it. Reading the
    header here lets the tool say it itself, before anything is promised.

    Returns ``{"ok": True, "tensors": n}``, ``{"ok": False, "reason": ...}``
    for a file that cannot hold its own data, or ``{"ok": None, ...}`` when
    the format is beyond this reader - an unverified file is never called
    broken, because a wrong accusation is worse than no verdict.
    """
    path = Path(path)
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            if size == 0:
                return {"ok": False, "reason": "empty file"}
            with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as buf:
                return _gguf_check_header(buf, size)
    except (OSError, ValueError) as exc:
        return {"ok": None, "reason": f"unreadable: {exc}"}


def _gguf_check_header(buf, size: int) -> dict:
    try:
        if bytes(buf[:4]) != b"GGUF":
            return {"ok": None, "reason": "not a GGUF file"}
        tensor_count, kv_count = struct.unpack_from("<QQ", buf, 8)
        pos = 24
        alignment = 32                      # general.alignment default
        for _ in range(kv_count):
            key, pos = _gguf_read_string(buf, pos)
            (vtype,) = struct.unpack_from("<I", buf, pos)
            pos += 4
            if key == "general.alignment" and vtype == 4:   # u32
                (alignment,) = struct.unpack_from("<I", buf, pos)
            pos = _gguf_skip_value(buf, pos, vtype)
        tensors: list[tuple[tuple[int, ...], int, int]] = []
        for _ in range(tensor_count):
            _, pos = _gguf_read_string(buf, pos)
            (n_dims,) = struct.unpack_from("<I", buf, pos)
            pos += 4
            dims = struct.unpack_from(f"<{n_dims}Q", buf, pos)
            pos += 8 * n_dims
            ttype, offset = struct.unpack_from("<IQ", buf, pos)
            pos += 12
            tensors.append((dims, ttype, offset))
    except (struct.error, ValueError, IndexError):
        return {"ok": None, "reason": "header beyond this reader"}

    if alignment <= 0:
        return {"ok": None, "reason": f"implausible alignment {alignment}"}
    data_start = -(-pos // alignment) * alignment
    required = data_start
    for dims, ttype, offset in tensors:
        block = _GGML_TYPE_BLOCK.get(ttype)
        if block is None:
            return {"ok": None, "reason": f"unknown tensor type {ttype}"}
        nbytes, per_block = block
        elements = 1
        for dim in dims:
            elements *= dim
        blocks = -(-elements // per_block)          # ceil
        required = max(required, data_start + offset + blocks * nbytes)
    if size < required:
        return {"ok": False, "reason": (
            f"truncated GGUF: needs {required} bytes, file is {size} "
            f"({required - size} bytes missing - an incomplete download)")}
    return {"ok": True, "tensors": len(tensors)}


# ---------------------------------------------------------------------------
# discovery: use what is already on disk, bounded, no network

MAX_SCAN_DEPTH = 4
MAX_SCAN_FILES = 200


def _configured_gguf_dirs() -> list[Path]:
    """``[llm] gguf_dirs`` from the resolved config layers, as paths.

    ``RP_LLM__GGUF_DIRS`` is the *live* pin for one shell; this is the
    *durable* one, so a model library registered in
    ``~/.config/rebel-profiler/config.toml`` (or any other config layer)
    is found from any working directory, not only from the tree the
    checkpoint happens to sit under. A malformed config never breaks
    discovery: it simply contributes no roots.
    """
    try:
        from ..core.config import get, load_config

        value = get(load_config(), "llm.gguf_dirs")
    except Exception:
        return []
    if isinstance(value, str):
        parts: list[str] = value.split(os.pathsep)
    elif isinstance(value, (list, tuple)):
        parts = [str(v) for v in value]
    else:
        return []
    return [Path(p).expanduser() for p in parts if str(p).strip()]


def default_gguf_roots() -> list[Path]:
    """Directories searched for local GGUF checkpoints, most specific first.

    ``RP_LLM__GGUF_DIRS`` (os.pathsep separated) always wins so an operator
    can pin an arbitrary model library location; ``[llm] gguf_dirs`` in any
    config layer is the durable equivalent of the same key.
    """
    roots: list[Path] = []
    for part in (os.environ.get("RP_LLM__GGUF_DIRS") or "").split(os.pathsep):
        part = part.strip()
        if part:
            roots.append(Path(part).expanduser())
    roots.extend(_configured_gguf_dirs())
    cwd = Path.cwd()
    roots.append(cwd)
    for rel in ("models", "gguf", "weights", "dphn"):
        roots.append(cwd / rel)
    # The project's own tree, checked from the package location up: a model
    # library checked out next to the source (a repo-local ``dphn/``) must be
    # discoverable even when the CLI is invoked from a different cwd.
    for base in (Path(__file__).resolve().parent,):
        for _ in range(3):
            base = base.parent
            for rel in ("models", "gguf", "weights", "dphn"):
                roots.append(base / rel)
    home = Path.home()
    for rel in (".cache/llama.cpp", "models", ".lmstudio/models", ".ollama/models"):
        roots.append(home / rel)

    seen: set[str] = set()
    unique: list[Path] = []
    for root in roots:
        try:
            key = str(root.resolve())
        except OSError:
            continue
        if key in seen:
            continue
        seen.add(key)
        if root.is_dir():
            unique.append(root)
    return unique


def _walk_gguf(root: Path, *, max_depth: int = MAX_SCAN_DEPTH,
               cap: int = MAX_SCAN_FILES) -> list[Path]:
    """Bounded directory walk for ``*.gguf`` files (no symlink following)."""
    found: list[Path] = []
    stack: list[tuple[Path, int]] = [(root, 0)]
    scanned = 0
    while stack and len(found) < cap and scanned < cap * 20:
        directory, depth = stack.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError:
            continue
        for entry in entries:
            scanned += 1
            name = entry.name
            if name.startswith("."):
                continue
            try:
                if entry.is_file() and name.lower().endswith(".gguf"):
                    found.append(Path(entry.path))
                elif entry.is_dir() and depth < max_depth:
                    stack.append((Path(entry.path), depth + 1))
            except OSError:
                continue
    return found


def discover_local_gguf(*, roots: list[str | Path] | None = None,
                        max_depth: int = MAX_SCAN_DEPTH) -> list[dict]:
    """List GGUF checkpoints already on this machine (bounded, offline)."""
    search = [Path(r).expanduser() for r in roots] if roots else default_gguf_roots()
    rows: list[dict] = []
    seen: set[str] = set()
    for root in search:
        if not root.is_dir():
            continue
        for path in _walk_gguf(root, max_depth=max_depth):
            try:
                key = str(path.resolve())
            except OSError:
                continue
            if key in seen:
                continue
            seen.add(key)
            tag, bits, compressed = parse_quant(path)
            try:
                size_bytes = path.stat().st_size
            except OSError:
                size_bytes = 0
            integrity = gguf_integrity(path)
            rows.append({
                "path": str(path),
                "name": path.name,
                "quant": tag,
                "quant_bits": bits,
                "compressed": compressed,
                "params_b": gguf_params_b(path),
                "size_gb": round(size_bytes / (1024 ** 3), 2),
                "engine": "gguf",
                "integrity_ok": integrity.get("ok"),
                "integrity_note": integrity.get("reason", ""),
            })
    rows.sort(key=lambda r: (r["name"].lower(), r["path"]))
    return rows


def _norm(text: str) -> str:
    """Lowercase alphanumeric key for tolerant name matching."""
    return re.sub(r"[^a-z0-9]", "", str(text).lower())


def resolve_local_gguf(model: str | Path, *, roots: list[str | Path] | None = None,
                       max_depth: int = MAX_SCAN_DEPTH) -> Path | None:
    """Find the on-disk GGUF that *model* names — or ``None``.

    Accepts a direct path (``…/model.gguf``), a directory holding ggufs, or a
    model id/name (``dphn/Dolphin3.0-Llama3.1-8B-GGUF``) matched against the
    discovered filenames with the quant tag and punctuation removed. Matching
    is deliberately conservative so an unrelated local model is never picked
    up for an explicit request.
    """
    requested = Path(str(model)).expanduser()
    if requested.is_file() and requested.suffix.lower() == ".gguf":
        return requested
    if requested.is_dir():
        hits = sorted(requested.glob("*.gguf"))
        if hits:
            return hits[0]
    key = _norm(strip_quant(requested.name))
    if len(key) < 4:
        return None
    for row in discover_local_gguf(roots=roots, max_depth=max_depth):
        cand = Path(row["path"])
        cand_key = _norm(strip_quant(cand.stem))
        if len(cand_key) < 4:
            continue
        if key in cand_key or cand_key in key:
            return cand
    return None


# ---------------------------------------------------------------------------
# the engine


def _physical_cpu_count() -> int | None:
    """Physical (not SMT) core count — the thread count llama.cpp wants.

    Counts unique (physical id, core id) pairs from /proc/cpuinfo, which is
    the honest core count on hyper-threaded x86; falls back to the logical
    count when the platform does not expose the split.
    """
    try:
        cores: set[tuple[str, str]] = set()
        phys: str | None = None
        with open("/proc/cpuinfo") as fh:
            for line in fh:
                field, _, value = line.strip().partition(":")
                if field.strip() == "physical id":
                    phys = value.strip()
                elif field.strip() == "core id" and phys is not None:
                    cores.add((phys, value.strip()))
        if cores:
            return len(cores)
    except Exception:
        pass
    try:
        return os.cpu_count()
    except Exception:
        return None


def _require_llama_cpp():
    try:
        import llama_cpp  # noqa: PLC0415 — heavy import, only when needed
    except ImportError as exc:
        from ..core.errors import DependencyUnavailableError

        raise DependencyUnavailableError(
            "The llama-cpp-python package is not installed",
            reason="GGUF checkpoints are executed by llama.cpp; the Python "
                   "binding is an optional dependency.",
            action="pip install llama-cpp-python   (or run "
                   "'rebel-profiler llm setup' for this machine's exact "
                   "install command)",
        ) from exc
    return llama_cpp


class GgufEngine:
    """llama.cpp-backed engine for single-file quantized checkpoints."""

    kind = "gguf"

    def __init__(self, model: str | Path, *, limits: Limits, budget: dict | None = None,
                 n_gpu_layers: int | None = None, n_threads: int | None = None,
                 **_options) -> None:
        _require_llama_cpp()   # structured error up front, not mid-load
        from ..core.errors import DependencyUnavailableError

        self.limits = limits
        self.guard = BudgetGuard(limits)
        self.requested = str(model)
        resolved = resolve_local_gguf(model)
        if resolved is None:
            raise DependencyUnavailableError(
                f"No GGUF checkpoint on disk for '{model}'",
                reason="The GGUF engine is local-only: it never downloads a "
                       "model, and no on-disk file matched this name.",
                action="Pass the path directly (--model /path/to/model.gguf), "
                       "or set RP_LLM__GGUF_DIRS to your model directory.",
            )
        self.path = resolved
        self.model_id = str(resolved)
        tag, bits, compressed = parse_quant(resolved)
        self.quant = tag
        self.quant_bits = bits
        self.compressed = compressed
        self.params_b = gguf_params_b(resolved)
        # llama.cpp dequantizes on the fly: quantized GGUF is CPU-safe, so the
        # budget guard's CUDA requirement does not apply (same rule as native).
        self.guard.check_model(self.params_b, compressed=compressed,
                              cuda_required=False)
        self._n_gpu_layers = n_gpu_layers
        self._n_threads = n_threads
        self._llm = None
        self.last_device = "cpu"
        self.profile: list[dict] = []

    # -- placement ------------------------------------------------------------

    def _gpu_layers(self) -> int:
        """Offload every layer only when the budget allows AND llama.cpp can."""
        if self._n_gpu_layers is not None:
            return int(self._n_gpu_layers)
        if not self.limits.allow_gpu:
            return 0
        try:
            import llama_cpp  # noqa: PLC0415 — optional

            probe = getattr(getattr(llama_cpp, "llama_cpp", None),
                            "llama_supports_gpu_offload", None)
            if probe is not None and probe():
                return -1
        except Exception:
            pass
        return 0

    # -- lifecycle ------------------------------------------------------------

    def load(self) -> None:
        if self._llm is not None:
            return
        self.guard.check_rss()
        llama_cpp = _require_llama_cpp()
        kwargs: dict = {
            "model_path": str(self.path),
            "n_ctx": int(self.limits.max_context_tokens),
            # Physical cores, not logical: llama.cpp saturating both SMT
            # siblings of a core contends for the same FP units and makes
            # prompt prefill *slower* than fewer, well-fed threads. Hyper-
            # threaded CPUs report 2× here; half of it is the honest count.
            "n_threads": int(self._n_threads
                            or _physical_cpu_count() or 4),
            "n_batch": 512,
            "verbose": False,
        }
        gpu_layers = self._gpu_layers()
        if gpu_layers:
            kwargs["n_gpu_layers"] = gpu_layers
        try:
            self._llm = llama_cpp.Llama(**kwargs)
        except Exception as exc:  # structured failure, never a stack-trace dump
            self.unload()
            from ..core.errors import DependencyUnavailableError

            raise DependencyUnavailableError(
                f"llama.cpp could not load '{self.path.name}'",
                reason=f"{type(exc).__name__}: {exc}",
                action="Check the file is a complete GGUF, that the machine "
                       "has RAM for its size class, and that llama-cpp-python "
                       "was built for this platform.",
            ) from exc
        self.last_device = "gpu" if gpu_layers else "cpu"
        try:
            self.guard.check_rss()
        except ModelBudgetError:
            # The ceiling is a *refusal*, not a licence to keep the weights:
            # without this the refused checkpoint stays mapped (about 4GB for
            # an 8B Q4) while the plane moves on to another engine, which
            # breaks the one-engine-at-a-time rule and inflates every RSS
            # reading the fallback then reports.
            self.unload()
            raise

    def unload(self) -> None:
        if self._llm is not None:
            self._llm = None
        gc.collect()

    @property
    def loaded(self) -> bool:
        return self._llm is not None

    # -- generation -----------------------------------------------------------

    def _tokenize(self, text: str) -> list[int]:
        try:
            return list(self._llm.tokenize(text.encode("utf-8"), add_bos=False))
        except Exception:
            return []

    def _fit_input(self, prompt: str) -> tuple[str, bool]:
        """Truncate the prompt to the tier's context ceiling (bounded input).

        Long agent sessions must not lose the *current* turn: front-only
        truncation severed the newest user message right when the context
        filled up, so the model answered a question it never saw. Keep the
        head (system rules) and the tail (the live exchange) instead.
        """
        ids = self._tokenize(prompt)
        if not ids or len(ids) <= self.limits.max_context_tokens:
            return prompt, False
        keep = max(1, self.limits.max_context_tokens - 8)
        head = int(keep * 0.6)
        tail = max(1, keep - head)
        try:
            fitted = b"\n".join((
                self._llm.detokenize(ids[:head]),
                b"...[older turns trimmed to fit the context window]...",
                self._llm.detokenize(ids[-tail:]),
            )).decode("utf-8", "replace")
        except Exception:
            fitted = prompt[: keep * 4]
        return fitted, True

    # ChatML/Llama-3 end-of-turn markers. Without these llama.cpp keeps
    # sampling past the turn boundary — a tool-calling agent then gets a
    # rambling 1024-token reply (and pays for every token) instead of a
    # bounded one. Harmless for plain-completion use: the markers only fire
    # if the model actually emits them.
    STOP_SEQUENCES = ("<|im_end|>", "<|im_start|>", "<|eot_id|>",
                      "<|end_header_id|>", "<|end_of_text|>")

    def generate(self, prompt: str, *, max_new_tokens: int | None = None,
                 temperature: float = 0.2) -> GenerationResult:
        self.load()
        self.guard.check_rss()
        started = time.time()
        fitted, truncated = self._fit_input(prompt)
        ids = self._tokenize(fitted)
        self.guard.check_context(len(ids))
        new_tokens = min(max_new_tokens or self.limits.max_new_tokens,
                         self.limits.max_new_tokens)
        self.guard.check_generate(new_tokens)
        try:
            out = self._llm.create_completion(
                fitted,
                max_tokens=new_tokens,
                temperature=max(0.0, float(temperature)),
                top_p=0.95,
                repeat_penalty=1.05,
                stop=list(self.STOP_SEQUENCES),
                echo=False,
            )
            choice = (out.get("choices") or [{}])[0]
            text = choice.get("text", "")
            usage = out.get("usage") or {}
        except Exception as exc:
            from ..core.errors import DependencyUnavailableError

            raise DependencyUnavailableError(
                "llama.cpp generation failed",
                reason=f"{type(exc).__name__}: {exc}",
                action="Reduce max_new_tokens/context, or re-run with the "
                       "tiny engine.",
            ) from exc
        elapsed = time.time() - started
        self.profile.append({"step": len(self.profile), "ms": round(elapsed * 1000, 1)})
        self.guard.check_rss()
        return GenerationResult(
            text=text, engine="gguf", model=self.model_id,
            input_tokens=int(usage.get("prompt_tokens", len(ids))),
            output_tokens=int(usage.get("completion_tokens", 0)),
            elapsed_s=elapsed,
            peak_rss_mb=self.guard.peak_rss_mb,
            compressed=self.compressed,
            truncated=truncated,
            device=self.last_device,
        )

    # -- chat template + profiling -------------------------------------------

    def chat_prompt(self, system: str, user: str) -> str:
        """Format a chat prompt for the checkpoint family (best effort)."""
        name = self.path.name.lower()
        # Dolphin 3.0 (a Llama 3.1 finetune) and Qwen both use ChatML.
        if "dolphin" in name or "qwen" in name:
            return (f"<|im_start|>system\n{system}<|im_end|>\n"
                    f"<|im_start|>user\n{user}<|im_end|>\n"
                    f"<|im_start|>assistant\n")
        if "llama" in name:
            return (f"<|start_header_id|>system<|end_header_id|>\n\n{system}"
                    f"<|eot_id|>\n<|start_header_id|>user<|end_header_id|>\n\n"
                    f"{user}<|eot_id|>\n<|start_header_id|>assistant"
                    f"<|end_header_id|>\n\n")
        if "gemma" in name:
            return (f"<start_of_turn>user\n{user}<end_of_turn>\n"
                    f"<start_of_turn>model\n")
        if "mistral" in name or "mixtral" in name:
            return f"[INST] {user} [/INST]"
        if "phi" in name:
            return (f"<|system|>\n{system}<|end|>\n<|user|>\n{user}<|end|>\n"
                    f"<|assistant|>\n")
        return f"{system}\n\n{user}\n"

    def profiling_summary(self) -> dict:
        if not self.profile:
            return {}
        total = sum(p["ms"] for p in self.profile)
        return {"steps": len(self.profile), "total_ms": round(total, 1),
                "avg_ms": round(total / len(self.profile), 1),
                "device": self.last_device, "quant": self.quant}

    def info(self) -> dict:
        return {
            "engine": "gguf",
            "model": self.model_id,
            "path": str(self.path),
            "quant": self.quant,
            "quant_bits": self.quant_bits,
            "compressed": self.compressed,
            "params_b": self.params_b,
            "device": self.last_device,
            "chat_template": self.path.name.lower(),
        }
