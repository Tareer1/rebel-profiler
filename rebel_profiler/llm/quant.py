"""Native block-wise weight quantization — AirLLM's compression feature, no bnb.

AirLLM's 4/8-bit mode quantizes checkpoint weights block-wise (bitsandbytes,
CUDA-only). This module implements the same *feature* natively so it works on
CPU-only and Apple-silicon machines with zero extra installs:

  * **block-wise absmax quantization** — weights are split into contiguous
    blocks (default 128 values, the bitsandbytes block size); each block gets
    one fp16 scale, values are stored as 4-bit (two per byte) or 8-bit ints,
  * :class:`QTensor` — the packed resident form; dequantization happens
    *per use* (one matmul at a time), so resident memory stays near the
    packed size, exactly the AirLLM tradeoff,
  * :func:`prepare_model_shards` — bakes a local checkpoint into per-layer
    shard files (AirLLM ``layer_shards_saving_path``) with quantized tensors
    and a hash manifest; ``delete_original`` reclaims the checkpoint disk
    only after every shard verified.

No network, no bitsandbytes, no CUDA — the same compression feature AirLLM
gates behind a GPU, here on any machine.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

SHARDS_DIRNAME = "rp_shards"
MANIFEST_NAME = "manifest.json"
DEFAULT_BLOCK_SIZE = 128

# bits -> (qmax, values per byte)
_BITS_SPEC = {4: (7, 2), 8: (127, 1)}


def vpb_for(bits: int) -> int:
    return _BITS_SPEC[bits][1]


class QuantError(Exception):
    """Raised for unsupported shapes/dtypes — callers map it to RPError."""


class QTensor:
    """A block-quantized weight matrix kept packed until it is used."""

    __slots__ = ("packed", "scales", "rows", "cols", "bits", "block_size",
                 "padded_cols", "shape")
    def __init__(self, packed, scales, rows: int, cols: int, bits: int,
                 block_size: int) -> None:
        self.packed = packed      # uint8 (rows, ceil(cols/vpb)) — torch
        self.scales = scales      # fp16 (rows, n_blocks) — torch
        self.rows = rows
        self.cols = cols
        self.bits = bits
        self.block_size = block_size
        self.padded_cols = packed.shape[1] * vpb_for(bits) if bits == 4 else packed.shape[1]
        self.shape = (rows, cols)

    def dequantize(self):
        """Materialize the fp32 weight (call-and-drop; never keep resident)."""
        import torch

        qmax, vpb = _BITS_SPEC[self.bits]
        packed = self.packed.to(torch.int32)
        if self.bits == 4:
            low = packed & 0x0F
            high = (packed >> 4) & 0x0F
            q = torch.stack([low, high], dim=-1).reshape(self.rows, -1)
            q = q[:, : self.cols]
        else:
            # 8-bit: packed keeps the block-padded width; slice to cols
            q = packed.reshape(self.rows, -1)[:, : self.cols]
        # map 0..(2qmax) back to -qmax..qmax
        q = q.to(torch.float32) - qmax
        scales = self.scales.to(torch.float32)
        # expand block scales across columns
        reps = (self.cols + self.block_size - 1) // self.block_size
        block_id = torch.arange(self.cols) // self.block_size
        scale_rows = scales[:, :reps]
        scale_full = scale_rows[:, block_id.clamp(max=scale_rows.shape[1] - 1)]
        return q * scale_full

    def nbytes(self) -> int:
        return int(self.packed.numel() + self.scales.numel() * 2)


def quantize_tensor(t, *, bits: int = 4, block_size: int = DEFAULT_BLOCK_SIZE):
    """Quantize a 2D tensor block-wise. Returns a :class:`QTensor`."""
    import torch

    if bits not in _BITS_SPEC:
        raise QuantError(f"unsupported bit width {bits!r} (use 4 or 8)")
    if t.dim() != 2:
        raise QuantError(f"quantization needs a 2D tensor, got shape {tuple(t.shape)}")
    qmax, vpb = _BITS_SPEC[bits]
    t = t.detach().to(torch.float32)
    rows, cols = t.shape
    padded_cols = ((cols + block_size - 1) // block_size) * block_size
    if padded_cols != cols:
        t = torch.nn.functional.pad(t, (0, padded_cols - cols))
    n_blocks = padded_cols // block_size
    blocks = t.reshape(rows, n_blocks, block_size)
    absmax = blocks.abs().amax(dim=-1).clamp(min=1e-12)          # (rows, blocks)
    scales = (absmax / qmax).to(torch.float16)
    q = torch.round(blocks / scales.to(torch.float32).unsqueeze(-1))
    q = q.clamp(-qmax, qmax).to(torch.int32) + qmax              # 0..2*qmax
    if bits == 4:
        q = q.reshape(rows, n_blocks * block_size)[:, :cols]
        # pack pairs: low nibble = even column, high nibble = odd column
        if cols % 2:
            q = torch.nn.functional.pad(q, (0, 1))
        packed = (q[:, 0::2] | (q[:, 1::2] << 4)).to(torch.uint8)
    else:
        # 8-bit: keep the padded width; dequantize slices back to cols
        packed = q.reshape(rows, n_blocks * block_size).to(torch.uint8)
    return QTensor(packed, scales, rows, cols, bits, block_size)


# ---------------------------------------------------------------------------
# safetensors writing (shards are written in safetensors format for reuse)


def write_safetensors(path: Path, tensors: dict) -> None:
    """Write ``{name: torch_tensor}`` as a standard safetensors file."""
    import torch

    header: dict = {}
    blob = bytearray()
    offset = 0
    for name, t in tensors.items():
        t = t.detach().contiguous().cpu()
        if t.dtype == torch.float32:
            dtype, itemsize = "F32", 4
        elif t.dtype == torch.float16:
            dtype, itemsize = "F16", 2
        elif t.dtype == torch.uint8:
            dtype, itemsize = "U8", 1
        elif t.dtype == torch.int64:
            dtype, itemsize = "I64", 8
        else:
            t = t.to(torch.float32)
            dtype, itemsize = "F32", 4
        nbytes = t.numel() * itemsize
        header[name] = {"dtype": dtype, "shape": list(t.shape),
                        "data_offsets": [offset, offset + nbytes]}
        blob += t.view(-1).numpy().tobytes() if t.numel() else b""
        offset += nbytes
    header_bytes = json.dumps(header, separators=(",", ":")).encode()
    padding = (8 - len(header_bytes) % 8) % 8
    header_bytes += b" " * padding
    path.write_bytes(struct.pack("<Q", len(header_bytes)) + header_bytes + bytes(blob))


# ---------------------------------------------------------------------------
# checkpoint → per-layer shards (AirLLM layer_shards_saving_path equivalent)


def _group_tensors(tensor_names: list[str], n_layers: int) -> dict:
    """Group names: shard 0 = embed(+norm+head), shard i+1 = layer i."""
    groups: dict[int, list[str]] = {0: []}
    for name in tensor_names:
        if ".layers." in name:
            try:
                layer_i = int(name.split(".layers.")[1].split(".")[0])
            except (IndexError, ValueError):
                groups.setdefault(0, []).append(name)
                continue
            if 0 <= layer_i < n_layers:
                groups.setdefault(layer_i + 1, []).append(name)
            else:
                groups.setdefault(0, []).append(name)
        else:
            groups.setdefault(0, []).append(name)
    return groups


def prepare_model_shards(snapshot: Path, out_dir: Path, *, bits: int = 0,
                         block_size: int = DEFAULT_BLOCK_SIZE,
                         delete_original: bool = False,
                         progress=None) -> dict:
    """Bake a local checkpoint into per-layer shards (optionally quantized).

    Returns a manifest dict: files, sizes, sha256 per shard, bits, layers.
    ``delete_original`` removes the original ``*.safetensors`` only after
    every shard was written and hashed — the checkpoint is never destroyed
    on a partial run.
    """
    import torch

    snapshot = Path(snapshot)
    cfg = json.loads((snapshot / "config.json").read_text())
    n_layers = int(cfg.get("num_hidden_layers", 0))
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    from .native import SafeTensorFile  # local reader, stdlib-only

    files = sorted(snapshot.glob("*.safetensors"))
    if not files:
        raise QuantError(f"no safetensors weights in {snapshot}")
    index: dict[str, tuple[Path, str]] = {}
    for f in files:
        with SafeTensorFile(f) as sf:  # SafeTensorFile.close releases the mmap
            for name in sf.tensor_names():
                index[name] = (f, name)
    groups = _group_tensors(sorted(index), n_layers)

    manifest = {
        "model": snapshot.name,
        "bits": bits,
        "block_size": block_size,
        "num_hidden_layers": n_layers,
        "shards": [],
        "format": "rp-shards-v1",
    }

    def _emit(shard_i: int, names: list[str]) -> None:
        tensors: dict = {}
        for name in names:
            src_path, _ = index[name]
            with SafeTensorFile(src_path) as sf:
                t = sf.load(name)
            if bits and t.dim() == 2 and "embed" not in name:
                qt = quantize_tensor(t, bits=bits, block_size=block_size)
                tensors[name + ".rp.packed"] = qt.packed
                tensors[name + ".rp.scales"] = qt.scales
                tensors[name + ".rp.meta"] = torch.tensor(
                    [qt.rows, qt.cols, bits, block_size], dtype=torch.int64)
            else:
                tensors[name] = t
        shard_name = f"shard_{shard_i:04d}.safetensors"
        shard_path = out_dir / shard_name
        write_safetensors(shard_path, tensors)
        digest = hashlib.sha256(shard_path.read_bytes()).hexdigest()
        manifest["shards"].append({
            "file": shard_name, "tensors": len(tensors),
            "bytes": shard_path.stat().st_size, "sha256": digest,
        })
        if progress:
            progress(shard_i, len(groups) - 1)

    for shard_i in sorted(groups):
        _emit(shard_i, groups[shard_i])

    (out_dir / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    removed: list[str] = []
    if delete_original:
        verified = all(
            hashlib.sha256((out_dir / s["file"]).read_bytes()).hexdigest() == s["sha256"]
            for s in manifest["shards"])
        if not verified:
            raise QuantError("shard verification failed; originals kept")
        for f in files:
            f.unlink()
            removed.append(f.name)
        (out_dir / "DELETED_ORIGINALS.txt").write_text(
            "original safetensors removed after verified shard bake:\n"
            + "\n".join(removed) + "\n")
        manifest["deleted_originals"] = removed
        (out_dir / MANIFEST_NAME).write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def find_shards_dir(snapshot: Path, explicit: str | Path | None = None) -> Path | None:
    """The shard dir for a snapshot: explicit path > <snapshot>/rp_shards."""
    if explicit:
        p = Path(explicit)
        return p if (p / MANIFEST_NAME).exists() else None
    default = Path(snapshot) / SHARDS_DIRNAME
    return default if (default / MANIFEST_NAME).exists() else None
