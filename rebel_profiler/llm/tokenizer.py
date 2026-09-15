"""Real tokenizer for the native engine — stdlib-only, no transformers.

The native engine previously reported generated token *ids* because no
tokenizer implementation shipped. This module closes that gap honestly:

  * **byte-level BPE** (the encoding family of Qwen2/Qwen3, Llama-3,
    Mistral, GPT-2/…) read straight from ``tokenizer.json`` in the local
    checkpoint — vocab, merges and added/special tokens are honored,
  * **pre-tokenization** uses the GPT-2/tiktoken-family scanner (contractions,
    letter runs, ≤3-digit chunks, punctuation runs, whitespace rules) — the
    pattern family every mainstream checkpoint ships,
  * **decode** also works for SentencePiece-family checkpoints (Gemma,
    Llama-2, Phi-3): id → token → ``▁``→space → ``<0xNN>`` byte fallback,
  * **honest fallback** — when no usable tokenizer.json exists, encode is a
    conservative length estimate (~3.5 chars/token) clearly labeled, decode
    reports the raw ids. Nothing is ever silently invented.

Contract mirrors the engines: :meth:`encode` → ids, :meth:`decode` → text,
eos ids detected from the tokenizer's added tokens and the model config.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

# SentencePiece-style word marker + byte-token pattern
_SP_MARKER = "▁"
_BYTE_TOKEN_RE = re.compile(r"^<0x([0-9A-Fa-f]{2})>$")

# Token contents that mean "stop generating" (plus the config eos_token_id).
_EOS_CONTENTS = frozenset({
    "<|im_end|>", "<|endoftext|>", "<|end_of_text|>", "<|eot_id|>",
    "<|end▁of▁sentence|>", "<eos>", "</s>", "<|eos|>", "<|return|>",
})

_CONTRACTIONS = ("'s", "'t", "'re", "'ve", "'m", "'ll", "'d")


# --- GPT-2 byte↔unicode table ------------------------------------------------

def _bytes_to_unicode() -> dict[int, str]:
    """GPT-2's reversible byte→unicode-char table (printable chars map 1:1)."""
    bs = (list(range(ord("!"), ord("~") + 1))
          + list(range(ord("¡"), ord("¬") + 1))
          + list(range(ord("®"), ord("ÿ") + 1)))
    cs = list(bs)
    n = 0
    for b in range(256):
        if b not in bs:
            bs.append(b)
            cs.append(256 + n)
            n += 1
    return dict(zip(bs, (chr(c) for c in cs)))


_BYTE_ENCODER = _bytes_to_unicode()
_BYTE_DECODER = {v: k for k, v in _BYTE_ENCODER.items()}


def _is_word_char(ch: str) -> bool:
    return ch.isalpha()


def _is_punct_symbol(ch: str) -> bool:
    return not ch.isspace() and not ch.isalnum()


def split_words(text: str) -> list[str]:
    """GPT-2/tiktoken-family pre-tokenization (deterministic scanner).

    Mirrors the regex all mainstream checkpoints ship: contractions first,
    then letter runs (with one optional leading space), digit chunks of ≤3,
    punctuation/symbol runs, and whitespace runs whose final space prefixes
    the next word. Output is a list of *words*; BPE runs per word.
    """
    words: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        # 1. contractions ('s, 't, 're, …) — case-insensitive
        if ch == "'":
            matched = False
            for suffix in _CONTRACTIONS:
                if text[i:i + len(suffix)].lower() == suffix:
                    words.append(text[i:i + len(suffix)])
                    i += len(suffix)
                    matched = True
                    break
            if matched:
                continue
        # 2. whitespace run of 2+; the final space belongs to the next word.
        #    A single space falls through to branch 3 (leading-space rule).
        if ch.isspace():
            j = i
            while j < n and text[j].isspace():
                j += 1
            if j >= n:                       # run to end-of-text
                words.append(text[i:j])
                i = j
                continue
            if j - i >= 2:                   # keep ONE space for the next word
                words.append(text[i:j - 1])
                i = j - 1
                continue
            # exactly one space before a word/punct char → branch 3 handles it
            if _is_word_char(text[j]) or _is_punct_symbol(text[j]):
                pass                          # fall through, do NOT advance
            else:
                words.append(text[i:j])       # space before whitespace-adjacent
                i = j
                continue
        # 3. optional single leading space (word/punct runs only, per the family)
        leading = ""
        start = i
        if ch == " " and i + 1 < n:
            nxt = text[i + 1]
            if _is_word_char(nxt) or _is_punct_symbol(nxt):
                leading = " "
                start = i + 1
        j = start
        if j < n and _is_word_char(text[j]):
            while j < n and _is_word_char(text[j]):
                j += 1
            words.append(leading + text[start:j])
            i = j
            continue
        if j < n and text[j].isdigit():
            # digits in chunks of ≤3 (tiktoken \p{N}{1,3})
            while j < n and text[j].isdigit():
                k = min(j + 3, n)
                words.append(leading + text[j:k])
                leading = ""
                j = k
            i = j
            continue
        if j < n and _is_punct_symbol(text[j]):
            while j < n and _is_punct_symbol(text[j]):
                j += 1
            words.append(leading + text[start:j])
            i = j
            continue
        # 4. fallback: one char (raw byte safety)
        words.append(text[i])
        i += 1
    return words


class TokenizerUnavailable(Exception):
    """No usable tokenizer.json — callers fall back to the honest estimate."""


class BpeTokenizer:
    """Byte-level BPE over a local ``tokenizer.json`` (Qwen/Llama-3/Mistral…)."""

    kind = "bpe"

    def __init__(self, vocab: dict[str, int], merges: list[tuple[str, str]],
                 special_tokens: list[str]) -> None:
        self.vocab = vocab
        self.id_to_token: dict[int, str] = {}
        for token, idx in vocab.items():
            self.id_to_token.setdefault(idx, token)
        self.ranks = {pair: i for i, pair in enumerate(merges)}
        self.special_tokens = sorted(set(special_tokens), key=len, reverse=True)
        self._special_re = (re.compile("|".join(re.escape(t) for t in self.special_tokens))
                            if self.special_tokens else None)
        self._word_cache: dict[str, list[int]] = {}

    # -- construction ----------------------------------------------------------

    @classmethod
    def from_snapshot(cls, snapshot: Path) -> "BpeTokenizer":
        path = Path(snapshot) / "tokenizer.json"
        if not path.exists():
            raise TokenizerUnavailable(f"no tokenizer.json in {snapshot}")
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise TokenizerUnavailable(f"tokenizer.json unreadable: {exc}") from exc
        model = data.get("model") or {}
        vocab = model.get("vocab") or {}
        if not vocab:
            raise TokenizerUnavailable("tokenizer.json has no BPE vocab")
        raw_merges = model.get("merges") or []
        merges: list[tuple[str, str]] = []
        for m in raw_merges:
            if isinstance(m, str):
                parts = m.split(" ")
                if len(parts) == 2:
                    merges.append((parts[0], parts[1]))
            elif isinstance(m, (list, tuple)) and len(m) == 2:
                merges.append((str(m[0]), str(m[1])))
        specials: list[str] = []
        for tok in data.get("added_tokens", []) or []:
            content = tok.get("content", "")
            if content:
                specials.append(content)
        for token in vocab:
            if re.fullmatch(r"<\|[a-zA-Z0-9_.-]+\|>", token):
                specials.append(token)
        return cls(vocab, merges, specials)

    # -- encoding ----------------------------------------------------------------

    def _bpe_ids(self, word: str) -> list[int]:
        cached = self._word_cache.get(word)
        if cached is not None:
            return cached
        # start from single byte-chars (GPT-2 byte-level BPE), then merge
        parts = [_BYTE_ENCODER[b] for b in word.encode("utf-8")]
        while len(parts) > 1:
            best = None
            best_rank = None
            for idx in range(len(parts) - 1):
                rank = self.ranks.get((parts[idx], parts[idx + 1]))
                if rank is not None and (best_rank is None or rank < best_rank):
                    best, best_rank = idx, rank
            if best is None:
                break
            parts[best:best + 2] = [parts[best] + parts[best + 1]]
        ids: list[int] = []
        for p in parts:
            tid = self.vocab.get(p)
            if tid is None:
                raise TokenizerUnavailable(f"vocab has no token for {p!r}")
            ids.append(tid)
        if len(self._word_cache) < 50_000:   # bounded cache
            self._word_cache[word] = ids
        return ids

    def encode(self, text: str, *, max_tokens: int | None = None) -> list[int]:
        ids: list[int] = []
        if self._special_re is None:
            for word in split_words(text):
                ids.extend(self._bpe_ids(word))
        else:
            pos = 0
            for m in self._special_re.finditer(text):
                if m.start() > pos:
                    for word in split_words(text[pos:m.start()]):
                        ids.extend(self._bpe_ids(word))
                tid = self.vocab.get(text[m.start():m.end()])
                if tid is not None:
                    ids.append(tid)
                pos = m.end()
            if pos < len(text):
                for word in split_words(text[pos:]):
                    ids.extend(self._bpe_ids(word))
        if max_tokens is not None:
            ids = ids[:max_tokens]
        return ids

    # -- decoding ---------------------------------------------------------------

    def _token_to_text(self, token: str) -> str:
        m = _BYTE_TOKEN_RE.match(token)
        if m:
            try:
                return bytes([int(m.group(1), 16)]).decode("utf-8", errors="replace")
            except ValueError:
                return token
        raw = bytearray()
        ok = True
        for ch in token:
            b = _BYTE_DECODER.get(ch)
            if b is None:
                ok = False
                break
            raw.append(b)
        if ok:
            return raw.decode("utf-8", errors="replace")
        # SentencePiece-style token (▁ word marker) — decode textually
        text = token.replace(_SP_MARKER, " ")
        return text

    def decode(self, ids: list[int]) -> str:
        out: list[str] = []
        for i in ids:
            token = self.id_to_token.get(int(i))
            if token is None:
                continue
            if token in self.special_tokens:
                out.append(token)
                continue
            out.append(self._token_to_text(token))
        return "".join(out)

    # -- eos ---------------------------------------------------------------------

    def eos_ids(self, cfg: dict | None = None) -> set[int]:
        eos: set[int] = set()
        for token in _EOS_CONTENTS:
            tid = self.vocab.get(token)
            if tid is not None:
                eos.add(tid)
        for token in self.special_tokens:
            if token in _EOS_CONTENTS:
                tid = self.vocab.get(token)
                if tid is not None:
                    eos.add(tid)
        value = (cfg or {}).get("eos_token_id")
        if isinstance(value, int) and value >= 0:
            eos.add(value)
        return eos


class ApproxTokenizer:
    """Honest fallback: bounded length estimate, decode reports raw ids.

    Used when a checkpoint ships no usable tokenizer.json (rare: raw
    ``tokenizer.model``-only snapshots). Encode is a conservative estimate so
    the budget guard still bounds context; decode is clearly labeled.
    """

    kind = "approx"

    def encode(self, text: str, *, max_tokens: int | None = None) -> list[int]:
        approx = max(1, int(len(text) / 3.5) + 8)
        return list(range(min(approx, max_tokens or approx)))

    def decode(self, ids: list[int]) -> str:
        return (f"[approx tokenizer — generated {len(ids)} token ids: "
                f"{ids[:16]}…]")

    def eos_ids(self, cfg: dict | None = None) -> set[int]:
        value = (cfg or {}).get("eos_token_id")
        return {value} if isinstance(value, int) and value >= 0 else set()


def load_tokenizer(snapshot: Path) -> BpeTokenizer | ApproxTokenizer:
    """Load the best tokenizer available for a snapshot — never raises."""
    try:
        return BpeTokenizer.from_snapshot(snapshot)
    except TokenizerUnavailable:
        return ApproxTokenizer()
