"""Bug-bounty program scope documents → case scope entries.

A published bug-bounty program scope *is* the authorization document: the
program states which assets may be tested and under what constraints. This
module turns that document into scope entries the fail-closed scope engine can
enforce, and records the program as the authorization source.

Accepted inputs (auto-detected):

* **HackerOne-style JSON** — ``{"data": [{"attributes": {...}}]}`` or a bare
  list of asset objects. Common key spellings are recognized (``asset_identifier``
  / ``identifier`` / ``target``, ``asset_type`` / ``type``, ``eligible_for_submission``,
  ``instruction`` …).
* **CSV** with a header row (the program page's "Download CSV" export).
* **A plain list** — one target per line; ``#`` starts a comment, ``!target``
  or ``-target`` marks an exclusion, and ``in:`` / ``out:`` prefixes work too.

Two rules keep this honest:

1. **Only host-like assets become scope.** Source-code repositories, hardware,
   mobile-store IDs, smart contracts and ASNs cannot be matched by a host scope
   engine; they are *skipped with a reason* rather than silently mapped to
   something wrong.
2. **Ineligible assets are imported as exclusions.** An asset a program marks
   as not eligible for submission is not worth a finding there, so the
   conservative (fail-closed) choice is to exclude it and say so.
"""

from __future__ import annotations

import csv
import io
import json
import re

_ASSET_KEYS = ("asset_identifier", "identifier", "asset", "target", "host",
               "domain", "url", "value", "endpoint")
_TYPE_KEYS = ("asset_type", "type", "kind", "category")
_ELIGIBLE_KEYS = ("eligible_for_submission", "eligible", "bounty_eligible",
                  "in_scope")
_NOTE_KEYS = ("instruction", "instructions", "notes", "note", "description",
              "max_severity")
_SCOPE_KEYS = ("scope", "status", "excluded", "out_of_scope")

# Asset types that are NOT host-mappable by this engine (skipped, with reason).
_NON_HOST_TYPES = {
    "source_code", "hardware", "other", "downloadable_executables",
    "apple_store_app_id", "google_play_app_id", "other_apk", "smart_contract",
    "ai_model", "asn", "executable", "binary", "document", "file",
}

_HOST_IP_LIKE_TYPES = {"cidr", "ip_address", "ip", "ipv4", "ipv6", "network_range"}

_IP_OR_CIDR = re.compile(r"^[0-9a-f:.]{1,45}(?:/\d{1,3})?$", re.I)

_FALSEY = {"false", "no", "0", "n"}
_TRUTHY = {"true", "yes", "1", "y", "in", "in_scope", "in-scope"}


def _norm_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(key).strip().lower()).strip("_")


def _pick(row: dict, keys: tuple[str, ...]) -> str:
    lowered = {_norm_key(k): v for k, v in row.items()}
    for key in keys:
        if key in lowered and lowered[key] not in (None, ""):
            return str(lowered[key]).strip()
    return ""


def normalize_asset(value: str, asset_type: str = "") -> str | None:
    """Reduce an asset identifier to the host-ish form the scope engine matches.

    Returns ``None`` when the asset cannot be expressed as a scope value.
    """
    raw = (value or "").strip()
    if not raw:
        return None
    kind = _norm_key(asset_type)
    if kind in _NON_HOST_TYPES:
        return None
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    if kind in _HOST_IP_LIKE_TYPES or _IP_OR_CIDR.match(raw):
        return raw.rstrip("/").lower() or None
    # host[:port][/path][?query]  (keep leading wildcard form)
    raw = re.split(r"[?#]", raw)[0]
    raw = raw.split("/", 1)[0]
    if raw.count(":") == 1:            # host:port — IPv6 keeps its colons
        raw = raw.split(":", 1)[0]
    raw = raw.strip().lower().rstrip(".")
    if not raw:
        return None
    if raw.startswith("*."):
        raw = "*." + raw[2:].strip(".")
        return raw if len(raw) > 2 else None
    return raw


def _classify_rows(rows: list[dict], *, default_excluded: bool = False) -> dict:
    includes: list[dict] = []
    excludes: list[dict] = []
    skipped: list[dict] = []

    def _add(bucket: list[dict], value: str, note: str, kind: str) -> None:
        bucket.append({"value": value, "note": note, "asset_type": kind})

    for row in rows:
        if not isinstance(row, dict):
            skipped.append({"asset": str(row)[:120], "reason": "not an object"})
            continue
        identifier = _pick(row, _ASSET_KEYS)
        kind = _pick(row, _TYPE_KEYS)
        note = _pick(row, _NOTE_KEYS)
        eligible_raw = _pick(row, _ELIGIBLE_KEYS).lower()
        scope_raw = _pick(row, _SCOPE_KEYS).lower()

        host = normalize_asset(identifier, kind)
        if host is None:
            reason = ("non-host asset type "
                      f"'{kind or 'unknown'}'") if identifier else "no asset identifier"
            skipped.append({"asset": identifier[:120], "reason": reason})
            continue

        excluded = default_excluded
        if scope_raw in _FALSEY or scope_raw in {"out_of_scope", "out-of-scope", "out"}:
            excluded = True
        elif scope_raw in _TRUTHY:
            excluded = False
        if eligible_raw in _FALSEY:
            # Not eligible for submission ⇒ not worth testing here. Fail closed.
            excluded = True
            note = (note + " | not eligible for submission (program scope)"
                    if note else "not eligible for submission (program scope)")

        _add(excludes if excluded else includes, host, note, kind)
    return {"includes": includes, "excludes": excludes, "skipped": skipped}


def _parse_plain(text: str) -> dict:
    rows: list[dict] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        note = ""
        if "#" in line:
            line, _, note = line.partition("#")
            line, note = line.strip(), note.strip()
        if not line:
            continue
        excluded = False
        lowered = line.lower()
        if line[0] in "!-":
            excluded, line = True, line[1:].strip()
        elif lowered.startswith("out:"):
            excluded, line = True, line[4:].strip()
        elif lowered.startswith("in:"):
            line = line[3:].strip()
        if not line:
            continue
        rows.append({"identifier": line, "instruction": note,
                     "eligible_for_submission": "false" if excluded else "true"})
    return _classify_rows(rows)


def _looks_like_csv(text: str) -> bool:
    first = text.lstrip().splitlines()[0] if text.strip() else ""
    if "," not in first:
        return False
    return bool(re.search(r"(?i)(identifier|asset|target|domain|url|host)", first))


def _parse_json(text: str) -> dict:
    data = json.loads(text)
    if isinstance(data, dict):
        for key in ("in_scope", "inscope", "include", "includes"):
            if isinstance(data.get(key), list):
                return _classify_rows(
                    [d.get("attributes", d) if isinstance(d, dict) else d
                     for d in data[key]])
        rows = data.get("data", data.get("assets", data.get("scopes")))
    else:
        rows = data
    if not isinstance(rows, list):
        raise ValueError("unrecognized scope document shape")
    flat = []
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("attributes"), dict):
            flat.append(row["attributes"])
        else:
            flat.append(row)
    return _classify_rows(flat)


def parse_scope_document(text: str, *, program: str = "") -> dict:
    """Parse a scope document into include/exclude entries + provenance.

    Raises :class:`ValueError` when the document is neither CSV, JSON nor a
    usable plain list — the caller turns that into a structured CLI error.
    """
    if not text or not text.strip():
        raise ValueError("scope document is empty")
    stripped = text.lstrip()
    if stripped[0] in "{[":
        parsed = _parse_json(text)
    elif _looks_like_csv(text):
        reader = csv.DictReader(io.StringIO(text))
        parsed = _classify_rows([dict(r) for r in reader])
    else:
        parsed = _parse_plain(text)

    return {
        "schema_version": 1,
        "program": program,
        "authorization_source": (f"bug-bounty program scope ({program})"
                                 if program else "bug-bounty program scope"),
        **parsed,
        "stats": {
            "includes": len(parsed["includes"]),
            "excludes": len(parsed["excludes"]),
            "skipped": len(parsed["skipped"]),
        },
    }


def parse_scope_file(path, *, program: str = "") -> dict:
    from pathlib import Path

    p = Path(path)
    if not p.exists():
        raise ValueError(f"scope file not found: {p}")
    return parse_scope_document(p.read_text(encoding="utf-8", errors="replace"),
                                program=program)
