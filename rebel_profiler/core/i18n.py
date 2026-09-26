"""Localization (ROADMAP Phase 12): Urdu + English operator messages.

The law this module obeys: the machine contracts stay language-neutral.
JSON / JSONL / CSV output, exit codes, schema versions and keys are byte-
identical in every language — only the HUMAN-mode strings localize.

Selection is environment-driven and fail-safe:

    RP_LANG=ur      → Urdu operator strings
    anything else   → English (the default, and the fallback for a
                      key a language has not translated yet)

RTL note: Urdu strings render right-to-left inside the terminal per the
Unicode bidi algorithm — frames and tables stay LTR structural glyphs, so
no manual reversal happens here and none should ever be added.

Default (English) output stays byte-identical to pre-localization releases:
every original fragment remains findable in the ``en`` table below.
"""

from __future__ import annotations

import os

_URDU_CODES = {"ur", "urdu", "ur_pk"}

_LANG = "ur" if os.environ.get("RP_LANG", "").strip().lower() in _URDU_CODES else "en"


def lang() -> str:
    """The active operator language (``en`` or ``ur``)."""
    return _LANG


STRINGS: dict[str, dict[str, str]] = {
    "en": {
        # structured error frame (cli/theme.py)
        "theme.reason": "Reason:",
        "theme.action": "Action:",
        "theme.exit_footer": "exit {code} ∴ every denial is audited",
        # shared verdict words
        "verdict.ok": "ok",
        "verdict.warn": "warn",
        "verdict.denied": "denied",
    },
    "ur": {
        "theme.reason": "وجہ:",
        "theme.action": "ایکشن:",
        "theme.exit_footer": "ایگزٹ {code} ∴ ہر انکار آڈٹ میں درج ہے",
        "verdict.ok": "ٹھیک",
        "verdict.warn": "خطرہ",
        "verdict.denied": "مسترد",
    },
}


def t(key: str, **kwargs: object) -> str:
    """Translate ``key`` in the active language, English as the fallback.

    A key no language declares comes back as the key itself — a missing
    translation is a visible key name, never an empty string.
    """
    entry = STRINGS.get(_LANG, {}).get(key)
    if entry is None:
        entry = STRINGS["en"].get(key)
    if entry is None:
        return key
    return entry.format(**kwargs) if kwargs else entry
