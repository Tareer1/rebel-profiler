"""Localization (ROADMAP Phase 12): Hinglish + Urdu + English operator strings.

The law this module obeys: the machine contracts stay language-neutral.
JSON / JSONL / CSV output, exit codes, schema versions and keys are byte-
identical in every language — only the HUMAN-mode strings localize.

Selection is environment-driven and fail-safe:

    RP_LANG=hi-ur   → Hinglish (Roman-Urdu/Hindi: Latin script, Devanagari-free)
    RP_LANG=ur      → Urdu (Perso-Arabic script)
    anything else   → English (the default, and the fallback for a
                      key a language has not translated yet)

RTL note: Urdu strings render right-to-left inside the terminal per the
Unicode bidi algorithm — frames and tables stay LTR structural glyphs, so
no manual reversal happens here and none should ever be added. Hinglish is
plain Latin script, so it is the safe choice for terminals with no RTL
shaping (and what most operators actually type).

Default (English) output stays byte-identical to pre-localization releases:
every original fragment remains findable in the ``en`` table below.
"""

from __future__ import annotations

import os

_HINGLISH_CODES = {"hi-ur", "hinglish", "hi", "roman-urdu"}
_URDU_CODES = {"ur", "urdu", "ur_pk"}

_RAW_LANG = os.environ.get("RP_LANG", "").strip().lower()
if _RAW_LANG in _HINGLISH_CODES:
    _LANG = "hi-ur"
elif _RAW_LANG in _URDU_CODES:
    _LANG = "ur"
else:
    _LANG = "en"


def lang() -> str:
    """The active operator language (``en``, ``hi-ur`` or ``ur``)."""
    return _LANG


STRINGS: dict[str, dict[str, str]] = {
    "en": {
        # structured error frame (cli/theme.py)
        "theme.reason": "Reason:",
        "theme.action": "Action:",
        "theme.exit_footer": "exit {code} ∴ every denial is audited",
        # banner (cli/theme.py) — brand line stays fixed, taglines localize
        "banner.tagline": "authorized security operations — the LLM reasons "
                          "· the system decides",
        "banner.laws": "scope fails closed · no raw shell · no claim without "
                       "evidence · :help inside shell",
        # doctor verdict (cli/main.py)
        "doctor.all_ok": "doctor: ALL CHECKS PASSED {glyph}",
        "doctor.issues": "doctor: ISSUES FOUND {glyph} (see table)",
        # sci-fi shell (cli/shell.py)
        "shell.help_title": "console map",
        "shell.help_everything": "everything else runs as a rebel-profiler CLI command",
        "shell.examples": "examples:",
        "shell.pin_first": "pin a case first: :case <id>",
        "shell.pinned": "pinned → {case}",
        "shell.link_closed": "⌁ link closed",
        "shell.session_closed": "session closed · chains remain verifiable",
        "shell.unknown_cmd": "unknown console command '{cmd}'",
        "shell.unknown_hint": "— :help lists them",
        "shell.exit_note": "exit={code} — structured errors carry the fix",
        # shared verdict words
        "verdict.ok": "ok",
        "verdict.warn": "warn",
        "verdict.denied": "denied",
    },
    # Hinglish — Roman script, the operator's spoken register. Same law:
    # fragments stay short, structural glyphs are never localized.
    "hi-ur": {
        "theme.reason": "Wajah:",
        "theme.action": "Kya karein:",
        "theme.exit_footer": "exit {code} ∴ har denial audit me darj hai",
        "banner.tagline": "authorized security operations — LLM sochta hai "
                          "· system faisla karta hai",
        "banner.laws": "scope fail-closed · koi raw shell nahi · bina evidence "
                       "koi claim nahi · :help shell ke andar",
        "doctor.all_ok": "doctor: sab checks pass {glyph}",
        "doctor.issues": "doctor: masle mile {glyph} (table dekhein)",
        "shell.help_title": "console ka naqsha",
        "shell.help_everything": "baqi sab rebel-profiler CLI command ki tarah chalta hai",
        "shell.examples": "misalein:",
        "shell.pin_first": "pehle case pin karein: :case <id>",
        "shell.pinned": "pin ho gaya → {case}",
        "shell.link_closed": "⌁ link band",
        "shell.session_closed": "session band · chains ab bhi verify ho sakti hain",
        "shell.unknown_cmd": "ye console command samajh nahi aayi '{cmd}'",
        "shell.unknown_hint": "— :help dekh lein",
        "shell.exit_note": "exit={code} — structured errors me hal maujood hai",
        "verdict.ok": "theek",
        "verdict.warn": "khatra",
        "verdict.denied": "reject",
    },
    "ur": {
        "theme.reason": "وجہ:",
        "theme.action": "ایکشن:",
        "theme.exit_footer": "ایگزٹ {code} ∴ ہر انکار آڈٹ میں درج ہے",
        "banner.tagline": "مجاز سیکیورٹی آپریشنز — LLM سوچتا ہے · سسٹم فیصلہ کرتا ہے",
        "banner.laws": "اسکوب بند ناکام · کوئی خام شیل نہیں · بغیر ثوت کوئی دعویٰ نہیں"
                       " · :help شیل کے اندر",
        "doctor.all_ok": "doctor: تمام چیکس پاس {glyph}",
        "doctor.issues": "doctor: مسائل موجود {glyph} (ٹیبل دیکھیں)",
        "shell.help_title": "کنسول کا نقشہ",
        "shell.help_everything": "باقی سب rebel-profiler CLI کمانڈ کی طرح چلتا ہے",
        "shell.examples": "مثالیں:",
        "shell.pin_first": "پہلے کیس pin کریں: :case <id>",
        "shell.pinned": "pin ہو گیا → {case}",
        "shell.link_closed": "⌁ رابطہ بند",
        "shell.session_closed": "سیشن بند · چینز اب بھی تصدیق کے قابل ہیں",
        "shell.unknown_cmd": "یہ کنسول کمانڈ سمجھ نہیں آئی '{cmd}'",
        "shell.unknown_hint": "— :help دیکھیں",
        "shell.exit_note": "ایگزٹ={code} — ترتیب شدہ غلطیوں میں حل موجود ہے",
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
