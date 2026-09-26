"""The sci-fi theme: unicode + ANSI rendering for the human output mode.

Every command's data still comes from the same ``emit`` envelope — the theme
only decorates the HUMAN mode. JSON / JSONL / CSV modes are untouched: they
stay machine-strict, byte-for-byte.

Rules the theme obeys:
  - additive only — every original text fragment stays findable (tests and
    scripts grep the human stream);
  - degrade gracefully — when stdout is not a TTY (pipes, CI), ANSI colour is
    dropped but unicode structure remains;
  - NO_COLOR / RP_PLAIN=1 disables the whole aesthetic for accessibility.
"""

from __future__ import annotations

import os
import sys

from ..core.i18n import t as _t

# ── enable detection ───────────────────────────────────────────────────────

_NO_COLOR = bool(os.environ.get("NO_COLOR"))
_PLAIN = bool(os.environ.get("RP_PLAIN"))


def _stdout_is_tty() -> bool:
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


_COLOR_ON = (not _NO_COLOR) and (not _PLAIN) and _stdout_is_tty()
_UNICODE_ON = not (_NO_COLOR or _PLAIN)


def _c(code: str) -> str:
    return f"\033[{code}m" if _COLOR_ON else ""


# ── palette ────────────────────────────────────────────────────────────────

RESET, DIM, BOLD = _c("0"), _c("2"), _c("1")
CYAN, GREEN, RED, YELLOW, MAGENTA, BLUE = (
    _c("36"), _c("32"), _c("31"), _c("33"), _c("35"), _c("34"))

# ── glyphs ─────────────────────────────────────────────────────────────────

GLYPHS = {
    "shield": "⬢",       # the project mark
    "bolt": "⌁",         # energy / live
    "node": "◈",         # a case / an entity
    "ok": "✓",
    "no": "✗",
    "warn": "⚠",
    "arrow": "→",
    "dots": "∴",
    "star": "✦",
    "eye": "◉",
    "net": "⌬",
    "chip": "⌗",
    "lock": "🔒",
    "skull": "☠",
}

# box-drawing set for tables and frames — ASCII when the aesthetic is off
BOX = {
    "tl": "╭", "tr": "╮", "bl": "╰", "br": "╯",
    "h": "─", "v": "│",
    "ml": "├", "mr": "┤",
    "sep": "┄",           # light dashed separator inside tables
} if _UNICODE_ON else {
    "tl": "+", "tr": "+", "bl": "+", "br": "+",
    "h": "-", "v": "|",
    "ml": "+", "mr": "+",
    "sep": "-",
}

# Glyphs go ASCII in plain mode too — same truthiness, terminal-safe shapes.
if not _UNICODE_ON:
    GLYPHS = {
        "shield": "#", "bolt": "~", "node": "o", "ok": "+", "no": "x",
        "warn": "!", "arrow": "->", "dots": ".", "star": "*", "eye": "*",
        "net": "#", "chip": "#", "lock": "[L]", "skull": "X",
    }

WIDTH = 78


# ── banner ─────────────────────────────────────────────────────────────────

def banner() -> str:
    bar = BOX["h"] * (WIDTH - 2)
    lines = [
        f"{CYAN}{BOLD} {GLYPHS['shield']}{GLYPHS['shield']}{GLYPHS['shield']} "
        f"R E B E L · P R O F I L E R{RESET}",
        f"{DIM} {bar}{RESET}",
        f"{MAGENTA} {GLYPHS['bolt']} authorized security operations — "
        f"the LLM reasons · the system decides{RESET}",
        f"{DIM} scope fails closed · no raw shell · no claim without evidence · "
        f":help inside shell{RESET}",
    ]
    return "\n".join(lines)


def status_line(text: str) -> str:
    return f"{DIM}{GLYPHS['bolt']} {text}{RESET}"


# ── error frame ────────────────────────────────────────────────────────────

def _edge(left: str, label: str, right: str, color: str = "") -> str:
    """A full-width box edge with an embedded label, aligned to WIDTH."""
    inner = WIDTH - 2
    label = f" {label} " if label else ""
    fill = max(1, inner - _display_width(label))
    body = label + BOX["h"] * fill
    return f"{color}{left}{body}{right}{RESET}"


def error_frame(title: str, message: str, reason: str, action: str,
                exit_code: int) -> str:
    """Structured error, decorated. Keep every original fragment findable."""
    out = [_edge(BOX["tl"], f"{GLYPHS['no']} {title}", BOX["tr"],
                 color=f"{RED}{BOLD}")]
    out.append(f"{RED}{BOX['v']}{RESET} {BOLD}{message}{RESET}")
    if reason:
        out.append(f"{RED}{BOX['v']}{RESET} {DIM}{_t('theme.reason')}{RESET}")
        for ln in _wrap(reason, WIDTH - 6):
            out.append(f"{RED}{BOX['v']}{RESET}   {ln}")
    if action:
        out.append(f"{RED}{BOX['v']}{RESET} {DIM}{_t('theme.action')}{RESET}")
        for ln in _wrap(action, WIDTH - 8):
            out.append(f"{RED}{BOX['v']}{RESET}   {CYAN}{GLYPHS['arrow']} {ln}{RESET}")
    out.append(_edge(BOX["bl"], _t("theme.exit_footer", code=exit_code),
                     BOX["br"], color=f"{RED}{BOLD}"))
    return "\n".join(out)


# ── tables ─────────────────────────────────────────────────────────────────

def _display_width(text: str) -> int:
    """Terminal cells: most box glyphs are single-width; emoji are 2."""
    return sum(2 if ord(ch) > 0x1F000 else 1 for ch in text)


def _pad(text: str, width: int) -> str:
    gap = width - _display_width(text)
    return text + " " * max(0, gap)


def _wrap(text: str, width: int) -> list[str]:
    words = str(text).split()
    lines: list[str] = []
    cur = ""
    for w in words:
        if cur and _display_width(cur) + 1 + _display_width(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines or [""]


def table(rows: list[dict]) -> str:
    """A unicode-ruled table. Falls back to plain columns when not a TTY."""
    cols: list[str] = []
    for r in rows:
        for k in r:
            if k not in cols:
                cols.append(k)
    if not cols:
        return ""
    widths = {c: max([_display_width(c),
                      *(_display_width(str(r.get(c, ""))) for r in rows)])
              for c in cols}
    inner = sum(widths.values()) + 2 * (len(cols) - 1) + 2

    def rule(left: str, right: str) -> str:
        return f"{DIM}{left}{BOX['h'] * inner}{right}{RESET}"

    out = [rule(BOX["tl"], BOX["tr"])]
    header = (f"{BOLD}{GLYPHS['chip']}{RESET}" if _COLOR_ON else GLYPHS["chip"]) \
        + " " + "  ".join(_pad(c, widths[c]) for c in cols)
    out.append(header)
    out.append(rule(BOX["ml"], BOX["mr"]))
    for i, r in enumerate(rows):
        cells = "  ".join(_pad(str(r.get(c, "")), widths[c]) for c in cols)
        marker = f"{DIM}{GLYPHS['dots']}{RESET}" if _COLOR_ON else " "
        out.append(f"{marker} {cells}")
        if i != len(rows) - 1 and len(rows) > 4:
            out.append(f"{DIM} {BOX['sep'] * (inner - 1)}{RESET}")
    out.append(rule(BOX["bl"], BOX["br"]))
    return "\n".join(out)


# ── panel (human text + data table) ───────────────────────────────────────

def panel(human: str, data_rows: list[dict] | None) -> str:
    """Human narrative, then an optional data table below it."""
    parts = [human]
    if data_rows:
        rendered = table(data_rows)
        if rendered:
            parts.append(rendered)
    return "\n".join(p for p in parts if p)
