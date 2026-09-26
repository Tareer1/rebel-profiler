"""The SCIFI shell: rebel-profiler's interactive terminal.

``rebel-profiler shell`` drops into a readline loop with a Unicode sci-fi
prompt. Every command typed here is dispatched to the SAME argparse main —
no second parser, no second set of gates. The shell only decorates:

    ╭─[# REBEL·PROFILER ── case 66bb5b9b7702 ]────
    ╰─◈ rebel ❯ intel attack-plan 66bb5b9b7702

Built-in quality-of-life commands (starting with ``:``) never touch the
network: :help, :case (pick active case), :status, :plan (attack plan),
:cover (vuln coverage), :clear, :exit. Anything else is passed to the CLI
verbatim, output re-rendered through the unicode frame.

The aesthetic is unicode + ANSI only — no external TUI dependency, so the
shell runs on any Kali terminal.
"""

from __future__ import annotations

import os

from ..core.i18n import t as _t
from . import theme

try:
    import readline  # noqa: F401 — history + arrow keys where available
    _HAS_READLINE = True
except ImportError:   # pragma: no cover
    _HAS_READLINE = False

# The shell reuses the shared theme palette — one aesthetic everywhere.
GLYPHS = theme.GLYPHS
CYAN, GREEN, RED, YELLOW, MAGENTA = (theme.CYAN, theme.GREEN, theme.RED,
                                     theme.YELLOW, theme.MAGENTA)
RESET, DIM, BOLD = theme.RESET, theme.DIM, theme.BOLD

def _render_banner(ctx) -> None:
    print(theme.banner())
    try:
        cases = ctx.list_cases()
        active = [c for c in cases if c.get("status") == "active"]
        print(f"{DIM}  ── cases: {len(cases)} total · {len(active)} active ──{RESET}")
    except Exception:
        pass
    print()


def _prompt(case_id: str) -> str:
    case_part = f" ── {CYAN}{case_id}{RESET}" if case_id else ""
    return (f"\n{MAGENTA}╭─[{BOLD}# REBEL{RESET}{MAGENTA} ──{RESET}"
            f"{DIM} rebel-profiler{RESET}{case_part}{MAGENTA} ─{RESET}\n"
            f"{MAGENTA}╰─{CYAN}◈{RESET}{CYAN} rebel ❯{RESET} ")


def _short_status(ctx, case_id: str) -> str:
    try:
        db = ctx.open_case(case_id)
        try:
            claims = len(db.claims_for(case_id, None))
        finally:
            db.close()
        return f"{GREEN}{GLYPHS['ok']} case {case_id}: {claims} claims{RESET}"
    except Exception:
        return f"{RED}{GLYPHS['no']} case {case_id} unavailable{RESET}"


def _help() -> str:
    rows = [
        (":help", "this map"),
        (":case [id]", "pin the session case (or list them)"),
        (":status", "claims + chains for the pinned case"),
        (":plan", "attack plan for the pinned case"),
        (":cover", "vulnerability coverage matrix"),
        (":tools", "the executable action registry"),
        (":banner", "re-render the banner"),
        (":clear", "clear the screen"),
        (":exit / :q", "leave the shell"),
        ("everything else", _t("shell.help_everything")),
    ]
    out = [f"{BOLD}{_t('shell.help_title')}{RESET}"]
    for cmd, desc in rows:
        out.append(f"  {CYAN}{cmd:<16}{RESET} {DIM}{desc}{RESET}")
    out.append(f"\n{DIM}{_t('shell.examples')}{RESET}")
    out.append(f"  {DIM}intel collect <case> subfinder-enum crypto.com{RESET}")
    out.append(f"  {DIM}bounty hunt crypto --no-author{RESET}")
    out.append(f"  {DIM}intel payload deploy <case> ssti --target <url> --approve{RESET}")
    return "\n".join(out)


def _run_cli(argv: list[str]) -> int:
    from .main import main

    try:
        return main(argv)
    except SystemExit as exc:      # argparse exits on bad usage
        return int(exc.code or 0) if isinstance(exc.code, int) else 0
    except KeyboardInterrupt:
        return 130


def run_shell(ctx, argv: list[str] | None = None) -> int:
    """The interactive loop. ``argv`` reserved for future flags."""
    from .main import build_parser   # reuse ONE parser everywhere

    build_parser()
    pinned = ""
    _render_banner(ctx)
    if _HAS_READLINE:
        try:
            readline.read_history_file(os.path.expanduser("~/.rp_history"))
        except OSError:
            pass

    while True:
        try:
            line = input(_prompt(pinned)).strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{DIM}{_t('shell.link_closed')}{RESET}")
            break
        if not line:
            continue
        if line in {":exit", ":q", "exit", "quit"}:
            print(f"{CYAN}{GLYPHS['shield']} {_t('shell.session_closed')}{RESET}")
            break
        if line == ":clear":
            os.system("clear")   # noqa: S605 — cosmetic, fixed command
            continue
        if line == ":banner":
            _render_banner(ctx)
            continue
        if line == ":help":
            print(_help())
            continue
        if line == ":tools":
            _run_cli(["adapters"])
            continue
        if line.startswith(":case"):
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                pinned = parts[1].strip()
                print(f"{GLYPHS['node']} " + _t("shell.pinned", case=f"{CYAN}{pinned}{RESET}"))
            else:
                _run_cli(["case", "list"])
            continue
        if line == ":status":
            if not pinned:
                print(f"{YELLOW}{GLYPHS['warn']} {_t('shell.pin_first')}{RESET}")
                continue
            print(_short_status(ctx, pinned))
            continue
        if line == ":plan":
            if not pinned:
                print(f"{YELLOW}{GLYPHS['warn']} {_t('shell.pin_first')}{RESET}")
                continue
            _run_cli(["intel", "attack-plan", pinned])
            continue
        if line == ":cover":
            if not pinned:
                print(f"{YELLOW}{GLYPHS['warn']} {_t('shell.pin_first')}{RESET}")
                continue
            _run_cli(["intel", "vuln-coverage", pinned])
            continue
        if line.startswith(":"):
            print(f"{RED}{GLYPHS['no']} {_t('shell.unknown_cmd', cmd=line)}{RESET} "
                  f"{DIM}{_t('shell.unknown_hint')}{RESET}")
            continue
        # Everything else: the real CLI, verbatim.
        code = _run_cli(line.split())
        if code not in (0, 130):
            print(f"{DIM}{GLYPHS['dots']} {_t('shell.exit_note', code=code)}{RESET}")

    if _HAS_READLINE:
        try:
            readline.write_history_file(os.path.expanduser("~/.rp_history"))
        except OSError:
            pass
    return 0
