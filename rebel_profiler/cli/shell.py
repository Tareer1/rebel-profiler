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

BANNER_LINES = (
    f"{CYAN}{BOLD}  ⬢⬢⬢  R E B E L · P R O F I L E R{RESET}",
    f"{DIM}  ═══════════════════════════════════{RESET}",
    f"{MAGENTA}  ⌁ authorized security operations ⌁{RESET}",
    f"{DIM}  the LLM reasons · the system decides{RESET}",
    f"{DIM}  type :help for the console map{RESET}",
)


def _render_banner(ctx) -> None:
    print(theme.banner())
    for line in BANNER_LINES[2:]:
        print(line)
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
            f"{DIM} rebel-profiler{RESET}{case_part}\n"
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
        ("everything else", "runs as a rebel-profiler CLI command"),
    ]
    out = [f"{BOLD}console map{RESET}"]
    for cmd, desc in rows:
        out.append(f"  {CYAN}{cmd:<16}{RESET} {DIM}{desc}{RESET}")
    out.append(f"\n{DIM}examples:{RESET}")
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
            print(f"\n{DIM}⌁ link closed{RESET}")
            break
        if not line:
            continue
        if line in {":exit", ":q", "exit", "quit"}:
            print(f"{CYAN}{GLYPHS['shield']} session closed · chains remain verifiable{RESET}")
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
                print(f"{GLYPHS['node']} pinned → {CYAN}{pinned}{RESET}")
            else:
                _run_cli(["case", "list"])
            continue
        if line == ":status":
            if not pinned:
                print(f"{YELLOW}{GLYPHS['warn']} pin a case first: :case <id>{RESET}")
                continue
            print(_short_status(ctx, pinned))
            continue
        if line == ":plan":
            if not pinned:
                print(f"{YELLOW}{GLYPHS['warn']} pin a case first: :case <id>{RESET}")
                continue
            _run_cli(["intel", "attack-plan", pinned])
            continue
        if line == ":cover":
            if not pinned:
                print(f"{YELLOW}{GLYPHS['warn']} pin a case first: :case <id>{RESET}")
                continue
            _run_cli(["intel", "vuln-coverage", pinned])
            continue
        if line.startswith(":"):
            print(f"{RED}{GLYPHS['no']} unknown console command '{line}'{RESET} "
                  f"{DIM}— :help lists them{RESET}")
            continue
        # Everything else: the real CLI, verbatim.
        code = _run_cli(line.split())
        if code not in (0, 130):
            print(f"{DIM}{GLYPHS['dots']} exit={code} — structured errors carry the fix{RESET}")

    if _HAS_READLINE:
        try:
            readline.write_history_file(os.path.expanduser("~/.rp_history"))
        except OSError:
            pass
    return 0
