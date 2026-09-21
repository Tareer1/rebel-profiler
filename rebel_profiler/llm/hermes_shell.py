"""The Hermes shell: the interactive chat UX, cloned from the Hermes agent CLI.

The installed Hermes agent (``~/.hermes/hermes-agent``) greets the operator
with a caduceus banner (model, cwd, session, tool counts, ``/help for
commands``), drives the session through a registry-owned slash-command
surface (``/help``, ``/status``, ``/model``, ``/new``, ``/tools`` …), and
keeps every non-slash line flowing to the model. This module gives Rebel
Profiler's ``hermes`` front door the same shape:

  * :func:`build_banner`            — the welcome banner (hero + info panel)
  * :class:`SlashRegistry`          — one registry, every view derives from it
  * :func:`run_repl`                — the loop: banner → prompt → dispatch
    (slash commands handled locally; anything else runs one bounded Hermes
    agent loop through the broker gates, exactly like before)

Slash commands (mirroring the Hermes agent CLI, backed by the operator
tools so the data is real):

  /help [filter]   /status        /model [name]   /new [name]
  /case            /tools [flt]   /scope          /clear
  /exit (/quit)

Registry-owned like the original: help text, dispatch and completion all
read from :data:`REGISTRY` — add a command once, every view updates.
"""

from __future__ import annotations

import shutil
import sys
import time

from ..core.redact import redact

# ---------------------------------------------------------------------------
# banner


def _c(code: str, text: str) -> str:
    if not sys.stdout.isatty():
        return str(text)
    return f"\033[{code}m{text}\033[0m"


def _dim(text: str) -> str:
    return _c("2", text)


def _accent(text: str) -> str:
    return _c("33", text)   # amber, the Hermes-agent accent


def _bold(text: str) -> str:
    return _c("1", text)


HERMES_CADUCEUS = r"""
             _
          _-(_)-  |\
       _-( _) -   | \
     _-(_)-  _-(  |  \
  _-(_) - _-(    |   \     REBEL PROFILER · HERMES
_( _) -_(  _     |    ;      authorized security operations
   - _ -   _ -   |  -'        the LLM proposes — the gates decide
             \  |\_
               \ |
                \|
"""


def build_banner(*, model: str, case: dict, tools: int,
                 adapters: int, bridge_up: bool, data_dir: str = "",
                 width: int | None = None) -> str:
    """The welcome banner: hero on the left, session facts on the right."""
    cols = width or shutil.get_terminal_size().columns
    lines: list[str] = []
    hero = [line for line in HERMES_CADUCEUS.splitlines()]
    scope_n = case.get("scope_entries", "?")
    claims_n = case.get("claims", "?")
    status = str(case.get("status", "?")).upper()
    info = [
        f"{_accent('Model')}     {model}",
        f"{_accent('Case')}     {_bold(str(case.get('id', '?')))} {_dim('[' + status + ']')}"
        f" {_dim(str(case.get('name', '')))}",
        f"{_accent('Workspace')} {_dim(data_dir or '~/.local/share/rebel-profiler')}",
        f"{_accent('Tools')}    {_bold(str(tools))} operator + {_bold(str(adapters))} gated adapters"
        f" {_dim('· scope ' + str(scope_n) + ' · claims ' + str(claims_n))}",
        f"{_accent('Bridge')}   {'● live 127.0.0.1:8765' if bridge_up else _dim('○ down — rp bridge')}",
        "",
        f"{_dim('/help for commands  ·  plain language works too')}",
    ]
    term = max(80, min(cols, 100))
    n = max(len(hero), len(info))
    hero_w = 40
    for i in range(n):
        left = hero[i] if i < len(hero) else ""
        right = info[i] if i < len(info) else ""
        pad = max(1, hero_w - len(left))
        lines.append(left + " " * pad + right)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# slash-command registry


class SlashCommand:
    """One slash command, defined once."""

    def __init__(self, name: str, description: str, category: str,
                 aliases: tuple[str, ...] = (), args_hint: str = "") -> None:
        self.name = name
        self.description = description
        self.category = category
        self.aliases = aliases
        self.args_hint = args_hint


def _cmd(name: str, description: str, category: str,
         aliases: tuple[str, ...] = (), args_hint: str = "") -> SlashCommand:
    return SlashCommand(name, description, category, aliases, args_hint)


REGISTRY: list[SlashCommand] = [
    _cmd("help", "Show available commands (/help <text> filters)", "Info",
         aliases=("h", "?")),
    _cmd("status", "Show session, case, tool and chain-integrity info", "Session"),
    _cmd("model", "Switch model for this session (bare shows the current one)",
         "Configuration", args_hint="[name]"),
    _cmd("new", "Start a fresh case and move this session onto it",
         "Session", aliases=("reset",), args_hint="[name]"),
    _cmd("case", "Show the case this session works on", "Session"),
    _cmd("tools", "List the tools the model may call (/tools <text> filters)",
         "Tools", args_hint="[filter]"),
    _cmd("scope", "Show this case's authorized targets", "Tools"),
    _cmd("clear", "Clear the screen", "Session", aliases=("cls",)),
    _cmd("exit", "Unload the model and leave", "Session",
         aliases=("quit", "q")),
]


class SlashRegistry:
    """Dispatch + help + lookup, all derived from :data:`REGISTRY`."""

    def __init__(self, handlers: dict[str, callable]) -> None:
        self._handlers = handlers

    def resolve(self, line: str) -> tuple[str | None, str]:
        """Return ``(command_name, args)`` for a slash line, or ``(None, line)``."""
        if not line.startswith("/"):
            return None, line
        word, _, rest = line[1:].partition(" ")
        word = word.strip().lower()
        for cmd in REGISTRY:
            if word == cmd.name or word in cmd.aliases:
                return cmd.name, rest.strip()
        return "", line[1:].strip()   # unknown slash — signal, keep args

    def help_text(self, filt: str = "") -> str:
        rows = []
        for cmd in REGISTRY:
            hay = f"{cmd.name} {cmd.description} {cmd.category}".lower()
            if filt and filt.lower() not in hay:
                continue
            alias = f" ({', '.join('/' + a for a in cmd.aliases)})" if cmd.aliases else ""
            hint = f" {cmd.args_hint}" if cmd.args_hint else ""
            rows.append(f"  {_accent('/' + cmd.name + hint):<28}{cmd.description}{_dim(alias)}")
        return "\n".join(rows) if rows else f"  {_dim('no command matches: ' + filt)}"

    def names(self) -> list[str]:
        out: list[str] = []
        for cmd in REGISTRY:
            out.append(cmd.name)
            out.extend(cmd.aliases)
        return out

    def dispatch(self, name: str, args: str, session: dict) -> bool:
        """Run a command handler; returns False when the REPL should exit."""
        handler = self._handlers.get(name)
        if handler is None:
            return True
        return handler(args, session) is not False


# ---------------------------------------------------------------------------
# tool listing

def tool_schemas_named(registry) -> list[tuple[str, str]]:
    """(name, description) for the whole merged surface — /tools view."""
    from .operator_tools import OPERATOR_TOOLS
    from .hermes import tool_schema

    rows = [(spec.name, spec.description) for spec in OPERATOR_TOOLS.values()]
    rows += [(t["function"]["name"], t["function"]["description"])
             for t in tool_schema(registry)]
    return rows


# ---------------------------------------------------------------------------
# the REPL

class ShellSession:
    """Everything the slash handlers touch: ctx, case, db, plane, args."""

    def __init__(self, ctx, case_rec: dict, db, plane, args) -> None:
        self.ctx = ctx
        self.case_rec = case_rec
        self.db = db
        self.plane = plane
        self.args = args
        self.turns = 0          # agent loops run this session
        self.llm_turns = 0      # LLM replies served (drives the first-turn note)
        self.started = time.time()


def _handler_status(args: str, s: ShellSession) -> None:
    from ..evidence.audit import AuditChain
    from ..evidence.store import EvidenceStore

    rec = s.ctx.find_case(s.case_rec["id"])
    try:
        ev = EvidenceStore(s.db, blobs_dir=s.ctx.case_dir(rec["id"]) / "blobs"
                           ).verify_case(rec["id"])
        audit = AuditChain(s.db).verify(rec["id"])
        chains = f"evidence {'✓' if ev.get('chain_ok') else '✗'} · audit {'✓' if audit.get('chain_ok') else '✗'}"
    except Exception:
        chains = _dim("chains not verifiable")
    entries = s.db.scope_entries(rec["id"])
    claims = s.db.claims_for(rec["id"], None)
    model = getattr(s.plane.engine, "model_id", "?") if s.plane.engine else "?"
    elapsed = int(time.time() - s.started)
    print(f"  {_accent('case')}    {rec['id']} [{rec['status']}] {rec.get('name', '')}")
    print(f"  {_accent('model')}   {model}")
    print(f"  {_accent('scope')}   {len(entries)} entry(ies) · {_accent('claims')} {len(claims)}")
    print(f"  {_accent('chains')}  {chains}")
    print(f"  {_accent('session')} {s.turns} agent loop(s) · {elapsed // 60}m{elapsed % 60}s this session")


def _handler_model(args: str, s: ShellSession) -> None:
    current = getattr(s.plane.engine, "model_id", "?") if s.plane.engine else "?"
    if not args.strip():
        print(f"  current model: {_bold(str(current))}")
        print(f"  {_dim('switch with: /model <path or id>  (session-scoped; hermes.toml pins the default)')}")
        return
    try:
        s.plane.select_engine(args.strip())
    except Exception as exc:
        print(f"  ✗ could not switch: {redact(str(exc))[:160]}")
        return
    new = getattr(s.plane.engine, "model_id", "?")
    print(f"  ✓ model switched to {_bold(str(new))} (session-scoped)")


def _handler_new(args: str, s: ShellSession) -> None:
    name = args.strip() or "Hermes Session"
    rec = s.ctx.create_case(name, "created in the hermes shell")
    try:
        s.db.close()
    except Exception:
        pass
    s.case_rec = rec
    s.db = s.ctx.open_case(rec["id"])
    print(f"  ✓ new case {_bold(rec['id'])} [{rec['status']}] — {name}")
    print(f"  {_dim('say e.g. ' + chr(39) + 'authorize example.com and map it' + chr(39))}")


def _handler_case(args: str, s: ShellSession) -> None:
    rec = s.ctx.find_case(s.case_rec["id"])
    print(f"  case {rec['id']} [{rec['status']}] — {rec.get('name', '')}")
    print(f"  {_dim('created ' + time.strftime('%Y-%m-%d %H:%M', time.localtime(rec.get('created_at', 0))))}")
    print(f"  {_dim('/scope shows the authorized targets; ask for a report in chat')}")


def _handler_tools(args: str, s: ShellSession) -> None:
    from .hermes import operator_tool_count

    rows = tool_schemas_named(s.ctx.broker(s.db).adapters)
    shown = 0
    for name, description in rows:
        if args and args.lower() not in f"{name} {description}".lower():
            continue
        print(f"  {_accent(name):<24}{description}")
        shown += 1
    if not shown:
        print(f"  {_dim('no tool matches: ' + args)}")
    summary = (f"{shown} of {len(rows)} tools "
               f"({operator_tool_count()} operator + adapters)")
    print(f"  {_dim(summary)}")


def _handler_scope(args: str, s: ShellSession) -> None:
    entries = [dict(r) for r in s.db.scope_entries(s.case_rec["id"])]
    if not entries:
        print(f"  {_dim('no scope entries yet — say e.g. ' + chr(39) + 'authorize example.com' + chr(39))}")
        return
    for e in entries:
        mark = "✗ exclude" if e.get("excluded") else "✓ include"
        print(f"  {mark:<10}{e['value']}")


def _handler_clear(args: str, s: ShellSession) -> None:
    sys.stdout.write("\033[2J\033[H" if sys.stdout.isatty() else "")
    sys.stdout.flush()


def _handler_help(args: str, s: ShellSession) -> None:
    print(_accent("commands:"))
    print(registry_help(args))


def _handler_exit(args: str, s: ShellSession) -> None:
    return None   # handled by run_repl via sentinel


_HANDLERS: dict[str, callable] = {
    "status": _handler_status,
    "model": _handler_model,
    "new": _handler_new,
    "case": _handler_case,
    "tools": _handler_tools,
    "scope": _handler_scope,
    "clear": _handler_clear,
    "help": _handler_help,
    "exit": _handler_exit,
}

REGISTRY_OBJ = SlashRegistry(_HANDLERS)


def registry_help(filt: str = "") -> str:
    return REGISTRY_OBJ.help_text(filt)


def run_repl(ctx, case_rec: dict, args, plane) -> int:
    """The Hermes-agent-style shell: banner → prompt → slash dispatch → agent loops."""
    from .hermes import HermesAgentLoop, tool_schema
    from .inference import TinyLlmEngine

    db = ctx.open_case(case_rec["id"])
    s = ShellSession(ctx, case_rec, db, plane, args)
    try:
        if plane.engine is None:
            plane.select_engine(_model_pin(ctx, args))
        if isinstance(plane.engine, TinyLlmEngine):
            from ..core.errors import DependencyUnavailableError

            raise DependencyUnavailableError(
                "Interactive Hermes needs real weights; only the tiny engine loaded",
                reason=plane.fallback_reason,
                action="Install an engine (pip install 'rebel-profiler[gguf]' or "
                       "'rebel-profiler[airllm]'), pull a model ('llm setup', "
                       "'llm local'), pin one already on disk (--llm "
                       "/path/to/model.gguf), widen the budget (--tier high), "
                       "or use 'agent run --plan' for the deterministic path.",
            )

        def _banner_case() -> dict:
            rec = ctx.find_case(s.case_rec["id"])
            try:
                rec = dict(rec)
                rec["scope_entries"] = len(db.scope_entries(rec["id"]))
                rec["claims"] = len(db.claims_for(rec["id"], None))
            except Exception:
                pass
            return rec

        model = getattr(plane.engine, "model_id", "?") or "?"
        tools_total = len(tool_schemas_named(ctx.broker(db).adapters))
        print(build_banner(
            model=model, case=_banner_case(), tools=tools_total,
            adapters=len(tool_schema(ctx.broker(db).adapters)),
            bridge_up=_bridge_probe(), data_dir=str(getattr(ctx, "data_dir", ""))))
        pending = str(getattr(args, "goal_seed", "") or "").strip()
        while True:
            if pending:
                line, pending = pending, ""
                print(f"\n{_accent('you>') } {line}")
            else:
                try:
                    line = input(f"\n{_accent('hermes❯')} ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    break
            if not line:
                continue
            name, rest = REGISTRY_OBJ.resolve(line)
            if name is None:                       # plain language → agent loop
                # A bare "exit" is a goodbye, not a goal for the LLM: without
                # this guard the model burns a multi-minute CPU turn guessing
                # what the operator meant by it.
                if line.strip().lower() in {"exit", "quit", "q", ":q", ":q!",
                                            "bye", "goodbye"}:
                    break
                s.turns += 1
                _run_agent_turn(ctx, s, line)
                continue
            if name == "":                         # unknown slash
                print(f"  {_dim('unknown command: /' + rest)} — try /help")
                continue
            if name == "exit":
                break
            if name == "help" and not rest:
                _handler_help("", s)
                continue
            REGISTRY_OBJ.dispatch(name, rest, s)
        return 0
    finally:
        plane.unload()   # the machine goes quiet again
        try:
            db.close()
        except Exception:
            pass


def _run_agent_turn(ctx, s: ShellSession, line: str) -> None:
    from .hermes import HermesAgentLoop

    if not s.llm_turns:
        # The first turn pays the full system-prompt prefill: minutes on a
        # laptop CPU. Saying so turns a "frozen" wait into a known cost.
        print(_dim("  hermes is working… (first turn reads the whole "
                   "tool contract — this can take a few minutes on CPU)"))
    else:
        print(_dim("  hermes is working…"))
    loop = HermesAgentLoop(
        s.case_rec["id"], line, plane=s.plane,
        broker=s.ctx.broker(s.db), evidence=s.ctx.evidence_store(s.db, s.case_rec["id"]),
        db=s.db, max_turns=getattr(s.args, "max_turns", 8), ctx=s.ctx,
    )
    report = loop.run()
    s.llm_turns += 1
    for call in report["calls"]:
        state = "✓" if not call.get("error") else "✗"
        target = (call.get("target", "") or call.get("added", "")
                  or call.get("url", ""))
        print(f"  {_dim('[' + str(call.get('turn', '?')) + ']')} {state} "
              f"{call.get('action', '')} {target}")
    answer = report.get("final_answer") or "(no answer — turn budget hit)"
    print(f"{_accent('hermes>')} {answer}")
    elapsed = report.get("elapsed_s")
    turns = report.get("turns_used")
    if elapsed is not None and turns is not None:
        print(_dim(f"  ({turns} turn(s), {float(elapsed):.0f}s)"))


def _model_pin(ctx, args) -> str:
    import os

    from ..core.config import get as _cfg_get

    return (str(getattr(args, "llm", "") or "")
            or os.environ.get("RP_LLM__MODEL", "").strip()
            or str(_cfg_get(ctx.config, "llm.model", "") or ""))


def _bridge_probe() -> bool:
    import socket

    try:
        with socket.create_connection(("127.0.0.1", 8765), timeout=0.4):
            return True
    except OSError:
        return False
