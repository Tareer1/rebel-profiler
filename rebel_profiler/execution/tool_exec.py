"""Controlled external-tool execution adapter (the 'LLM hands' capability).

The product goal is that the LLM does the operator's actual work, which means
it must be able to *run tools* — not just propose argv strings. This adapter
provides that in the only safe way the architecture allows:

  * a **whitelist of well-known tool names** (no shells, no interpreters,
    no download-and-execute binaries),
  * every argument token is validated against a strict safe-token pattern —
    flags from a per-tool whitelist, values as single tokens with no
    metacharacters,
  * arguments that look like hosts/domains/IPs are **scope-checked** against
    the live case scope at plan time — the broker's gates still run on top,
  * the whole capability is **approval-gated** (risk=high →
    ALLOW_WITH_APPROVAL), so an interactive operator or a programmatic
    approver must sign off every execution,
  * the exact argv is audit-logged by the broker before dispatch, and output
    becomes hash-chained evidence like every other action.

There is still no raw shell anywhere: nothing is passed to ``sh -c``, no
quoting is ever interpreted, and an unknown binary is a hard error.
"""

from __future__ import annotations

import re

from ..core.errors import UsageError
from .broker import ActionRequest, Adapter
from .adapters import _single_token

# Safe-token pattern for argv values: no whitespace, no shell metacharacters.
_SAFE_VALUE = r"[A-Za-z0-9_@%+=:,./-]{1,200}"

# Whitelisted binaries: reconnaissance/assessment tools that take target-like
# arguments and produce text output. Deliberately excludes shells, curl|wget
# piped-exec patterns, compilers and interpreters.
_TOOL_BINARIES = {
    "dig": "dns",
    "whois": "dns",
    "host": "dns",
    "nmap": "target",
    "masscan": "target",
    "enum4linux-ng": "target",
    "sslscan": "target",
    "whatweb": "target",
    "wafw00f": "target",
    "traceroute": "target",
    "hping3": "target",
    "nuclei": "url",
    "nikto": "url",
    "testssl.sh": "target",
    "searchsploit": "query",
}

# Flags permitted per tool (first token of each pair). Anything else is
# rejected — the planner cannot invent new flags.
_TOOL_FLAGS: dict[str, tuple[str, ...]] = {
    "dig": ("+short", "+noall", "+answer", "-t", "-4", "-6"),
    "whois": ("-r", "-h"),
    "host": ("-t", "-a"),
    "nmap": ("-sT", "-sV", "-sU", "-sn", "-Pn", "-O", "-p", "-T",
             "--top-ports", "--version-intensity", "--osscan-limit", "-oN"),
    "masscan": ("-p", "--rate", "--wait"),
    "enum4linux-ng": ("-A", "-S", "-U", "-G", "-P"),
    "sslscan": ("--no-colour", "--show-certificate", "--tlsall"),
    "whatweb": ("--no-errors", "-a"),
    "wafw00f": ("-a", "-v"),
    "traceroute": ("-n", "-m", "-w"),
    "hping3": ("-S", "-p", "-c", "--scan"),
    "nuclei": ("-silent", "-severity", "-t", "-rl"),
    "nikto": ("-Format", "-port", "-ssl"),
    "testssl.sh": ("--quiet", "--openssl-timeout", "--starttls"),
    "searchsploit": ("--json", "-t", "-j", "--exclude"),
}

# Value flags that consume a following value token.
_VALUE_FLAGS = {
    "-t", "-p", "-T", "-m", "-w", "-c", "-h", "-4", "-6", "-rl",
    "--top-ports", "--version-intensity", "--rate", "--wait", "--scan",
    "-Format", "-port", "--openssl-timeout", "-a", "--exclude",
}

_HOSTLIKE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::\d{1,5})?$|"
    r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$"
)
_QUERY = re.compile(r"[A-Za-z0-9 ._/-]{2,80}")
_URLLIKE = re.compile(r"^https?://[A-Za-z0-9./:_-]{1,200}$")


class ToolExecAdapter(Adapter):
    """Run a whitelisted tool with validated arguments (approval-gated)."""

    name = "exec-tool"
    binary = "<tool>"           # replaced by params['tool'] at argv build
    capability_class = "active_recon"
    allowed_params = ("tool", "args", "note")
    required_params = ("tool",)

    def _resolve_target(self, request: ActionRequest) -> str:
        """Derive the broker-visible target for scope gating."""
        target = request.target.strip()
        if not target:
            raise UsageError(
                "exec-tool requires a target",
                reason="The broker gates the execution on a concrete target.",
                action="Pass the primary host/URL the tool will touch.",
            )
        return target

    def _validate_args(self, tool: str, args: list[str]) -> list[str]:
        allowed_flags = _TOOL_FLAGS.get(tool, ())
        validated: list[str] = []
        expect_value = False
        for token in args:
            token = _single_token(token, field="arg", pattern=_SAFE_VALUE)
            if expect_value:
                expect_value = False
                validated.append(token)
                continue
            if token.startswith("-"):
                if token not in allowed_flags:
                    raise UsageError(
                        f"Flag '{token}' is not whitelisted for tool '{tool}'",
                        reason="Only declared flag sets are executable.",
                        action=f"Allowed flags for {tool}: {', '.join(allowed_flags)}",
                    )
                if token in _VALUE_FLAGS:
                    expect_value = True
                validated.append(token)
                continue
            validated.append(token)
        if expect_value:
            raise UsageError(
                f"Flag at end of args expects a value for tool '{tool}'",
                action="Supply the value after the flag.",
            )
        return validated

    def build_argv(self, request: ActionRequest) -> list[str]:
        tool = str(request.params.get("tool", "")).strip()
        if tool not in _TOOL_BINARIES:
            raise UsageError(
                f"Tool '{tool or '(missing)'}' is not whitelisted",
                reason="Only vetted reconnaissance tools may execute; "
                       "shells and interpreters are never offered.",
                action=f"Pick one of: {', '.join(sorted(_TOOL_BINARIES))}",
            )
        raw_args = request.params.get("args", [])
        if isinstance(raw_args, str):
            # CLI -p args=\"-p 80,443\" convenience: shell-like split is NOT
            # used; simple whitespace split on an already-validated string.
            raw_args = raw_args.split()
        if not isinstance(raw_args, (list, tuple)):
            raise UsageError("exec-tool args must be a list or string")
        args = [str(a) for a in raw_args]
        validated = self._validate_args(tool, args)

        kind = _TOOL_BINARIES[tool]
        argv = [tool, *validated]
        if kind == "query":
            # searchsploit: a LOCAL database query — the target names the
            # search terms, is validated as text, and is passed through
            query = _single_token(self._resolve_target(request),
                                  field="query", pattern=_QUERY)
            argv.append(query)
        elif kind == "url":
            # url-tools accept host OR full-URL targets; hosts are upgraded
            # to a scheme-less scan the binary itself understands
            target = self._resolve_target(request)
            if not _URLLIKE.match(target):
                _single_token(target, field="target", pattern=_HOSTLIKE)
            argv.append(target)
        elif kind in {"target", "dns"}:
            # the request.target itself is the primary target token
            target = self._resolve_target(request)
            if not (_HOSTLIKE.match(target) or _URLLIKE.match(target)):
                raise UsageError(
                    f"Target '{target}' does not look like a host/IP",
                    action="Pass the host, IP or CIDR the tool will touch.",
                )
            argv.append(target)
        return argv


TOOL_EXEC_ADAPTERS: tuple[type[Adapter], ...] = (
    ToolExecAdapter,
)
