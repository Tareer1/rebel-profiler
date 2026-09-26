"""Rebel Profiler error taxonomy and exit codes.

Exit codes follow the CLI contract (PDF 3 section 36). Every error raised by
the application must be an RPError subclass so the CLI can render a
structured, beginner-friendly message (what / why / next action).
"""

from __future__ import annotations

from .i18n import t as _t

EXIT_SUCCESS = 0
EXIT_GENERAL = 1
EXIT_USAGE = 2
EXIT_CONFIG = 3
EXIT_PERMISSION = 4
EXIT_SCOPE = 5
EXIT_TARGET = 6
EXIT_DEPENDENCY = 7
EXIT_WORKFLOW = 8
EXIT_TIMEOUT = 9
EXIT_CANCELLED = 10
EXIT_EVIDENCE = 11
EXIT_STATE = 12
EXIT_UPDATE = 13
EXIT_PLUGIN = 14
EXIT_MODEL = 15


class RPError(Exception):
    """Base class for all Rebel Profiler errors."""

    exit_code = EXIT_GENERAL
    title = "Error"

    def __init__(self, message: str, *, reason: str = "", action: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.reason = reason
        self.action = action

    def render(self) -> str:
        lines = [f"{self.title}: {self.message}"]
        if self.reason:
            lines.append("")
            lines.append(_t("theme.reason"))
            lines.append(f"  {self.reason}")
        if self.action:
            lines.append("")
            lines.append(_t("theme.action"))
            lines.append(f"  {self.action}")
        return "\n".join(lines)


class UsageError(RPError):
    exit_code = EXIT_USAGE
    title = "Invalid usage"


class ConfigError(RPError):
    exit_code = EXIT_CONFIG
    title = "Configuration error"


class PermissionDeniedError(RPError):
    exit_code = EXIT_PERMISSION
    title = "Permission denied"


class ScopeViolationError(RPError):
    exit_code = EXIT_SCOPE
    title = "Scope violation"


class TargetValidationError(RPError):
    exit_code = EXIT_TARGET
    title = "Target validation failure"


class DependencyUnavailableError(RPError):
    exit_code = EXIT_DEPENDENCY
    title = "Dependency unavailable"


class StateError(RPError):
    exit_code = EXIT_STATE
    title = "State error"


class WorkflowError(RPError):
    exit_code = EXIT_WORKFLOW
    title = "Workflow error"


class EvidenceError(RPError):
    exit_code = EXIT_EVIDENCE
    title = "Evidence error"
