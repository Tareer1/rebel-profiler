"""Secret redaction.

Any text that may reach the terminal, logs, reports or LLM context should pass
through :func:`redact`. Patterns are intentionally conservative: it is better
to over-redact than to leak a credential.
"""

from __future__ import annotations

import re

_PLACEHOLDER = "[REDACTED]"

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "aws_access_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "openai_style_key",
        re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    ),
    (
        "private_key_block",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    ),
    (
        "assignment_secret",
        re.compile(
            r"(?i)\b(password|passwd|secret|token|api[_-]?key|apikey)\b\s*[:=]\s*\S+"
        ),
    ),
    (
        "bearer_token",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{8,}=*"),
    ),
)


def redact(text: str) -> str:
    """Return *text* with recognized secret material replaced."""
    result = text
    for _name, pattern in _PATTERNS:
        result = pattern.sub(_PLACEHOLDER, result)
    return result


def pattern_names() -> tuple[str, ...]:
    """Names of redaction rules, useful for doctor/help output."""
    return tuple(name for name, _ in _PATTERNS)
