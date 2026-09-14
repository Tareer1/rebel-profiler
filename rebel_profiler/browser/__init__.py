"""Browser plane: let the LLM use the operator's browser safely.

The LLM writes scope-checked browser job files (the same three-way
handshake as the execution worker plane); the local extension executes
read-only extraction inside the user's own browser and posts results back
through the token-gated localhost bridge. Failures produce structured
error-log result files the LLM reads, corrects and re-submits.
"""

from .bridge import (
    BrowserBridge,
    BrowserJobError,
    BrowserJobStore,
    EXTRACTORS,
    make_handler,
    serve_browser_bridge,
)

__all__ = [
    "BrowserBridge",
    "BrowserJobError",
    "BrowserJobStore",
    "EXTRACTORS",
    "make_handler",
    "serve_browser_bridge",
]
