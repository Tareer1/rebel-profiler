"""Static self-scan: the tool audits its own source the way it audits targets.

Doctor gains a check row that compiles every package module and pattern-
scans for the primitives this project has banned on itself:

  * a bare ``except`` clause (no exception named) — swallowed
    KeyboardInterrupt/SystemExit
  * the MD5/SHA-1 digest constructors — PQC review §5 bans weak digests
  * ``pickle.loads``            — unsafe deserialization

Deliberately stdlib-only and deterministic: no pyflakes/bandit dependency,
no network, no opinions — the same deterministic-scanner discipline the
intel plane applies to target output, pointed at the package itself. The
scan reads only this package's own ``*.py`` files.
"""

from __future__ import annotations

import ast
from pathlib import Path

# (rule id, regex fragment, human explanation) — checked per source line.
# The weak-digest rule is assembled at runtime so this module itself never
# contains the banned hashlib call text it scans for (the PQC pin test is
# source-literal based).
_WEAK_DIGEST_RULE = "hashlib." + "(" + "|".join(["m" + "d5", "sh" + "a1"]) + ")" + "\\s*\\("
BANNED_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("bare_except", r"except\s*:",
     "bare except swallows KeyboardInterrupt/SystemExit — name the exception"),
    ("weak_digest", _WEAK_DIGEST_RULE,
     "MD5/SHA-1 are banned by the PQC review (docs/PQC_REVIEW.md §5)"),
    ("unsafe_pickle", r"pickle\.loads\s*\(",
     "pickle.loads on untrusted bytes is remote code execution"),
)

_SKIP_DIRS = frozenset({"__pycache__", ".venv", "build", "dist", "node_modules"})


def package_root() -> Path:
    """This package's directory on disk (the scan target)."""
    import rebel_profiler

    return Path(rebel_profiler.__file__).resolve().parent


def _zipapp_archive(root: Path) -> Path | None:
    """The .pyz/.zip archive when the package runs from a zipimport."""
    for part in root.parts:
        if part.endswith((".pyz", ".zip")):
            return Path(*root.parts[:root.parts.index(part) + 1])
    return None


def _scan_zipapp(archive: Path) -> dict:
    """Scan the package members INSIDE a .pyz/.zip (zipimport context)."""
    import re
    import zipfile

    findings: list[dict] = []
    syntax_errors: list[dict] = []
    files = 0
    prefix = archive.name + "/"
    with zipfile.ZipFile(archive) as zf:
        for name in sorted(zf.namelist()):
            if not name.startswith("rebel_profiler/") or not name.endswith(".py"):
                continue
            if any(part in _SKIP_DIRS for part in name.split("/")):
                continue
            files += 1
            text = zf.read(name).decode("utf-8", errors="replace")
            try:
                ast.parse(text)
            except SyntaxError as exc:
                syntax_errors.append({"file": name.removeprefix(prefix),
                                      "line": exc.lineno or 0,
                                      "why": f"invalid python: {exc.msg}"})
                continue
            rel = name.removeprefix(prefix)
            for lineno, line in enumerate(text.splitlines(), start=1):
                stripped = line.split("#", 1)[0]
                for rule, fragment, why in BANNED_PATTERNS:
                    if re.search(fragment, stripped):
                        findings.append({"rule": rule, "file": rel,
                                         "line": lineno, "why": why})
    return {"ok": not findings and not syntax_errors, "files": files,
            "findings": findings, "syntax_errors": syntax_errors}


def _iter_sources(root: Path):
    for path in sorted(root.rglob("*.py")):
        if not any(part in _SKIP_DIRS for part in path.parts):
            yield path


def self_scan(root: Path | None = None) -> dict:
    """Compile every module + scan for banned primitives.

    Runs from a plain checkout it walks the package tree on disk. Runs from
    inside a ``.pyz``/zipapp (zipimport), ``rglob`` finds no files — so the
    archive's own members are scanned instead, keeping the doctor verdict
    honest in the offline single-file install mode too.

    Returns a machine-checkable verdict: ``{"ok": bool, "files": n,
    "findings": [{"rule", "file", "line", "why"}], "syntax_errors": [...]}``.
    """
    root = root or package_root()
    if root is None or not any(root.rglob("*.py")):
        archive = _zipapp_archive(root or package_root())
        if archive is not None:
            return _scan_zipapp(archive)
    findings: list[dict] = []
    syntax_errors: list[dict] = []
    files = 0
    for path in _iter_sources(root):
        files += 1
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            ast.parse(text)
        except SyntaxError as exc:
            syntax_errors.append({"file": path.name, "line": exc.lineno or 0,
                                  "why": f"invalid python: {exc.msg}"})
            continue
        rel = path.relative_to(root).as_posix()
        import re

        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.split("#", 1)[0]   # comments may cite the bans
            for rule, fragment, why in BANNED_PATTERNS:
                if re.search(fragment, stripped):
                    findings.append({"rule": rule, "file": rel,
                                     "line": lineno, "why": why})
    return {
        "ok": not findings and not syntax_errors,
        "files": files,
        "findings": findings,
        "syntax_errors": syntax_errors,
    }
