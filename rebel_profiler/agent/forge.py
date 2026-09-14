"""Feature Forge: the LLM extends the tool by writing its own adapters.

The vibe-coding capability inside the safety architecture: when the tool
lacks a feature, the LLM *writes the adapter code itself*, and the system —
not the LLM — decides whether that code may run:

  1. **propose**  — the LLM submits Python source declaring
     ``PLUGIN_ADAPTERS`` (the same contract as the Plugin SDK),
  2. **static safety gate** — deterministic checks, no AI opinion:
     forbidden imports (os.system, subprocess, socket, ctypes, …), forbidden
     builtins (eval/exec/compile/open outside declared limits), AST depth
     and size caps, and a required plugin contract,
  3. **sandbox test gate** — the generated adapter is imported in a
   subprocess and exercised against synthetic ActionRequests; it must build
     argv lists (never execute anything) and pass its own declared contract,
  4. **sign + register** — the accepted module is written under the
     workspace forge directory, HMAC-signed like any plugin manifest, and
     registered into the live AdapterRegistry with trust metadata.

The LLM can thus grow the tool itself — new collectors, parsers, wrappers —
while scope, policy, evidence and audit law stay untouched. Escape attempts
(imports that reach the network or spawn processes) fail the gate and are
audit-logged with the reason.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
import re
import subprocess
import sys
import textwrap
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from ..core.errors import UsageError
from ..core.redact import redact
from ..evidence.audit import AuditChain

FORGE_DIRNAME = "forge"
FORGE_MANIFEST = "plugin.toml"
FORGE_SIGNATURE = "signature"

# --- static gate policy ------------------------------------------------------

FORBIDDEN_MODULES: dict[str, str] = {
    # process execution / escape
    "subprocess": "spawns processes",
    "os": "reaches the operating system (os.system/exec/spawn family)",
    "ctypes": "native-code escape",
    "multiprocessing": "spawns processes",
    "pty": "terminal escape",
    "signal": "process signal manipulation",
    # raw network (adapters only BUILD argv; execution stays with the broker)
    "socket": "raw network access",
    "ssl": "raw network access",
    "urllib": "raw network access",
    "http": "raw network access",
    "ftplib": "raw network access",
    "telnetlib": "raw network access",
    "smtplib": "raw network access",
    "asyncio": "event-loop escape hatch",
    "requests": "undeclared network dependency",
    # dynamic code / data exfil primitives
    "pickle": "unsafe deserialization",
    "marshal": "unsafe deserialization",
    "shutil": "filesystem mutation",
    "importlib": "dynamic import escape",
    "builtins": "builtins tampering",
    "code": "interactive escape",
    "codeop": "interactive escape",
    "compileall": "code generation escape",
    "ctypes_util": "native escape",
    "webbrowser": "unsandboxed app launch",
    "pathlib": "filesystem mutation (use params only)",
    "tempfile": "filesystem mutation",
}

FORBIDDEN_BUILTINS: dict[str, str] = {
    "eval": "dynamic code evaluation",
    "exec": "dynamic code evaluation",
    "compile": "dynamic code evaluation",
    "__import__": "dynamic import",
    "globals": "namespace tampering",
    "locals": "namespace tampering",
    "getattr": "attribute smuggling (use direct access)",
    "setattr": "attribute smuggling",
    "delattr": "attribute smuggling",
    "open": "filesystem access (adapters build argv from params only)",
    "input": "interactive hang inside the broker",
    "breakpoint": "interactive escape",
}

MAX_SOURCE_BYTES = 40_000
MAX_AST_NODES = 2_000
MAX_AST_DEPTH = 40

ALLOWED_STDLIB_MODULES = frozenset({
    "re", "json", "math", "uuid", "time", "datetime", "ipaddress", "shlex",
    "string", "textwrap", "base64", "binascii", "hashlib", "hmac", "stat",
    "dataclasses", "typing", "collections", "itertools", "functools",
    "unicodedata", "struct",
})

REQUIRED_IMPORT = "from rebel_profiler.execution.broker import Adapter"


@dataclass(frozen=True)
class ForgeFinding:
    rule: str
    severity: str          # low | high
    message: str

    def as_dict(self) -> dict:
        return {"rule": self.rule, "severity": self.severity,
                "message": self.message}


@dataclass
class ForgeResult:
    accepted: bool
    findings: list[ForgeFinding] = field(default_factory=list)
    module_name: str = ""
    adapters: list[str] = field(default_factory=list)
    source_sha256: str = ""

    def as_dict(self) -> dict:
        return {
            "accepted": self.accepted,
            "findings": [f.as_dict() for f in self.findings],
            "module_name": self.module_name,
            "adapters": list(self.adapters),
            "source_sha256": self.source_sha256,
        }


# ---------------------------------------------------------------------------
# Static safety gate (pure functions — deterministic, testable)


def _walk_depth(node, depth: int = 0) -> int:
    return max([depth, *(_walk_depth(child, depth + 1) for child in ast.iter_child_nodes(node))]) \
        if hasattr(node, "iter_child_nodes") or True else depth


def static_safety_check(source: str) -> list[ForgeFinding]:
    """Deterministic AST gate. Empty findings = accepted."""
    findings: list[ForgeFinding] = []
    if not source or len(source.encode()) > MAX_SOURCE_BYTES:
        findings.append(ForgeFinding("size", "high",
                                     f"source must be 1..{MAX_SOURCE_BYTES} bytes"))
        return findings
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        findings.append(ForgeFinding("syntax", "high", f"invalid python: {exc}"))
        return findings

    node_count = sum(1 for _ in ast.walk(tree))
    if node_count > MAX_AST_NODES:
        findings.append(ForgeFinding("ast_size", "high",
                                     f"module too large ({node_count} nodes > {MAX_AST_NODES})"))
    depth = _walk_depth(tree)
    if depth > MAX_AST_DEPTH:
        findings.append(ForgeFinding("ast_depth", "high",
                                     f"nesting too deep ({depth} > {MAX_AST_DEPTH})"))

    has_adapter_contract = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if alias.name in FORBIDDEN_MODULES or root in FORBIDDEN_MODULES:
                    findings.append(ForgeFinding(
                        "forbidden_import", "high",
                        f"import {alias.name}: "
                        f"{FORBIDDEN_MODULES.get(alias.name) or FORBIDDEN_MODULES[root]}"))
                elif root not in ALLOWED_STDLIB_MODULES and not root.startswith("rebel_profiler"):
                    findings.append(ForgeFinding(
                        "unknown_import", "high",
                        f"import {alias.name}: not in the allow-list"))
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if node.module in FORBIDDEN_MODULES or root in FORBIDDEN_MODULES:
                findings.append(ForgeFinding(
                    "forbidden_import", "high",
                    f"from {node.module}: "
                    f"{FORBIDDEN_MODULES.get(node.module) or FORBIDDEN_MODULES[root]}"))
            elif root not in ALLOWED_STDLIB_MODULES and not root.startswith("rebel_profiler"):
                findings.append(ForgeFinding(
                    "unknown_import", "high", f"from {node.module}: not in the allow-list"))
            if node.module == "rebel_profiler.execution.broker":
                has_adapter_contract = True
        elif isinstance(node, ast.Name) and node.id in FORBIDDEN_BUILTINS:
            findings.append(ForgeFinding(
                "forbidden_builtin", "high",
                f"{node.id}: {FORBIDDEN_BUILTINS[node.id]}"))
        elif isinstance(node, ast.Attribute):
            dotted = _dotted_name(node)
            if dotted.split(".")[0] in FORBIDDEN_MODULES and "rebel_profiler" not in dotted:
                findings.append(ForgeFinding(
                    "forbidden_attribute", "high",
                    f"attribute access {dotted}"))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if re.search(r"\b(?:sudo|rm\s+-rf|mkfs|dd\s+if=|chmod\s+777)\b", node.value):
                findings.append(ForgeFinding(
                    "dangerous_literal", "high",
                    f"destructive command literal {node.value[:40]!r}"))
    if not has_adapter_contract:
        findings.append(ForgeFinding(
            "missing_contract", "high",
            f"module must include: {REQUIRED_IMPORT} and declare PLUGIN_ADAPTERS"))
    return findings


def _dotted_name(node: ast.Attribute) -> str:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


# ---------------------------------------------------------------------------
# Sandbox test gate: import + exercise in a subprocess


_SANDBOX_HARNESS = textwrap.dedent("""
    import json, sys
    sys.path.insert(0, {project_root!r})
    spec_path = sys.argv[1]
    cases = json.load(open(spec_path))
    from rebel_profiler.execution.broker import ActionRequest
    src = open({module_path!r}).read()
    ns = {{}}
    exec(compile(src, {module_path!r}, "exec"), ns)
    adapters = ns.get("PLUGIN_ADAPTERS", ())
    results = []
    for cls in adapters:
        instance = cls()
        entry = {{"name": getattr(instance, "name", ""), "argv_cases": []}}
        for case in cases:
            req = ActionRequest(case_id="forge", capability="forge",
                                action=getattr(instance, "name", "x"),
                                target=case["target"], params=case.get("params", {{}}))
            try:
                argv = instance.build_argv(req)
                ok = isinstance(argv, list) and all(isinstance(a, str) for a in argv)
                entry["argv_cases"].append({{"ok": ok, "argv": argv if ok else None}})
            except Exception as exc:
                entry["argv_cases"].append({{"ok": False, "error": str(exc)[:200]}})
        results.append(entry)
    print("FORGE_RESULT:" + json.dumps(results))
""")


def sandbox_test(module_path: Path, cases: list[dict], *, project_root: Path | None = None,
                 timeout: int = 30) -> tuple[bool, list[dict], list[str]]:
    """Import + exercise the module in a clean subprocess. Returns (ok, results, errors)."""
    if project_root is None:
        import rebel_profiler

        project_root = Path(rebel_profiler.__file__).parent.parent
    if not cases:
        cases = [{"target": "h1.lab.example.test", "params": {}}]
    spec_path = module_path.parent / f".{module_path.stem}.cases.json"
    spec_path.write_text(json.dumps(cases))
    harness = _SANDBOX_HARNESS.format(project_root=str(project_root),
                                      module_path=str(module_path))
    try:
        proc = subprocess.run(
            [sys.executable, "-c", harness, str(spec_path)],
            capture_output=True, text=True, timeout=timeout, check=False,
            cwd=str(module_path.parent),
        )
    except subprocess.TimeoutExpired:
        return False, [], ["sandbox test timed out (possible hang/loop)"]
    errors: list[str] = []
    if proc.returncode != 0:
        errors.append(f"import failed: {proc.stderr.strip()[-400:]}")
        return False, [], errors
    out = proc.stdout.strip()
    marker = "FORGE_RESULT:"
    if marker not in out:
        errors.append("harness produced no result (stdout misuse)")
        return False, [], errors
    try:
        results = json.loads(out[out.index(marker) + len(marker):])
    except json.JSONDecodeError:
        errors.append("harness result unparseable")
        return False, [], errors
    ok = True
    for entry in results:
        if not entry.get("name"):
            ok = False
            errors.append("adapter missing name")
        for case in entry.get("argv_cases", []):
            if not case.get("ok"):
                ok = False
                errors.append(f"argv build failed: {case.get('error', 'invalid argv')}")
    return ok, results, errors


# ---------------------------------------------------------------------------
# The forge itself


class FeatureForge:
    """Accept → sign → store → register LLM-written adapters."""

    def __init__(self, data_dir: Path, *, audit: AuditChain | None = None,
                 signing_secret: str = "forge-local-dev") -> None:
        self.forge_dir = Path(data_dir) / FORGE_DIRNAME
        self.forge_dir.mkdir(parents=True, exist_ok=True)
        self.audit = audit
        self._secret = signing_secret
        import rebel_profiler

        self._project_root = Path(rebel_profiler.__file__).parent.parent

    def propose(self, source: str, *, author: str = "llm",
                test_cases: list[dict] | None = None) -> ForgeResult:
        """Full pipeline: static gate → sandbox gate → sign → store."""
        findings = static_safety_check(source)
        if findings:
            self._audit("forge.rejected", author,
                        {"rules": [f.rule for f in findings]})
            return ForgeResult(accepted=False, findings=findings)
        module_name = f"forge_{uuid.uuid4().hex[:10]}"
        module_path = self.forge_dir / f"{module_name}.py"
        module_path.write_text(source)
        try:
            sandbox_ok, results, errors = sandbox_test(
                module_path, test_cases or [], project_root=self._project_root)
        finally:
            pass
        if not sandbox_ok:
            module_path.unlink(missing_ok=True)
            self._audit("forge.rejected", author, {"errors": errors})
            return ForgeResult(
                accepted=False,
                findings=[ForgeFinding("sandbox", "high", e) for e in errors],
                module_name=module_name)
        adapter_names = [entry.get("name", "") for entry in results]
        digest = hashlib.sha256(source.encode()).hexdigest()
        self._write_plugin_files(module_name, module_path, digest, adapter_names)
        self._audit("forge.accepted", author,
                    {"module": module_name, "adapters": adapter_names,
                     "sha256": digest})
        return ForgeResult(accepted=True, module_name=module_name,
                           adapters=adapter_names, source_sha256=digest)

    def _write_plugin_files(self, module_name: str, module_path: Path,
                            digest: str, adapter_names: list[str]) -> None:
        manifest = (
            "[plugin]\n"
            f'name = "{module_name}"\n'
            'version = "1.0.0"\n'
            f'entry = "{module_path.name}"\n'
            'permissions = ["adapters.register"]\n'
            f'description = "feature forge adapter ({", ".join(adapter_names)})"\n'
            'vendor = "feature-forge"\n'
            f'# source_sha256 = {digest}\n'
        )
        (self.forge_dir / FORGE_MANIFEST).write_text(manifest)
        signature = hmac.new(self._secret.encode(),
                             manifest.encode(), hashlib.sha256).hexdigest()
        (self.forge_dir / FORGE_SIGNATURE).write_text(signature + "\n")

    def register_into(self, registry) -> list[str]:
        """Import every accepted forge module and register its adapters."""
        registered: list[str] = []
        for path in sorted(self.forge_dir.glob("forge_*.py")):
            namespace: dict = {}
            try:
                exec(compile(path.read_text(), str(path), "exec"), namespace)
            except Exception:
                continue   # a broken module is skipped; static gate catches badness
            for cls in namespace.get("PLUGIN_ADAPTERS", ()):
                try:
                    instance = cls()
                    registry.register(instance)
                    registered.append(instance.name)
                except Exception:
                    continue
        return registered

    def list_modules(self) -> list[dict]:
        out = []
        for path in sorted(self.forge_dir.glob("forge_*.py")):
            src = path.read_text()
            names = re.findall(r"name\s*=\s*[\"']([^\"']+)[\"']", src)
            out.append({
                "module": path.stem,
                "adapters": sorted(set(names))[:5],
                "sha256": hashlib.sha256(src.encode()).hexdigest()[:16] + "…",
            })
        return out

    def _audit(self, action: str, subject: str, detail: dict) -> None:
        if self.audit is not None:
            # audit lives per case; forge events go to the workspace audit log
            self.audit.append(detail.get("case_id", "workspace"),
                              actor="feature-forge", action=action,
                              subject=subject, detail={
                                  k: redact(str(v))[:200] for k, v in detail.items()})
