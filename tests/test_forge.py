"""Tests: Feature Forge (LLM self-extension with deterministic gates)."""

from __future__ import annotations

import pytest

from rebel_profiler.agent.forge import (
    FeatureForge,
    static_safety_check,
    sandbox_test,
)


GOOD_ADAPTER = '''
from rebel_profiler.execution.broker import Adapter


class PingSweepAdapter(Adapter):
    name = "forge-ping"
    binary = "ping"
    capability_class = "discovery"
    allowed_params = ("count",)
    required_params = ()

    def build_argv(self, request):
        count = str(request.params.get("count", "1"))
        if not count.isdigit():
            raise ValueError("count must be a number")
        return [self.binary, "-c", count, request.target]


PLUGIN_ADAPTERS = (PingSweepAdapter,)
'''


class TestStaticGate:
    def test_clean_adapter_passes(self):
        assert static_safety_check(GOOD_ADAPTER) == []

    def test_subprocess_import_rejected(self):
        src = "import subprocess\nPLUGIN_ADAPTERS = ()\n"
        findings = static_safety_check(src)
        assert any(f.rule == "forbidden_import" for f in findings)

    def test_os_system_rejected(self):
        src = "import os\nPLUGIN_ADAPTERS = ()\n"
        findings = static_safety_check(src)
        assert any("os" in f.message for f in findings)

    def test_eval_and_open_rejected(self):
        src = ("from rebel_profiler.execution.broker import Adapter\n"
               "x = eval('1+1')\ny = open('/etc/passwd')\n")
        findings = static_safety_check(src)
        rules = {f.rule for f in findings}
        assert "forbidden_builtin" in rules

    def test_raw_network_rejected(self):
        src = "import socket\nPLUGIN_ADAPTERS = ()\n"
        assert any(f.rule == "forbidden_import" for f in static_safety_check(src))

    def test_missing_contract_rejected(self):
        findings = static_safety_check("x = 1\n")
        assert any(f.rule == "missing_contract" for f in findings)

    def test_syntax_error_rejected(self):
        findings = static_safety_check("def broken(:\n")
        assert any(f.rule == "syntax" for f in findings)

    def test_destructive_literal_rejected(self):
        src = ('from rebel_profiler.execution.broker import Adapter\n'
               'CMD = "sudo rm -rf /"\nPLUGIN_ADAPTERS = ()\n')
        assert any(f.rule == "dangerous_literal" for f in static_safety_check(src))

    def test_unknown_import_rejected(self):
        src = "import my_custom_lib\nPLUGIN_ADAPTERS = ()\n"
        assert any(f.rule == "unknown_import" for f in static_safety_check(src))


class TestSandboxGate:
    def test_good_module_builds_argv(self, tmp_path):
        module = tmp_path / "forge_test.py"
        module.write_text(GOOD_ADAPTER)
        ok, results, errors = sandbox_test(
            module, [{"target": "h1.lab.example.test", "params": {"count": "2"}}])
        assert ok, errors
        assert results[0]["name"] == "forge-ping"
        assert results[0]["argv_cases"][0]["argv"][0] == "ping"

    def test_crashing_module_fails(self, tmp_path):
        module = tmp_path / "forge_bad.py"
        module.write_text("import nonexistent_module_xyz\nPLUGIN_ADAPTERS = ()\n")
        ok, _results, errors = sandbox_test(module, [])
        assert not ok
        assert errors


class TestFeatureForge:
    def test_propose_accept_and_register(self, tmp_path):
        from rebel_profiler.execution.broker import AdapterRegistry

        forge = FeatureForge(tmp_path, audit=None)
        result = forge.propose(GOOD_ADAPTER, author="test-llm")
        assert result.accepted, result.as_dict()
        assert result.adapters == ["forge-ping"]

        registry = AdapterRegistry(include_extended=False)
        registered = forge.register_into(registry)
        assert "forge-ping" in registered
        assert registry.get("forge-ping") is not None

    def test_propose_rejects_malwareish_code(self, tmp_path):
        forge = FeatureForge(tmp_path, audit=None)
        result = forge.propose(
            "import subprocess\n"
            "from rebel_profiler.execution.broker import Adapter\n"
            "PLUGIN_ADAPTERS = ()\n", author="test-llm")
        assert not result.accepted
        assert any(f.rule == "forbidden_import" for f in result.findings)
        # rejected source is never persisted
        assert list(tmp_path.glob("forge_*.py")) == []

    def test_manifest_signature_written(self, tmp_path):
        import hashlib
        import hmac as hmac_mod

        forge = FeatureForge(tmp_path, audit=None, signing_secret="k1")
        result = forge.propose(GOOD_ADAPTER)
        assert result.accepted
        manifest = (tmp_path / "forge" / "plugin.toml").read_text()
        expected = hmac_mod.new(b"k1", manifest.encode(),
                                hashlib.sha256).hexdigest()
        assert (tmp_path / "forge" / "signature").read_text().strip() == expected

    def test_list_modules(self, tmp_path):
        forge = FeatureForge(tmp_path, audit=None)
        forge.propose(GOOD_ADAPTER)
        rows = forge.list_modules()
        assert len(rows) == 1
        assert "forge-ping" in rows[0]["adapters"]
