"""Hardening + hygiene pins: forge load-time trust, self-scan, exports.

Covers the fix batch that closed the static-analysis findings:
  * FeatureForge.register_into re-verifies the signed manifest and module
    hash at LOAD time (tamper/orphan refusal, audit-logged),
  * core.selfscan backs the doctor row (compile + banned primitives),
  * the hunters/adapters NucleiAdapter shadow is renamed apart
    (nuclei-scan vs vuln-correlate stay distinct, both exported).
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
from pathlib import Path

from rebel_profiler.agent.forge import (
    FORGE_DIRNAME,
    FeatureForge,
    static_safety_check,
)

GOOD_ADAPTER = (
    "from rebel_profiler.execution.broker import Adapter\n"
    "class Ping(Adapter):\n"
    "    name = \"forge-ping\"\n"
    "    binary = \"echo\"\n"
    "    capability_class = \"passive_recon\"\n"
    "    allowed_params = ()\n"
    "    required_params = ()\n"
    "    def build_argv(self, request):\n"
    "        return [self.binary, \"ping\"]\n"
    "PLUGIN_ADAPTERS = (Ping,)\n"
)


def _propose(forge: FeatureForge) -> None:
    result = forge.propose(GOOD_ADAPTER, author="test-llm")
    assert result.accepted, result.as_dict()


def _registry():
    from rebel_profiler.execution.broker import AdapterRegistry

    return AdapterRegistry(include_extended=False)


class TestForgeLoadTimeTrust:
    def test_accepted_module_still_registers(self, tmp_path):
        forge = FeatureForge(tmp_path, audit=None)
        _propose(forge)
        registered = forge.register_into(_registry())
        assert registered == ["forge-ping"]

    def test_tampered_module_is_refused(self, tmp_path):
        forge = FeatureForge(tmp_path, audit=None)
        _propose(forge)
        module = next((tmp_path / FORGE_DIRNAME).glob("forge_*.py"))
        module.write_text(module.read_text() + "\nEVIL = 1\n")  # bytes change
        registered = forge.register_into(_registry())
        assert registered == []          # never executed

    def test_orphan_module_is_refused(self, tmp_path):
        forge = FeatureForge(tmp_path, audit=None)
        _propose(forge)
        orphan = tmp_path / FORGE_DIRNAME / "forge_deadbeef.py"
        orphan.write_text(GOOD_ADAPTER.replace("forge-ping", "forge-evil"))
        registered = forge.register_into(_registry())
        # the forge-accepted module registers; the orphan never does
        assert "forge-ping" in registered
        assert "forge-evil" not in registered

    def test_tampered_signature_is_refused(self, tmp_path):
        forge = FeatureForge(tmp_path, audit=None, signing_secret="k1")
        _propose(forge)
        forge_dir = tmp_path / FORGE_DIRNAME
        side_sig = next(forge_dir.glob("forge_*.sig"))
        side_sig.write_text("0" * 64 + "\n")
        assert forge.register_into(_registry()) == []

    def test_missing_sidecars_refuse_but_root_manifest_still_works(self, tmp_path):
        forge = FeatureForge(tmp_path, audit=None)
        _propose(forge)
        forge_dir = tmp_path / FORGE_DIRNAME
        # remove ONLY the sidecars — the legacy root files stay valid
        for side in (*forge_dir.glob("forge_*.toml"), *forge_dir.glob("forge_*.sig")):
            side.unlink()
        assert forge.register_into(_registry()) == []
        # and the root manifest/signature pair is still internally consistent
        manifest = (forge_dir / "plugin.toml").read_text()
        expected = hmac_mod.new(b"forge-local-dev", manifest.encode(),
                                hashlib.sha256).hexdigest()
        assert (forge_dir / "signature").read_text().strip() == expected


class TestSelfScan:
    def test_package_is_clean(self):
        from rebel_profiler.core.selfscan import self_scan

        scan = self_scan()
        assert scan["files"] >= 100           # the real package, not a stub
        assert scan["ok"], (scan["findings"], scan["syntax_errors"])
        assert scan["findings"] == [] and scan["syntax_errors"] == []

    def test_finds_banned_primitives_in_a_fixture_tree(self, tmp_path):
        from rebel_profiler.core.selfscan import self_scan

        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "bad.py").write_text(
            "import pickle\ntry:\n    x = 1\nexcept:\n    pickle.loads(b'')\n")
        (tmp_path / "pkg" / "fine.py").write_text("x = 1\n")
        scan = self_scan(root=tmp_path)
        assert not scan["ok"]
        rules = {f["rule"] for f in scan["findings"]}
        assert rules == {"bare_except", "unsafe_pickle"}
        assert scan["syntax_errors"] == []

    def test_syntax_error_reported(self, tmp_path):
        from rebel_profiler.core.selfscan import self_scan

        (tmp_path / "broken.py").write_text("def broken(:\n")
        scan = self_scan(root=tmp_path)
        assert not scan["ok"] and scan["syntax_errors"]


class TestAdapterExports:
    def test_nuclei_adapters_are_distinct(self):
        import rebel_profiler.execution as ex
        from rebel_profiler.execution.hunters import NucleiScanAdapter
        from rebel_profiler.execution.adapters import NucleiAdapter

        assert NucleiScanAdapter.name == "nuclei-scan"
        assert NucleiAdapter.name == "vuln-correlate"
        assert ex.NucleiScanAdapter is NucleiScanAdapter
        assert ex.NucleiAdapter is NucleiAdapter

    def test_registry_has_both_actions(self):
        from rebel_profiler.execution.broker import AdapterRegistry

        registry = AdapterRegistry()
        assert registry.get("nuclei-scan") is not None
        assert registry.get("vuln-correlate") is not None

    def test_static_gate_still_rejects_escape_attempts(self):
        findings = static_safety_check("import socket\nPLUGIN_ADAPTERS = ()\n")
        assert any(f.rule == "forbidden_import" for f in findings)
