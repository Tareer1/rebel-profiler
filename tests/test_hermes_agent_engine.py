"""Tests for the hermes-agent engine: the operator's installed Nous Research
hermes-agent CLI as a ModelPlane engine.

Every test runs offline against a stub binary — the real agent is never
launched from the suite. The contract under test: binary resolution, the
safe-toolset argv, redaction both ways, bounded timeouts, and structured
failure with a fix hint.
"""

from __future__ import annotations

import os
import stat
import textwrap

import pytest

from rebel_profiler.llm.budget import DEFAULT_LIMITS
from rebel_profiler.llm.hermes_agent import (
    HermesAgentEngine,
    engine_env_status,
    resolve_hermes_agent_bin,
)
from rebel_profiler.llm.inference import ModelPlane


@pytest.fixture()
def stub_bin(tmp_path, monkeypatch):
    """A stub `hermes` binary that echoes a fixed answer, records its argv."""
    calls = tmp_path / "calls.txt"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "hermes"
    stub.write_text(textwrap.dedent(f"""\
        #!/bin/sh
        printf '%s\\n' "$@" >> "{calls}"
        echo "STUB-OK"
        """))
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    yield stub, calls
    monkeypatch.delenv("RP_HERMES_BIN", raising=False)
    monkeypatch.delenv("RP_HERMES_TOOLSETS", raising=False)
    monkeypatch.delenv("RP_HERMES_MODEL", raising=False)


def _engine(stub, **kw) -> HermesAgentEngine:
    return HermesAgentEngine("", limits=DEFAULT_LIMITS["mid"],
                             bin_path=str(stub), **kw)


class TestResolution:
    def test_env_pin_wins(self, stub_bin, monkeypatch):
        stub, _ = stub_bin
        monkeypatch.setenv("RP_HERMES_BIN", str(stub))
        assert resolve_hermes_agent_bin() == str(stub)

    def test_missing_binary_is_empty_not_guessed(self, monkeypatch, tmp_path):
        # Even the well-known install paths must not rescue the lookup here:
        # with no pin, no PATH hit and no known path, the answer is "".
        import rebel_profiler.llm.hermes_agent as ha

        monkeypatch.setattr(ha, "_KNOWN_BINS", ())
        monkeypatch.setattr(ha.shutil, "which", lambda name: None)
        assert resolve_hermes_agent_bin({"RP_HERMES_BIN": ""}) == ""

    def test_env_status_reports_installed(self, stub_bin, monkeypatch):
        stub, _ = stub_bin
        status = engine_env_status({"RP_HERMES_BIN": str(stub)})
        assert status["installed"] is True
        assert status["bin"] == str(stub)
        assert "safe" in status["toolsets"]


class TestContract:
    def test_oneshot_runs_safe_toolset_and_returns_text(self, stub_bin):
        stub, calls = stub_bin
        eng = _engine(stub)
        result = eng.generate("hello stub")
        assert result.text == "STUB-OK"
        assert result.engine == "hermes"
        argv = calls.read_text().splitlines()   # stub records one arg per line
        assert "-z" in argv
        ts_i = argv.index("--toolsets")
        assert argv[ts_i + 1] == "safe"
        assert "hello stub" in argv

    def test_toolset_env_override(self, stub_bin, monkeypatch):
        stub, calls = stub_bin
        monkeypatch.setenv("RP_HERMES_TOOLSETS", "safe,web")
        eng = _engine(stub)
        eng.generate("x")
        assert "safe,web" in calls.read_text().splitlines()

    def test_outbound_prompt_is_redacted(self, stub_bin, tmp_path):
        stub, calls = stub_bin
        eng = _engine(stub)
        eng.generate("the key is sk-abcdef1234567890abcdef")
        sent = calls.read_text()
        assert "sk-abcdef1234567890abcdef" not in sent
        assert "[REDACTED]" in sent

    def test_structured_failure_on_nonzero_exit(self, tmp_path):
        stub = tmp_path / "failing-hermes"
        stub.write_text("#!/bin/sh\n echo 'agent broke' >&2\n exit 3\n")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        eng = _engine(stub)
        from rebel_profiler.core.errors import DependencyUnavailableError

        with pytest.raises(DependencyUnavailableError) as exc:
            eng.generate("x")
        assert "exited 3" in str(exc.value.message)
        assert "hermes -z" in str(getattr(exc.value, "action", ""))

    def test_timeout_is_bounded(self, tmp_path):
        stub = tmp_path / "slow-hermes"
        stub.write_text("#!/bin/sh\n sleep 30\n")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        eng = _engine(stub, timeout_s=1)
        from rebel_profiler.core.errors import DependencyUnavailableError

        with pytest.raises(DependencyUnavailableError) as exc:
            eng.generate("x")
        assert "exceeded" in str(exc.value.message)


class TestPlaneWiring:
    def test_plane_pin_selects_hermes(self, stub_bin, monkeypatch):
        stub, _ = stub_bin
        # Hermetic: pin BOTH the engine and the binary — otherwise a machine
        # with a real ~/.local/bin/hermes would satisfy the pin and CI (which
        # has none) would raise, i.e. the test would pass on one box and fail
        # on another for an environmental reason.
        monkeypatch.setenv("RP_HERMES_BIN", str(stub))
        monkeypatch.setenv("RP_LLM__ENGINE", "hermes")
        plane = ModelPlane(limits=DEFAULT_LIMITS["mid"], prefer_engine="hermes")
        engine = plane.select_engine("")
        assert plane.engine_kind == "hermes"
        assert isinstance(engine, HermesAgentEngine)
        assert "hermes" in plane.fallback_reason
        plane.unload()

    def test_no_pin_never_lands_on_hermes(self, stub_bin, monkeypatch):
        # hermes is opt-in only: the auto chain must never silently pick it
        stub, _ = stub_bin
        monkeypatch.setenv("RP_HERMES_BIN", str(stub))
        monkeypatch.delenv("RP_LLM__ENGINE", raising=False)
        plane = ModelPlane(limits=DEFAULT_LIMITS["tiny"])
        engine = plane.select_engine("deterministic-tiny-nonexistent-model")
        assert plane.engine_kind != "hermes"
        plane.unload()
