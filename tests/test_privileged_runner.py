"""Tests: the --privileged runner (wireless plane, sudo-wrapped RF tools).

The privileged runner is NOT a shell path — it wraps only the whitelisted
wireless binaries (airmon-ng, airodump-ng) via sudo, keeps the adapter's
argv contract as the single source of every token, and leaves non-root
execution working identically when --privileged is absent.
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

from rebel_profiler.cli.context import AppContext
from rebel_profiler.core.errors import DependencyUnavailableError
from rebel_profiler.execution.broker import ExecutionBroker


@pytest.fixture
def ctx(tmp_path):
    return AppContext(data_dir=tmp_path / "data", privileged_runner=True)


@pytest.fixture
def plain_ctx(tmp_path):
    return AppContext(data_dir=tmp_path / "data2")


class TestPrivilegedRunner:
    def test_non_whitelisted_binary_bypasses_sudo(self, ctx):
        """Echo/other binaries run exactly like the default runner."""
        rc, out, err = ctx._privileged_runner(["echo", "hello"])
        assert rc == 0
        assert out.strip() == "hello"

    def test_empty_argv_is_rejected_cleanly(self, ctx):
        """Empty argv is a structured UsageError — never an IndexError."""
        from rebel_profiler.core.errors import UsageError

        with pytest.raises(UsageError):
            ctx._privileged_runner([])

    def test_wraps_airmon_with_sudo_n_when_no_askpass(self, ctx):
        """Non-root + no askpass → argv[0] becomes sudo -n <binary>."""
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return mock.Mock(returncode=0, stdout="ok", stderr="")

        with mock.patch.object(os, "geteuid", return_value=1000), \
                mock.patch("subprocess.run", side_effect=fake_run):
            rc, out, err = ctx._privileged_runner(["airmon-ng", "start", "wlan0"])

        assert rc == 0
        assert captured["cmd"][:3] == ["sudo", "-n", "airmon-ng"]

    def test_wraps_airodump_with_sudo_n(self, ctx):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return mock.Mock(returncode=0, stdout="CH 6", stderr="")

        with mock.patch.object(os, "geteuid", return_value=1000), \
                mock.patch("subprocess.run", side_effect=fake_run):
            rc, out, err = ctx._privileged_runner(["airodump-ng", "--help"])

        assert captured["cmd"][:3] == ["sudo", "-n", "airodump-ng"]

    def test_askpass_uses_sudo_A_and_sets_env(self, ctx):
        """RP_SUDO_ASKPASS → sudo -A + SUDO_ASKPASS forwarded to the child."""
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["env"] = kwargs.get("env", {})
            return mock.Mock(returncode=0, stdout="", stderr="")

        env_with_askpass = dict(os.environ)
        env_with_askpass["RP_SUDO_ASKPASS"] = "/tmp/askpass.sh"
        with mock.patch.object(os, "geteuid", return_value=1000), \
                mock.patch.dict(os.environ, env_with_askpass, clear=False), \
                mock.patch("subprocess.run", side_effect=fake_run):
            rc, out, err = ctx._privileged_runner(["airmon-ng", "check"])

        assert captured["cmd"][:3] == ["sudo", "-A", "airmon-ng"]
        assert captured["env"].get("SUDO_ASKPASS") == "/tmp/askpass.sh"

    def test_password_hint_appended_on_failure(self, ctx):
        """A sudo password failure gets the operator hint, never silence."""
        def fake_run(cmd, **kwargs):
            return mock.Mock(returncode=1, stdout="",
                             stderr="sudo: a password is required")

        with mock.patch.object(os, "geteuid", return_value=1000), \
                mock.patch("subprocess.run", side_effect=fake_run):
            rc, out, err = ctx._privileged_runner(["airmon-ng", "start", "wlan0"])

        assert rc == 1
        assert "RP_SUDO_ASKPASS" in err
        assert "NOPASSWD" in err

    def test_missing_sudo_raises_structured_dependency_error(self, ctx):
        """No sudo binary at all → a structured dependency error, honest."""
        from rebel_profiler.core.errors import DependencyUnavailableError

        with mock.patch.object(os, "geteuid", return_value=1000), \
                mock.patch("subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(DependencyUnavailableError) as excinfo:
                ctx._privileged_runner(["airodump-ng", "--help"])
        # the FileNotFoundError from the sudo attempt fell back to the
        # default runner, which reported the UNWRAPPED binary — proof that
        # the fallback ran without a sudo prefix
        assert "airodump-ng" in str(excinfo.value)

    def test_timeout_returns_124(self, ctx):
        import subprocess as sp

        with mock.patch.object(os, "geteuid", return_value=1000), \
                mock.patch("subprocess.run",
                           side_effect=sp.TimeoutExpired(cmd="sudo", timeout=3600)):
            rc, out, err = ctx._privileged_runner(["airodump-ng"])

        assert rc == 124
        assert "timeout" in err

    def test_root_user_never_wraps_sudo(self, ctx):
        """Already root → the default runner path, no sudo layer."""
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            raise FileNotFoundError(cmd[0] if cmd else "airmon-ng")

        with mock.patch.object(os, "geteuid", return_value=0), \
                mock.patch("subprocess.run", side_effect=fake_run):
            with pytest.raises(DependencyUnavailableError) as excinfo:
                ctx._privileged_runner(["airmon-ng", "start", "wlan0"])
        # the missing binary was airmon-ng itself — no sudo prefix ran
        assert "airmon-ng" in str(excinfo.value)
        assert captured["cmd"][0] == "airmon-ng"

    def test_without_flag_plain_ctx(self, plain_ctx):
        """Without --privileged the ctx wires the default runner."""
        assert plain_ctx.privileged_runner is False

    def test_broker_wiring_privileged(self, ctx, tmp_path):
        db = ctx.open_case("wired")
        broker = ctx.broker(db)
        assert broker._runner == ctx._privileged_runner

    def test_broker_wiring_plain(self, plain_ctx):
        db = plain_ctx.open_case("wired")
        broker = plain_ctx.broker(db)
        assert broker._runner == ExecutionBroker._default_runner


class TestFlagSurface:
    def test_parser_has_privileged_flag(self):
        from rebel_profiler.cli.main import build_parser

        parser = build_parser()
        argv = ["run", "x", "echo", "t", "--privileged"]
        args = parser.parse_args(argv)
        assert getattr(args, "privileged", False) is True

    def test_flag_defaults_absent(self):
        from rebel_profiler.cli.main import build_parser

        parser = build_parser()
        args = parser.parse_args(["run", "x", "echo", "t"])
        assert getattr(args, "privileged", False) is False

    def test_main_passes_flag_to_ctx(self, tmp_path, monkeypatch):
        """End-to-end: --privileged reaches AppContext.privileged_runner."""
        from rebel_profiler.cli import main as cli_main

        seen = {}

        class FakeCtx(AppContext):
            def __init__(self, **kwargs):
                seen.update(kwargs)
                raise SystemExit(0)  # stop right after construction

        monkeypatch.setattr(cli_main, "AppContext", FakeCtx)
        with pytest.raises(SystemExit):
            cli_main.main(["case", "list", "--privileged",
                           "--data-dir", str(tmp_path)])
        assert seen.get("privileged_runner") is True
