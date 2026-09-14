"""Tests for --config-file job profiles (recurring-job model/tier pinning)."""

from __future__ import annotations

import json

import pytest

from rebel_profiler.cli.main import main
from rebel_profiler.core.config import load_config
from rebel_profiler.core.errors import ConfigError
from rebel_profiler.llm.budget import DEFAULT_LIMITS, resolve_limits

PROFILE = """\
# recurring-job profile
[llm]
tier = "low"
model = "Qwen/Qwen3-4B"
max_new_tokens = 128

[core]
actor = "nightly-agent"
"""


class TestProfileLayer:
    def test_profile_merges_between_local_and_env(self, tmp_path, monkeypatch):
        profile = tmp_path / "job.toml"
        profile.write_text(PROFILE)
        monkeypatch.setenv("RP_CORE__OUTPUT_MODE", "json")  # env wins over profile
        config = load_config(
            local_path=tmp_path / "does-not-exist.toml",
            profile_path=profile,
        )
        assert config["llm"]["tier"] == "low"            # profile applied
        assert config["llm"]["model"] == "Qwen/Qwen3-4B"
        assert config["core"]["actor"] == "nightly-agent"
        assert "profile" in config["_meta"]["layers"]

    def test_env_beats_profile(self, tmp_path):
        profile = tmp_path / "job.toml"
        profile.write_text(PROFILE)
        config = load_config(
            local_path=tmp_path / "nope.toml", profile_path=profile,
            environ={"RP_LLM__TIER": "mid"},
        )
        assert config["llm"]["tier"] == "mid"            # env wins

    def test_missing_profile_is_config_error(self, tmp_path):
        with pytest.raises(ConfigError):
            load_config(local_path=tmp_path / "nope.toml",
                        profile_path=tmp_path / "ghost.toml")

    def test_profile_cannot_disable_protected_keys(self, tmp_path):
        profile = tmp_path / "evil.toml"
        profile.write_text('[evidence]\nredaction_enabled = false\n')
        with pytest.raises(ConfigError):
            load_config(local_path=tmp_path / "nope.toml", profile_path=profile)


class TestResolveLimitsWithProfile:
    def test_profile_pins_tier(self):
        config = {"llm": {"tier": "low"}}
        limits = resolve_limits(config=config)
        assert limits.tier == "low"

    def test_env_overrides_profile(self, monkeypatch):
        monkeypatch.setenv("RP_LLM__TIER", "mid")
        config = {"llm": {"tier": "low"}}
        limits = resolve_limits(config=config)
        assert limits.tier == "mid"

    def test_profile_tightens_caps_only(self):
        # A profile asking for a HIGHER cap than the tier default must lose:
        # low tier caps new tokens at 256; the profile asks 9999 -> stays 256.
        config = {"llm": {"tier": "low", "max_new_tokens": 9999}}
        limits = resolve_limits(config=config)
        assert limits.max_new_tokens == DEFAULT_LIMITS["low"].max_new_tokens

    def test_profile_can_lower_caps(self):
        config = {"llm": {"tier": "low", "max_new_tokens": 16}}
        limits = resolve_limits(config=config)
        assert limits.max_new_tokens == 16


class TestProfileCli:
    @pytest.fixture()
    def profile(self, tmp_path):
        p = tmp_path / "job.toml"
        p.write_text(PROFILE)
        return str(p)

    def test_status_honors_profile(self, tmp_path, capsys, profile):
        ws = ["--data-dir", str(tmp_path / "d")]
        assert main([*ws, "--config-file", profile, "llm", "status", "-o", "json"]) == 0
        data = json.loads(capsys.readouterr().out)["data"]
        assert data["tier"] == "low"
        assert data["limits"]["max_new_tokens"] == 128

    def test_explicit_tier_flag_beats_profile(self, tmp_path, capsys, profile):
        ws = ["--data-dir", str(tmp_path / "d")]
        assert main([*ws, "--config-file", profile, "llm", "status",
                     "--tier", "high", "-o", "json"]) == 0
        data = json.loads(capsys.readouterr().out)["data"]
        assert data["tier"] == "high"

    def test_missing_profile_is_structured_error(self, tmp_path, capsys):
        ws = ["--data-dir", str(tmp_path / "d")]
        rc = main([*ws, "--config-file", str(tmp_path / "ghost.toml"),
                   "llm", "status", "-o", "json"])
        assert rc == 3
        err = json.loads(capsys.readouterr().err)
        assert err["error"]["exit_code"] == 3
        assert "profile" in err["error"]["message"].lower()

    def test_missing_profile_human_error(self, tmp_path, capsys):
        ws = ["--data-dir", str(tmp_path / "d")]
        rc = main([*ws, "--config-file", str(tmp_path / "ghost.toml"),
                   "llm", "status"])
        assert rc == 3
        assert "profile" in capsys.readouterr().err
