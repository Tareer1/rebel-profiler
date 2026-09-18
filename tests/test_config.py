"""Config system tests: layered precedence + protected security keys."""

from __future__ import annotations

from pathlib import Path

import pytest

from rebel_profiler.core.config import DEFAULTS, get, load_config
from rebel_profiler.core.errors import ConfigError


def test_defaults_load_without_files(tmp_path, monkeypatch):
    cfg = load_config(environ={}, local_path=tmp_path / "none.toml")
    assert get(cfg, "core.output_mode") == "auto"
    assert get(cfg, "scope.fail_closed") is True


def test_env_layer_overrides_defaults(tmp_path):
    cfg = load_config(
        environ={"RP_CORE__OUTPUT_MODE": "json"},
        local_path=tmp_path / "none.toml",
    )
    assert get(cfg, "core.output_mode") == "json"


def test_local_file_overrides_defaults(tmp_path):
    local = tmp_path / "rebel-profiler.toml"
    local.write_text('[core]\noutput_mode = "jsonl"\n')
    cfg = load_config(environ={}, local_path=local)
    assert get(cfg, "core.output_mode") == "jsonl"


def test_env_beats_local_file(tmp_path):
    local = tmp_path / "rebel-profiler.toml"
    local.write_text('[core]\noutput_mode = "jsonl"\n')
    cfg = load_config(environ={"RP_CORE__OUTPUT_MODE": "csv"}, local_path=local)
    assert get(cfg, "core.output_mode") == "csv"


@pytest.mark.parametrize(
    "env",
    [
        {"RP_EVIDENCE__REDACTION_ENABLED": "false"},
        {"RP_EVIDENCE__AUDIT_CHAIN_ENABLED": "false"},
        {"RP_SCOPE__FAIL_CLOSED": "false"},
    ],
)
def test_protected_keys_cannot_be_weakened(tmp_path, env):
    with pytest.raises(ConfigError):
        load_config(environ=env, local_path=tmp_path / "none.toml")


def test_invalid_toml_is_config_error(tmp_path):
    local = tmp_path / "broken.toml"
    local.write_text("not [valid toml")
    with pytest.raises(ConfigError):
        load_config(environ={}, local_path=local)


def test_user_config_layer_follows_home(tmp_path, monkeypatch):
    """Relocating HOME relocates the user config layer.

    Regression: the path was a module constant resolved at import time, so
    the CLI test suite read the developer's real ``~/.config`` profile and its
    tier/fit assertions silently depended on the machine running them.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    profile = tmp_path / ".config" / "rebel-profiler"
    profile.mkdir(parents=True)
    (profile / "config.toml").write_text('[llm]\ntier = "high"\n')
    cfg = load_config(local_path=tmp_path / "none.toml")
    assert get(cfg, "llm.tier") == "high"


def test_user_config_is_not_read_from_an_unrelated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "elsewhere"))
    cfg = load_config(local_path=tmp_path / "none.toml")
    assert get(cfg, "llm.tier") is None


def test_user_config_path_honors_an_explicit_environ(tmp_path):
    from rebel_profiler.core.config import user_config_path

    assert user_config_path({"HOME": str(tmp_path)}) == (
        tmp_path / ".config" / "rebel-profiler" / "config.toml")


def test_get_dotted_paths():
    assert get(DEFAULTS, "evidence.redaction_enabled") is True
    assert get(DEFAULTS, "missing.path", "fallback") == "fallback"


def test_meta_records_layers(tmp_path):
    cfg = load_config(environ={}, local_path=tmp_path / "none.toml")
    assert "environment" in cfg["_meta"]["layers"]
