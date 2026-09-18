"""Config resolution with layered precedence and protected security keys.

Layers, in precedence order (lowest to highest):
  1. Built-in defaults
  2. System config   (e.g. /etc/rebel-profiler/config.toml)
  3. User config     (e.g. ~/.config/rebel-profiler/config.toml — see
                      :func:`user_config_path`; resolved per call)
  4. Local project   (./rebel-profiler.toml)
  5. Environment     (RP_* variables)
  6. CLI flags       (applied by the caller)

Protected security keys can only be *tightened*, never loosened, through
non-default layers. A layer that tries to weaken them is an error, not a
silent override.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

from ..core.errors import ConfigError

SYSTEM_CONFIG = Path("/etc/rebel-profiler/config.toml")
LOCAL_CONFIG = Path("rebel-profiler.toml")


def user_config_path(environ: dict[str, str] | None = None) -> Path:
    """The user config layer's path, resolved *now* rather than at import.

    This is deliberately a function, not a constant: ``$HOME`` is read on
    every call, so a caller that relocates it — a test sandbox, a container,
    an operator's wrapper — gets *its* config instead of whichever one
    happened to be in effect when this module was first imported. A constant
    here made the CLI test suite read the developer's real ``~/.config``
    profile, so its tier and fit verdicts depended on the machine running it.
    """
    env = os.environ if environ is None else environ
    home = env.get("HOME") or Path.home()
    return Path(home) / ".config" / "rebel-profiler" / "config.toml"

PROTECTED_SECURITY_KEYS: tuple[tuple[str, str], ...] = (
    ("policy", "risk_to_outcome_mapping"),
    ("evidence", "redaction_enabled"),
    ("evidence", "audit_chain_enabled"),
    ("scope", "fail_closed"),
)

# The built-in values are the strictest interpretation of each protected key.
_BUILT_IN_SECURITY = {
    ("policy", "risk_to_outcome_mapping"): "default",
    ("evidence", "redaction_enabled"): True,
    ("evidence", "audit_chain_enabled"): True,
    ("scope", "fail_closed"): True,
}

DEFAULTS: dict = {
    "core": {
        "output_mode": "auto",       # auto | json | jsonl | csv
        "color": "auto",             # auto | always | never
        "confirmations": "interactive",
        "actor": "operator",          # acting subject for RBAC
        "rbac": False,                # enforce case membership roles
        "queue_approvals": True,      # headless approval gate → durable queue
    },
    "paths": {
        "data_dir": "~/.local/share/rebel-profiler",
        "queue_dir": "",              # worker/browser job files (empty ⇒ data_dir/queue)
    },
    "policy": {
        "risk_to_outcome_mapping": "default",
    },
    "evidence": {
        "redaction_enabled": True,
        "audit_chain_enabled": True,
        "retention_days": 0,
    },
    "scope": {
        "fail_closed": True,
    },
}

_SECTION_ALIASES = {
    "RP_": "",  # prefix mapping handled in _env_layer
}


def _deep_merge(base: dict, overlay: dict, *, path: tuple[str, ...] = ()) -> dict:
    result = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value, path=path + (key,))
        else:
            result[key] = value
    return result


def _load_toml(path: Path, layer: str) -> dict:
    if not path.exists():
        return {}
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(
            f"Invalid TOML in {path}",
            reason=f"Layer '{layer}' could not be parsed: {exc}",
            action=f"Fix the syntax error in {path} or remove the file.",
        ) from exc


def _env_layer(environ: dict[str, str] | None = None) -> dict:
    env = dict(os.environ if environ is None else environ)
    layer: dict = {}
    for key, value in env.items():
        if not key.startswith("RP_"):
            continue
        parts = key[3:].lower().split("__")
        if not parts or not all(p for p in parts):
            continue
        # RP_CORE__OUTPUT_MODE=json -> {"core": {"output_mode": "json"}}
        # Non-string values are parsed conservatively.
        parsed: object = value
        low = value.strip().lower()
        if low in {"true", "false"}:
            parsed = low == "true"
        elif low in {"null", "none"}:
            parsed = None
        else:
            try:
                parsed = int(value)
            except ValueError:
                pass
        node = layer
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = parsed
    return layer


def _security_check(layer: dict, layer_name: str) -> None:
    """Reject attempts to loosen protected security keys."""
    for section, key in PROTECTED_SECURITY_KEYS:
        if section in layer and key in layer[section]:
            incoming = layer[section][key]
            default = _BUILT_IN_SECURITY[(section, key)]
            # Boolean protected keys may only be true (strictest) in layers;
            # "default" for the policy mapping is the built-in strict set.
            if default is True and incoming is not True:
                raise ConfigError(
                        f"Protected security key '{section}.{key}' cannot be disabled",
                        reason=(
                            "Layered configuration may tighten security settings "
                            "but never weaken them."
                        ),
                        action=f"Remove '{section}.{key}' from the {layer_name} layer.",
                    )


def load_config(
    *,
    local_path: Path | None = None,
    environ: dict[str, str] | None = None,
    profile_path: Path | str | None = None,
    skip_missing: bool = True,
) -> dict:
    """Resolve the effective configuration from all layers.

    ``profile_path`` is the ``--config-file`` job profile: a TOML file merged
    *between* the local project config and the environment, so a recurring
    job can pin e.g. ``[llm] tier = "low"`` / ``model = "Qwen/Qwen3-4B"``
    while live environment variables still win. Protected security keys in a
    profile follow the same tighten-only rule as every other layer.
    """
    local = local_path if local_path is not None else LOCAL_CONFIG
    layers: list[tuple[str, dict]] = [("defaults", DEFAULTS)]
    layers.append(("system", _load_toml(SYSTEM_CONFIG, "system")))
    layers.append(("user", _load_toml(user_config_path(environ), "user")))
    layers.append(("local", _load_toml(Path(local), "local")))
    if profile_path is not None:
        profile = Path(profile_path).expanduser()
        if not profile.exists():
            raise ConfigError(
                f"Config profile not found: {profile}",
                reason="--config-file must point at an existing TOML file.",
                action="Create the profile or check the path.",
            )
        layers.append(("profile", _load_toml(profile, "profile")))
    env_layer = _env_layer(environ)
    layers.append(("environment", env_layer))

    merged: dict = {}
    for name, layer in layers:
        _security_check(layer, name)
        merged = _deep_merge(merged, layer)
    merged.setdefault("_meta", {})["layers"] = [name for name, _ in layers]
    return merged


def get(config: dict, dotted: str, default=None):
    """Read a dotted path (``evidence.redaction_enabled``) from a config dict."""
    node: object = config
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node
