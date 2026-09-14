"""Plugin SDK: manifests, signing, trust levels, permission grants (PDF 15).

A plugin is a directory with:

    plugin.toml     — the manifest (name, version, entry module, permissions)
    signature       — HMAC-SHA256 over the manifest, keyed by the plugin
                      signing secret (RP_PLUGIN_SECRET; deployments may pin
                      their own key, making unsigned plugins unusable)
    <entry>.py      — the adapter code

Trust model (deterministic, fail closed):

  * ``trusted``    — signature valid AND permission set ⊆ granted set
  * ``unsigned``   — no signature; loadable only when the deployment allows
                     unsigned plugins (off by default)
  * ``rejected``   — signature invalid, or manifest requests permissions
                     that were never granted → never loaded

Permissions gate what a plugin's adapters may touch; the broker's six gates
still decide every execution at runtime. A plugin can only *add* adapters —
it can never alter scope, policy, risk, evidence or audit code.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ConfigError, UsageError

PLUGIN_MANIFEST = "plugin.toml"
SIGNATURE_FILE = "signature"

TRUST_LEVELS = ("trusted", "unsigned", "rejected")

# Permissions a plugin may request; anything else is rejected outright.
KNOWN_PERMISSIONS = frozenset({
    "adapters.register",        # may add adapters to the registry
    "network.fetch",            # adapters may perform network I/O
    "filesystem.read",          # adapters may read files under the case dir
    "knowledge.extend",         # may contribute knowledge entries
})


def load_master_secret(environ: dict[str, str] | None = None) -> str:
    import os

    env = environ if environ is not None else dict(os.environ)
    return env.get("RP_PLUGIN_SECRET", "")


def manifest_digest(manifest_bytes: bytes) -> str:
    return hashlib.sha256(manifest_bytes).hexdigest()


def sign_manifest(manifest_path: Path, secret: str) -> str:
    """Produce the HMAC-SHA256 signature line for a manifest."""
    data = manifest_path.read_bytes()
    return hmac.new(secret.encode("utf-8"), data, hashlib.sha256).hexdigest()


@dataclass
class PluginManifest:
    name: str
    version: str
    entry: str
    permissions: list[str] = field(default_factory=list)
    description: str = ""
    vendor: str = ""

    def as_dict(self) -> dict:
        return {
            "name": self.name, "version": self.version, "entry": self.entry,
            "permissions": list(self.permissions),
            "description": self.description, "vendor": self.vendor,
        }


@dataclass
class PluginHandle:
    manifest: PluginManifest
    path: Path
    trust: str
    granted: list[str] = field(default_factory=list)
    adapters: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "manifest": self.manifest.as_dict(),
            "trust": self.trust,
            "granted": list(self.granted),
            "adapters": [getattr(a, "name", "?") for a in self.adapters],
        }


def parse_manifest(data: bytes) -> PluginManifest:
    try:
        doc = tomllib.loads(data.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"Invalid plugin manifest: {exc}") from exc
    plugin = doc.get("plugin", {})
    name = str(plugin.get("name", "")).strip()
    entry = str(plugin.get("entry", "")).strip()
    if not name or not entry:
        raise ConfigError(
            "Plugin manifest needs plugin.name and plugin.entry",
            action="Add [plugin] name = \"…\", entry = \"adapters.py\".")
    version = str(plugin.get("version", "0.0.0"))
    permissions = [str(p) for p in plugin.get("permissions", [])]
    unknown = set(permissions) - KNOWN_PERMISSIONS
    if unknown:
        raise ConfigError(
            f"Plugin requests unknown permissions: {', '.join(sorted(unknown))}",
            action=f"Allowed permissions: {', '.join(sorted(KNOWN_PERMISSIONS))}")
    return PluginManifest(
        name=name, version=version, entry=entry, permissions=permissions,
        description=str(plugin.get("description", "")),
        vendor=str(plugin.get("vendor", "")),
    )


def load_plugin(
    plugin_dir: Path,
    *,
    secret: str = "",
    granted: list[str] | None = None,
    allow_unsigned: bool = False,
) -> PluginHandle:
    """Validate + trust-check + import a plugin's adapters. Fail closed."""
    plugin_dir = Path(plugin_dir)
    manifest_path = plugin_dir / PLUGIN_MANIFEST
    if not manifest_path.exists():
        raise ConfigError(f"No {PLUGIN_MANIFEST} in {plugin_dir}")
    manifest_bytes = manifest_path.read_bytes()
    manifest = parse_manifest(manifest_bytes)
    granted_set = set(granted or [])

    # --- trust decision -----------------------------------------------------
    unknown_perms = set(manifest.permissions) - granted_set
    sig_path = plugin_dir / SIGNATURE_FILE
    signature = sig_path.read_text().strip() if sig_path.exists() else ""
    if not secret:
        trust = "rejected"
        reason = "no plugin signing secret configured (RP_PLUGIN_SECRET)"
    elif unknown_perms:
        trust = "rejected"
        reason = f"permissions not granted: {', '.join(sorted(unknown_perms))}"
    elif not signature:
        trust = "unsigned" if allow_unsigned else "rejected"
        reason = "no signature file"
    elif not hmac.compare_digest(
        signature,
        hmac.new(secret.encode("utf-8"), manifest_bytes, hashlib.sha256).hexdigest(),
    ):
        trust = "rejected"
        reason = "signature mismatch"
    else:
        trust = "trusted"
        reason = ""

    if trust == "rejected":
        raise ConfigError(
            f"Plugin '{manifest.name}' rejected: {reason}",
            reason="Plugins load only when signed and permission-granted.",
            action="Sign the manifest (rebel-profiler plugin sign) and grant"
                   " its permissions in config.",
        )

    # --- import ---------------------------------------------------------------
    entry_path = plugin_dir / manifest.entry
    if not entry_path.exists():
        raise ConfigError(f"Plugin entry '{manifest.entry}' missing in {plugin_dir}")
    if trust == "unsigned":
        granted_set = set()   # unsigned plugins get no permissions at all
    spec = importlib.util.spec_from_file_location(
        f"rp_plugin_{manifest.name.replace('-', '_')}", entry_path)
    if spec is None or spec.loader is None:
        raise ConfigError(f"Cannot import plugin entry {entry_path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise ConfigError(f"Plugin '{manifest.name}' import failed: {exc}") from exc

    adapters = []
    if "adapters.register" in granted_set:
        exported = getattr(module, "PLUGIN_ADAPTERS", ())
        for cls in exported:
            instance = cls()
            if not getattr(instance, "name", ""):
                raise ConfigError(
                    f"Plugin '{manifest.name}' adapter missing a name")
            adapters.append(instance)
    return PluginHandle(
        manifest=manifest, path=plugin_dir, trust=trust,
        granted=sorted(granted_set), adapters=adapters,
    )


def load_plugins_from(
    root: Path,
    *,
    secret: str = "",
    granted: list[str] | None = None,
    allow_unsigned: bool = False,
) -> list[PluginHandle]:
    """Load every valid plugin directory under *root*; bad ones raise."""
    root = Path(root)
    if not root.exists():
        return []
    handles = []
    for child in sorted(p for p in root.iterdir() if p.is_dir()):
        if (child / PLUGIN_MANIFEST).exists():
            handles.append(load_plugin(
                child, secret=secret, granted=granted,
                allow_unsigned=allow_unsigned))
    return handles
