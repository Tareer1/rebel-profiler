"""Nmap discovery adapters (Phase 3).

Authorized discovery modules built on nmap with fixed, whitelisted flag
sets — the same contract as every other adapter:

  * ``build_argv()`` emits only the declared binary plus whitelisted literals
    derived from validated params,
  * any value failing validation raises UsageError — never sanitized silently,
  * timing templates are limited to the polite end of the scale (T2–T4);
    T5 (insane) is not offered,
  * no adapter implies authorization — the broker's six gates still decide
    every execution, and the runner still fails hard when nmap is missing.

Output parsing lives in ``intel/collection.py`` (``_parse_nmap``); adapters
stay pure argv builders.
"""

from __future__ import annotations

from ..core.errors import UsageError
from .broker import ActionRequest, Adapter
from .adapters import _single_token

_HOSTNAME = r"[A-Za-z0-9.-]+"
_PORT_SPEC = r"\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*"
_TIMING = ("T2", "T3", "T4")


class PortScanAdapter(Adapter):
    """Authorized TCP port discovery (nmap -sT). Moderate risk."""

    name = "port-scan"
    binary = "nmap"
    capability_class = "discovery"
    allowed_params = ("ports", "timing")
    required_params = ()

    _MODE = ("-sT", "-Pn")   # TCP connect + no ping (host validated by scope)

    def build_argv(self, request: ActionRequest) -> list[str]:
        target = _single_token(request.target, field="target", pattern=_HOSTNAME)
        argv = [self.binary, *self._MODE]
        ports = request.params.get("ports")
        if ports is not None:
            ports = _single_token(ports, field="ports", pattern=_PORT_SPEC)
            argv += ["-p", ports]
        timing = str(request.params.get("timing", "T3")).upper()
        if timing not in _TIMING:
            raise UsageError(
                f"Unknown timing template '{timing}'",
                reason=f"Only polite templates are offered: {', '.join(_TIMING)}.",
                action="Pick T2 (slow), T3 (normal) or T4 (fast).",
            )
        argv.append(f"-{timing}")
        argv.append(target)
        return argv


class ServiceDetectAdapter(Adapter):
    """Service/version detection on authorized hosts (nmap -sV). High risk."""

    name = "service-detect"
    binary = "nmap"
    capability_class = "active_recon"
    allowed_params = ("ports", "timing", "intensity")
    required_params = ()

    _MODE = ("-sV", "-Pn")
    _INTENSITY = r"[0-9]"

    def build_argv(self, request: ActionRequest) -> list[str]:
        target = _single_token(request.target, field="target", pattern=_HOSTNAME)
        argv = [self.binary, *self._MODE]
        ports = request.params.get("ports")
        if ports is not None:
            ports = _single_token(ports, field="ports", pattern=_PORT_SPEC)
            argv += ["-p", ports]
        intensity = request.params.get("intensity")
        if intensity is not None:
            intensity = _single_token(intensity, field="intensity", pattern=self._INTENSITY)
            if not (0 <= int(intensity) <= 9):
                raise UsageError(f"Intensity out of range: {intensity}")
            argv += [f"--version-intensity={intensity}"]
        timing = str(request.params.get("timing", "T3")).upper()
        if timing not in _TIMING:
            raise UsageError(
                f"Unknown timing template '{timing}'",
                action=f"Pick one of: {', '.join(_TIMING)}",
            )
        argv.append(f"-{timing}")
        argv.append(target)
        return argv


class OsFingerprintAdapter(Adapter):
    """OS fingerprinting via TCP/IP signatures (nmap -O). High risk."""

    name = "os-fingerprint"
    binary = "nmap"
    capability_class = "active_recon"
    allowed_params = ("timing",)
    required_params = ()

    _MODE = ("-O", "-Pn", "--osscan-limit")

    def build_argv(self, request: ActionRequest) -> list[str]:
        target = _single_token(request.target, field="target", pattern=_HOSTNAME)
        timing = str(request.params.get("timing", "T3")).upper()
        if timing not in _TIMING:
            raise UsageError(
                f"Unknown timing template '{timing}'",
                action=f"Pick one of: {', '.join(_TIMING)}",
            )
        return [self.binary, *self._MODE, f"-{timing}", target]


DISCOVERY_ADAPTERS: tuple[type[Adapter], ...] = (
    PortScanAdapter,
    ServiceDetectAdapter,
    OsFingerprintAdapter,
)
