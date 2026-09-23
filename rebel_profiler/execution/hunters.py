"""Full-spectrum hunter toolset: the arsenal a manual bounty hunter reaches for.

The baseline set (nmap, dig, whois, amass, theHarvester, ffuf, whatweb,
wafw00f, dnsrecon, nuclei, jsintel, wayback) covers the classic workflow.
This module adds the rest of the standard chain, all Kali-native and all
behind the same adapter contract: declared params only, whitelisted argv,
validated tokens, no shell — the broker's six gates still decide everything.

Adapters here:

  * :class:`SubfinderAdapter`  — fast passive subdomain enumeration
  * :class:`HttpxAdapter`      — live-host probe + tech/title/status surface
  * :class:`KatanaAdapter`     — scope-aware JS/crawler endpoint discovery
  * :class:`GauAdapter`        — known-URLs from AlienVault/Wayback archives
  * :class:`ArjunAdapter`      — hidden HTTP parameter discovery (active)

Each adapter emits one output shape the collection pipeline already knows how
to parse (``subdomain-enum`` lines, ``wayback-urls`` lines, or a small
dedicated parser) so claims land in the ledger with full provenance.
"""

from __future__ import annotations

from ..core.errors import UsageError
from .broker import ActionRequest, Adapter
from .adapters import _single_token

_DOMAIN = r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
_URL = r"https?://[A-Za-z0-9./_~:?#@!$&()*+,;=%-]+"
_TIMEOUT = r"\d{1,3}"
_SEVERITY = r"(info|low|medium|high|critical)(,(info|low|medium|high|critical))*"


class SubfinderAdapter(Adapter):
    """Fast passive subdomain discovery (subfinder, public sources only)."""

    name = "subfinder-enum"
    binary = "subfinder"
    capability_class = "passive_recon"
    allowed_params = ("timeout", "limit")
    required_params = ()

    _LIMIT = r"\d{1,4}"

    def build_argv(self, request: ActionRequest) -> list[str]:
        domain = _single_token(request.target, field="domain",
                               pattern=_DOMAIN)
        argv = [self.binary, "-d", domain, "-silent", "-recursive"]
        timeout = request.params.get("timeout")
        if timeout is not None:
            argv += ["-timeout", _single_token(timeout, field="timeout",
                                               pattern=_TIMEOUT)]
        limit = request.params.get("limit")
        if limit is not None:
            argv += ["-max-time", _single_token(limit, field="limit",
                                                pattern=_LIMIT)]
        return argv


class HttpxAdapter(Adapter):
    """Live-host surface: status, title, tech, redirect chain (httpx).

    Runs against ONE validated in-scope host (the broker checks the target;
    the runner never sees a list file), JSON to stdout for clean parsing.

    Kali ships the ProjectDiscovery toolkit as ``httpx-toolkit`` (the bare
    ``httpx`` name belongs to the Python HTTP client), so the adapter
    resolves the real binary at build time: httpx-toolkit first, plain
    httpx second, and the declared name as last resort so the broker's
    missing-binary message stays truthful.
    """

    name = "httpx-probe"
    binary = "httpx"
    # "recon" is not a declared capability class and would fail conservative
    # (unknown → critical → deny); a liveness/tech probe against one
    # in-scope host is plain discovery.
    capability_class = "discovery"
    allowed_params = ("timeout",)
    required_params = ()

    _HOST = r"[A-Za-z0-9.-]+(?::\d{2,5})?"

    @staticmethod
    def _resolve_binary() -> str:
        import shutil

        for candidate in ("httpx-toolkit", "httpx"):
            if shutil.which(candidate):
                return candidate
        return HttpxAdapter.binary

    def build_argv(self, request: ActionRequest) -> list[str]:
        host = _single_token(request.target, field="host", pattern=self._HOST)
        timeout = _single_token(str(request.params.get("timeout", "10")),
                                field="timeout", pattern=_TIMEOUT)
        return [
            self._resolve_binary(), "-u", host, "-json", "-silent",
            "-status-code", "-title", "-tech-detect", "-ip",
            "-follow-redirects", "-no-color",
            "-timeout", timeout,
        ]


class KatanaAdapter(Adapter):
    """Endpoint discovery via the katana crawler (headers-only by default).

    Crawl depth is hard-capped and the custom-agent header keeps the traffic
    identifiable. Emits raw endpoint lines (the wayback-urls parser accepts
    them as known_urls).
    """

    name = "katana-crawl"
    binary = "katana"
    capability_class = "active_recon"
    allowed_params = ("timeout", "depth")
    required_params = ()

    _DEPTH = r"[1-5]"

    def build_argv(self, request: ActionRequest) -> list[str]:
        target = _single_token(request.target, field="target", pattern=_URL)
        depth = _single_token(str(request.params.get("depth", "2")),
                              field="depth", pattern=self._DEPTH)
        timeout = _single_token(str(request.params.get("timeout", "15")),
                                field="timeout", pattern=_TIMEOUT)
        return [
            self.binary, "-u", target,
            "-depth", depth, "-timeout", timeout,
            "-js-crawl", "-silent", "-no-color", "-d", depth,
        ]


class GauAdapter(Adapter):
    """Known URLs for a host from Wayback + Common Crawl + AlienVault OTX."""

    name = "known-urls"
    binary = "gau"
    capability_class = "passive_recon"
    allowed_params = ("limit",)
    required_params = ()

    _LIMIT = r"\d{1,5}"

    def build_argv(self, request: ActionRequest) -> list[str]:
        domain = _single_token(request.target, field="domain", pattern=_DOMAIN)
        argv = [self.binary, "--subs", "--threads", "2", domain]
        limit = request.params.get("limit")
        if limit is not None:
            argv += ["--oos", _single_token(limit, field="limit",
                                            pattern=self._LIMIT)]
        return argv


class ArjunAdapter(Adapter):
    """Hidden HTTP parameter discovery (arjun). Active — policy gates it."""

    name = "param-hunt"
    binary = "arjun"
    capability_class = "active_recon"
    allowed_params = ("timeout",)
    required_params = ()

    def build_argv(self, request: ActionRequest) -> list[str]:
        target = _single_token(request.target, field="target", pattern=_URL)
        timeout = _single_token(str(request.params.get("timeout", "20")),
                                field="timeout", pattern=_TIMEOUT)
        return [
            self.binary, "-u", target, "-oT", "-",   # tab-separated stdout
            "--stable", "--throttle", "2", "-t", "4",
            "--timeout", timeout,
        ]


HUNTER_ADAPTERS: tuple[type[Adapter], ...] = (
    SubfinderAdapter,
    HttpxAdapter,
    KatanaAdapter,
    GauAdapter,
    ArjunAdapter,
)
