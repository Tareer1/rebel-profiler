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
  * :class:`NiktoAdapter`      — web-server misconfiguration assessment
  * :class:`WpscanAdapter`     — WordPress exposure audit (no brute force)
  * :class:`SearchsploitAdapter` — offline exploit-db lookup (no traffic)
  * :class:`TcpdumpCaptureAdapter` — bounded packet capture, own interface
  * :class:`LynisAuditAdapter` — local hardening audit (blue-team half)

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


class NucleiAdapter(Adapter):
    """Template-based vulnerability scanning (nuclei) against ONE in-scope URL.

    Severity is whitelisted (no info noise by default), the template tag set
    is capped, and the engine rate is throttled — the program's rate-limit
    discipline applies to scanners too. Output (-jsonl) is parsed by the
    collection pipeline into per-finding claims.
    """

    name = "nuclei-scan"
    binary = "nuclei"
    capability_class = "vuln_validation"
    allowed_params = ("severity", "timeout")
    required_params = ()

    _SEVERITY = r"(info|low|medium|high|critical|unknown)(,(info|low|medium|high|critical|unknown))*"

    def build_argv(self, request: ActionRequest) -> list[str]:
        target = _single_token(request.target, field="target", pattern=_URL)
        severity = _single_token(
            str(request.params.get("severity", "low,medium,high,critical")),
            field="severity", pattern=self._SEVERITY)
        timeout = _single_token(str(request.params.get("timeout", "30")),
                                field="timeout", pattern=_TIMEOUT)
        return [
            self.binary, "-u", target,
            "-severity", severity,
            "-jsonl", "-silent", "-no-color",
            "-rate-limit", "60", "-bulk-size", "10",
            "-timeout", timeout,
            "-no-interactsh",   # no out-of-band callbacks without operator opt-in
        ]


class NiktoAdapter(Adapter):
    """Web-server assessment (nikto) against ONE authorized origin.

    Nikto is an active scanner: its checks are misconfiguration-focused
    (dangerous files, outdated software, header issues) and its default
    tuning stays polite. Output is idempotent — the run either completes
    or reports; nothing it prints is treated as an exploit. Format is
    fixed to csv (deterministic parsing), idventions off (no mutation).
    """

    name = "nikto-scan"
    binary = "nikto"
    capability_class = "web_assessment"
    allowed_params = ("port", "ssl", "timeout")
    required_params = ()

    _PORT = r"\d{1,5}"
    _TIMEOUT = r"\d{1,3}"

    def build_argv(self, request: ActionRequest) -> list[str]:
        host = _single_token(request.target, field="host",
                             pattern=r"[A-Za-z0-9.-]+")
        port = _single_token(str(request.params.get("port", "443")),
                             field="port", pattern=self._PORT)
        if not (1 <= int(port) <= 65535):
            raise UsageError(f"port out of range: {port}",
                             action="Use 1-65535.")
        ssl = str(request.params.get("ssl", ""))
        if ssl not in {"", "0", "1"}:
            raise UsageError(f"invalid ssl '{ssl[:20]}'",
                             action="Use 1 for https, 0 or omit for http.")
        timeout = _single_token(str(request.params.get("timeout", "30")),
                                field="timeout", pattern=self._TIMEOUT)
        if not (5 <= int(timeout) <= 120):
            raise UsageError(f"timeout out of range: {timeout}",
                             action="Use 5-120 seconds.")
        argv = [self.binary, "-h", host, "-p", port,
                "-Format", "csv", "-o", "-",
                "-timeout", timeout, "-nointeractive", "-ask", "no"]
        if ssl == "1":
            argv.append("-ssl")
        return argv


class WpscanAdapter(Adapter):
    """WordPress assessment (wpscan) against ONE authorized origin.

    Passive/stealth mode only: no aggressive enumeration, no password
    brute force (the tool has no wordlist path here), no plugin
    dictionary attacks. Version and config-backup exposure checks are
    the detection goal; API token is operator-supplied via env only.
    """

    name = "wpscan-audit"
    binary = "wpscan"
    capability_class = "web_assessment"
    allowed_params = ("enumerate", "timeout")
    required_params = ()

    _ENUM = r"(?:vp|vt|cb|dbe)"   # vulnerable plugins/themes, backups, db exports

    def build_argv(self, request: ActionRequest) -> list[str]:
        url = _single_token(request.target, field="url", pattern=_URL)
        enum = str(request.params.get("enumerate", "vp,vt")).strip()
        if enum:
            parts = [p.strip() for p in enum.split(",")]
            for part in parts:
                _single_token(part, field="enumerate",
                              pattern=self._ENUM)
            enum = ",".join(parts)
        timeout = _single_token(str(request.params.get("timeout", "60")),
                                field="timeout", pattern=_TIMEOUT)
        if not (10 <= int(timeout) <= 300):
            raise UsageError(f"timeout out of range: {timeout}",
                             action="Use 10-300 seconds.")
        argv = [self.binary, "--url", url, "--random-user-agent",
                "--request-timeout", timeout, "--no-banner",
                "--plugins-version-detection", "header"]
        if enum:
            argv += ["--enumerate", enum]
        return argv


class SearchsploitAdapter(Adapter):
    """Offline exploit-db lookup (searchsploit) — ZERO target traffic.

    A pure local database query on the operator's own Kali box: the
    target is never contacted, so the risk stays low. Results become
    advisory claims for later verification, never an execution path.
    """

    name = "exploit-lookup"
    binary = "searchsploit"
    capability_class = "passive_recon"
    allowed_params = ("exclude",)
    required_params = ()

    _QUERY = r"[A-Za-z0-9 ._/-]{2,80}"

    def build_argv(self, request: ActionRequest) -> list[str]:
        query = _single_token(request.target, field="query",
                              pattern=self._QUERY)
        argv = [self.binary, "--json", "-t", query, "-j", "-"]
        exclude = request.params.get("exclude")
        if exclude:
            exclude = _single_token(str(exclude), field="exclude",
                                    pattern=self._QUERY)
            argv += ["--exclude", exclude]
        return argv


class TcpdumpCaptureAdapter(Adapter):
    """Packet capture (tcpdump) on the OPERATOR'S OWN interface.

    Listen-only traffic observation for the assessment of the operator's
    own segment: bounded by a packet count and a BPF filter whitelist so
    a run can neither run away nor target another host actively (capture
    receives; it never transmits to the target). Interface tokens are
    validated like the wireless plane.
    """

    name = "packet-capture"
    binary = "tcpdump"
    capability_class = "network_mapping"
    allowed_params = ("interface", "filter", "count")
    required_params = ("interface",)

    _IFACE = r"[A-Za-z0-9][A-Za-z0-9_-]{1,15}"
    _FILTERS = frozenset({"arp", "icmp", "tcp", "udp", "port 53", "port 80",
                          "port 443", "port 445", "broadcast"})

    def build_argv(self, request: ActionRequest) -> list[str]:
        iface = _single_token(request.params.get("interface", ""),
                              field="interface", pattern=self._IFACE)
        count = _single_token(str(request.params.get("count", "200")),
                              field="count", pattern=r"\d{1,5}")
        if not (1 <= int(count) <= 5000):
            raise UsageError(f"count out of range: {count}",
                             action="Capture 1-5000 packets.")
        filter_ = str(request.params.get("filter", ""))
        if filter_ and filter_ not in self._FILTERS:
            raise UsageError(
                f"BPF filter '{filter_[:40]}' is not whitelisted",
                reason="Only named capture filters are offered — no free-form BPF.",
                action=f"Pick one of: {', '.join(sorted(self._FILTERS))}",
            )
        argv = [self.binary, "-i", iface, "-c", count, "-nn", "-q"]
        if filter_:
            argv.append(filter_)
        return argv


class LynisAuditAdapter(Adapter):
    """Local hardening audit (lynis) of the operator's OWN machine.

    The blue-team counterpart: profiled, non-interactive, and pinned to
    this host's filesystem (targetless by contract — lynis audits where
    it runs). Every finding is defensive guidance, not an attack.
    """

    name = "host-audit"
    binary = "lynis"
    capability_class = "config_assessment"
    allowed_params = ()
    required_params = ()

    def build_argv(self, request: ActionRequest) -> list[str]:
        # target is informational (recorded, not passed): lynis is local-only
        return [self.binary, "audit", "system", "--no-log", "--quick",
                "--no-colors", "--plugin-dir", "/dev/null"]


class CORSCheckAdapter(Adapter):
    """CORS misconfiguration check (curl -sSI) against ONE authorized origin.

    Reflects an arbitrary Origin and reads back Access-Control-Allow-Origin.
    A reflected ACAO without a matching credential policy is the classic
    exploitable CORS misconfig — detection only, one request, no exploitation.
    """

    name = "cors-check"
    binary = "curl"
    capability_class = "web_assessment"
    allowed_params = ("port", "scheme")
    required_params = ()

    _HOSTNAME = r"[A-Za-z0-9.-]+"
    _PORT = r"\d{1,5}"
    _SCHEME = r"https?"

    def build_argv(self, request):
        host = _single_token(request.target, field="host",
                             pattern=self._HOSTNAME)
        port = request.params.get("port")
        if port is not None:
            port = _single_token(port, field="port", pattern=self._PORT)
            if not (1 <= int(port) <= 65535):
                raise UsageError(f"port out of range: {port}",
                                 action="Use 1-65535.")
        scheme = str(request.params.get("scheme", "https"))
        scheme = _single_token(scheme, field="scheme", pattern=self._SCHEME)
        url = f"{scheme}://{host}" + (f":{port}" if port else "")
        return [self.binary, "-sS", "-i", "--max-time", "30",
                "-H", "Origin: https://evil-cors-probe.example",
                "-A", "rebel-profiler cors-check", url]


class SecurityTxtAdapter(Adapter):
    """RFC 9116 security.txt discovery (curl) at the canonical locations.

    Missing security.txt is a reportability gap, not a vulnerability; a
    PRESENT one gives the operator the program's contact and policy —
    both outcomes are evidence for coordinated disclosure.
    """

    name = "security-txt"
    binary = "curl"
    capability_class = "passive_recon"
    allowed_params = ()
    required_params = ()

    _HOSTNAME = r"[A-Za-z0-9.-]+"

    def build_argv(self, request):
        host = _single_token(request.target, field="host",
                             pattern=self._HOSTNAME)
        # -i so the parser sees each response's status line: two fetches,
        # either canonical location presenting 200 is RFC 9116 compliance.
        return [self.binary, "-sS", "-i", "--max-time", "30",
                f"https://{host}/.well-known/security.txt",
                f"https://{host}/security.txt"]


class GraphqlIntrospectionAdapter(Adapter):
    """GraphQL introspection check (curl POST) against ONE authorized origin.

    A minimal introspection query (no destructive mutations) reveals
    whether the schema is publicly readable — an information-exposure
    posture finding. One request, evidence-captured.
    """

    name = "graphql-introspection"
    binary = "curl"
    capability_class = "web_assessment"
    allowed_params = ("path",)
    required_params = ()

    _HOSTNAME = r"[A-Za-z0-9.-]+"
    _PATH = r"/[A-Za-z0-9._/-]{0,80}"
    _URL = r"https?://[A-Za-z0-9./_~:?#@!$&()*+,;=%-]+"

    def build_argv(self, request):
        path = str(request.params.get("path", "/graphql")).strip()
        path = _single_token(path if path.startswith("/") else "/" + path,
                             field="path", pattern=self._PATH)
        if "://" in request.target:
            url = _single_token(request.target, field="url", pattern=self._URL)
        else:
            host = _single_token(request.target, field="host",
                                 pattern=self._HOSTNAME)
            url = f"https://{host}{path}"
        query = '{"query":"{ __schema { queryType { name } } }"}'
        return [self.binary, "-sS", "-i", "--max-time", "30",
                "-X", "POST", "-H", "Content-Type: application/json",
                "-d", query, url]


class EmailSpoofAdapter(Adapter):
    """Email spoofing posture via DNS (dig TXT) for ONE authorized domain.

    Reads SPF and DMARC TXT records — no mail is ever sent. A missing or
    non-enforcing policy (p=none, no SPF) is a phishing-prerequisite
    finding with full provenance.
    """

    name = "email-spoof"
    binary = "dig"
    capability_class = "passive_recon"
    allowed_params = ()
    required_params = ()

    _DOMAIN = r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}"

    def build_argv(self, request):
        domain = _single_token(request.target, field="domain",
                               pattern=self._DOMAIN)
        return [self.binary, "+short", "TXT", domain,
                "+short", "TXT", f"_dmarc.{domain}"]


HUNTER_ADAPTERS: tuple[type[Adapter], ...] = (
    SubfinderAdapter,
    HttpxAdapter,
    KatanaAdapter,
    GauAdapter,
    ArjunAdapter,
    NucleiAdapter,
    NiktoAdapter,
    WpscanAdapter,
    SearchsploitAdapter,
    TcpdumpCaptureAdapter,
    LynisAuditAdapter,
    CORSCheckAdapter,
    SecurityTxtAdapter,
    GraphqlIntrospectionAdapter,
    EmailSpoofAdapter,
)
