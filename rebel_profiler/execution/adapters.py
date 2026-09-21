"""Extended real-tool adapters (Phase 2 recon & assessment set).

Every adapter here follows the same contract as the built-ins in
``broker.py``: declared params only, whitelisted argv construction, no shell.
A tool's presence in this module never implies authorization — the broker's
gate sequence still decides every execution, and the runner still fails hard
with DependencyUnavailableError when a binary is missing.

Design rules mirrored from broker.Adapter:
  * build_argv() may only emit the declared binary plus whitelisted literals
    derived from validated params.
  * Any value that fails validation raises UsageError — never sanitized
    silently.
  * No adapter accepts free-form strings that reach argv unvalidated.
"""

from __future__ import annotations

import re

from ..core.errors import UsageError
from .broker import ActionRequest, Adapter


def _single_token(value: object, *, field: str, pattern: str) -> str:
    """Validate a param as a single shell-safe token matching *pattern*."""
    import re

    text = str(value).strip()
    if not text or not re.fullmatch(pattern, text):
        raise UsageError(
            f"Invalid {field} '{text}'",
            reason=f"{field} must match the safe pattern {pattern}.",
            action=f"Supply a plain {field} without metacharacters.",
        )
    return text


class WhoisAdapter(Adapter):
    """Domain registration intelligence (whois). Passive."""

    name = "whois-lookup"
    binary = "whois"
    capability_class = "passive_recon"
    allowed_params = ("registrar",)
    required_params = ()

    _DOMAIN = r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}"

    def build_argv(self, request: ActionRequest) -> list[str]:
        target = _single_token(request.target, field="target", pattern=self._DOMAIN)
        argv = [self.binary, target]
        registrar = request.params.get("registrar")
        if registrar is not None:
            argv += ["-r"]  # request raw output; registrar param is informational
        return argv


class CertTransparencyAdapter(Adapter):
    """Certificate transparency log review for subdomain visibility.

    Uses curl against the crt.sh JSON endpoint: passive, read-only, no
    target-side interaction.
    """

    name = "cert-transparency"
    binary = "curl"
    capability_class = "passive_recon"
    allowed_params = ("limit",)
    required_params = ()

    _DOMAIN = r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}"

    def build_argv(self, request: ActionRequest) -> list[str]:
        domain = _single_token(request.target, field="domain", pattern=self._DOMAIN)
        limit = request.params.get("limit", "100")
        limit = _single_token(limit, field="limit", pattern=r"\d{1,5}")
        url = f"https://crt.sh/?q=%25.{domain}&output=json&limit={limit}"
        return [self.binary, "-fsS", "--max-time", "60", url]


class TlsPostureAdapter(Adapter):
    """TLS version/cipher configuration assessment (sslscan)."""

    name = "tls-posture"
    binary = "sslscan"
    capability_class = "web_assessment"
    allowed_params = ("port", "no_color")
    required_params = ()

    _HOSTNAME = r"[A-Za-z0-9.-]+"
    _PORT = r"\d{1,5}"

    def build_argv(self, request: ActionRequest) -> list[str]:
        host = _single_token(request.target, field="host", pattern=self._HOSTNAME)
        port = request.params.get("port", "443")
        port = _single_token(port, field="port", pattern=self._PORT)
        if not (1 <= int(port) <= 65535):
            raise UsageError(f"Port out of range: {port}")
        argv = [self.binary, "--no-colour", f"{host}:{port}"]
        return argv


class HttpProbeAdapter(Adapter):
    """HTTP endpoint/technology surface discovery (httpx)."""

    name = "web-crawl"
    binary = "httpx"
    capability_class = "web_assessment"
    allowed_params = ("ports", "threads", "tech_detect")
    required_params = ()

    _HOSTNAME = r"[A-Za-z0-9.-]+"
    _PORTS = r"\d{1,5}(,\d{1,5})*"
    _THREADS = r"\d{1,3}"

    def build_argv(self, request: ActionRequest) -> list[str]:
        host = _single_token(request.target, field="host", pattern=self._HOSTNAME)
        argv = [self.binary, "-u", host, "-title", "-status-code", "-no-color"]
        ports = request.params.get("ports")
        if ports is not None:
            ports = _single_token(ports, field="ports", pattern=self._PORTS)
            argv += ["-ports", ports]
        threads = request.params.get("threads")
        if threads is not None:
            threads = _single_token(threads, field="threads", pattern=self._THREADS)
            if not (1 <= int(threads) <= 50):
                raise UsageError(f"Threads out of range: {threads}")
            argv += ["-threads", threads]
        if request.params.get("tech_detect"):
            argv += ["-tech-detect"]
        return argv


class HeaderAuditAdapter(Adapter):
    """Security-header and cookie-flag review (curl -I)."""

    name = "header-audit"
    binary = "curl"
    capability_class = "web_assessment"
    allowed_params = ("port", "scheme")
    required_params = ()

    _HOSTNAME = r"[A-Za-z0-9.-]+"
    _PORT = r"\d{1,5}"
    _SCHEME = r"https?"

    def build_argv(self, request: ActionRequest) -> list[str]:
        host = _single_token(request.target, field="host", pattern=self._HOSTNAME)
        port = request.params.get("port")
        if port is not None:
            port = _single_token(port, field="port", pattern=self._PORT)
        scheme = str(request.params.get("scheme", "https"))
        scheme = _single_token(scheme, field="scheme", pattern=self._SCHEME)
        url = f"{scheme}://{host}" + (f":{port}" if port else "")
        argv = [self.binary, "-sSI", "--max-time", "30", url]
        return argv


class SmbEnumAdapter(Adapter):
    """SMB share/session enumeration (enum4linux-ng) on authorized hosts."""

    name = "smb-enum"
    binary = "enum4linux-ng"
    capability_class = "network_mapping"
    allowed_params = ("shares", "users")
    required_params = ()

    _HOSTNAME = r"[A-Za-z0-9.-]+"

    def build_argv(self, request: ActionRequest) -> list[str]:
        host = _single_token(request.target, field="host", pattern=self._HOSTNAME)
        argv = [self.binary, "-A", host]
        # Flags fixed by adapter; params only toggle already-whitelisted sets.
        if request.params.get("shares"):
            argv += ["-S"]
        if request.params.get("users"):
            argv += ["-U"]
        return argv


class TracerouteAdapter(Adapter):
    """Path/hop analysis for segmentation review (traceroute)."""

    name = "route-analysis"
    binary = "traceroute"
    capability_class = "network_mapping"
    allowed_params = ("max_hops",)
    required_params = ()

    _HOSTNAME = r"[A-Za-z0-9.-]+"
    _HOPS = r"\d{1,2}"

    def build_argv(self, request: ActionRequest) -> list[str]:
        host = _single_token(request.target, field="host", pattern=self._HOSTNAME)
        argv = [self.binary, host]
        hops = request.params.get("max_hops")
        if hops is not None:
            hops = _single_token(hops, field="max_hops", pattern=self._HOPS)
            if not (1 <= int(hops) <= 30):
                raise UsageError(f"max_hops out of range: {hops}")
            argv += ["-m", hops]
        return argv


class PassiveDnsMultiAdapter(Adapter):
    """Multi-record-type DNS collection (dig +short) with declared types.

    Unlike the builtin ``dns-lookup`` (A records only), this adapter accepts
    any whitelisted record type so the collection pipeline can parse answers
    type-aware (MX ≠ hostname, TXT ≠ ip). Passive: touches resolvers only.
    """

    name = "passive-dns"
    binary = "dig"
    capability_class = "passive_recon"
    allowed_params = ("record_type",)
    required_params = ()

    _DOMAIN = r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    _RTYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "CAA")

    def build_argv(self, request: ActionRequest) -> list[str]:
        rtype = str(request.params.get("record_type", "A")).strip().upper()
        if rtype not in self._RTYPES:
            raise UsageError(
                f"Unknown record type '{rtype}'",
                reason=f"Only whitelisted record types are allowed: {', '.join(self._RTYPES)}.",
                action="Pick one of the declared record types.",
            )
        target = _single_token(request.target, field="target", pattern=self._DOMAIN)
        return [self.binary, "+short", "-t", rtype, target]


class DorkSearchAdapter(Adapter):
    """Search-engine dorking (Google / DuckDuckGo / Ahmia-over-Tor).

    The query is a NAMED template from intel.dorks plus the validated
    domain target — free-form strings never reach argv. Result page is
    parsed defensively by the collection pipeline (engine markup is
    untrusted data).
    """

    name = "dork-search"
    binary = "curl"
    capability_class = "passive_recon"
    allowed_params = ("engine", "dork", "tld")
    required_params = ("engine", "dork")

    def build_argv(self, request: ActionRequest) -> list[str]:
        from ..intel.dorks import build_dork_argv

        engine = str(request.params.get("engine", ""))
        dork = str(request.params.get("dork", ""))
        tld = request.params.get("tld")
        return build_dork_argv(engine=engine, dork=dork,
                               target=request.target,
                               tld=str(tld) if tld is not None else None)


class SubdomainEnumAdapter(Adapter):
    """Passive subdomain discovery via amass (no active probing).

    amass enum -passive -d <domain>: datasources only, zero target-side
    packets. Output lines are bare hostnames; the pipeline turns each into
    a hostname claim. The progress spinner goes to stderr, so stdout is
    clean lines even on a tty.
    """

    name = "subdomain-enum"
    binary = "amass"
    capability_class = "passive_recon"
    allowed_params = ("timeout",)
    required_params = ()

    _DOMAIN = r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    _TIMEOUT = r"\d{1,3}"

    def build_argv(self, request: ActionRequest) -> list[str]:
        domain = _single_token(request.target, field="domain",
                               pattern=self._DOMAIN)
        timeout = _single_token(str(request.params.get("timeout", "10")),
                                field="timeout", pattern=self._TIMEOUT)
        argv = [self.binary, "enum", "-passive", "-d", domain,
                "-timeout", timeout]
        # amass prints its spinner to stderr; under the broker's runner
        # stderr is captured separately, so nothing extra needed here.
        return argv


class EmailOsintAdapter(Adapter):
    """Email/host/credential surface via theHarvester (passive sources).

    Runs a bounded passive search and writes JSON to stdout; the pipeline
    parses emails and hosts into claims.
    """

    name = "email-osint"
    binary = "theHarvester"
    capability_class = "passive_recon"
    allowed_params = ("limit", "source")
    required_params = ()

    _DOMAIN = r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    _LIMIT = r"\d{1,4}"
    _SOURCE = r"[a-z]{2,20}"

    def build_argv(self, request: ActionRequest) -> list[str]:
        domain = _single_token(request.target, field="domain",
                               pattern=self._DOMAIN)
        limit = _single_token(str(request.params.get("limit", "100")),
                              field="limit", pattern=self._LIMIT)
        argv = [self.binary, "-d", domain, "-l", limit, "-b", "baidu"]
        return argv


class DirEnumAdapter(Adapter):
    """Directory/file enumeration via ffuf against the authorized origin.

    Uses the dirb common wordlist, JSON output to stdout, and a strict
    match list so the run stays small and readable. Active but low-volume.
    """

    name = "dir-enum"
    binary = "ffuf"
    capability_class = "web_assessment"
    allowed_params = ("wordlist", "extensions")
    required_params = ()

    _URL = r"https?://[A-Za-z0-9./_-]+"
    _PATH = r"[A-Za-z0-9._/-]{1,200}"
    _EXT = r"\.(?:php|asp|aspx|jsp|html|txt|bak|old|zip|sql|json|xml)"

    def build_argv(self, request: ActionRequest) -> list[str]:
        url = _single_token(request.target, field="url", pattern=self._URL)
        if not url.endswith("/"):
            url += "/"        # small.txt by default: polite on slow targets (959 reqs vs 4614 for
        # common.txt); operators can opt into the bigger list via params.
        wordlist = str(request.params.get("wordlist", "/usr/share/wordlists/dirb/small.txt"))
        wordlist = _single_token(wordlist, field="wordlist", pattern=self._PATH)
        argv = [self.binary, "-u", url + "FUZZ", "-w", wordlist,
                "-of", "json", "-o", "-",  # JSON to stdout
                "-mc", "200,204,301,302,307,401,403",
                "-ac",   # auto-calibrate: filters soft-404 hosts that 200 everything
                "-t", "15", "-timeout", "6"]
        extensions = request.params.get("extensions")
        if extensions:
            exts = str(extensions)
            if not re.fullmatch(r"(?:\.[a-z0-9]{1,5})(?:,\.[a-z0-9]{1,5})*", exts):
                raise UsageError(f"Invalid extensions '{exts[:40]}…'",
                                 action="Comma list like .php,.bak")
            argv += ["-e", exts]
        return argv


class TechFingerprintAdapter(Adapter):
    """Web technology fingerprinting via whatweb (polite, one pass)."""

    name = "tech-fingerprint"
    binary = "whatweb"
    capability_class = "web_assessment"
    allowed_params = ()
    required_params = ()

    _URL = r"https?://[A-Za-z0-9./_-]+"

    def build_argv(self, request: ActionRequest) -> list[str]:
        url = _single_token(request.target, field="url", pattern=self._URL)
        # no -q: quiet mode suppresses the result line we parse
        return [self.binary, "--no-errors", "--color=never", url]


class DnsEnumAdapter(Adapter):
    """DNS enumeration via dnsrecon: standard records + zone transfer check
    + reverse lookups on the target's own range. JSON to stdout."""

    name = "dns-enum"
    binary = "dnsrecon"
    capability_class = "passive_recon"
    allowed_params = ()
    required_params = ()

    _DOMAIN = r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}"

    def build_argv(self, request: ActionRequest) -> list[str]:
        domain = _single_token(request.target, field="domain",
                               pattern=self._DOMAIN)
        # std only: brute (brt) needs a dictionary file and is an *active*
        # technique — dnsrecon exits rc=1 when no wordlist is given, which
        # would mark every run failed. Zone brute stays out of the passive
        # path; the GUI/Hermes can expose a dedicated active action later.
        return [self.binary, "-d", domain, "-t", "std", "--lifetime", "10",
                "-n", "1.1.1.1"]


class WafDetectAdapter(Adapter):
    """WAF detection via wafw00f against the authorized origin."""

    name = "waf-detect"
    binary = "wafw00f"
    capability_class = "web_assessment"
    allowed_params = ()
    required_params = ()

    _URL = r"https?://[A-Za-z0-9./_-]+"

    def build_argv(self, request: ActionRequest) -> list[str]:
        url = _single_token(request.target, field="url", pattern=self._URL)
        # positional URL (NOT -H: that flag sets custom request headers)
        return [self.binary, "-a", "--no-colors", url]


class NucleiAdapter(Adapter):
    """Template-driven vulnerability validation (nuclei). High risk."""

    name = "vuln-correlate"
    binary = "nuclei"
    capability_class = "vuln_validation"
    allowed_params = ("severity", "templates")
    required_params = ()

    _URL = r"https?://[A-Za-z0-9./_-]+"
    _SEVERITY = r"(info|low|medium|high|critical)(,(info|low|medium|high|critical))*"
    _TEMPLATE = r"[a-z0-9-]{1,64}"

    def build_argv(self, request: ActionRequest) -> list[str]:
        target = _single_token(request.target, field="target", pattern=self._URL)
        argv = [self.binary, "-u", target, "-silent"]
        severity = request.params.get("severity")
        if severity is not None:
            severity = _single_token(severity, field="severity", pattern=self._SEVERITY)
            argv += ["-severity", severity]
        templates = request.params.get("templates")
        if templates is not None:
            templates = _single_token(templates, field="templates", pattern=self._TEMPLATE)
            argv += ["-t", templates]
        return argv


EXTENDED_ADAPTERS: tuple[type[Adapter], ...] = (
    WhoisAdapter,
    CertTransparencyAdapter,
    TlsPostureAdapter,
    HttpProbeAdapter,
    HeaderAuditAdapter,
    SmbEnumAdapter,
    TracerouteAdapter,
    PassiveDnsMultiAdapter,
    DorkSearchAdapter,
    SubdomainEnumAdapter,
    EmailOsintAdapter,
    DirEnumAdapter,
    TechFingerprintAdapter,
    DnsEnumAdapter,
    WafDetectAdapter,
    NucleiAdapter,
)
