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
    NucleiAdapter,
)
