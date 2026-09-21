"""Collection pipeline: tool output → evidence → claims.

Bridges the execution plane (adapters/broker) and the intel plane. One call::

    collect_from_adapter(broker_result, case_id, ledger, evidence_store, db=…)

parses structured tool output — DNS short answers (record-type aware), WHOIS
key/value lines and crt.sh certificate-transparency JSON — registers the raw
blob as evidence (hash-chained, via the Phase 1 store), sanitizes it for
prompt-injection content, and emits claims with deterministic confidence from
the source scoring. Every claim keeps provenance: source key, method (action),
observation time, task id and evidence id.

The pipeline never decides authorization — it consumes broker results that
already passed the six gates. Parsing failures are conservative: unknown
output yields no claims, never invented ones.
"""

from __future__ import annotations

import json
import re
import time

from ..evidence.store import EvidenceStore
from .claims import ClaimLedger
from .injection import scan_injection, sanitize_external
from .normalize import canonical_hostname
from .sources import SourceRegistry

_WHOIS_KV = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 _-]{0,40}?):\s*(\S.{0,200})$")
_NMAP_PORT = re.compile(
    r"^(\d{1,5})/(tcp|udp)\s+(open|filtered|closed)\s*(\S+)?(?:\s+(.*))?$"
)
_NMAP_SERVICE_META = re.compile(
    r"^(?P<product>[^;]+?)(?:;version:(?P<version>[^;]*))?(?:;ostype:(?P<ostype>[^;]*))?$"
)


def _parse_nmap(stdout: str) -> tuple[list[tuple[str, str]], str]:
    """Parse nmap grepable/list output into (pairs, observed_ip).

    Understands two shapes:
      * grepable (-oG -):  ``Host: 1.2.3.4 ()\tPorts: 80/open/tcp//http///``
      * list (-oN - style) port table lines: ``80/tcp   open  http  nginx 1.2``

    Returns pairs of kinds: ip, port, service, product, version. Unparseable
    lines are dropped — never invented.
    """
    pairs: list[tuple[str, str]] = []
    observed_ip = ""
    for raw_line in stdout.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        # "Nmap scan report for host (1.2.3.4)" — carries the resolved IP
        if not observed_ip:
            report_match = re.search(
                r"scan report for \S+ \((\d{1,3}(?:\.\d{1,3}){3})\)", line
            )
            if report_match:
                observed_ip = report_match.group(1)
                pairs.append(("ip", observed_ip))
                continue
        # grepable shape
        if line.startswith("Host:") and "Ports:" in line:
            try:
                host_part, ports_part = line.split("\t", 1)
            except ValueError:
                continue
            ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", host_part)
            if ip_match and not observed_ip:
                observed_ip = ip_match.group(1)
                pairs.append(("ip", observed_ip))
            if "Ports:" in ports_part:
                ports_field = ports_part.split("Ports:", 1)[1]
                for entry in ports_field.split(", "):
                    entry = entry.strip(" ")
                    match = re.match(
                        r"(\d{1,5})/(open|filtered|closed)/(tcp|udp)//([^/]*)/?/?",
                        entry,
                    )
                    if not match:
                        continue
                    port, state, proto, service = match.groups()
                    if state != "open":
                        continue
                    pairs.append(("port", f"{port}/{proto}"))
                    if service:
                        pairs.append(("service", f"{port}/{proto}:{service}"))
            continue
        # list table shape: "80/tcp   open  http  nginx 1.24.0"
        match = _NMAP_PORT.match(line.strip())
        if match:
            port, proto, state, service, rest = match.groups()
            if state != "open":
                continue
            pairs.append(("port", f"{port}/{proto}"))
            if service:
                pairs.append(("service", f"{port}/{proto}:{service}"))
            rest = (rest or "").strip()
            if rest:
                # split trailing version number off the product name
                version = ""
                prod_match = re.match(
                    r"^(?P<product>.*?)(?:\s+(?P<version>[0-9]+(?:\.[0-9]+)+))?$",
                    rest,
                )
                if prod_match:
                    product = (prod_match.group("product") or "").strip()
                    version = (prod_match.group("version") or "").strip()
                else:  # pragma: no cover - regex above always matches
                    product = rest
                if product:
                    pairs.append(("product", f"{port}/{proto}:{product}"))
                if version:
                    pairs.append(("version", f"{port}/{proto}:{version}"))
        else:
            ip_only = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})", line.strip())
            if ip_only and not observed_ip:
                observed_ip = ip_only.group(1)
                pairs.append(("ip", observed_ip))
    return pairs, observed_ip
_WHOIS_INTERESTING = {
    "registrar": "registrar",
    "creation date": "created",
    "created": "created",
    "expiry date": "expires",
    "registry expiry date": "expires",
    "updated date": "updated",
}
_DNS_LINE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")
_IPV4 = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
_HOSTNAME_LIKE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
_MX_PREF = re.compile(r"^(\d{1,3})\s+(\S+)$")
_SOA = re.compile(r"^(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$")

# Adapter action -> DNS record type hint (used when the request has no params).
_ACTION_RTYPE_DEFAULT = {"dns-lookup": "A", "passive-dns": "A"}


def _safe_value(text: str, *, max_len: int = 253) -> str:
    """Conservative value check: single token, no control chars, bounded."""
    value = text.strip().rstrip(".")
    if not value or len(value) > max_len:
        return ""
    if not _HOSTNAME_LIKE.match(value):
        return ""
    return value


_DNS_LINE = _HOSTNAME_LIKE  # retained alias for backward-compatible imports


def _parse_dns_answer(stdout: str, rtype: str) -> list[tuple[str, str]]:
    """Parse `dig +short -t <rtype>` output into (kind, value) pairs.

    Type-aware: MX preference lines and SOA m-bodies are structural, not
    claims about hosts. Unknown/ambiguous lines are dropped (fail closed for
    parsing too).
    """
    rtype = rtype.upper()
    pairs: list[tuple[str, str]] = []

    def add(kind: str, raw_value: str) -> None:
        value = _safe_value(raw_value)
        if value:
            pairs.append((kind, value))

    for line in stdout.splitlines():
        line = line.strip()
        # printable-ASCII guard (spaces allowed: MX/SOA/TXT/CAA lines have them)
        if not line or len(line) > 500 or any(ord(ch) < 32 or ord(ch) > 126 for ch in line):
            continue
        if rtype == "A":
            if _IPV4.fullmatch(line):
                add("ip", line)
        elif rtype == "AAAA":
            if ":" in line and _DNS_LINE.match(line.rstrip(".")):
                add("ipv6", line.rstrip("."))
        elif rtype == "CNAME":
            if _HOSTNAME_LIKE.match(line.rstrip(".")):
                add("cname", line.rstrip("."))
        elif rtype == "NS":
            if _HOSTNAME_LIKE.match(line.rstrip(".")):
                add("nameserver", line.rstrip("."))
        elif rtype == "PTR":
            if _HOSTNAME_LIKE.match(line.rstrip(".")):
                add("ptr", line.rstrip("."))
        elif rtype == "MX":
            match = _MX_PREF.match(line.rstrip("."))
            if match:
                add("mx", match.group(2))
        elif rtype == "TXT":
            # TXT records are free text; keep them verbatim but bounded.
            text = line.strip('"')
            if 0 < len(text) <= 255:
                pairs.append(("txt", text))
        elif rtype == "SOA":
            match = _SOA.match(line.rstrip("."))
            if match:
                add("nameserver", match.group(1))
                add("soa_contact", match.group(2))
        elif rtype == "CAA":
            # "0 issue "ca.example.org"" style — extract the issuer tag value.
            caa = re.match(r'^\d+\s+(issue|issuewild|iodef)\s+"?([^"]+)"?$', line)
            if caa:
                pairs.append(("caa", f"{caa.group(1)}:{caa.group(2).strip()}"))
    return pairs


def _parse_whois(stdout: str) -> list[tuple[str, str]]:
    """Parse WHOIS key/value lines into normalized field pairs."""
    pairs: list[tuple[str, str]] = []
    for line in stdout.splitlines():
        match = _WHOIS_KV.match(line)
        if not match:
            continue
        key = match.group(1).strip().lower()
        value = match.group(2).strip()
        mapped = _WHOIS_INTERESTING.get(key)
        if mapped and value:
            pairs.append((mapped, value))
    return pairs


def _parse_dork_hits(stdout: str, *, engine: str, dork: str
                     ) -> list[tuple[str, str]]:
    """Parse one search-engine result page into (kind, value) pairs.

    Each hit contributes a ``search_hit`` claim whose value is the hit URL,
    plus, for on-domain hits, a ``hostname`` pair (the engine surfaced a
    host on the audited domain). Engine markup is untrusted: every URL is
    scheme-checked and bounded before it becomes a claim value.
    """
    from urllib.parse import urlparse

    from .dorks import parse_dork_stdout

    pairs: list[tuple[str, str]] = []
    for hit in parse_dork_stdout(engine, stdout):
        url = hit.get("url", "")
        if not url:
            continue
        pairs.append(("search_hit", f"[{dork}] {url}"))
        host = (urlparse(url).hostname or "").lower()
        if host:
            pairs.append(("hostname", host))
    return pairs


_HOST_LINE = re.compile(r"^([A-Za-z0-9*_-]{1,80}(?:\.[A-Za-z0-9*_-]+)+)\s*$")
_EMAIL_LINE = re.compile(r"([A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}))")


def _parse_subdomain_lines(stdout: str, subject: str) -> list[tuple[str, str]]:
    """amass passive output: one FQDN per line (spinner goes to stderr).

    Only hostnames inside (or wildcarded under) the queried domain become
    claims — a data source returning unrelated hosts is noise, not scope.
    """
    base = subject.lower().lstrip("*.").split(".")[-2:]  # registrable tail
    tail = ".".join(base)
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        m = _HOST_LINE.match(line.strip())
        if not m:
            continue
        host = m.group(1).lower()
        if host in seen:
            continue
        if not (host == tail or host.endswith("." + tail)):
            continue
        seen.add(host)
        pairs.append(("hostname", host))
    return pairs


def _parse_harvester(stdout: str, subject: str) -> list[tuple[str, str]]:
    """theHarvester console output: 'Emails found' / 'Hosts found' sections."""
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for match in _EMAIL_LINE.finditer(stdout):
        email, domain = match.group(1).lower(), match.group(2).lower()
        if ("email", email) in seen:
            continue
        seen.add(("email", email))
        pairs.append(("email", email))
        if domain.endswith("." + subject.lower()) or domain == subject.lower():
            if ("hostname", domain) not in seen:
                seen.add(("hostname", domain))
                pairs.append(("hostname", domain))
    for m in _HOST_LINE.finditer(stdout):
        host = m.group(1).lower()
        if ("hostname", host) in seen:
            continue
        if host.endswith("." + subject.lower()) or host == subject.lower():
            seen.add(("hostname", host))
            pairs.append(("hostname", host))
    return pairs


def _parse_ffuf(stdout: str) -> list[tuple[str, str]]:
    """ffuf output: JSON results[] (input.FUZZ + status + url), or the bare
    word-per-line stream printed by ``-s``.

    Real-world note: some ffuf builds (2.1.0-dev) suppress ``-o -`` JSON in
    silent mode, so the word stream is the fallback contract, not noise.
    """
    pairs: list[tuple[str, str]] = []
    # The runner may interleave ANSI progress frames; the JSON object is the
    # payload — find the last one that parses.
    start = stdout.find('{"commandline"')
    if start >= 0:
        try:
            data = json.loads(stdout[start:])
            for row in (data.get("results") or [])[:100]:
                if not isinstance(row, dict):
                    continue
                fuzz = str((row.get("input") or {}).get("FUZZ", "")).strip()
                status = row.get("status")
                url = str(row.get("url", ""))
                if not fuzz and not url:
                    continue
                value = f"/{fuzz} [{status}]" if fuzz else f"{url} [{status}]"
                pairs.append(("web_path", value))
            return pairs
        except json.JSONDecodeError:
            pass
    # Fallback: the interactive progress stream. Builds without working
    # ``-o -`` print ``<word>  [Status: NNN, Size: ...]`` lines (ANSI-padded)
    # on stdout; ``-s`` prints bare words. Parse both.
    clean = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", stdout)
    for match in re.finditer(r"\b(\S{1,60}?)\s+\[Status:\s*(\d{3})", clean):
        word, status = match.group(1).strip().rstrip("/"), match.group(2)
        if re.fullmatch(r"[A-Za-z0-9._@-]{1,60}", word):
            pairs.append(("web_path", f"/{word} [{status}]"))
    if not pairs:
        for line in clean.splitlines():
            word = line.strip().rstrip("/").lstrip("/")
            if not word or " " in word or "[" in word or "{" in word:
                continue
            if not re.fullmatch(r"[A-Za-z0-9._@-]{1,60}", word):
                continue
            pairs.append(("web_path", f"/{word} [discovered]"))
    return pairs[:100]


def _parse_whatweb(stdout: str) -> list[tuple[str, str]]:
    """whatweb default output: url [plugins...] — extract Plugin[value] pairs."""
    pairs: list[tuple[str, str]] = []
    for line in stdout.splitlines():
        if "[" not in line:
            continue
        for pm in re.finditer(r"([A-Za-z0-9 ._-]{2,40})(?:\[([^\]]{0,120})\])?",
                              line.split("]", 1)[-1] if line.startswith("http") else line):
            plugin, val = pm.group(1).strip(), pm.group(2)
            if not plugin:
                continue
            pairs.append(("tech", f"{plugin}={val}" if val else plugin))
        break   # one target per run; first line carries everything
    # dedupe, bounded
    out, seen = [], set()
    for kind, value in pairs:
        if (kind, value) in seen:
            continue
        seen.add((kind, value))
        out.append((kind, value))
    return out[:40]


def _parse_dnsrecon(stdout: str) -> list[tuple[str, str]]:
    """dnsrecon console output: 'TYPE name value' INFO lines.

    dnsrecon logs to stderr, but the broker passes stdout and stderr merged
    through this parser — negative lines ("No SRV Records Found", "No answer
    for DNSSEC") must not become fake records, so each match must carry an
    explicit value token after the record name.
    """
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in stdout.splitlines():
        if not line.strip():
            continue
        # Negative results are logged at ERROR/WARNING ("No SRV Records
        # Found", "No answer for DNSSEC"); data records are INFO lines.
        if "ERROR" in line or "WARNING" in line:
            continue
        # Require TYPE + name + value: bare 'TYPE name' lines are noise
        # ("Enumerating SRV Records").
        m = re.search(r"\b(SOA|NS|MX|A|AAAA|TXT|SRV|CNAME|PTR)\s+"
                      r"([A-Za-z0-9._-]{1,253})\s+"
                      r"([0-9a-fA-F:.]{1,45}|[A-Za-z0-9._-]{1,253})", line)
        if not m:
            continue
        rtype, name, value = m.group(1), m.group(2), m.group(3)
        if value.rstrip(".") == name.rstrip("."):
            continue   # SOA self-reference style echo, not a data record
        rec = f"{name} {value}"
        key = (rtype, rec)
        if key in seen:
            continue
        seen.add(key)
        pairs.append((f"dns_{rtype.lower()}", rec))
    return pairs[:60]


def _parse_wafw00f(stdout: str) -> list[tuple[str, str]]:
    """wafw00f: '[+] The site … is behind <Name> WAF.' or nothing found.

    Generic-detection output ("seems to be behind a WAF or some sort of
    security solution") is still a real signal — recorded as ``waf generic``
    with the detection reason when present.
    """
    pairs: list[tuple[str, str]] = []
    m = re.search(r"is behind\s+(.+?)\s+WAF", stdout)
    if m:
        pairs.append(("waf", m.group(1).strip()))
    elif re.search(r"seems to be behind a WAF", stdout, re.I):
        reason = re.search(r"Reason:\s*(.+)", stdout)
        detail = reason.group(1).strip()[:120] if reason else "generic detection"
        pairs.append(("waf", f"generic ({detail})"))
    elif re.search(r"No WAF (detected|found)|seems to be behind no WAF", stdout, re.I):
        pairs.append(("waf", "none detected"))
    return pairs


def _parse_js_intel(stdout: str) -> list[tuple[str, str]]:
    """js-intel: run the jsintel extractor over one fetched JS document."""
    from .jsintel import extract

    report = extract(stdout)
    pairs: list[tuple[str, str]] = []
    for item in report["endpoints"]:
        pairs.append(("js_endpoint", item["value"]))
    for item in report["secrets"]:
        pairs.append((f"js_secret:{item['kind']}", item["value"]))
    for item in report["hosts"]:
        pairs.append(("js_cloud_host", item["value"]))
    return pairs[:120]


_WAYBACK_URL_RE = re.compile(r"https?://\S{4,300}")


def _parse_wayback(stdout: str, subject: str) -> list[tuple[str, str]]:
    """wayback-urls: CDX 'original' column lines; keep in-scope hosts only.

    The archive returns URLs for any host whose capture matched the CDX
    query — including out-of-scope CDNs the target once referenced. Claims
    are only emitted for URLs on the queried subject, so the ledger never
    silently grows claims about hosts the case never authorized.
    """
    from urllib.parse import urlparse

    host_suffix = "." + subject.lower().lstrip(".")
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        url = line.strip()
        if not url or url in seen:
            continue
        seen.add(url)
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            continue
        if host == subject.lower() or host.endswith(host_suffix):
            pairs.append(("wayback_url", url[:300]))
        if len(pairs) >= 150:
            break
    return pairs


def _parse_probe(stdout: str) -> list[tuple[str, str]]:
    """probe: parse the response head — status line + selected headers."""
    pairs: list[tuple[str, str]] = []
    m = re.search(r"HTTP/[0-9.]+\s+(\d{3})(?:[^\r\n]*)?", stdout)
    if m:
        pairs.append(("probe_status", m.group(1)))
    for name in ("server", "content-type", "content-length", "location",
                 "www-authenticate", "x-powered-by"):
        hm = re.search(rf"^{re.escape(name)}:\s*(.{{1,200}})\s*$",
                       stdout, re.I | re.M)
        if hm:
            pairs.append(("probe_header", f"{name}: {hm.group(1).strip()}"))
    return pairs


def _parse_ct_json(stdout: str, *, limit: int = 50) -> list[tuple[str, str]]:
    """Parse crt.sh JSON output into (kind, value) pairs.

    Each entry contributes a certificate (name, id) pair plus hostname
    candidates from name_value. Malformed JSON yields nothing — never guesses.
    """
    pairs: list[tuple[str, str]] = []
    try:
        entries = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return pairs
    if not isinstance(entries, list):
        return pairs
    for entry in entries[:limit]:
        if not isinstance(entry, dict):
            continue
        cert_id = entry.get("id")
        common = entry.get("common_name") or ""
        if isinstance(cert_id, (int, str)) and common:
            pairs.append(("certificate", f"id={cert_id} cn={common}"))
        names_field = entry.get("name_value") or ""
        if isinstance(names_field, str):
            for name in names_field.split("\n"):
                host = _safe_value(name)
                if host:
                    pairs.append(("hostname", host))
    return pairs


class CollectionPipeline:
    """Turns executed-action outputs into evidence-linked claims.

    When a :class:`~rebel_profiler.storage.database.Database` is supplied,
    emitted claims are persisted (migration v2 ``claims`` table) so CLI and
    reporting layers can read them back.
    """

    def __init__(
        self,
        ledger: ClaimLedger,
        evidence: EvidenceStore,
        registry: SourceRegistry | None = None,
        db=None,
    ) -> None:
        self.ledger = ledger
        self.evidence = evidence
        self.registry = registry or SourceRegistry()
        self._db = db

    def ingest(
        self,
        case_id: str,
        *,
        action: str,
        target: str,
        stdout: str,
        stderr: str = "",
        returncode: int = 0,
        task_id: str = "",
        evidence_id: str | None = None,
        source_key: str = "",
        params: dict | None = None,
    ) -> dict:
        """Ingest one completed action result.

        If *evidence_id* is empty the raw output is registered as new evidence
        (hash-chained). Returns a report: evidence id, sanitization findings
        and the claims emitted (deduplicated per (kind, value) within the
        batch — each claim still carries full provenance).
        """
        params = params or {}
        if not evidence_id:
            blob = (
                f"action: {action}\ntarget: {target}\ntask: {task_id}\n"
                f"rc: {returncode}\n\n{stdout}\n{stderr}"
            ).encode()
            rec = self.evidence.register(
                case_id, kind="tool_output", data=blob, source=action,
                note=f"collection for {target}", meta={"task_id": task_id, "action": action},
            )
            evidence_id = rec.id

        # Injection scan on the raw text — findings attach to the report; the
        # sanitized form is what any LLM-facing consumer should receive.
        findings = scan_injection(stdout + "\n" + stderr)
        source_key = source_key or self._default_source_for(action)

        subject = canonical_hostname(target)
        now = time.time()
        emitted: list = []
        seen: set[tuple[str, str]] = set()

        # exec-tool wrapping a whitelisted tool: route parsing by the wrapped tool
        effective_action = action
        effective_params = params
        if action == "exec-tool":
            tool = str(params.get("tool", "")).lower()
            if tool == "nmap":
                effective_action = "service-detect"   # nmap-shaped output
            # dig/whois wrap into their natural parsers via source mapping below
            elif tool in {"dig", "host"}:
                effective_action = "dns-lookup"
            elif tool == "whois":
                effective_action = "whois-lookup"

        if effective_action in {"port-scan", "service-detect", "os-fingerprint"}:
            pairs, observed_ip = _parse_nmap(stdout)
            # nmap reports the resolved IP of the scoped host — record it as a
            # claim on the same subject so exposure mapping can bind ports.
            for kind, value in pairs:
                key = (kind, value.strip().lower())
                if key in seen:
                    continue
                seen.add(key)
                emitted.append(self.ledger.add(
                    case_id, subject=subject, kind=kind, value=value,
                    source=source_key or "scan.nmap", method=action,
                    observed_at=now, evidence_id=evidence_id,
                    notes=f"task={task_id}"
                    + ("; " + "; ".join(f.rule for f in findings) if findings else ""),
                ))
            report_claims = [c.as_dict() for c in emitted]
            if self._db is not None:
                self._persist(emitted, case_id)
            return {
                "case_id": case_id,
                "action": action,
                "target": target,
                "evidence_id": evidence_id,
                "injection_findings": [f.as_dict() for f in findings],
                "clean": not findings,
                "claims_emitted": [c.id for c in emitted],
                "claims": report_claims,
                "observed_ip": observed_ip,
                "sanitized_preview": sanitize_external(stdout, source=action) if findings else "",
            }

        if effective_action == "cert-transparency":
            pairs = _parse_ct_json(stdout)
        elif effective_action in _ACTION_RTYPE_DEFAULT:
            rtype = str(effective_params.get("record_type", _ACTION_RTYPE_DEFAULT[effective_action]))
            pairs = _parse_dns_answer(stdout, rtype)
        elif effective_action == "whois-lookup":
            pairs = _parse_whois(stdout)
        elif effective_action == "dork-search":
            pairs = _parse_dork_hits(stdout,
                                     engine=str(effective_params.get("engine", "google")),
                                     dork=str(effective_params.get("dork", "")))
        elif effective_action == "subdomain-enum":
            pairs = _parse_subdomain_lines(stdout, subject)
        elif effective_action == "email-osint":
            pairs = _parse_harvester(stdout, subject)
        elif effective_action == "dir-enum":
            pairs = _parse_ffuf(stdout)
        elif effective_action == "tech-fingerprint":
            pairs = _parse_whatweb(stdout)
        elif effective_action == "dns-enum":
            # dnsrecon logs its findings to stderr — parse the merged stream
            pairs = _parse_dnsrecon(stdout + "\n" + stderr)
        elif effective_action == "waf-detect":
            pairs = _parse_wafw00f(stdout)
        elif effective_action == "js-intel":
            pairs = _parse_js_intel(stdout)
        elif effective_action == "wayback-urls":
            pairs = _parse_wayback(stdout, subject)
        elif effective_action == "probe":
            pairs = _parse_probe(stdout)
        else:
            pairs = []

        for kind, value in pairs:
            key = (kind, value.strip().lower())
            if key in seen:
                continue
            seen.add(key)
            claim = self.ledger.add(
                case_id, subject=subject, kind=kind, value=value,
                source=source_key, method=action, observed_at=now,
                evidence_id=evidence_id,
                notes=f"task={task_id}" + ("; " + "; ".join(f.rule for f in findings) if findings else ""),
            )
            emitted.append(claim)

        if self._db is not None:
            self._persist(emitted, case_id)

        return {
            "case_id": case_id,
            "action": action,
            "target": target,
            "evidence_id": evidence_id,
            "injection_findings": [f.as_dict() for f in findings],
            "clean": not findings,
            "claims_emitted": [c.id for c in emitted],
            "claims": [c.as_dict() for c in emitted],
            "sanitized_preview": sanitize_external(stdout, source=action) if findings else "",
        }

    def _persist(self, emitted, case_id: str) -> None:
        for claim in emitted:
            self._db.record_claim(
                claim.id, case_id,
                subject=claim.subject, kind=claim.kind, value=claim.value,
                source=claim.source, method=claim.method,
                observed_at=claim.observed_at, confidence=claim.confidence,
                evidence_id=claim.evidence_id, state=claim.state,
                notes=claim.notes,
            )
            self._db.record_observation(
                case_id, kind=claim.kind, value=claim.value,
                confidence=claim.confidence, source=claim.source,
                method=claim.method, evidence_id=claim.evidence_id,
                observed_at=claim.observed_at,
            )

    @staticmethod
    def _default_source_for(action: str) -> str:
        return {
            "dns-lookup": "dns.authoritative",
            "passive-dns": "dns.authoritative",
            "whois-lookup": "whois.registrar",
            "cert-transparency": "ct.logs",
            "port-scan": "scan.nmap",
            "service-detect": "scan.nmap",
            "os-fingerprint": "scan.nmap",
            "exec-tool": "scan.tool",
            "dork-search": "search.engine",
            "subdomain-enum": "osint.datasource",
            "email-osint": "osint.datasource",
            "dir-enum": "scan.web",
            "tech-fingerprint": "scan.web",
            "dns-enum": "dns.authoritative",
            "waf-detect": "scan.web",
            "js-intel": "js.static",
            "wayback-urls": "archive.wayback",
            "probe": "scan.web",
        }.get(action, "unknown")


def collect_from_adapter(
    execution_result,
    case_id: str,
    ledger: ClaimLedger,
    evidence: EvidenceStore,
    registry: SourceRegistry | None = None,
    db=None,
    params: dict | None = None,
) -> dict:
    """Convenience bridge from an ExecutionResult (broker) to the pipeline."""
    pipeline = CollectionPipeline(ledger, evidence, registry, db=db)
    return pipeline.ingest(
        case_id,
        action=execution_result.action,
        target=execution_result.target,
        stdout=execution_result.stdout,
        stderr=execution_result.stderr,
        returncode=execution_result.returncode or 1,
        task_id=execution_result.task_id,
        evidence_id=execution_result.evidence_id,
        params=params,
    )
