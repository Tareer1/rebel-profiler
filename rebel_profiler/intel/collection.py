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

import csv
import io
import json
import re
import time
from urllib.parse import urlsplit

from ..evidence.store import EvidenceStore
from .claims import ClaimLedger
from .injection import scan_injection, sanitize_external
from .normalize import canonical_hostname
from .sources import SourceRegistry


def _parse_wireless_survey(stdout: str, stderr: str = "") -> list[tuple[str, str]]:
    """Collect airodump CSV pairs from a survey run's captured streams.

    airodump-ng writes the CSV file (rp_survey-01.csv) rather than stdout;
    both the file contents (when a runner merged it) and any stdout echo are
    accepted. Parsing is the same deterministic CSV discipline as every
    other parser: unknown lines yield nothing.
    """
    from ..execution.wireless import parse_airodump_csv

    pairs: list[tuple[str, str]] = []
    for stream in (stdout, stderr):
        if "First time seen" in stream or "BSSID" in stream:
            pairs.extend(parse_airodump_csv(stream))
    return pairs


_WHOIS_KV = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 _-]{0,40}?):\s*(\S.{0,200})$")
_NMAP_PORT = re.compile(
    r"^(\d{1,5})/(tcp|udp)\s+(open|filtered|closed)\s*(\S+)?(?:\s+(.*))?$"
)
_NMAP_SERVICE_META = re.compile(
    r"^(?P<product>[^;]+?)(?:;version:(?P<version>[^;]*))?(?:;ostype:(?P<ostype>[^;]*))?$"
)


def _parse_nmap(stdout: str) -> tuple[list[tuple[str, str]], str]:
    """Parse nmap grepable/list output into (pairs, observed_ip).

    Understands three shapes:
      * sweep (-sn, host-discovery): ``Nmap scan report for 1.2.3.4`` +
        ``MAC Address: AA:BB:.. (Vendor)`` → per-host ``lan_device`` claims
      * grepable (-oG -):  ``Host: 1.2.3.4 ()\tPorts: 80/open/tcp//http///``
      * list (-oN - style) port table lines: ``80/tcp   open  http  nginx 1.2``

    Returns pairs of kinds: lan_device, ip, port, service, product, version.
    Unparseable lines are dropped — never invented.
    """
    pairs: list[tuple[str, str]] = []
    observed_ip = ""
    pending_host = ""          # sweep shape: host seen, MAC line may follow
    for raw_line in stdout.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        # sweep shape: "Nmap scan report for 1.2.3.4" or "... for host (1.2.3.4)"
        report_match = re.search(
            r"scan report for (?:\S+ \()?(\d{1,3}(?:\.\d{1,3}){3})\)?", line
        )
        if report_match:
            ip = report_match.group(1)
            pending_host = ip
            pairs.append(("lan_device", ip))
            if not observed_ip:
                observed_ip = ip
                pairs.append(("ip", observed_ip))
            continue
        # sweep shape vendor line: "MAC Address: E4:A8:B6:33:A5:63 (Huawei...)"
        mac_match = re.match(
            r"MAC Address:\s*([0-9A-Fa-f:]{17})(?:\s*\(([^)]+)\))?", line.strip()
        )
        if mac_match and pending_host:
            mac, vendor = mac_match.group(1).upper(), (mac_match.group(2) or "").strip()
            value = f"{pending_host} {mac}" + (f" ({vendor})" if vendor else "")
            pairs.append(("lan_device", value))
            pending_host = ""
            continue
        if "Host is up" in line:
            continue
        # "Nmap done: 256 IP addresses (3 hosts up) scanned" — summary noise
        if line.startswith("Nmap done:"):
            continue
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
    """js-intel: run the jsintel extractor over one fetched JS document.

    The broker's stdout arrives *redacted* (assignment_secret pattern), so
    ``apiKey: "<value>"`` shapes may show ``[REDACTED]`` as the value. The
    fact a key-shaped assignment exists is still the finding — recorded as
    a secret-candidate claim with the redaction noted, never silently
    dropped. Confidence stays honest: unverifiable candidates.
    """
    from .jsintel import extract

    report = extract(stdout)
    pairs: list[tuple[str, str]] = []
    for item in report["endpoints"]:
        pairs.append(("js_endpoint", item["value"]))
    for item in report["secrets"]:
        redacted = "[REDACTED]" in item["value"] or "REDACTED" in item["value"]
        value = "(redacted in transit — key-shaped assignment present)" if redacted \
            else item["value"]
        pairs.append((f"js_secret:{item['kind']}", value))
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


def _parse_httpx_json(stdout: str) -> list[tuple[str, str]]:
    """httpx -json: one JSON object per live host (newline-delimited).

    Extracts the bounty-relevant head: status code, page title, detected
    technologies and the resolved IP. A malformed line is skipped, never
    guessed — the rest of the batch still parses.
    """
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        host = str(row.get("host") or row.get("url") or "").strip()
        if not host:
            continue
        status = row.get("status_code")
        if status:
            key = ("httpx_status", f"{host}:{status}")
            if key not in seen:
                seen.add(key)
                pairs.append(("httpx_status", f"{host}:{status}"))
        title = str(row.get("title") or "").strip()
        if title:
            key = ("httpx_title", title[:200])
            if key not in seen:
                seen.add(key)
                pairs.append(("httpx_title", title[:200]))
        for tech in (row.get("technologies") or []):
            name = str(tech if isinstance(tech, str) else tech.get("name", "")).strip()
            if name:
                key = ("httpx_tech", name[:120])
                if key not in seen:
                    seen.add(key)
                    pairs.append(("httpx_tech", name[:120]))
        ip = str(row.get("ip") or "").strip()
        if ip:
            key = ("ip", ip)
            if key not in seen:
                seen.add(key)
                pairs.append(("ip", ip))
        if len(pairs) >= 200:
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


def _parse_param_hunt(stdout: str, subject: str) -> list[tuple[str, str]]:
    """arjun output: '<url>\t<param>' rows (-oT) or bare param names.

    Only in-scope hosts become claims — same discipline as the wayback
    parser: out-of-scope noise from the tool is filtered, never stored.
    """
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    base = subject.lower().lstrip("*.").split(".")[-2:]
    tail = ".".join(base)
    for line in stdout.splitlines():
        line = line.strip()
        if not line or "\t" not in line and "/" in line:
            # '<url>\t<param>' expected; a URL with no tab is the row header
            if "\t" in line:
                pass
            else:
                continue
        url_part, _, param = line.partition("\t")
        param = (param or url_part).strip().strip("/")
        if not param or len(param) > 60 or " " in param:
            continue
        if "\t" in line:
            host = (urlsplit(url_part.strip()).hostname or "").lower()
            if host and not (host == tail or host.endswith("." + tail)):
                continue
        if param in seen:
            continue
        seen.add(param)
        pairs.append(("param", param))
    return pairs[:100]


def _parse_nikto_csv(stdout: str) -> list[tuple[str, str]]:
    """nikto -Format csv -o -: header line + one finding per row.

    nikto CSV columns: Item,Name,References,Method,URI,IP,Hostname,Timestamp.
    The Name column carries the finding text; the URI, when present, names
    where it lives. Rows without a name are the run summary — skipped.
    """
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in csv.reader(io.StringIO(stdout)):
        if not row or not row[0].strip().isdigit():
            continue   # header line, blank lines, footer
        if len(row) < 3:
            continue
        name = row[1].strip()
        if not name or name.lower().startswith(("+", "items tested")):
            continue
        uri = row[4].strip() if len(row) > 4 else ""
        value = f"{name[:160]}" + (f" @ {uri[:120]}" if uri else "")
        refs = row[2].strip() if len(row) > 2 else ""
        key = ("nikto_finding", value.lower())
        if key in seen:
            continue
        seen.add(key)
        pairs.append(("nikto_finding", value))
        if refs:
            pairs.append(("nikto_reference", refs[:160]))
    return pairs[:80]


def _parse_wpscan_text(stdout: str) -> list[tuple[str, str]]:
    """wpscan text output: '[i]|(!)|[!] Section: detail' lines.

    The alert lines (!) are the findings; info lines (i) carry the
    version/tech context. Brute-force / config-backup sections never
    appear because the adapter cannot run them (no wordlist params).
    """
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line or len(line) < 8:
            continue
        m = re.match(r"^\[([!i])\]\s+([^\n]{4,180})", line)
        if not m:
            continue
        level, text = m.group(1), m.group(2).strip()
        kind = "wp_finding" if level == "!" else "wp_info"
        # wpscan flags interesting files as 'The URL is...' findings too;
        # both shapes carry a URL or a version — keep those readable
        key = (kind, text.lower())
        if key in seen:
            continue
        seen.add(key)
        pairs.append((kind, text[:200]))
    return pairs[:60]


def _parse_cors_headers(stdout: str) -> list[tuple[str, str]]:
    """curl -i response to a foreign-Origin request: the ACAO verdict.

    One POST-less GET, one verdict claim. Reflected ACAO with credentials
    allowed is the exploitable CORS misconfig shape; a missing ACAO (the
    correct posture) is recorded as a clean check so the report can say
    the control was tested — an empty result is indistinguishable from an
    unrun one, and the deterministic-parser discipline forbids that.
    """
    # curl -sS appends error lines to stderr; stdout of -i is headers+body
    acao = ""
    acac = ""
    for line in stdout.splitlines():
        stripped = line.strip()
        low = stripped.lower()
        if low.startswith("access-control-allow-origin:"):
            acao = stripped.split(":", 1)[1].strip()
        elif low.startswith("access-control-allow-credentials:"):
            acac = stripped.split(":", 1)[1].strip().lower()
    if not acao:
        return [("cors_check", "acao_reflected:no")]
    reflected = "evil-cors-probe.example" in acao.lower()
    if reflected and acac == "true":
        verdict = "acao_reflected:yes; allow-credentials:true — exploitable shape"
    elif reflected:
        verdict = "acao_reflected:yes; allow-credentials not true"
    else:
        verdict = f"acao_present:{acao[:80]}"
    return [("cors_check", verdict)]


def _parse_security_txt(stdout: str) -> list[tuple[str, str]]:
    """Two curl fetches (/.well-known/security.txt, /security.txt) → verdict.

    Either canonical location counts as present (RFC 9116); presence is
    the control. Field lines (Contact:, Policy:) become context claims —
    they tell the operator where to report, they are not findings.
    """
    pairs: list[tuple[str, str]] = []
    present = False
    for block in stdout.split("--\r\n"):
        head = block[:2048]
        if not head.strip("\r\n"):
            continue
        # first line of a curl -i response block is the HTTP status line
        status_line = head.splitlines()[0] if head.splitlines() else ""
        if re.search(r"HTTP/[\d.]+\s+2\d\d", status_line):
            present = True
        for line in head.splitlines()[1:]:
            stripped = line.strip()
            if stripped[:8].lower() in {"contact:", "policy:", "expires:"}:
                value = stripped[:160]
                if ("securitytxt_field", value.lower()) not in [
                        (k, v.lower()) for k, v in pairs]:
                    pairs.append(("securitytxt_field", value))
    pairs.append(("securitytxt_check",
                  "security.txt present (RFC 9116)" if present
                  else "security.txt missing at both canonical locations"))
    return pairs[:20]


def _parse_graphql_introspection(stdout: str) -> list[tuple[str, str]]:
    """curl POST of a minimal __schema probe → one exposure verdict.

    The probe asks ONLY for the query type's name — no schema dump, no
    mutations. A JSON body naming a queryType means introspection is
    publicly readable (CWE-200 posture); an error/denial body means it is
    closed. Anything unparseable yields NO claim.
    """
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []
    if "errors" in payload and "data" not in payload:
        detail = str(payload["errors"])[:140]
        return [("graphql_introspection", f"introspection:disabled ({detail})")]
    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("__schema"), dict):
        qtype = (data["__schema"].get("queryType") or {}).get("name")
        if qtype:
            return [("graphql_introspection",
                     f"introspection:enabled; queryType={qtype[:60]} — "
                     "schema is publicly readable (CWE-200 posture)")]
    return []


def _parse_dmarc(stdout: str) -> list[tuple[str, str]]:
    """dig +short TXT domain + _dmarc.domain → SPF/DMARC posture.

    dig prints one TXT record per line (quoted chunks). The FIRST chunk
    matching v=spf1 / v=DMARC1 wins per protocol; enforcement is read
    from the policy tag. A domain with no SPF and p=none (or no DMARC at
    all) is spoofable — the phishing-prerequisite finding.
    """
    spf: str | None = None
    dmarc: str | None = None
    for raw in stdout.splitlines():
        line = raw.strip().strip('"')
        low = line.lower()
        if spf is None and low.startswith("v=spf1"):
            spf = line
        elif dmarc is None and low.startswith("v=dmarc1"):
            dmarc = line
    if spf is None and dmarc is None:
        return [("email_spoofing",
                 "spoofing posture:no SPF and no DMARC — domain is spoofable")]
    spf_state = ("spf:present" if spf else "spf:absent")
    if dmarc is None:
        dmarc_state = "dmarc:absent"
    else:
        m = re.search(r"p=(\w+)", dmarc, re.IGNORECASE)
        policy = (m.group(1).lower() if m else "none")
        dmarc_state = f"dmarc:present; p={policy}"
        if policy not in {"quarantine", "reject"}:
            dmarc_state += " — non-enforcing (spoofing possible)"
    return [("email_spoofing", f"spoofing posture:{spf_state}; {dmarc_state}")]


def _parse_searchsploit_json(stdout: str) -> list[tuple[str, str]]:
    """searchsploit --json: {"RESULTS_EXPLOIT":[{Title,ID,...}]}.

    Advisory-only: each result becomes one exploit_candidate claim with
    its EDB id — the operator reads them; nothing is ever executed.
    """
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    results = payload.get("RESULTS_EXPLOIT") or []
    if not isinstance(results, list):
        return []
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for row in results[:40]:
        if not isinstance(row, dict):
            continue
        title = str(row.get("Title", "")).strip()[:160]
        edb = str(row.get("EDB-ID", row.get("Code", ""))).strip()[:20]
        if not title:
            continue
        key = title.lower()
        if key in seen:
            continue
        seen.add(key)
        pairs.append(("exploit_candidate", f"{title} (EDB-{edb})" if edb else title))
    return pairs


def _parse_tcpdump_summary(stdout: str) -> list[tuple[str, str]]:
    """tcpdump -nn -q: one summary line per captured packet.

    Claims are PROTOCOL AGGREGATES (packet counts per proto/port pair),
    never per-packet dumps — no addresses of bystanders, no payloads.
    """
    counts: dict[str, int] = {}
    for line in stdout.splitlines():
        if ">" not in line:
            continue
        # 'IP 10.0.0.1.53022 > 10.0.0.2.443: tcp 0' → proto 'tcp:443'
        # (the DESTINATION port names the service; match caselessly —
        # tcpdump -q prints the proto in lowercase)
        dst = line.split(">", 1)[-1]
        m = re.search(r"\.([0-9]{1,5}):\s*(tcp|udp)\b", dst, re.IGNORECASE)
        if m:
            proto = m.group(2).lower()
            key = f"{proto}:{m.group(1)}"
        else:
            # ICMP/ARP lines carry no port: aggregate by proto only
            m2 = re.search(r":\s*(icmp|arp)\b", dst, re.IGNORECASE)
            if not m2:
                continue
            key = m2.group(1).lower()
        counts[key] = counts.get(key, 0) + 1
    # aggregates only: 'packets tcp:443=137' — no addresses, no payloads
    return [("capture_summary", f"packets {k}={v}")
            for k, v in sorted(counts.items())][:30]


def _parse_checksec(stdout: str) -> list[tuple[str, str]]:
    """checksec --file= output: 'CANARY	true'-style mitigation rows.

    Each ENABLED/DISABLED mitigation becomes one claim so the report can
    state the binary's exploit-prevention posture factually.
    """
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z][A-Za-z0-9 _-]{1,30}?)\s*[:|=]\s*"
                     r"(Canary|NX|PIE|RELRO| fortify|no fortify|FORTIFY)?"
                     r"\s*(enabled|disabled|yes|no|true|false|full|partial|"
                     r"no relro|partial relro|full relro|nx enabled|nx disabled)",
                     line, re.IGNORECASE)
        if m:
            name = m.group(1).strip().lower().replace(" ", "_")
            value = m.group(3).lower()
            key = f"{name}={value}"
            if key in seen:
                continue
            seen.add(key)
            pairs.append(("binary_mitigation", key))
            continue
        low = line.lower()
        for mitigation in ("canary", "nx", "pie", "relro", "fortify"):
            if mitigation in low and ("enabled" in low or "disabled" in low
                                      or "relro" in low):
                state = "disabled" if ("disabled" in low or "no " + mitigation in low) \
                    else "enabled"
                key = f"{mitigation}={state}"
                if key not in seen:
                    seen.add(key)
                    pairs.append(("binary_mitigation", key))
                break
    return pairs[:20]


def _parse_binary_info(stdout: str) -> list[tuple[str, str]]:
    """readelf -h -d: header class/machine/type + needed libraries.

    Identity card of the sample: what it is, what it links against.
    """
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^Class:\s*(.+)$", line)
        if m:
            pairs.append(("binary_class", m.group(1).strip()[:60]))
            continue
        m = re.match(r"^Machine:\s*(.+)$", line)
        if m:
            pairs.append(("binary_arch", m.group(1).strip()[:80]))
            continue
        m = re.match(r"^Type:\s*(.+)$", line)
        if m:
            pairs.append(("binary_type", m.group(1).strip()[:60]))
            continue
        m = re.match(r"^\s*NEEDED\s+(?:Shared library:\s*)?\[?(.+?)\]?\s*$", line)
        if m:
            lib = m.group(1).strip()[:120]
            key = f"lib:{lib.lower()}"
            if lib and key not in seen:
                seen.add(key)
                pairs.append(("binary_library", lib))
        m = re.match(r"^\s*(RUNPATH|RPATH)\s+\[?(.+?)\]?\s*$", line)
        if m:
            pairs.append(("binary_runpath", m.group(2).strip()[:200]))
    # dedupe, keep order, bounded
    out, seen2 = [], set()
    for kind, value in pairs:
        key = (kind, value.lower())
        if key in seen2:
            continue
        seen2.add(key)
        out.append((kind, value))
    return out[:40]


def _parse_strings(stdout: str, *, max_claims: int = 60) -> list[tuple[str, str]]:
    """Printable strings → IOC-candidate claims, pattern-classified.

    Full string dumps would flood the ledger; the parser keeps only
    strings that LOOK like artifacts (URLs, IPs, domains, file paths,
    registry keys, base64-ish blobs) and caps the count. Everything else
    is noise and never becomes a claim.
    """
    patterns = (
        ("string_url", re.compile(r"(?:https?|ftp)://[A-Za-z0-9./_?&=%~-]{4,120}")),
        ("string_ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
        ("string_domain", re.compile(r"\b[A-Za-z0-9][A-Za-z0-9-]{1,40}\.(?:com|net|org|io|ru|cn|xyz|top|info|biz)(?:\.[a-z]{2,3})?\b")),
        ("string_path", re.compile(r"(?:/[A-Za-z0-9._-]{2,30}){2,}|[A-Z]:\\\\[A-Za-z0-9._\\-]{2,60}")),
        ("string_regkey", re.compile(r"HKEY_[A-Z_]+\\\\[A-Za-z0-9_\\-]{2,60}")),
        ("string_crypto", re.compile(r"(?:AES|RSA|DES|RC4|base64|md5|sha1|sha256|Crypt(?:Encrypt|Decrypt))", re.IGNORECASE)),
    )
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw in stdout.splitlines():
        if len(pairs) >= max_claims:
            break
        s = raw.strip()
        if len(s) < 6:
            continue
        for kind, pattern in patterns:
            m = pattern.search(s)
            if m:
                value = m.group(0)[:160]
                key = value.lower()
                if key not in seen:
                    seen.add(key)
                    pairs.append((kind, value))
                break
    return pairs


def _parse_symbols(stdout: str, *, max_claims: int = 40) -> list[tuple[str, str]]:
    """nm -D output: undefined imports are the behavioral hints.

    Only interesting imports (network, process, crypto, dynamic code) and
    the exported symbol count become claims — the full table is noise.
    """
    interesting = re.compile(
        r"\b(socket|connect|bind|listen|accept|send|recv|execve?|system|fork|"
        r"popen|dlopen|dlsym|mmap|crypt|encrypt|decrypt|CreateProcess|"
        r"WinExec|URLDownload|InternetOpen|VirtualAlloc|WriteProcessMemory)\b",
        re.IGNORECASE)
    exports = 0
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        symbol = parts[-1]
        if len(parts) >= 2 and parts[0].upper() in {"U", "W"}:
            kind = "symbol_import"
        elif symbol and not line.strip().startswith(("//", "nm:")):
            exports += 1
            kind = ""
        else:
            kind = ""
        if kind and symbol and symbol.lower() not in seen:
            if interesting.search(symbol):
                seen.add(symbol.lower())
                pairs.append((kind, symbol[:120]))
    if exports:
        pairs.insert(0, ("symbol_exports", f"{exports} exported symbols"))
    return pairs[:max_claims]


def _parse_disasm(stdout: str) -> list[tuple[str, str]]:
    """objdump disassembly → section-level observations, not instruction dumps.

    Calls to interesting libc functions and the instruction count become
    claims; individual instructions stay in evidence, never in the ledger.
    """
    calls: list[str] = []
    instructions = 0
    for line in stdout.splitlines():
        if ">:" in line and line.strip().endswith(":"):
            continue
        if re.search(r"\bcall\b", line):
            m = re.search(r"call.*<([^>]+)>", line)
            if m:
                calls.append(m.group(1).strip()[:100])
        elif re.search(r"\b(mov|push|pop|lea|jmp|jne|je|ret|test|cmp|xor)\b", line):
            instructions += 1
    pairs: list[tuple[str, str]] = []
    if instructions:
        pairs.append(("disasm_summary", f"{instructions} instructions disassembled"))
    seen: set[str] = set()
    for call in calls[:20]:
        if call.lower() not in seen:
            seen.add(call.lower())
            pairs.append(("disasm_call", call))
    return pairs[:30]


def _parse_lynis(stdout: str) -> list[tuple[str, str]]:
    """lynis audit system: 'suggestion[]' lines are the hardening gaps.

    Lynis prints 'suggestion[]LYN-TSTN-XXX|Category|Detail' rows in the
    results block. Each becomes one hardening_suggestion claim — defensive
    guidance for the operator's own machine, never offensive data.
    """
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("suggestion["):
            continue
        payload = line[len("suggestion["):].split("]", 1)[-1]
        parts = payload.split("|")
        if not parts:
            continue
        detail = (parts[-1] if len(parts) > 2 else parts[0]).strip()[:180]
        test_id = parts[0].strip() if parts else ""
        value = f"{test_id}: {detail}" if test_id else detail
        key = value.lower()
        if not detail or key in seen:
            continue
        seen.add(key)
        pairs.append(("hardening_suggestion", value))
    return pairs[:100]


def _parse_nuclei_jsonl(stdout: str) -> list[tuple[str, str]]:
    """nuclei -jsonl: one JSON object per finding on stdout.

    Each finding contributes (nuclei_finding, '<template> [<severity>] <host>')
    plus (nuclei_detail, template-meta). Malformed lines are skipped — the
    engine's progress chatter never becomes a claim.
    """
    pairs: list[tuple[str, str]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        template = str(row.get("template-id") or row.get("templateID") or "").strip()
        if not template or len(template) > 120:
            continue
        severity = str(row.get("info", {}).get("severity", "unknown")
                       if isinstance(row.get("info"), dict) else "unknown")
        host = str(row.get("host") or row.get("matched") or "")[:200]
        name = str((row.get("info") or {}).get("name", "") if isinstance(row.get("info"), dict) else "")[:120]
        value = f"{template} [{severity}] {host}" + (f" — {name}" if name else "")
        pairs.append(("nuclei_finding", value))
        extracted = row.get("extracted-results") or []
        if isinstance(extracted, list) and extracted:
            pairs.append(("nuclei_detail", f"{template}: {str(extracted[0])[:160]}"))
    return pairs[:100]


_HEADER_INTEREST = re.compile(
    r"^(strict-transport-security|content-security-policy|x-frame-options|"
    r"x-content-type-options|referrer-policy|permissions-policy|location|"
    r"server|x-powered-by)\s*:\s*(.{1,200})$", re.I)
_COOKIE_LINE = re.compile(r"^set-cookie\s*:\s*([^=;]{1,60}=)(.{0,200})", re.I)


def _parse_header_head(stdout: str) -> list[tuple[str, str]]:
    """curl -sSI header head: security headers + cookie FLAGS become claims.

    Cookie values are secrets — only the name and the flags
    (Secure/HttpOnly/SameSite) are recorded, never the value.
    """
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        cookie = _COOKIE_LINE.match(line)
        if cookie:
            name, rest = cookie.group(1).rstrip("="), cookie.group(2).lower()
            flags = [f for f in ("secure", "httponly", "samesite=strict",
                                 "samesite=lax", "samesite=none") if f in rest]
            value = f"{name}: {'; '.join(flags) if flags else 'no security flags'}"
            key = f"cookie:{name.lower()}"
            if key not in seen:
                seen.add(key)
                pairs.append(("cookie_flag", value))
            continue
        hm = _HEADER_INTEREST.match(line)
        if hm:
            name, value = hm.group(1).lower(), hm.group(2).strip()
            key = f"header:{name}"
            if key not in seen:
                seen.add(key)
                pairs.append(("header_obs", f"{name}: {value}"))
    return pairs[:40]


def _parse_sslscan(stdout: str) -> list[tuple[str, str]]:
    """sslscan output: enabled/disabled protocols + cipher + vuln markers."""
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        line = line.strip()
        pm = re.match(r"^(SSLv2|SSLv3|TLSv1\.[0-3]|TLSv1)\s+(enabled|disabled)", line, re.I)
        if pm:
            proto, state = pm.group(1).lower(), pm.group(2).lower()
            key = f"proto:{proto}"
            if key not in seen:
                seen.add(key)
                # enabled legacy protocol is the finding; enabled TLS1.2/1.3 is a pass
                if state == "enabled":
                    pairs.append(("tls_protocol", f"{proto} enabled"
                                  + (" (legacy — downgrade risk)" if proto in {"sslv2", "sslv3", "tlsv1.0", "tlsv1.1"} else "")))
            continue
        vm = re.search(r"(heartbleed|CCS|logjam|FREAK|POODLE)[:\s]", line, re.I)
        if vm:
            # Skip sslscan section headers ('Heartbleed:') and 'not
            # vulnerable' noise; only an actual vulnerable verdict is a claim.
            is_header = line.rstrip().endswith(":")
            says_not = "not vulnerable" in line.lower()
            if vm and not is_header and not says_not:
                key = f"vuln:{vm.group(1).lower()}"
                if key not in seen:
                    seen.add(key)
                    pairs.append(("tls_vuln", line[:120]))
            continue
    return pairs[:40]


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
                # a -sn sweep is host DISCOVERY, not a port probe: route to
                # the sweep parser so each live LAN host becomes a claim
                if "-sn" in str(params.get("args", "")):
                    effective_action = "host-discovery"
                else:
                    effective_action = "service-detect"   # nmap-shaped output
            # dig/whois wrap into their natural parsers via source mapping below
            elif tool in {"dig", "host"}:
                effective_action = "dns-lookup"
            elif tool == "whois":
                effective_action = "whois-lookup"

        if effective_action in {"port-scan", "service-detect", "os-fingerprint",
                                "host-discovery"}:
            pairs, observed_ip = _parse_nmap(stdout)
            if effective_action == "host-discovery":
                # SWEEP: each live host is its own claim, subject = the IP
                # itself ("192.168.55.9" with MAC + vendor when ARP gave one)
                for kind, value in pairs:
                    key = (kind, value.strip().lower())
                    if key in seen:
                        continue
                    seen.add(key)
                    dev_subject = value.split()[0] if kind == "lan_device" else subject
                    emitted.append(self.ledger.add(
                        case_id, subject=dev_subject, kind=kind, value=value,
                        source="scan.nmap", method=action,
                        observed_at=now, evidence_id=evidence_id,
                        notes=f"task={task_id}; sweep"
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
                    "claims": report_claims,
                    "claims_emitted": [c.id for c in emitted],
                    "clean": not findings,
                    "sanitized_preview": sanitize_external(stdout, source=action)[:400] if findings else "",
                }
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
        elif effective_action in {"subdomain-enum", "subfinder-enum"}:
            # amass and subfinder print one FQDN per line — the same
            # in-scope-only parser feeds both, so a passive enumeration
            # never turns out-of-scope archive noise into a claim.
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
        elif effective_action in {"known-urls", "katana-crawl"}:
            # gau / katana emit raw URL lines — the same in-scope filter the
            # wayback parser applies, so out-of-scope archive noise never
            # becomes a claim.
            pairs = _parse_wayback(stdout, subject)
        elif effective_action == "httpx-probe":
            pairs = _parse_httpx_json(stdout)
        elif effective_action == "probe":
            pairs = _parse_probe(stdout)
        elif effective_action == "param-hunt":
            # arjun -oT prints "<url>\t<param>" per discovered parameter;
            # bare parameter names (no tab) are the fallback contract.
            pairs = _parse_param_hunt(stdout, subject)
        elif effective_action == "nuclei-scan":
            pairs = _parse_nuclei_jsonl(stdout)
        elif effective_action == "cors-check":
            pairs = _parse_cors_headers(stdout)
        elif effective_action == "security-txt":
            pairs = _parse_security_txt(stdout + "\n" + stderr)
        elif effective_action == "graphql-introspection":
            pairs = _parse_graphql_introspection(stdout)
        elif effective_action == "email-spoof":
            pairs = _parse_dmarc(stdout + "\n" + stderr)
        elif effective_action == "nikto-scan":
            pairs = _parse_nikto_csv(stdout)
        elif effective_action == "wpscan-audit":
            pairs = _parse_wpscan_text(stdout + "\n" + stderr)
        elif effective_action == "exploit-lookup":
            pairs = _parse_searchsploit_json(stdout)
        elif effective_action == "packet-capture":
            pairs = _parse_tcpdump_summary(stdout)
        elif effective_action == "host-audit":
            pairs = _parse_lynis(stdout)
        elif effective_action == "checksec":
            pairs = _parse_checksec(stdout)
        elif effective_action == "binary-info":
            pairs = _parse_binary_info(stdout)
        elif effective_action == "string-dump":
            pairs = _parse_strings(stdout)
        elif effective_action == "symbol-dump":
            pairs = _parse_symbols(stdout)
        elif effective_action == "disasm":
            pairs = _parse_disasm(stdout)
        elif effective_action == "header-audit":
            pairs = _parse_header_head(stdout)
        elif effective_action == "tls-posture":
            pairs = _parse_sslscan(stdout)
        elif effective_action == "wlan-survey":
            pairs = _parse_wireless_survey(stdout, stderr)
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
            "subfinder-enum": "osint.datasource",
            "email-osint": "osint.datasource",
            "dir-enum": "scan.web",
            "tech-fingerprint": "scan.web",
            "dns-enum": "dns.authoritative",
            "waf-detect": "scan.web",
            "js-intel": "js.static",
            "wayback-urls": "archive.wayback",
            "known-urls": "archive.wayback",
            "katana-crawl": "scan.web",
            "httpx-probe": "scan.web",
            "param-hunt": "scan.web",
            "nuclei-scan": "scan.nuclei",
            "nikto-scan": "scan.web",
            "wpscan-audit": "scan.web",
            "exploit-lookup": "db.exploit",
            "packet-capture": "sniff.local",
            "host-audit": "audit.lynis",
            "checksec": "binary.static",
            "binary-info": "binary.static",
            "string-dump": "binary.static",
            "symbol-dump": "binary.static",
            "disasm": "binary.static",
            "header-audit": "scan.web",
            "tls-posture": "scan.tls",
            "wlan-survey": "scan.wireless",
            "wlan-monitor": "scan.wireless",
            "wlan-ap-audit": "scan.wireless",
            "probe": "scan.web",
            "cors-check": "scan.web",
            "security-txt": "scan.web",
            "graphql-introspection": "scan.web",
            "email-spoof": "dns.authoritative",
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
