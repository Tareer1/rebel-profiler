"""Bug-bounty triage: collected evidence → reportable findings.

This is the *assessment* half of the bounty workflow. It reads nothing but the
case's own claim ledger, so every reported item traces back to hash-chained
evidence — no demo data, no placeholder, no invented finding, and an honest
empty report when nothing was observed.

Each observed condition is mapped to:

* a vulnerability **class** and a short title,
* an advisory **severity** and a **CWE**,
* a **reproduce** command built from the URL the evidence actually came from,
* a **remediation** line the program's triager can act on.

Severity here is *advisory*: every program has its own taxonomy and payout
rules, and the report says so. Missing security headers, for instance, are
informational on most programs and only escalate when they cause concrete
impact — the mapping below reflects that rather than inflating everything.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

SEVERITIES = ("informational", "low", "medium", "high", "critical")
_SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}

# Confidence floor: below this a claim is context, not a reportable finding.
_MIN_CONFIDENCE = 0.2

# A finding must still be live; contradicted/stale claims never ship.
_LIVE_STATES = {"open", "corroborated"}


@dataclass(frozen=True)
class Rule:
    """One observed check → vulnerability class mapping."""

    prefix: str            # matched against the claim value's leading check
    title: str
    severity: str
    cwe: str
    remediation: str
    reproduce: str = "curl -sSI {url}"
    impact: str = ""


# Check names come from intel/web.py (`_audit_*` families) — the claim value is
# always "<check>:<detail>". Longest prefixes are matched first.
RULES: tuple[Rule, ...] = (
    Rule(
        prefix="cleartext_password_form",
        title="Password form submitted over cleartext HTTP",
        severity="high",
        cwe="CWE-319",
        remediation="Serve the form and its action endpoint over HTTPS only and "
                    "redirect HTTP to HTTPS before any credentials are entered.",
        reproduce="curl -sS {url} | grep -iE '<form|<input[^>]+type=\"?password'",
        impact="Credentials are transmitted unencrypted and can be read by any "
               "on-path observer.",
    ),
    Rule(
        prefix="tls:protocol",
        title="Legacy TLS protocol version accepted",
        severity="medium",
        cwe="CWE-326",
        remediation="Disable TLS 1.0/1.1 and SSLv3; require TLS 1.2+ with "
                    "modern cipher suites.",
        reproduce="openssl s_client -connect {host}:443 -tls1 2>/dev/null | "
                  "grep -E 'Protocol|Cipher'",
        impact="Deprecated protocols have known cryptographic weaknesses and "
               "fail modern compliance baselines.",
    ),
    Rule(
        prefix="header:CSP",
        title="Missing Content-Security-Policy",
        severity="informational",
        cwe="CWE-693",
        remediation="Deploy a Content-Security-Policy that disallows inline "
                    "script and restricts script-src to trusted origins.",
        reproduce="curl -sSI {url} | grep -i content-security-policy",
        impact="Removes a defence-in-depth layer against cross-site scripting; "
               "report it as a finding only when combined with an actual XSS.",
    ),
    Rule(
        prefix="header:HSTS",
        title="Missing Strict-Transport-Security",
        severity="low",
        cwe="CWE-319",
        remediation="Send Strict-Transport-Security with a long max-age on all "
                    "HTTPS responses (add includeSubDomains once verified).",
        reproduce="curl -sSI {url} | grep -i strict-transport-security",
        impact="Users can be downgraded to cleartext HTTP on hostile networks.",
    ),
    Rule(
        prefix="header:X-Frame-Options",
        title="Missing anti-framing header",
        severity="informational",
        cwe="CWE-1021",
        remediation="Send X-Frame-Options: DENY (or a CSP frame-ancestors "
                    "directive) on responses that must not be framed.",
        reproduce="curl -sSI {url} | grep -iE 'x-frame-options|frame-ancestors'",
        impact="Enables clickjacking where a sensitive action lacks other "
               "confirmations.",
    ),
    Rule(
        prefix="header:X-Content-Type-Options",
        title="Missing X-Content-Type-Options",
        severity="informational",
        cwe="CWE-693",
        remediation="Send X-Content-Type-Options: nosniff on all responses.",
        reproduce="curl -sSI {url} | grep -i x-content-type-options",
        impact="Browser MIME sniffing can turn an upload into script execution.",
    ),
    Rule(
        prefix="header:Referrer-Policy",
        title="Missing Referrer-Policy",
        severity="informational",
        cwe="CWE-200",
        remediation="Send Referrer-Policy: strict-origin-when-cross-origin (or "
                    "no-referrer where appropriate).",
        reproduce="curl -sSI {url} | grep -i referrer-policy",
        impact="URLs containing sensitive parameters leak via the Referer header.",
    ),
    Rule(
        prefix="cookie:Secure",
        title="Cookie set without the Secure flag",
        severity="low",
        cwe="CWE-614",
        remediation="Set the Secure attribute on every cookie that carries "
                    "session or identity data.",
        reproduce="curl -sSI {url} | grep -i set-cookie",
        impact="The cookie can be transmitted over cleartext HTTP and captured "
               "on-path.",
    ),
    Rule(
        prefix="cookie:HttpOnly",
        title="Cookie set without the HttpOnly flag",
        severity="low",
        cwe="CWE-1004",
        remediation="Set HttpOnly on session cookies so scripts cannot read them.",
        reproduce="curl -sSI {url} | grep -i set-cookie",
        impact="Any cross-site scripting flaw can exfiltrate the session token.",
    ),
    Rule(
        prefix="cookie:SameSite",
        title="Cookie set without SameSite",
        severity="informational",
        cwe="CWE-1275",
        remediation="Set SameSite=Lax (or Strict) unless cross-site sending is "
                    "actually required, and audit CSRF defences.",
        reproduce="curl -sSI {url} | grep -i set-cookie",
        impact="Raises cross-site request forgery exposure for state-changing "
               "requests.",
    ),
    Rule(
        prefix="redirect_cleartext",
        title="Redirect to cleartext HTTP",
        severity="low",
        cwe="CWE-319",
        remediation="Redirect to the https:// URL directly instead of bouncing "
                    "through http://.",
        reproduce="curl -sSI {url} | grep -i '^location'",
        impact="The cleartext hop can be intercepted before the upgrade.",
    ),
    # ---- scanner findings (nuclei) & marker findings (offense plane) ----
    Rule(
        prefix="nuclei_finding",
        title="Template-based scanner hit",
        severity="medium",
        cwe="CWE-2000",   # severity rides the template; triager re-checks
        remediation="Verify the template hit manually (probe) and patch the "
                    "affected component; the template-id names the class.",
        reproduce="nuclei -u {url} -severity medium,high,critical -silent",
        impact="A public template matched a known vulnerable pattern.",
    ),
    Rule(
        prefix="nuclei_detail",
        title="Scanner extractor captured data",
        severity="informational",
        cwe="CWE-200",
        remediation="Review the extracted value; tighten whatever exposes it.",
        reproduce="nuclei -u {url} -silent",
        impact="The scanner's extractor returned content worth reviewing.",
    ),
    Rule(
        prefix="tls_vuln",
        title="Legacy TLS vulnerability marker",
        severity="high",
        cwe="CWE-326",
        remediation="Upgrade OpenSSL/TLS stack; disable vulnerable protocol "
                    "extensions (heartbleed/CCS/logjam/FREAK/POODLE class).",
        reproduce="sslscan {host}:443 | grep -iA2 -E 'heartbleed|CCS|logjam|FREAK|POODLE'",
        impact="A known TLS-protocol attack applies to this endpoint.",
    ),
    Rule(
        prefix="tls_protocol",
        title="Legacy TLS protocol enabled (sslscan)",
        severity="medium",
        cwe="CWE-326",
        remediation="Disable SSLv2/v3 and TLS 1.0/1.1; require TLS 1.2+.",
        reproduce="sslscan {host}:443 | grep -i 'enabled'",
        impact="Downgrade attacks become possible on legacy protocol versions.",
    ),
    Rule(
        prefix="cookie_flag:no security flags",
        title="Cookie without any security flags (direct audit)",
        severity="low",
        cwe="CWE-1004",
        remediation="Set Secure; HttpOnly; and an explicit SameSite on every cookie.",
        reproduce="curl -sSI {url} | grep -i set-cookie",
        impact="Session material may leak to scripts or cleartext transport.",
    ),
    # ---- nikto / wpscan / exploit-lookup / capture (Kali expansion) ----
    Rule(
        prefix="nikto_finding",
        title="Web-server misconfiguration (nikto)",
        severity="low",
        cwe="CWE-16",
        remediation="Review the flagged file/behaviour: remove default and "
                    "sample content, patch outdated software, restrict "
                    "dangerous methods.",
        reproduce="nikto -h {host} -Format csv -o -",
        impact="A known dangerous file or server misconfiguration is reachable.",
    ),
    Rule(
        prefix="nikto_reference",
        title="nikto reference detail",
        severity="informational",
        cwe="CWE-200",
        remediation="Follow the reference (OSVDB/CVE) to confirm whether the "
                    "flagged item applies to this deployment.",
        reproduce="nikto -h {host} -Format csv -o -",
        impact="Supporting reference for a nikto finding.",
    ),
    Rule(
        prefix="wp_finding",
        title="WordPress exposure (wpscan)",
        severity="medium",
        cwe="CWE-1104",
        remediation="Update the flagged core/plugin/theme; remove exposed "
                    "backup and debug files; disable XML-RPC if unused.",
        reproduce="wpscan --url {url} --enumerate vp,vt",
        impact="A vulnerable CMS component version is publicly identifiable.",
    ),
    Rule(
        prefix="wp_info",
        title="WordPress surface detail (wpscan)",
        severity="informational",
        cwe="CWE-200",
        remediation="Keep core/plugins/themes current; version disclosure "
                    "alone is context for the findings above.",
        reproduce="wpscan --url {url}",
        impact="CMS version/component details aid targeted attacks.",
    ),
    # ---- CORS / security.txt / GraphQL / email-spoof (web-expansion) ----
    Rule(
        prefix="cors_check:acao_reflected:yes",
        title="CORS reflects arbitrary origin",
        severity="high",
        cwe="CWE-942",
        remediation="Do not reflect the Origin header; serve an explicit "
                    "allow-list of trusted origins and never combine a "
                    "reflected ACAO with Access-Control-Allow-Credentials.",
        reproduce="curl -sSI -H 'Origin: https://attacker.example' {url}",
        impact="Any website can read authenticated responses from the "
               "victim's browser when credentials are allowed.",
    ),
    Rule(
        prefix="cors_check:acao_reflected:no",
        title="CORS control present (no reflection)",
        severity="informational",
        cwe="CWE-942",
        remediation="No action: the origin check held against a foreign "
                    "Origin probe.",
        reproduce="curl -sSI -H 'Origin: https://attacker.example' {url}",
        impact="Cross-origin reads are blocked — recorded so the report can "
               "show the control was tested.",
    ),
    Rule(
        prefix="cors_check:acao_present",
        title="CORS allows specific origins",
        severity="informational",
        cwe="CWE-942",
        remediation="Verify the allow-listed origins are all intended; an "
                    "over-broad list (wildcard subdomains, abandoned "
                    "domains) widens the cross-origin surface.",
        reproduce="curl -sSI -H 'Origin: https://attacker.example' {url}",
        impact="Cross-origin access is limited to named origins.",
    ),
    Rule(
        prefix="securitytxt_check:security.txt missing",
        title="Missing security.txt (RFC 9116)",
        severity="informational",
        cwe="CWE-16",
        remediation="Publish /.well-known/security.txt with a Contact field "
                    "so researchers can reach you instead of exploiting.",
        reproduce="curl -sS {url}/.well-known/security.txt",
        impact="Researchers lack a disclosure channel — a reportability gap, "
               "not a vulnerability.",
    ),
    Rule(
        prefix="securitytxt_check:security.txt present",
        title="security.txt published (RFC 9116)",
        severity="informational",
        cwe="CWE-16",
        remediation="No action: the disclosure contact is discoverable. Keep "
                    "the Expires field current.",
        reproduce="curl -sS {url}/.well-known/security.txt",
        impact="Coordinated disclosure is supported.",
    ),
    Rule(
        prefix="graphql_introspection:introspection:enabled",
        title="GraphQL introspection publicly enabled",
        severity="low",
        cwe="CWE-200",
        remediation="Disable introspection on production endpoints (allow "
                    "it only for whitelisted tooling) and require "
                    "authentication for schema reads.",
        reproduce="curl -sS {url} -X POST -H 'Content-Type: application/json' "
                  '-d \'{"query":"{ __schema { queryType { name } } }"}\'',
        impact="The full API schema is readable by anyone, handing attackers "
               "a complete map of queries and mutations.",
    ),
    Rule(
        prefix="graphql_introspection:introspection:disabled",
        title="GraphQL introspection disabled",
        severity="informational",
        cwe="CWE-200",
        remediation="No action: the schema is not publicly readable.",
        reproduce="curl -sS {url} -X POST -H 'Content-Type: application/json' "
                  "-d '{\"query\":\"{ __schema { queryType { name } } }\"}'",
        impact="Schema exposure is mitigated.",
    ),
    Rule(
        prefix="email_spoofing:spoofing posture:no SPF",
        title="Domain spoofable: no SPF and no DMARC",
        severity="medium",
        cwe="CWE-359",
        remediation="Publish an SPF record listing authorised senders and a "
                    "DMARC record starting at p=none with reports, moving "
                    "to p=quarantine/reject once clean.",
        reproduce="dig +short TXT {host}; dig +short TXT _dmarc.{host}",
        impact="Anyone can send email that passes casual checks as this "
               "domain — a direct phishing prerequisite.",
    ),
    Rule(
        prefix="email_spoofing:spoofing posture:spf:absent",
        title="Missing SPF record",
        severity="low",
        cwe="CWE-359",
        remediation="Publish an SPF record listing authorised senders; keep "
                    "DMARC enforcement in place.",
        reproduce="dig +short TXT {host}",
        impact="Unlisted senders are not filtered by receiver-side SPF.",
    ),
    Rule(
        prefix="email_spoofing:spoofing posture:dmarc:present; p=none",
        title="DMARC policy is p=none (not enforcing)",
        severity="low",
        cwe="CWE-359",
        remediation="Move DMARC from p=none to p=quarantine, then p=reject, "
                    "once reports confirm legitimate senders align.",
        reproduce="dig +short TXT _dmarc.{host}",
        impact="Spoofed mail still reaches inboxes; only monitoring happens.",
    ),
    Rule(
        prefix="email_spoofing:spoofing posture:dmarc:absent",
        title="No DMARC record",
        severity="medium",
        cwe="CWE-359",
        remediation="Publish a DMARC record (v=DMARC1) with rua reports; "
                    "enforce with p=quarantine/reject when ready.",
        reproduce="dig +short TXT _dmarc.{host}",
        impact="Receivers have no domain-owner guidance for handling "
               "spoofed mail.",
    ),
    Rule(
        prefix="exploit_candidate",
        title="Published exploit exists (offline EDB lookup)",
        severity="informational",
        cwe="CWE-1395",
        remediation="Correlate the EDB entry with the deployed version and "
                    "patch; publication does not prove exploitability here.",
        reproduce="searchsploit -t '<product> <version>' --json",
        impact="A public exploit targets software resembling this surface.",
    ),
    Rule(
        prefix="capture_summary",
        title="Cleartext protocol observed on the local segment",
        severity="low",
        cwe="CWE-319",
        remediation="Encrypt the flagged protocol (TLS everywhere) or move it "
                    "to a trusted management segment.",
        reproduce="tcpdump -i <iface> -c 200 -nn -q <filter>",
        impact="Traffic aggregates show a protocol worth encrypting.",
    ),
    Rule(
        prefix="hardening_suggestion",
        title="Local hardening gap (lynis, own machine)",
        severity="informational",
        cwe="CWE-16",
        remediation="Apply the lynis suggestion; re-run 'host-audit' to verify.",
        reproduce="lynis audit system --quick",
        impact="The operator's own baseline has a hardening gap.",
    ),
    # ---- reverse-engineering plane (static, offline, analysis-only) ----
    Rule(
        prefix="binary_mitigation:disabled",
        title="Binary shipped without exploit mitigation",
        severity="low",
        cwe="CWE-693",
        remediation="Rebuild with NX, PIE, stack canaries and full RELRO "
                    "enabled; note the gap in the advisory.",
        reproduce="checksec --file=<sample>",
        impact="Memory-corruption flaws in this binary are easier to exploit.",
    ),
    Rule(
        prefix="binary_mitigation:enabled",
        title="Binary mitigation present",
        severity="informational",
        cwe="CWE-693",
        remediation="No action — recorded so the report states the posture "
                    "factually.",
        reproduce="checksec --file=<sample>",
        impact="Mitigation evidence for the analysis write-up.",
    ),
    Rule(
        prefix="string_url",
        title="URL artifact inside analyzed sample",
        severity="informational",
        cwe="CWE-200",
        remediation="Treat as an IOC candidate: verify reachability and "
                    "reputation; never fetch it from an operator machine.",
        reproduce="strings -n 6 <sample>",
        impact="The sample references a network resource worth recording.",
    ),
    Rule(
        prefix="string_ip",
        title="Embedded IP address in sample",
        severity="informational",
        cwe="CWE-200",
        remediation="Check the address against threat-intel sources; record "
                    "as a potential C2/config artifact.",
        reproduce="strings -n 6 <sample>",
        impact="A hardcoded endpoint suggests network behavior.",
    ),
    Rule(
        prefix="string_domain",
        title="Embedded domain in sample",
        severity="informational",
        cwe="CWE-200",
        remediation="Passive-check the domain (whois/DNS history); add to "
                    "monitoring if it resolves.",
        reproduce="strings -n 6 <sample>",
        impact="A referenced domain may be infrastructure or a decoy.",
    ),
    Rule(
        prefix="symbol_import",
        title="Behavioral import observed (static)",
        severity="informational",
        cwe="CWE-200",
        remediation="Note the capability hint (network/process/crypto) in the "
                    "analysis; imports are hints, not proof of behavior.",
        reproduce="nm -D <sample>",
        impact="The sample imports an API worth calling out in the analysis.",
    ),
    Rule(
        prefix="disasm_call",
        title="Disassembled call to notable function",
        severity="informational",
        cwe="CWE-200",
        remediation="Read the calling context before concluding anything; "
                    "disassembly is reading, the sample never ran.",
        reproduce="objdump -d <sample>",
        impact="Static view of what the code references.",
    ),
)

# Cleartext / over-exposed services seen in discovery output.
RISKY_SERVICES: dict[str, tuple[str, str, str]] = {
    # service name: (severity, cwe, remediation)
    "telnet": ("medium", "CWE-319", "Replace Telnet with SSH."),
    "ftp": ("medium", "CWE-319", "Replace FTP with SFTP/FTPS."),
    "pop3": ("medium", "CWE-319", "Enable POP3S (implicit TLS) and disable cleartext POP3."),
    "imap": ("medium", "CWE-319", "Enable IMAPS (implicit TLS) and disable cleartext IMAP."),
    "rlogin": ("medium", "CWE-319", "Retire rlogin/rsh in favour of SSH."),
    "vnc": ("medium", "CWE-284", "Restrict VNC to a management network and require "
                                 "strong authentication."),
    "rdp": ("informational", "CWE-284", "Restrict RDP to a management network, enable "
                                        "NLA and MFA."),
    "smb": ("informational", "CWE-284", "Restrict SMB to trusted segments; block at "
                                        "the perimeter."),
    "mongodb": ("medium", "CWE-284", "Enable authentication and never expose MongoDB "
                                     "to untrusted networks."),
    "redis": ("medium", "CWE-284", "Enable requirepass/ACLs and bind to trusted "
                                   "interfaces only."),
    "mysql": ("informational", "CWE-284", "Bind database ports to the application "
                                          "network only."),
    "postgresql": ("informational", "CWE-284", "Bind database ports to the application "
                                               "network only."),
}


@dataclass
class BountyFinding:
    subject: str
    title: str
    severity: str
    cwe: str
    detail: str
    remediation: str
    reproduce: str
    impact: str
    confidence: float
    evidence_ids: tuple[str, ...]
    claim_ids: tuple[str, ...]
    source: str
    method: str
    observed_at: float
    url: str = ""

    def as_dict(self) -> dict:
        return {
            "asset": self.subject,
            "title": self.title,
            "severity": self.severity,
            "cwe": self.cwe,
            "detail": self.detail,
            "reproduce": self.reproduce,
            "impact": self.impact,
            "remediation": self.remediation,
            "confidence": round(self.confidence, 4),
            "evidence_ids": list(self.evidence_ids),
            "claim_ids": list(self.claim_ids),
            "source": self.source,
            "method": self.method,
            "observed_at": self.observed_at,
            "url": self.url,
        }


@dataclass
class BountyReport:
    case_id: str
    program: str
    generated_at: float
    findings: list[BountyFinding] = field(default_factory=list)
    unmapped: list[dict] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "schema_version": 1,
            "case_id": self.case_id,
            "program": self.program,
            "generated_at": self.generated_at,
            "severity_note": ("Advisory mapping only — the program's own taxonomy "
                              "and payout rules take precedence."),
            "stats": self.stats,
            "findings": [f.as_dict() for f in self.findings],
            "unmapped_observations": self.unmapped,
        }

    def render_human(self) -> str:
        lines = [
            f"Bug-bounty report — case {self.case_id}",
            f"program   : {self.program or '(not recorded)'}",
            f"generated : {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(self.generated_at))}",
            f"findings  : {len(self.findings)}",
            "",
        ]
        if not self.findings:
            lines.append("  No reportable findings from the collected evidence.")
            lines.append("  Collect more in-scope data "
                         "(bounty run / intel crawl / intel collect), then re-assess.")
            lines.append("")
        for finding in self.findings:
            lines.append(f"[{finding.severity.upper()}] {finding.title}")
            lines.append(f"  asset      : {finding.subject}")
            lines.append(f"  cwe        : {finding.cwe}")
            lines.append(f"  detail     : {finding.detail}")
            lines.append(f"  reproduce  : {finding.reproduce}")
            lines.append(f"  impact     : {finding.impact}")
            lines.append(f"  remediation: {finding.remediation}")
            evidence = finding.evidence_ids[0] if finding.evidence_ids else "-"
            lines.append(f"  evidence   : {evidence} (conf={finding.confidence:.2f},"
                         f" source={finding.source})")
            lines.append("")
        if self.unmapped:
            lines.append(f"  {len(self.unmapped)} observation(s) had no vulnerability "
                         "mapping (kept in the ledger, listed under -o json).")
        lines.append("  Advisory severities — the program's own taxonomy wins.")
        lines.append("  Verify evidence anytime: rebel-profiler evidence verify "
                     f"{self.case_id}")
        return "\n".join(lines)


def _severity_rank(severity: str) -> int:
    return _SEVERITY_ORDER.get(severity, 0)


def _match_rule(value: str) -> Rule | None:
    best: Rule | None = None
    for rule in RULES:
        if value.startswith(rule.prefix + ":") or value == rule.prefix:
            if best is None or len(rule.prefix) > len(best.prefix):
                best = rule
    return best


def _url_from(claim) -> str:
    notes = getattr(claim, "notes", "") or ""
    for part in notes.split("|"):
        part = part.strip()
        if part.startswith("url=") and len(part) > 4:
            return part[4:].strip()
    return ""


def _host_from_url(url: str, fallback: str) -> str:
    if "://" in url:
        host = url.split("://", 1)[1].split("/", 1)[0]
        if ":" in host and host.count(":") == 1:
            host = host.split(":", 1)[0]
        return host or fallback
    return fallback


def _fill(template: str, *, url: str, host: str) -> str:
    return template.replace("{url}", url or f"https://{host}").replace("{host}", host)


def _from_web_claim(claim) -> tuple[BountyFinding, bool]:
    """One web_finding claim → a finding (or an unmapped observation).

    Non-``web_finding`` kinds (js endpoints, wayback URLs, probe results)
    are triaged by :func:`_from_recon_claim`; anything not matched there
    lands in the report's unmapped list for a human to judge.
    """
    value = claim.value or ""
    rule = _match_rule(value)
    url = _url_from(claim)
    host = _host_from_url(url, claim.subject)
    detail = value
    if rule is not None and value.startswith(rule.prefix + ":"):
        detail = value[len(rule.prefix) + 1:]
    elif rule is not None:
        detail = value

    if rule is None:
        return (BountyFinding(
            subject=claim.subject, title=f"Web observation: {value.split(':', 1)[0]}",
            severity="informational", cwe="", detail=detail,
            remediation="Review the observation and decide whether it is "
                        "reportable under the program's policy.",
            reproduce=f"curl -sSI {url or 'https://' + host}",
            impact="", confidence=claim.confidence,
            evidence_ids=(claim.evidence_id,) if claim.evidence_id else (),
            claim_ids=(claim.id,), source=claim.source, method=claim.method,
            observed_at=claim.observed_at, url=url,
        ), False)

    return (BountyFinding(
        subject=claim.subject, title=rule.title, severity=rule.severity,
        cwe=rule.cwe, detail=detail, remediation=rule.remediation,
        reproduce=_fill(rule.reproduce, url=url, host=host), impact=rule.impact,
        confidence=claim.confidence,
        evidence_ids=(claim.evidence_id,) if claim.evidence_id else (),
        claim_ids=(claim.id,), source=claim.source, method=claim.method,
        observed_at=claim.observed_at, url=url,
    ), True)


def _from_service_claim(claim) -> tuple[BountyFinding, bool]:
    name = (claim.value or "").strip().lower().split("/")[0].split()[0]
    spec = RISKY_SERVICES.get(name)
    if spec is None:
        return (BountyFinding(
            subject=claim.subject, title=f"Exposed service: {claim.value}",
            severity="informational", cwe="", detail=f"service {claim.value}",
            remediation="Confirm the service is intended to be reachable from "
                        "this network.",
            reproduce=f"nmap -sV -p <port> {claim.subject}",
            impact="", confidence=claim.confidence,
            evidence_ids=(claim.evidence_id,) if claim.evidence_id else (),
            claim_ids=(claim.id,), source=claim.source, method=claim.method,
            observed_at=claim.observed_at,
        ), False)
    severity, cwe, remediation = spec
    return (BountyFinding(
        subject=claim.subject, title=f"Exposed {name} service", severity=severity,
        cwe=cwe, detail=f"service {claim.value} reachable on the target",
        remediation=remediation,
        reproduce=f"nmap -sV -p <port> {claim.subject}",
        impact=("Cleartext or unauthenticated exposure widens the attack surface."
                if severity != "informational" else
                "Exposed administrative/service port enlarges the attack surface."),
        confidence=claim.confidence,
        evidence_ids=(claim.evidence_id,) if claim.evidence_id else (),
        claim_ids=(claim.id,), source=claim.source, method=claim.method,
        observed_at=claim.observed_at,
    ), True)


def _from_recon_claim(claim) -> tuple[BountyFinding, bool]:
    """js_secret:* claims → informational triage entries.

    A key/secret *shape* found in shipped JS is a candidate, not a
    vulnerability: Bugsnag/Sentry client keys are public identifiers by
    design, cloud bucket URLs appear in legitimate front-ends. The finding
    exists so the human reviewer sees it with its evidence chain and the
    honest severity — informational until verified out-of-band.
    """
    kind = claim.kind.split(":", 1)[1]
    value = (claim.value or "")[:200]
    # Public-by-design client identifiers (e.g. a short alphanumeric
    # generic_api_key that is a public analytics id) are not even candidates.
    is_public_client = kind == "generic_api_key" and len(value) <= 40 \
        and value.isalnum()
    return (BountyFinding(
        subject=claim.subject,
        title=f"JS secret candidate ({kind})"
              + (" — public client identifier, likely benign" if is_public_client
                 else ""),
        severity="informational",
        cwe="",
        detail=f"kind={kind} value={value} origin-noted-in-evidence",
        remediation=("Verify out-of-band whether this credential is live and "
                     "secret. Public client identifiers (Bugsnag/Sentry/"
                     "Stripe publishable) are not vulnerabilities. If a real "
                     "secret: revoke+rotate first, then disclose."),
        reproduce=f"inspect the JS bundle referenced by claim {claim.id}",
        impact="Potential credential exposure if the value is server-side.",
        confidence=claim.confidence,
        evidence_ids=(claim.evidence_id,) if claim.evidence_id else (),
        claim_ids=(claim.id,),
        source=claim.source,
        method=claim.method,
        observed_at=claim.observed_at,
    ), True)


def assess_claims(claims, *, case_id: str, program: str = "") -> BountyReport:
    """Triage claims into a bounty report. Pure function — no network, no DB."""
    findings: list[BountyFinding] = []
    unmapped: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for claim in claims:
        if claim.state not in _LIVE_STATES or claim.confidence < _MIN_CONFIDENCE:
            continue
        if claim.kind == "web_finding":
            finding, mapped = _from_web_claim(claim)
        elif claim.kind == "service":
            finding, mapped = _from_service_claim(claim)
        elif claim.kind.startswith("js_secret:"):
            finding, mapped = _from_recon_claim(claim)
        else:
            continue

        key = (finding.subject, finding.title)
        if mapped:
            if key in seen:
                continue          # one finding per (asset, class)
            seen.add(key)
            findings.append(finding)
        else:
            unmapped.append({
                "asset": finding.subject, "title": finding.title,
                "detail": finding.detail, "claim_id": claim.id,
                "evidence_id": claim.evidence_id,
            })

    findings.sort(key=lambda f: (-_severity_rank(f.severity), f.subject, f.title))
    counts: dict[str, int] = {name: 0 for name in SEVERITIES}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return BountyReport(
        case_id=case_id, program=program, generated_at=time.time(),
        findings=findings, unmapped=unmapped,
        stats={"findings": len(findings), "by_severity": counts,
               "unmapped": len(unmapped),
               "assets": len({f.subject for f in findings})},
    )


def assess(ledger, case_id: str, *, program: str = "") -> BountyReport:
    """Triage every claim in the ledger for *case_id*."""
    return assess_claims(ledger.list(case_id), case_id=case_id, program=program)
