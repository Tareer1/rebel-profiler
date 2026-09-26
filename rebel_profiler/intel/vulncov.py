"""Vulnerability-coverage matrix: every class → how this tool detects it.

The question the operator keeps asking: *"kya ye har tarah ki vulnerability
dhoondh sakta hai?"* This matrix is the honest, executable answer. Each row
pairs a vulnerability CLASS with the live actions that look for it and the
payload class (if any) whose marker verifies it — so `bounty cover` can
report, per case, which classes the collected evidence has actually probed
and which remain blind spots.

Rows are data, not magic: the `action` names are validated against the live
AdapterRegistry by tests, so the matrix can never drift from what the tool
actually executes.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VulnClass:
    key: str                       # canonical short key
    title: str
    cwe: str
    detect_actions: tuple[str, ...]   # executable actions that look for it
    payload_class: str = ""           # offense-plane verifier, if one exists
    note: str = ""


VULN_CLASSES: tuple[VulnClass, ...] = (
    VulnClass("xss", "Cross-site scripting (reflected/stored/DOM)",
              "CWE-79", ("web-crawl", "js-intel", "katana-crawl", "header-audit"),
              payload_class="reflected_xss",
              note="marker proves reflection; header audit shows CSP posture"),
    VulnClass("server_misconfig", "Web-server misconfiguration (dangerous files, defaults)",
              "CWE-16", ("nikto-scan", "web-crawl"),
              note="nikto findings are misconfiguration evidence for the report"),
    VulnClass("cms_exposure", "CMS/plugin exposure (WordPress core, plugins, backups)",
              "CWE-1104", ("wpscan-audit", "tech-fingerprint"),
              note="version + config-backup exposure; no brute force in this tool"),
    VulnClass("published_exploit", "Published exploit availability (correlation only)",
              "CWE-1395", ("exploit-lookup", "nuclei-scan", "vuln-correlate"),
              note="offline EDB lookup — advisory; verification stays gated"),
    VulnClass("plaintext_protocol", "Cleartext protocols observable on the segment",
              "CWE-319", ("packet-capture", "service-detect"),
              note="protocol aggregates only; capture is listen-only, own interface"),
    VulnClass("host_hardening", "Local hardening baseline (own machine)",
              "CWE-16", ("host-audit",),
              note="lynis on the operator's own box — the blue-team half"),
    VulnClass("binary_mitigation_gap", "Missing binary exploit mitigations (NX/PIE/canary/RELRO)",
              "CWE-693", ("checksec",),
              note="mitigation posture of shipped binaries; offline read of evidence"),
    VulnClass("sample_ioc", "Sample artifacts & indicators (strings, imports, calls)",
              "CWE-200", ("string-dump", "symbol-dump", "disasm", "binary-info"),
              note="static IOC hunting in a possessed sample; bytes as data, never executed"),
    VulnClass("sqli", "SQL injection (error/boolean/time-based)",
              "CWE-89", ("param-hunt", "wayback-urls", "known-urls"),
              payload_class="sqli_error",
              note="param discovery locates injectables; probe verifies"),
    VulnClass("ssti", "Server-side template injection",
              "CWE-1336", ("param-hunt", "dir-enum", "wayback-urls"),
              payload_class="ssti",
              note="safe ${7*7} math marker only"),
    VulnClass("cmdi", "Command injection",
              "CWE-78", ("param-hunt", "dir-enum"),
              payload_class="cmdi_echo",
              note="echo-marker only; no command execution beyond echo"),
    VulnClass("idor", "Insecure direct object references / broken authz",
              "CWE-639", ("js-intel", "katana-crawl", "wayback-urls"),
              payload_class="idor_pivot",
              note="JS-mined API endpoints are the classic source"),
    VulnClass("redirect", "Open redirect",
              "CWE-601", ("wayback-urls", "js-intel", "param-hunt"),
              payload_class="open_redirect",
              note="self-referencing redirect marker, no exfil"),
    VulnClass("path_traversal", "Path traversal / local file read",
              "CWE-22", ("dir-enum", "param-hunt", "wayback-urls"),
              payload_class="traversal",
              note="single-file read-only marker"),
    VulnClass("tls", "Weak TLS / protocol & cipher issues",
              "CWE-326", ("tls-posture", "web-crawl")),
    VulnClass("headers", "Missing security headers",
              "CWE-693", ("header-audit", "web-crawl")),
    VulnClass("cookies", "Insecure cookie flags",
              "CWE-1004", ("header-audit", "web-crawl")),
    VulnClass("cleartext", "Cleartext transmission of credentials",
              "CWE-319", ("web-crawl", "web-crawl")),
    VulnClass("known_cve", "Known CVEs / published vulnerable patterns",
              "CWE-1395", ("nuclei-scan", "vuln-correlate")),
    VulnClass("tech_exposure", "Risky technology exposure / versions",
              "CWE-1104", ("tech-fingerprint", "service-detect", "web-crawl")),
    VulnClass("waf_gap", "No WAF / unprotected origin",
              "CWE-1059", ("waf-detect",)),
    VulnClass("hidden_params", "Undocumented attack-surface parameters",
              "CWE-471", ("param-hunt", "wayback-urls")),
    VulnClass("api_surface", "Unauthenticated API surface",
              "CWE-306", ("js-intel", "katana-crawl", "web-crawl",
                          "graphql-introspection"),
              payload_class="idor_pivot"),
    VulnClass("subdomain_takeover", "Dangling DNS → takeover prerequisites",
              "CWE-350", ("subfinder-enum", "subdomain-enum", "httpx-probe",
                          "cert-transparency"),
              note="httpx NXDX/CNAME claims flag takeover candidates"),
    VulnClass("info_disclosure", "Information disclosure (keys, secrets, comments)",
              "CWE-200", ("js-intel", "dork-search", "wayback-urls")),
    VulnClass("email_exposure", "Email/personnel surface (phishing prerequisites)",
              "CWE-359", ("email-osint",)),
    VulnClass("email_spoofing", "Email spoofing prerequisites (missing/soft SPF-DMARC)",
              "CWE-359", ("email-spoof",),
              note="DNS-only observation: no mail is ever sent; p=none/absent "
                   "DMARC IS the finding"),
    VulnClass("cors_misconfig", "CORS misconfiguration (reflected origin, credentials)",
              "CWE-942", ("cors-check", "header-audit"),
              note="one foreign-Origin probe; reflected ACAO + credentials = "
                   "the exploitable shape"),
    VulnClass("security_contact", "Missing security.txt / disclosure contact (RFC 9116)",
              "CWE-16", ("security-txt",),
              note="reportability gap, not a vuln: presence is the control"),
    VulnClass("dns_health", "DNS misconfiguration (zone transfer, dangling records)",
              "CWE-16", ("dns-enum", "dns-lookup", "passive-dns")),
    VulnClass("service_exposure", "Cleartext/risky network services",
              "CWE-319", ("smb-enum", "port-scan", "service-detect")),
    VulnClass("net_topology", "Segmentation / routing exposure",
              "CWE-1004", ("route-analysis", "host-discovery")),
    VulnClass("wifi_legacy_encryption", "Legacy Wi-Fi encryption (WEP/TKIP/open)",
              "CWE-327", ("wlan-survey", "wlan-ap-audit"),
              note="observation-only: the posture claim IS the finding"),
    VulnClass("wifi_rogue_ap", "Rogue / unknown access points on an authorized site",
              "CWE-940", ("wlan-survey",),
              note="unknown BSSID vs the asset register is the reportable gap"),
    VulnClass("wifi_privacy_surface", "Client privacy surface (STA exposure, probe hygiene)",
              "CWE-200", ("wlan-survey",),
              note="association-only records; probe SSIDs never captured"),
    VulnClass("auth_session_hygiene", "Authenticated-session hygiene (cookie flags, rotation, cache)",
              "CWE-614", ("docker-audit", "host-audit"),
              note="one credentialed login per run via the web-auth-audit "
                   "in-process plane (intel/auth_audit) — the operator's own "
                   "test account, session flags + rotation + cache-control; "
                   "paired here with the host/runtime hardening actions"),
    VulnClass("container_posture", "Container runtime posture (privileged/root containers, exposure)",
              "CWE-250", ("docker-audit",),
              note="read-only `docker ps` inspection of the operator's own runtime"),
    VulnClass("iac_misconfig", "IaC misconfiguration (Dockerfile/compose/K8s/Terraform)",
              "CWE-16", ("iac-audit",),
              note="offline trivy config scan of a file already on disk"),
)


def vuln_classes() -> tuple[VulnClass, ...]:
    return VULN_CLASSES


# Actions that expect a URL-shaped target (scheme included). Every other
# detect action is host/domain-shaped. Tests pin this split against the
# live AdapterRegistry so a renamed action can never fall between sets.
URL_TARGET_ACTIONS = frozenset({
    "web-crawl",    "katana-crawl", "header-audit", "param-hunt", "dir-enum",
    "js-intel", "nuclei-scan", "tech-fingerprint", "waf-detect",
    "httpx-probe", "tls-posture", "nikto-scan", "wpscan-audit",
    "cors-check", "graphql-introspection", "security-txt",
    "web-auth-audit",
})


def coverage_plan(ledger, case_id: str, *, max_actions: int = 8) -> dict:
    """Coverage blind spots → concrete, executable proposals.

    The default next action after a first recon pass: every class the case
    has NOT probed yet becomes a proposal naming a live action and a subject
    the case already observed (URL-shaped subjects for URL actions, hosts
    for the rest). Nothing here executes — the caller still passes these
    through the same planner validation and the broker's six gates.

    Returns {"proposals": [{action, target, params, reason}], "skipped":
    [{class, action, why}], "plan_text": "action:target;..."} — plan_text is
    a ready `agent run --plan` payload for the host/URL steps alike.
    """
    report = coverage_for_case(ledger, case_id)

    url_subjects: list[str] = []
    host_subjects: list[str] = []
    seen: set[str] = set()
    for claim in ledger.list(case_id):
        subject = str(getattr(claim, "subject", "") or "")
        if not subject or subject in seen:
            continue
        seen.add(subject)
        if subject.startswith(("http://", "https://")):
            url_subjects.append(subject)
        else:
            host_subjects.append(subject)

    proposals: list[dict] = []
    skipped: list[dict] = []
    used: set[tuple[str, str]] = set()
    for row in report["classes"]:
        if row["status"] != "available":
            continue
        for action in row["detect_actions"]:
            if action in row["probed"]:
                continue
            pool = url_subjects if action in URL_TARGET_ACTIONS else host_subjects
            if not pool:
                skipped.append({
                    "class": row["class"], "action": action,
                    "why": "no " + ("URL" if action in URL_TARGET_ACTIONS else "host")
                           + " subject observed in this case yet",
                })
                continue
            key = (action, pool[0])
            if key in used:
                continue
            used.add(key)
            proposals.append({
                "action": action, "target": pool[0], "params": {},
                "reason": f"coverage:{row['class']}",
            })
            if len(proposals) >= max_actions:
                break
        if len(proposals) >= max_actions:
            break

    plan_text = ";".join(f"{p['action']}:{p['target']}" for p in proposals)
    return {
        "schema_version": 1,
        "case_id": case_id,
        "proposals": proposals,
        "skipped": skipped,
        "plan_text": plan_text,
        "rule": (
            "Blind spots only (status=available); already-probed classes are "
            "never re-proposed. Execution still passes the six gates."
        ),
    }


def coverage_for_case(ledger, case_id: str) -> dict:
    """Which classes this case's evidence has actually probed vs blind spots.

    A class counts as COVERED when at least one of its detect actions has
    produced a claim for the case (method field matches the action name).
    """
    from ..execution.broker import AdapterRegistry

    registry = AdapterRegistry()
    live = set(registry.names())
    probed_actions: set[str] = set()
    for claim in ledger.list(case_id):
        method = str(getattr(claim, "method", "") or "")
        if method:
            probed_actions.add(method)

    rows = []
    for vc in VULN_CLASSES:
        detect = [a for a in vc.detect_actions if a in live]
        probed = [a for a in detect if a in probed_actions]
        rows.append({
            "class": vc.key,
            "title": vc.title,
            "cwe": vc.cwe,
            "detect_actions": detect,
            "payload_class": vc.payload_class,
            "probed": probed,
            "status": ("covered" if probed
                       else "available" if detect
                       else "no-adapter"),
        })
    covered = sum(1 for r in rows if r["status"] == "covered")
    return {
        "schema_version": 1,
        "case_id": case_id,
        "classes": rows,
        "covered": covered,
        "available": sum(1 for r in rows if r["status"] == "available"),
        "no_adapter": sum(1 for r in rows if r["status"] == "no-adapter"),
        "total": len(rows),
        "rule": (
            "Covered = at least one detect action already produced claims in "
            "this case. Available = executable but not yet run here. "
            "Detection ≠ exploitation; every verify stays approval-gated."
        ),
    }
