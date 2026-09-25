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
              "CWE-306", ("js-intel", "katana-crawl", "web-crawl"),
              payload_class="idor_pivot"),
    VulnClass("subdomain_takeover", "Dangling DNS → takeover prerequisites",
              "CWE-350", ("subfinder-enum", "subdomain-enum", "httpx-probe",
                          "cert-transparency"),
              note="httpx NXDX/CNAME claims flag takeover candidates"),
    VulnClass("info_disclosure", "Information disclosure (keys, secrets, comments)",
              "CWE-200", ("js-intel", "dork-search", "wayback-urls")),
    VulnClass("email_exposure", "Email/personnel surface (phishing prerequisites)",
              "CWE-359", ("email-osint",)),
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
)


def vuln_classes() -> tuple[VulnClass, ...]:
    return VULN_CLASSES


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
