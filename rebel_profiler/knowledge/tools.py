"""Kali tool capability matrix.

Maps capability classes to the standard Kali Linux tooling that provides
them. This is a *capability-to-provider* registry: it tells the planner and
the adapter layer which external tooling exists for a capability class, and
which authorization gates apply. Presence in this matrix never implies
authorization — the policy engine decides that.

Adapters declare their own manifests at runtime (PDF 13: no-fake-adapter
policy). This matrix is reference data for planning and help output only.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Tool:
    name: str
    binary: str
    capability_class: str
    gates: tuple[str, ...]                    # required policy gates
    summary: str                              # original one-line description
    domains: tuple[str, ...] = ()             # knowledge domain keys
    structured_output: bool = True            # adapter can parse output

    @property
    def requires_confirmation(self) -> bool:
        return "confirmation" in self.gates

    @property
    def requires_approval(self) -> bool:
        return "approval" in self.gates


@dataclass(frozen=True)
class ToolGroup:
    """A set of tools for one capability class + policy gate summary."""

    capability_class: str
    risk: str
    tools: tuple[Tool, ...]

    @property
    def highest_gate(self) -> str:
        if any(t.requires_approval for t in self.tools):
            return "approval"
        if any(t.requires_confirmation for t in self.tools):
            return "confirmation"
        return "none"


_GROUPS: tuple[ToolGroup, ...] = (
    ToolGroup(
        capability_class="passive_recon",
        risk="low",
        tools=(
            Tool("dns-lookup", "dig", "passive_recon", (),
                 "Authoritative DNS record collection via resolver queries.",
                 ("networking", "footprinting")),
            Tool("exploit-lookup", "searchsploit", "passive_recon", (),
                 "Offline exploit-db correlation for fingerprinted software — "
                 "zero target traffic, advisory output only.",
                 ("footprinting", "scanning")),
            Tool("whois-lookup", "whois", "passive_recon", (),
                 "Domain registration intelligence from public registries.",
                 ("footprinting",)),
            Tool("cert-transparency", "certctl", "passive_recon", (),
                 "Certificate transparency log review for subdomain visibility.",
                 ("footprinting",)),
            Tool("dork-search", "curl", "passive_recon", (),
                 "Search-engine dorking: named dork templates (files, "
                 "directories, portals, buckets) over Google, DuckDuckGo "
                 "and Ahmia-over-Tor (.onion).",
                 ("footprinting", "enumeration")),
            Tool("subdomain-enum", "amass", "passive_recon", (),
                 "Passive subdomain discovery from public datasets.",
                 ("footprinting", "enumeration")),
            Tool("js-intel", "curl", "passive_recon", (),
                 "Fetch one JS asset and extract embedded API paths, "
                 "absolute URLs, key/secret candidates and cloud-host "
                 "references (S3, Firebase, Supabase...).",
                 ("enumeration", "web")),
            Tool("wayback-urls", "curl", "passive_recon", (),
                 "Historical URL surface from the Wayback CDX index "
                 "(archive-side lookup; the target is never touched).",
                 ("footprinting", "enumeration")),
            Tool("probe", "curl", "vuln_validation", (),
                 "Single manual verification request (method/path/payload "
                 "chosen by the operator); approval-gated, evidence-captured.",
                 ("web", "exploitation")),
            Tool("email-osint", "theHarvester", "passive_recon", (),
                 "Email and host surface from passive search sources.",
                 ("footprinting",)),
            Tool("dns-enum", "dnsrecon", "passive_recon", (),
                 "Standard DNS enumeration incl. zone-transfer checks.",
                 ("footprinting", "enumeration")),
        ),
    ),
    ToolGroup(
        capability_class="discovery",
        risk="moderate",
        tools=(
            Tool("host-discovery", "nmap", "discovery", ("confirmation",),
                 "Authorized live-host detection via ICMP/ARP/TCP probes.",
                 ("scanning",)),
            Tool("port-scan", "nmap", "discovery", ("confirmation",),
                 "TCP/UDP service and port state enumeration on authorized hosts.",
                 ("scanning",)),
            Tool("service-version", "nmap", "discovery", ("confirmation",),
                 "Service/version fingerprinting from network signatures.",
                 ("scanning",)),
        ),
    ),
    ToolGroup(
        capability_class="network_mapping",
        risk="moderate",
        tools=(
            Tool("route-analysis", "traceroute", "network_mapping", (),
                 "Path and hop analysis for segmentation review.",
                 ("networking",)),
            Tool("packet-craft", "hping3", "network_mapping", ("confirmation",),
                 "Crafted-probe generation for edge-filter validation on authorized segments.",
                 ("scanning", "networking")),
            Tool("smb-enum", "enum4linux-ng", "network_mapping", ("confirmation",),
                 "SMB/NetBIOS share and session enumeration.",
                 ("enumeration",)),
            Tool("snmp-check", "snmpcheck", "network_mapping", ("confirmation",),
                 "SNMP community and MIB-2 exposure checks.",
                 ("enumeration",)),
            Tool("dns-enum", "dnsenum", "network_mapping", ("confirmation",),
                 "DNS enumeration including AXFR misconfiguration checks.",
                 ("enumeration",)),
            Tool("packet-capture", "tcpdump", "network_mapping", ("confirmation",),
                 "Bounded, listen-only packet capture on the operator's own "
                 "interface; protocol aggregates only, named BPF filters.",
                 ("sniffing", "networking")),
        ),
    ),
    ToolGroup(
        capability_class="web_assessment",
        risk="moderate",
        tools=(
            Tool("web-crawl", "httpx", "web_assessment", ("confirmation",),
                 "Authorized endpoint and technology surface discovery.",
                 ("attack_defense", "enumeration")),
            Tool("dir-enum", "ffuf", "web_assessment", ("confirmation",),
                 "Directory/file enumeration against the authorized origin.",
                 ("enumeration",)),
            Tool("tech-fingerprint", "whatweb", "web_assessment", (),
                 "Web technology fingerprinting from the live site.",
                 ("footprinting", "enumeration")),
            Tool("waf-detect", "wafw00f", "web_assessment", (),
                 "WAF detection in front of the authorized origin.",
                 ("footprinting",)),
            Tool("web-dir-enum", "dirb", "web_assessment", ("confirmation",),
                 "Directory/endpoint listing on authorized web properties.",
                 ("enumeration", "attack_defense")),
            Tool("tech-fingerprint", "whatweb", "web_assessment", (),
                 "Web technology fingerprinting from passive responses.",
                 ("footprinting", "enumeration")),
            Tool("tls-posture", "sslscan", "web_assessment", ("confirmation",),
                 "TLS version/cipher configuration assessment.",
                 ("cryptography",)),
            Tool("header-audit", "curl", "web_assessment", ("confirmation",),
                 "Security-header and cookie-flag review.",
                 ("attack_defense",)),
            Tool("nikto-scan", "nikto", "web_assessment", ("confirmation",),
                 "Web-server misconfiguration sweep: dangerous defaults, "
                 "outdated software, risky methods (polite tuning).",
                 ("scanning", "attack_defense")),
            Tool("wpscan-audit", "wpscan", "web_assessment", ("confirmation",),
                 "WordPress version/plugin/theme exposure audit — no brute "
                 "force, no aggressive enumeration.",
                 ("scanning", "enumeration")),
        ),
    ),
    ToolGroup(
        capability_class="active_recon",
        risk="high",
        tools=(
            Tool("banner-probe", "nc", "active_recon", ("confirmation",),
                 "Banner interaction with authorized services.",
                 ("footprinting",)),
            Tool("wireless-survey", "airodump-ng", "active_recon",
                 ("confirmation", "approval"),
                 "Authorized RF survey for AP/SSID inventory.",
                 ("wireless",)),
        ),
    ),
    ToolGroup(
        capability_class="vuln_validation",
        risk="high",
        tools=(
            Tool("vuln-correlate", "nuclei", "vuln_validation",
                 ("confirmation", "approval"),
                 "Template-driven vulnerability validation on authorized targets.",
                 ("scanning",)),
            Tool("vuln-scan", "openvas", "vuln_validation",
                 ("confirmation", "approval"),
                 "Authenticated vulnerability scan of authorized assets.",
                 ("scanning", "attack_defense")),
            Tool("fuzz-probe", "fuzz", "vuln_validation",
                 ("confirmation", "approval"),
                 "Rate-limited input robustness testing on designated services.",
                 ("system_hacking",)),
        ),
    ),
    ToolGroup(
        capability_class="intrusive_testing",
        risk="high",
        tools=(
            Tool("password-audit", "hydra", "intrusive_testing",
                 ("confirmation", "approval"),
                 "Rate-limited credential validation against designated test accounts.",
                 ("system_hacking", "social_engineering")),
            Tool("phishing-sim", "gophish", "intrusive_testing",
                 ("confirmation", "approval"),
                 "Consented phishing simulation with synthetic payloads.",
                 ("social_engineering",)),
        ),
    ),
    ToolGroup(
        capability_class="config_assessment",
        risk="moderate",
        tools=(
            Tool("host-audit", "lynis", "config_assessment", (),
                 "Local hardening audit of the operator's OWN machine — "
                 "the blue-team baseline (targetless, defensive only).",
                 ("attack_defense", "system")),
        ),
    ),
    ToolGroup(
        capability_class="exploit_validation",
        risk="critical",
        tools=(
            Tool("exploit-validation", "metasploit", "exploit_validation",
                 ("confirmation", "approval"),
                 "Controlled exploit validation on designated lab targets only.",
                 ("system_hacking",)),
        ),
    ),
)


def capability_classes() -> tuple[str, ...]:
    return tuple(g.capability_class for g in _GROUPS)


def find_group(capability_class: str) -> ToolGroup | None:
    for g in _GROUPS:
        if g.capability_class == capability_class:
            return g
    return None


def tools_for_domain(domain_key: str) -> tuple[Tool, ...]:
    key = domain_key.strip().lower()
    result: list[Tool] = []
    for g in _GROUPS:
        for t in g.tools:
            if key in t.domains:
                result.append(t)
    return tuple(result)


def planner_tool_context() -> dict:
    """Machine-readable tool matrix for the LLM planner.

    ``executable`` reflects the live AdapterRegistry: an action listed here
    but marked ``executable: false`` has no adapter yet — the planner must
    not propose it (the broker would refuse with a no-fake-adapter error).
    """
    from ..execution.broker import AdapterRegistry

    registry = AdapterRegistry()
    executable = set(registry.names())
    return {
        "schema_version": 1,
        "groups": [
            {
                "capability_class": g.capability_class,
                "risk": g.risk,
                "tools": [
                    {
                        "name": t.name,
                        "binary": t.binary,
                        "gates": list(t.gates),
                        "summary": t.summary,
                        "domains": list(t.domains),
                        "executable": t.name in executable,
                    }
                    for t in g.tools
                ],
            }
            for g in _GROUPS
        ],
        "executable_actions": sorted(executable),
        "rule": (
            "Tools are providers of a capability class. The broker invokes them "
            "as structured actions only after scope validation and policy "
            "approval. Tool presence never implies authorization. Propose only "
            "actions with executable=true; anything else has no adapter and "
            "will be refused."
        ),
    }
