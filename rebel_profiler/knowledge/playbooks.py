"""Authorized playbooks: step-ordered investigation guidance per domain.

Each playbook is a *sequence of steps* an operator (or the LLM planner
presenting a plan to the operator) follows. Steps declare the capability
class they need; the broker's gate sequence still decides each step at run
time. Nothing here executes anything by itself.

Original content authored for Rebel Profiler.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PlaybookStep:
    order: int
    title: str
    capability_class: str       # what the step needs; policy gates it
    action_hint: str            # adapter action name, if one exists
    description: str


@dataclass(frozen=True)
class Playbook:
    key: str
    title: str
    objective: str
    domain_keys: tuple[str, ...]
    steps: tuple[PlaybookStep, ...]


PLAYBOOKS: tuple[Playbook, ...] = (
    Playbook(
        key="authorized_recon",
        title="Authorized Reconnaissance (Passive-First)",
        objective=(
            "Build an evidence-backed picture of the target's public footprint "
            "without touching target infrastructure, then escalate only where "
            "scope explicitly allows."
        ),
        domain_keys=("ethical_hacking", "footprinting", "networking"),
        steps=(
            PlaybookStep(1, "Confirm authorization & scope", "info", "",
                         "Verify RoE, scope entries and case activation before anything else."),
            PlaybookStep(2, "Collect registry intelligence", "passive_recon", "whois-lookup",
                         "WHOIS records for the organizational domains."),
            PlaybookStep(3, "Collect DNS records", "passive_recon", "dns-lookup",
                         "A/AAAA/MX/NS/TXT/CAA per domain; note anomalies."),
            PlaybookStep(4, "Review certificate transparency", "passive_recon", "cert-transparency",
                         "Subdomain and certificate visibility from CT logs."),
            PlaybookStep(5, "Dork the search engines", "passive_recon", "dork-search",
                         "Named dorks (files, open dirs, portals, buckets) on "
                         "google/duckduckgo; ahmia over Tor for .onion."),
            PlaybookStep(6, "Enumerate subdomains passively", "passive_recon", "subdomain-enum",
                         "amass passive run; add notable hosts to scope."),
            PlaybookStep(7, "Map the mail surface", "passive_recon", "email-osint",
                         "theHarvester for @domain addresses (phishing "+ "recon)."),
            PlaybookStep(8, "Reconcile findings into the case", "info", "",
                         "Register observations with source, time and confidence."),
        ),
    ),
    Playbook(
        key="network_inventory",
        title="Authorized Network Inventory",
        objective=(
            "Map live hosts and exposed services inside an explicitly "
            "authorized range, preserving uncertainty in every result."
        ),
        domain_keys=("networking", "scanning", "enumeration"),
        steps=(
            PlaybookStep(1, "Confirm range authorization", "info", "",
                         "CIDR ranges must exist as active scope entries."),
            PlaybookStep(2, "Live-host discovery", "discovery", "host-discovery",
                         "ICMP/ARP/TCP probes; record state as up/down/filtered/unknown."),
            PlaybookStep(3, "Service & version discovery", "discovery", "service-version",
                         "Enumerate open ports and banner/version info per host."),
            PlaybookStep(4, "Share/directory exposure review", "network_mapping", "smb-enum",
                         "SMB/NFS/LDAP/SNMP enumeration where in scope."),
            PlaybookStep(5, "Correlate & flag misconfigurations", "info", "",
                         "Zone transfers, default communities, null sessions."),
        ),
    ),
    Playbook(
        key="web_posture",
        title="Web & TLS Posture Review",
        objective=(
            "Assess the configuration security of authorized web properties: "
            "TLS posture, headers, cookie flags and exposed endpoints."
        ),
        domain_keys=("cryptography", "attack_defense", "footprinting"),
        steps=(
            PlaybookStep(1, "Confirm web targets in scope", "info", "",
                         "FQDNs and ports must be active scope entries."),
            PlaybookStep(2, "TLS configuration scan", "web_assessment", "tls-posture",
                         "Protocol versions, cipher suites, certificate chain health."),
            PlaybookStep(3, "Security header audit", "web_assessment", "header-audit",
                         "HSTS, CSP, cookie flags, cache-control."),
            PlaybookStep(4, "Endpoint surface discovery", "web_assessment", "web-crawl",
                         "Authorized crawling within path boundaries."),
            PlaybookStep(5, "Report configuration findings", "info", "",
                         "Weak suites and missing headers become findings with evidence."),
        ),
    ),
    Playbook(
        key="purple_validation",
        title="Purple-Team Detection Validation",
        objective=(
            "Execute controlled technique simulations against authorized "
            "segments and verify whether telemetry and alerts fire."
        ),
        domain_keys=("attack_defense", "system_hacking", "security_architecture"),
        steps=(
            PlaybookStep(1, "Confirm technique list & window", "info", "",
                         "Purple-team plan approved and signed off by both teams."),
            PlaybookStep(2, "Baseline check", "info", "",
                         "Confirm SIEM ingestion healthy before simulating."),
            PlaybookStep(3, "Run controlled simulations", "config_assessment", "",
                         "Atomic-style technique execution on designated hosts."),
            PlaybookStep(4, "Verify alert coverage", "info", "",
                         "Map fired vs expected alerts; document gaps."),
            PlaybookStep(5, "Close gaps & retest", "info", "",
                         "Detection engineering loop with evidence trail."),
        ),
    ),
    Playbook(
        key="phishing_sim",
        title="Consented Phishing Simulation",
        objective=(
            "Measure human-layer resilience with explicit approval, designated "
            "recipients and zero real credential collection."
        ),
        domain_keys=("social_engineering",),
        steps=(
            PlaybookStep(1, "Written approval & recipient list", "info", "",
                         "HR/legal sign-off; designated recipients only."),
            PlaybookStep(2, "Synthetic payload preparation", "info", "",
                         "No real credential capture; landing pages record clicks only."),
            PlaybookStep(3, "Send simulation", "intrusive_testing", "phishing-sim",
                         "Rate-limited dispatch through approved infrastructure."),
            PlaybookStep(4, "Collect metrics", "info", "",
                         "Open/click/report rates feed awareness programs."),
            PlaybookStep(5, "Publish aggregate results", "info", "",
                         "Never individual punishment; awareness is the goal."),
        ),
    ),
    Playbook(
        key="lab_wireless",
        title="Lab Wireless Security Validation",
        objective=(
            "Validate Wi-Fi posture on owned lab APs: survey, configuration "
            "review and handshake-strength demonstration in isolation."
        ),
        domain_keys=("wireless", "cryptography"),
        steps=(
            PlaybookStep(1, "Confirm RF authorization & isolation", "info", "",
                         "Owned APs, isolated segment, RF legal review done."),
            PlaybookStep(2, "AP/SSID survey", "active_recon", "wireless-survey",
                         "Channels, encryption modes, rogue identification."),
            PlaybookStep(3, "Configuration review", "config_assessment", "",
                         "WPA3/802.1X presence; WEP/TKIP/WPS absence."),
            PlaybookStep(4, "Handshake strength demo (lab)", "exploit_validation", "",
                         "Owned-AP handshake capture; passphrase policy validation."),
            PlaybookStep(5, "Harden & retest", "info", "",
                         "PMF, SAE, strong passphrases; re-run survey."),
        ),
    ),
    Playbook(
        key="cloud_posture",
        title="Cloud & Container Posture Review",
        objective=(
            "Review tenant-side cloud configuration: identities, storage "
            "exposure, container posture — provider-side controls excluded."
        ),
        domain_keys=("cloud_iot", "security_architecture"),
        steps=(
            PlaybookStep(1, "Confirm tenant scope & read-only credentials", "info", "",
                         "Assessment role with read-only permissions, in scope."),
            PlaybookStep(2, "Asset inventory", "config_assessment", "cloud-inventory",
                         "Accounts, roles, buckets, instances, clusters."),
            PlaybookStep(3, "Storage exposure check", "config_assessment", "bucket-exposure",
                         "Public access blocks, bucket policies."),
            PlaybookStep(4, "IAM policy review", "config_assessment", "iam-policy-review",
                         "Wildcards, privilege spread, unused roles."),
            PlaybookStep(5, "Container posture audit", "config_assessment", "container-audit",
                         "Image hygiene, RBAC, secrets exposure."),
        ),
    ),
    Playbook(
        key="full_assessment",
        title="Full Authorized Assessment (Staged)",
        objective=(
            "End-to-end engagement flow: authorization, passive footprint, "
            "discovery, enumeration, controlled validation, reporting — "
            "every stage gated as usual."
        ),
        domain_keys=("ethical_hacking", "footprinting", "scanning", "enumeration", "attack_defense"),
        steps=(
            PlaybookStep(1, "Confirm authorization & scope", "info", "",
                         "Signed RoE, active case, scope entries verified."),
            PlaybookStep(2, "Passive footprint", "passive_recon", "whois-lookup",
                         "Registry, DNS and certificate intelligence."),
            PlaybookStep(3, "Host & service discovery", "discovery", "host-discovery",
                         "Live hosts and exposed services inside scope."),
            PlaybookStep(4, "Structured enumeration", "network_mapping", "smb-enum",
                         "SMB/SNMP/LDAP/NFS listings on discovered hosts."),
            PlaybookStep(5, "Vulnerability correlation", "vuln_validation", "vuln-correlate",
                         "Observed tech mapped to vulnerability intel."),
            PlaybookStep(6, "Controlled validation (lab/approval)", "exploit_validation", "exploit-validation",
                         "Only designated targets, explicit approval, full audit."),
            PlaybookStep(7, "Report with evidence", "info", "",
                         "Findings reference evidence IDs; unknowns stay unknown."),
        ),
    ),
    Playbook(
        key="vuln_triage",
        title="Vulnerability Scan & Triage",
        objective=(
            "Scan authorized assets, validate scanner findings against "
            "context, and produce prioritized, evidence-backed results."
        ),
        domain_keys=("scanning", "attack_defense"),
        steps=(
            PlaybookStep(1, "Confirm scan window & targets", "info", "",
                         "Written window, target list, scan intensity agreed."),
            PlaybookStep(2, "Authenticated vulnerability scan", "vuln_validation", "vuln-scan",
                         "Credentialed scan where authorized; unauthenticated otherwise."),
            PlaybookStep(3, "False-positive triage", "info", "",
                         "Every finding needs contextual evidence before it is real."),
            PlaybookStep(4, "Validate exploitable candidates (lab)", "exploit_validation", "exploit-validation",
                         "Only on designated lab targets with approval."),
            PlaybookStep(5, "Prioritize & report", "info", "",
                         "Severity by impact and exploitability, with evidence."),
        ),
    ),
    Playbook(
        key="sniffing_audit",
        title="Traffic & Sniffing Exposure Audit",
        objective=(
            "Audit cleartext exposure and spoofing resilience on authorized "
            "segments using capture-based evidence."
        ),
        domain_keys=("sniffing", "networking"),
        steps=(
            PlaybookStep(1, "Confirm capture authorization", "info", "",
                         "Owned segments, SPAN/tap access, retention agreed."),
            PlaybookStep(2, "Authorized capture", "network_mapping", "",
                         "Filtered capture with interface/time/hash as evidence."),
            PlaybookStep(3, "Cleartext exposure review", "config_assessment", "",
                         "HTTP/FTP/Telnet credentials visible on the wire."),
            PlaybookStep(4, "Spoofing resilience review", "vuln_validation", "",
                         "DAI, snooping, DNSSEC configuration checks."),
            PlaybookStep(5, "Encrypt & retest", "info", "",
                         "TLS rollout, legacy protocol retirement, re-capture."),
        ),
    ),
    Playbook(
        key="physical_se_review",
        title="Physical & Human-Layer Resilience Review",
        objective=(
            "Assess physical and call-center resilience through governed "
            "review and consented simulation only."
        ),
        domain_keys=("social_engineering", "ethical_hacking"),
        steps=(
            PlaybookStep(1, "Confirm sign-off & identification rules", "info", "",
                         "Facility approval, visible operator ID, no covert entry."),
            PlaybookStep(2, "Physical control review", "info", "",
                         "Badges, mantraps, visitor logs, clean-desk, shredding."),
            PlaybookStep(3, "Consented vishing simulation", "intrusive_testing", "",
                         "Scripted pretexts, designated staff, no real credentials."),
            PlaybookStep(4, "Report-button & verification culture check", "info", "",
                         "How staff verify identities and report attempts."),
            PlaybookStep(5, "Awareness findings & training plan", "info", "",
                         "Metrics feed training, never punishment."),
        ),
    ),
    Playbook(
        key="dos_resilience",
        title="DoS Resilience Review (Analysis-Only)",
        objective=(
            "Review denial-of-service exposure through configuration and "
            "architecture analysis — no flooding without written approval."
        ),
        domain_keys=("attack_defense", "networking"),
        steps=(
            PlaybookStep(1, "Confirm review-only scope", "info", "",
                         "No traffic generation without provider coordination."),
            PlaybookStep(2, "Bandwidth & amplification exposure", "config_assessment", "",
                         "Open amplifiers, bandwidth ceilings, upstream filtering."),
            PlaybookStep(3, "Rate-limit & connection-table review", "config_assessment", "",
                         "Per-source limits, slowloris-style headers, backlog settings."),
            PlaybookStep(4, "Absorption architecture review", "info", "",
                         "CDN/anycast, scrubbing services, failover runbooks."),
            PlaybookStep(5, "Resilience findings", "info", "",
                         "Gaps reported with evidence and retest plan."),
        ),
    ),
)


def find_playbook(key: str) -> Playbook | None:
    key = key.strip().lower().replace("-", "_")
    for pb in PLAYBOOKS:
        if pb.key == key:
            return pb
    return None


def playbooks_for_domain(domain_key: str) -> list[Playbook]:
    key = domain_key.strip().lower().replace("-", "_")
    return [pb for pb in PLAYBOOKS if key in pb.domain_keys]


def playbooks_context() -> dict:
    """Machine-readable playbook set for the LLM planner."""
    return {
        "schema_version": 1,
        "playbooks": [
            {
                "key": pb.key,
                "title": pb.title,
                "objective": pb.objective,
                "domains": list(pb.domain_keys),
                "steps": [
                    {
                        "order": s.order,
                        "title": s.title,
                        "capability_class": s.capability_class,
                        "action_hint": s.action_hint,
                        "description": s.description,
                    }
                    for s in pb.steps
                ],
            }
            for pb in PLAYBOOKS
        ],
        "rule": (
            "Playbooks are step templates. Each step is still an individual "
            "action request that must pass scope + policy gates at run time."
        ),
    }
