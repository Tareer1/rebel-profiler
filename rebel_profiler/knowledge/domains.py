"""Knowledge domains: the full ethical-hacking coverage map.

Each domain mirrors a standard curriculum area (CEH v13 blueprint ordering) as
*topics and capability guidance* authored for Rebel Profiler. No external text
is reproduced; this is the project's own reference model used for planning,
tool selection and explanation.

Every domain and topic is wired to:
  * capability classes (what the system may do)
  * authorization gates (what policy must decide)
  * Kali tooling (who provides it)
  * defensive counterpart (blue-team relevance)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Topic:
    key: str
    title: str
    capability_class: str          # maps to security/risk.py classes
    summary: str                   # original, exam-domain-level explanation
    defensive: str                 # blue-team / hardening relevance
    keywords: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class KnowledgeDomain:
    key: str
    number: int
    title: str
    objective: str
    topics: tuple[Topic, ...]

    def topic(self, key: str) -> Topic | None:
        for t in self.topics:
            if t.key == key:
                return t
        return None


DOMAINS: tuple[KnowledgeDomain, ...] = (
    KnowledgeDomain(
        key="ethical_hacking",
        number=1,
        title="Ethical Hacking Foundations",
        objective=(
            "Operate within an authorized engagement model: explicit written "
            "authorization, defined scope, legal boundaries, and staged "
            "methodology from reconnaissance through reporting."
        ),
        topics=(
            Topic(
                key="authorization",
                title="Authorization & Rules of Engagement",
                capability_class="info",
                summary=(
                    "Every operation requires documented authorization, scope "
                    "ownership, time windows and emergency contacts before any "
                    "capability runs. The system enforces scope independently of "
                    "the operator or LLM."
                ),
                defensive=(
                    "Organizations should define rules of engagement so internal "
                    "teams can distinguish authorized testing from real attacks."
                ),
                keywords=("authorization", "roe", "scope", "legal", "consent"),
            ),
            Topic(
                key="kill_chain",
                title="Cyber Kill Chain & Attack Lifecycle",
                capability_class="info",
                summary=(
                    "Attack progression model: reconnaissance, weaponization, "
                    "delivery, exploitation, installation, command & control, "
                    "actions on objectives. Used to stage assessments and to "
                    "map defensive controls to each stage."
                ),
                defensive=(
                    "Mapping detections to kill-chain stages reveals which "
                    "stages your controls actually cover."
                ),
                keywords=("kill chain", "attack lifecycle", "stages", "att&ck"),
            ),
            Topic(
                key="methodology",
                title="Five-Phase Methodology",
                capability_class="info",
                summary=(
                    "Standard phases: (1) reconnaissance/footprinting, "
                    "(2) scanning & enumeration, (3) gaining access, "
                    "(4) maintaining access, (5) covering tracks. In this "
                    "framework, phases 4-5 are modeled only as detection "
                    "validation, never as unauthorized persistence."
                ),
                defensive=(
                    "Blue teams use the same phases to design detection and "
                    "response coverage."
                ),
                keywords=("methodology", "phases", "workflow"),
            ),
        ),
    ),
    KnowledgeDomain(
        key="networking",
        number=2,
        title="Networking Foundations",
        objective=(
            "Understand layered communication, addressing, routing and core "
            "protocols so discovery and assessment outputs are interpreted "
            "correctly."
        ),
        topics=(
            Topic(
                key="models",
                title="OSI & TCP/IP Models",
                capability_class="info",
                summary=(
                    "Seven-layer OSI reference and the four-layer TCP/IP "
                    "architecture. Protocol behavior at each layer determines "
                    "which discovery technique applies (e.g., ARP at L2, ICMP "
                    "at L3, TCP/UDP services at L4+)."
                ),
                defensive="Layer-aware segmentation and filtering strategies.",
                keywords=("osi", "tcp/ip", "layers", "protocols"),
            ),
            Topic(
                key="ip_addressing",
                title="IP Addressing, Subnetting & CIDR",
                capability_class="discovery",
                summary=(
                    "IPv4/IPv6 addressing, subnet masks, CIDR notation and "
                    "private ranges. Scope parsing accepts CIDR notation so "
                    "authorized ranges can be expressed precisely."
                ),
                defensive="Network segmentation limits lateral movement.",
                keywords=("ip", "subnet", "cidr", "ipv6", "private ranges"),
            ),
            Topic(
                key="core_protocols",
                title="Core Protocols (ARP, DNS, DHCP, ICMP, TCP/UDP)",
                capability_class="discovery",
                summary=(
                    "Resolution and transport primitives. DNS records (A, AAAA, "
                    "MX, NS, TXT, CNAME, SOA, PTR, CAA) are a primary passive "
                    "intelligence source; ARP/ICMP behavior informs live-host "
                    "techniques."
                ),
                defensive="Protocol-level logging (DNS, DHCP, ARP) aids anomaly detection.",
                keywords=("dns", "dhcp", "arp", "icmp", "tcp", "udp"),
            ),
            Topic(
                key="routing",
                title="Routing & Path Analysis",
                capability_class="network_mapping",
                summary=(
                    "Routing tables, traceroute behavior and path visibility. "
                    "Used in authorized network mapping to understand exposure "
                    "and segmentation boundaries."
                ),
                defensive="Route hygiene and egress filtering reduce pivot options.",
                keywords=("routing", "traceroute", "path", "ttl"),
            ),
            Topic(
                key="cloud_services",
                title="Cloud Service Models (SaaS/PaaS/IaaS)",
                capability_class="info",
                summary=(
                    "Storage/Infrastructure/Platform/Software-as-a-Service "
                    "models and how the responsibility split shifts with each. "
                    "Determines which controls a cloud assessment may examine "
                    "and which belong to the provider."
                ),
                defensive="Document the split so tenant-side controls are not assumed away.",
                keywords=("saas", "paas", "iaas", "cloud", "responsibility"),
            ),
        ),
    ),
    KnowledgeDomain(
        key="security_foundations",
        number=3,
        title="Security Foundations",
        objective=(
            "Apply CIA triad thinking, threat modeling and control mapping so "
            "findings are expressed as business-relevant risk."
        ),
        topics=(
            Topic(
                key="cia_triad",
                title="CIA Triad & Security Goals",
                capability_class="info",
                summary=(
                    "Confidentiality, integrity and availability as the core "
                    "impact dimensions; every finding should state which "
                    "dimension(s) it threatens."
                ),
                defensive="Impact statements anchor risk prioritization.",
                keywords=("cia", "confidentiality", "integrity", "availability"),
            ),
            Topic(
                key="threat_modeling",
                title="Threat Modeling & Attack Surface",
                capability_class="info",
                summary=(
                    "Identify assets, entry points, trust boundaries and "
                    "adversary capabilities. The attack-surface graph in this "
                    "framework is the structural output of this topic."
                ),
                defensive="Threat models drive control placement and test coverage.",
                keywords=("threat model", "attack surface", "trust boundary"),
            ),
            Topic(
                key="controls",
                title="Security Controls & Defense in Depth",
                capability_class="info",
                summary=(
                    "Preventive, detective, corrective and compensating "
                    "controls across layers. Assessment findings map to the "
                    "control that failed or was missing."
                ),
                defensive="Layered controls avoid single-point failure.",
                keywords=("controls", "defense in depth", "compensating"),
            ),
            Topic(
                key="parkerian_hexad",
                title="Parkerian Hexad",
                capability_class="info",
                summary=(
                    "Extends the triad with possession/control, authenticity "
                    "and utility. Useful when a finding affects ownership or "
                    "usability of information without a classic CIA impact."
                ),
                defensive="Broader impact vocabulary produces more complete risk statements.",
                keywords=("parkerian", "hexad", "possession", "authenticity", "utility"),
            ),
            Topic(
                key="security_operations",
                title="Security Technologies & Operations",
                capability_class="info",
                summary=(
                    "Firewalls, IDS/IPS, EDR and SIEM: what each observes, "
                    "blocks and logs. Assessments validate that these controls "
                    "are placed, tuned and actually ingesting telemetry."
                ),
                defensive="Layered detection stack with tested alert paths.",
                keywords=("firewall", "ids", "ips", "edr", "siem"),
            ),
        ),
    ),
    KnowledgeDomain(
        key="footprinting",
        number=4,
        title="Footprinting & Reconnaissance",
        objective=(
            "Collect authorized public and passive intelligence about targets: "
            "domains, DNS, certificates, organizations and digital footprint — "
            "with provenance on every observation."
        ),
        topics=(
            Topic(
                key="passive_recon",
                title="Passive Reconnaissance",
                capability_class="passive_recon",
                summary=(
                    "Gather information without touching target infrastructure: "
                    "DNS records, certificate transparency, public registries, "
                    "archives and search-engine intelligence. Every result "
                    "retains source, time and confidence."
                ),
                defensive="Minimize public exposure: review DNS records, certificates and public documents.",
                keywords=("passive", "osint", "dns", "certificate", "whois"),
            ),
            Topic(
                key="active_recon",
                title="Active Reconnaissance",
                capability_class="active_recon",
                summary=(
                    "Direct interaction with authorized targets (DNS queries to "
                    "authoritative servers, banner checks). Requires scope "
                    "validation and is risk-gated higher than passive work."
                ),
                defensive="Detect and rate-limit probing patterns at edge controls.",
                keywords=("active", "enumeration", "banner", "probe"),
            ),
            Topic(
                key="email_intelligence",
                title="Email & Identifier Intelligence",
                capability_class="passive_recon",
                summary=(
                    "Public email format discovery, identifier correlation and "
                    "exposure checks through legitimate sources. Identity "
                    "claims are always confidence-scored, never asserted as "
                    "confirmed persons."
                ),
                defensive="DMARC/SPF/DKIM reduce spoofing and harvesting value.",
                keywords=("email", "identifier", "username", "breach"),
            ),
            Topic(
                key="competitive_intel",
                title="Organization & Footprint Intelligence",
                capability_class="osint",
                summary=(
                    "Map the organization's public footprint: domains, brands, "
                    "locations, technologies and public announcements into the "
                    "entity graph with alias resolution."
                ),
                defensive="Inventory public assets to find shadow infrastructure.",
                keywords=("organization", "footprint", "brand", "alias"),
            ),
            Topic(
                key="social_osint",
                title="People & Social-Network Intelligence",
                capability_class="passive_recon",
                summary=(
                    "Lawful collection of public professional profiles, org "
                    "charts and exposed identifiers for authorized engagement "
                    "boundaries (e.g., awareness programs). Privacy rules and "
                    "RoE govern scope; every claim stays confidence-scored."
                ),
                defensive="Staff privacy training; minimize public role exposure.",
                keywords=("people", "social network", "profiles", "privacy"),
            ),
        ),
    ),
    KnowledgeDomain(
        key="scanning",
        number=5,
        title="Scanning Networks",
        objective=(
            "Build an authorized, evidence-backed inventory of live hosts, "
            "open services and versions, and map exposure."
        ),
        topics=(
            Topic(
                key="host_discovery",
                title="Host Discovery",
                capability_class="discovery",
                summary=(
                    "Determine which hosts respond on authorized networks using "
                    "ICMP, ARP, TCP/UDP probes. Host states: up, down, "
                    "filtered, unknown — uncertainty is preserved."
                ),
                defensive="ICMP/probe rate monitoring detects discovery sweeps.",
                keywords=("host discovery", "ping", "arp scan", "live hosts"),
            ),
            Topic(
                key="port_scanning",
                title="Port & Service Scanning",
                capability_class="discovery",
                summary=(
                    "TCP connect, SYN, UDP and version-detection techniques "
                    "against authorized hosts. Port states (open/closed/"
                    "filtered) always carry method, time and evidence."
                ),
                defensive="Service exposure review; close or firewall unneeded ports.",
                keywords=("port scan", "syn", "udp scan", "service", "open ports"),
            ),
            Topic(
                key="os_fingerprinting",
                title="OS & Service Fingerprinting",
                capability_class="discovery",
                summary=(
                    "Infer operating system and service versions from network "
                    "signatures. Fingerprinting is probabilistic: results "
                    "include confidence, never presented as certain."
                ),
                defensive="Standardized banners reduce information leakage.",
                keywords=("os fingerprint", "banner grabbing", "version"),
            ),
            Topic(
                key="vulnerability_scanning",
                title="Vulnerability Scanning & Correlation",
                capability_class="vuln_validation",
                summary=(
                    "Correlate observed technologies with vulnerability "
                    "intelligence. A database match alone is a *potential* "
                    "finding; validation requires contextual evidence."
                ),
                defensive="Prioritized patching driven by verified applicability.",
                keywords=("vulnerability", "cve", "scanner", "correlation"),
            ),
            Topic(
                key="packet_crafting",
                title="Packet Crafting & Manipulation",
                capability_class="network_mapping",
                summary=(
                    "Hand-built probes (hping-style), fragmented and "
                    "malformed-packet generation used to test how edge "
                    "devices handle abnormal traffic. Runs only against "
                    "authorized segments with rate limits."
                ),
                defensive="Normalize/validate abnormal traffic; monitor crafted-packet signatures.",
                keywords=("hping", "packet crafting", "fragmentation", "probes"),
            ),
            Topic(
                key="scan_evasion",
                title="Scan Evasion Awareness",
                capability_class="info",
                summary=(
                    "How fragmentation, decoys, timing and source manipulation "
                    "affect scan visibility. Modeled so operators understand "
                    "detectability trade-offs and defenders can validate "
                    "detection — stealth itself is never a capability."
                ),
                defensive="Tune IDS to fragmented/slow scans; alert on decoy patterns.",
                keywords=("evasion", "decoy", "fragmentation", "ids", "timing"),
            ),
        ),
    ),
    KnowledgeDomain(
        key="enumeration",
        number=6,
        title="Enumeration",
        objective=(
            "Extract structured listings (users, shares, routes, applications) "
            "from authorized systems to understand identity and resource "
            "exposure."
        ),
        topics=(
            Topic(
                key="netbios_smb",
                title="NetBIOS & SMB Enumeration",
                capability_class="network_mapping",
                summary=(
                    "Enumerate NetBIOS names, SMB shares and session "
                    "information on authorized Windows estates; identify null "
                    "sessions and open shares as findings."
                ),
                defensive="Restrict null sessions; audit share permissions.",
                keywords=("netbios", "smb", "shares", "null session"),
            ),
            Topic(
                key="snmp_ldap",
                title="SNMP & LDAP Enumeration",
                capability_class="network_mapping",
                summary=(
                    "Query authorized SNMP (community strings as findings when "
                    "default) and LDAP directories for users, groups and "
                    "topology."
                ),
                defensive="SNMPv3, ACLs and directory hardening.",
                keywords=("snmp", "ldap", "community string", "directory"),
            ),
            Topic(
                key="nfs_smtp_dns_enum",
                title="NFS, SMTP & DNS Enumeration",
                capability_class="network_mapping",
                summary=(
                    "Enumerate NFS exports, SMTP relay behavior/user "
                    "verification and DNS zone-transfer exposure (a classic "
                    "misconfiguration finding)."
                ),
                defensive="Disable unneeded zone transfers; restrict relay.",
                keywords=("nfs", "smtp", "zone transfer", "axfr"),
            ),
            Topic(
                key="rpc_web_enum",
                title="RPC & Web-Application Enumeration",
                capability_class="network_mapping",
                summary=(
                    "RPC endpoint mapping (portmapper, endpoint mappers) and "
                    "structured web-surface listing: directories, endpoints, "
                    "technologies and exposed admin interfaces on authorized "
                    "web properties."
                ),
                defensive="Restrict RPC exposure; remove listing/directory browsing.",
                keywords=("rpc", "portmapper", "web", "directories", "endpoints"),
            ),
        ),
    ),
    KnowledgeDomain(
        key="system_hacking",
        number=7,
        title="System Hacking (Authorized Validation)",
        objective=(
            "Model credential-attack and privilege-abuse risk through "
            "controlled validation only; persistence concepts are used for "
            "detection engineering, never deployed."
        ),
        topics=(
            Topic(
                key="password_attacks",
                title="Password Attack Modeling",
                capability_class="intrusive_testing",
                summary=(
                    "Understand dictionary, brute-force and hybrid attack "
                    "mechanics to assess password policy strength. In this "
                    "framework these run only as authorized, rate-limited, "
                    "scoped validations against designated test accounts."
                ),
                defensive="MFA, lockout policies, credential-stuffing detection.",
                keywords=("password", "brute force", "dictionary", "lockout"),
            ),
            Topic(
                key="privilege_escalation",
                title="Privilege Escalation Assessment",
                capability_class="vuln_validation",
                summary=(
                    "Assess misconfigurations that permit privilege escalation: "
                    "SUID binaries, writable service paths, group memberships, "
                    "token/rule gaps. Each candidate requires verification "
                    "before becoming a finding."
                ),
                defensive="Least privilege, patch cadence, configuration baselines.",
                keywords=("privilege escalation", "suid", "sudo", "tokens"),
            ),
            Topic(
                key="persistence_detection",
                title="Persistence & Detection Validation",
                capability_class="config_assessment",
                summary=(
                    "Model persistence techniques (scheduled tasks, services, "
                    "run keys) for detection engineering and purple-team "
                    "validation. Deploying persistence is not a core "
                    "capability; validating detection of it is."
                ),
                defensive="Baseline monitoring of autoruns, services and scheduled tasks.",
                keywords=("persistence", "autorun", "scheduled task", "detection"),
            ),
            Topic(
                key="data_exfiltration_risk",
                title="Exfiltration Path Analysis",
                capability_class="network_mapping",
                summary=(
                    "Map egress paths (DNS, HTTPS, cloud storage) that could "
                    "carry data out of an environment, to validate DLP and "
                    "egress controls. Uses synthetic data only."
                ),
                defensive="Egress filtering, DLP, DNS monitoring.",
                keywords=("exfiltration", "egress", "dlp", "c2"),
            ),
            Topic(
                key="exploit_research",
                title="Exploit Research & Validation Prep",
                capability_class="info",
                summary=(
                    "Locating public exploit/patch-diff intelligence and "
                    "mapping it to observed versions. Research is passive; "
                    "any validation runs later through the exploit-validation "
                    "gate on designated lab targets."
                ),
                defensive="Patch intelligence tracked faster than adversary weaponization.",
                keywords=("exploit", "exploit-db", "patches", "research"),
            ),
            Topic(
                key="fuzzing",
                title="Fuzzing & Input Robustness",
                capability_class="vuln_validation",
                summary=(
                    "Feeding malformed input to authorized services to surface "
                    "crash/robustness defects. Runs with rate limits and "
                    "watchdogs on designated targets; every crash becomes an "
                    "evidence-backed finding."
                ),
                defensive="Input validation, fuzzing in CI, crash triage process.",
                keywords=("fuzzing", "malformed input", "robustness", "crash"),
            ),
            Topic(
                key="lotl",
                title="Living-off-the-Land Signals",
                capability_class="config_assessment",
                summary=(
                    "Native admin tools used abusively (scripting hosts, remote "
                    "exec utilities) produce few artifacts. Assessments review "
                    "logging of these binaries so abuse is detectable."
                ),
                defensive="Command-line auditing and application allow-listing.",
                keywords=("lotl", "lolbas", "native tools", "detection"),
            ),
        ),
    ),
    KnowledgeDomain(
        key="malware",
        number=8,
        title="Malware Threat Analysis",
        objective=(
            "Static, sandboxed, evidence-first analysis of suspicious artifacts "
            "with IOC extraction and threat correlation — never execution "
            "outside controlled environments."
        ),
        topics=(
            Topic(
                key="malware_types",
                title="Malware Taxonomy",
                capability_class="info",
                summary=(
                    "Trojans, worms, ransomware, rootkits, spyware, fileless "
                    "techniques — behavior classes that shape expected "
                    "artifacts and IOCs during investigation."
                ),
                defensive="Taxonomy informs detection rules and user training.",
                keywords=("trojan", "ransomware", "rootkit", "fileless"),
            ),
            Topic(
                key="static_analysis",
                title="Static Analysis & Metadata",
                capability_class="config_assessment",
                summary=(
                    "Inspect files without execution: hashes, strings, "
                    "imports, packer indicators, embedded IOCs, YARA-oriented "
                    "matching. All artifacts quarantined by default."
                ),
                defensive="Quarantine-first handling; hash-based blocklists.",
                keywords=("static", "strings", "yara", "hash", "packer"),
            ),
            Topic(
                key="sandboxing",
                title="Sandbox & Behavior Analysis",
                capability_class="config_assessment",
                summary=(
                    "Reference controlled detonation workflows and interpret "
                    "behavior reports (process, file, registry, network "
                    "activity). Detonation happens in dedicated infrastructure, "
                    "never on operator workstations."
                ),
                defensive="Isolated analysis environments; behavioral detections.",
                keywords=("sandbox", "detonation", "behavior", "isolated"),
            ),
            Topic(
                key="ioc_extraction",
                title="IOC Extraction & Threat Correlation",
                capability_class="osint",
                summary=(
                    "Extract IPs, domains, hashes, mutexes and URLs from "
                    "artifacts and reports into the IOC lifecycle "
                    "(new -> validated -> active -> stale) and threat graph."
                ),
                defensive="IOC feeds integrated into SIEM detection.",
                keywords=("ioc", "indicator", "threat intel", "campaign"),
            ),
        ),
    ),
    KnowledgeDomain(
        key="sniffing",
        number=9,
        title="Sniffing & Traffic Analysis",
        objective=(
            "Capture and interpret authorized network traffic to assess "
            "cleartext exposure, protocol abuse and defensive telemetry "
            "quality."
        ),
        topics=(
            Topic(
                key="capture_basics",
                title="Capture Fundamentals",
                capability_class="network_mapping",
                summary=(
                    "Promiscuous mode, capture filters and span/mirror ports "
                    "on authorized segments. Every capture retains interface, "
                    "time range, filter and hash as evidence."
                ),
                defensive="Detect unauthorized promiscuous interfaces.",
                keywords=("capture", "promiscuous", "pcap", "span port"),
            ),
            Topic(
                key="cleartext_protocols",
                title="Cleartext Protocol Exposure",
                capability_class="config_assessment",
                summary=(
                    "Assess cleartext services (HTTP, FTP, Telnet, SMTP "
                    "without TLS) that expose credentials or data on the wire — "
                    "a standard finding category."
                ),
                defensive="TLS everywhere; HSTS; legacy protocol retirement.",
                keywords=("cleartext", "http", "ftp", "telnet", "plaintext"),
            ),
            Topic(
                key="spoofing",
                title="ARP/NDP & Name-Resolution Spoofing Risk",
                capability_class="vuln_validation",
                summary=(
                    "Model on-path attack risk (ARP/NDP spoofing, rogue DHCP, "
                    "DNS spoofing) via configuration and segmentation review. "
                    "Active spoof tests only on isolated lab segments."
                ),
                defensive="Dynamic ARP inspection, DHCP snooping, DNSSEC.",
                keywords=("arp spoofing", "rogue dhcp", "dns spoofing", "mitm"),
            ),
        ),
    ),
    KnowledgeDomain(
        key="social_engineering",
        number=10,
        title="Social Engineering (Authorized Simulation)",
        objective=(
            "Assess human-layer resilience through governed, consented "
            "simulation and awareness measurement — with strict approval "
            "gates."
        ),
        topics=(
            Topic(
                key="se_types",
                title="Social Engineering Taxonomy",
                capability_class="info",
                summary=(
                    "Phishing, vishing, smishing, pretexting, tailgating, "
                    "baiting — human attack vectors and their indicators."
                ),
                defensive="Awareness training and reporting culture.",
                keywords=("phishing", "pretexting", "vishing", "tailgating"),
            ),
            Topic(
                key="phishing_simulation",
                title="Authorized Phishing Simulation",
                capability_class="intrusive_testing",
                summary=(
                    "Run consented phishing simulations with explicit written "
                    "approval, designated recipients, synthetic payloads and "
                    "no real credential collection. Results feed awareness "
                    "metrics, not punishment."
                ),
                defensive="Report-button culture; phishing triage playbooks.",
                keywords=("phishing simulation", "consent", "awareness", "metrics"),
            ),
            Topic(
                key="impersonation",
                title="Identity & Impersonation Indicators",
                capability_class="osint",
                summary=(
                    "Detect look-alike domains, fake profiles and brand abuse "
                    "through passive intelligence; evidence-backed "
                    "correlation only."
                ),
                defensive="Brand monitoring and takedown processes.",
                keywords=("impersonation", "lookalike domain", "brand abuse"),
            ),
            Topic(
                key="physical_se",
                title="Physical & On-Premise Vectors",
                capability_class="info",
                summary=(
                    "Tailgating, badge handling, device baiting and call-based "
                    "pretexts: modeled for awareness measurement and physical "
                    "control review. Any authorized exercise requires facility "
                    "sign-off and visible operator identification."
                ),
                defensive="Mantraps, badge discipline, visitor policy, shred/collect hygiene.",
                keywords=("tailgating", "badge", "baiting", "physical", "pretext"),
            ),
        ),
    ),
    KnowledgeDomain(
        key="wireless",
        number=11,
        title="Wireless Security",
        objective=(
            "Assess Wi-Fi and adjacent wireless posture within explicit "
            "hardware/authorization boundaries."
        ),
        topics=(
            Topic(
                key="wifi_standards",
                title="Wi-Fi Standards & Encryption",
                capability_class="info",
                summary=(
                    "802.11 family, WEP (broken), WPA/WPA2/WPA3, enterprise vs "
                    "personal modes. WEP/TKIP presence is a direct finding."
                ),
                defensive="WPA3/Enterprise deployment, deprecation of legacy modes.",
                keywords=("wifi", "wpa2", "wpa3", "wep", "802.11"),
            ),
            Topic(
                key="wireless_discovery",
                title="Wireless Discovery & Rogue Detection",
                capability_class="active_recon",
                summary=(
                    "Authorized RF survey: APs, SSIDs, channels, security "
                    "configuration, rogue/unknown AP identification. Requires "
                    "designated interfaces and legal review (RF regulation)."
                ),
                defensive="Rogue AP detection, WIDS/WIPS deployment.",
                keywords=("rogue ap", "survey", "ssid", "wids"),
            ),
            Topic(
                key="wpa_validation",
                title="WPA Handshake Validation (Lab)",
                capability_class="exploit_validation",
                summary=(
                    "Handshake-capture-based validation of passphrase strength "
                    "runs only against lab/owned APs on isolated segments, "
                    "never third-party networks."
                ),
                defensive="Strong passphrases, 802.1X, protected management frames.",
                keywords=("handshake", "wpa2", "capture", "lab only"),
            ),
            Topic(
                key="bluetooth_iot_rf",
                title="Bluetooth & Other RF",
                capability_class="active_recon",
                summary=(
                    "Bluetooth device discovery/classification and other RF "
                    "surface mapping in authorized environments."
                ),
                defensive="Disable unused radios; BT pairing policy.",
                keywords=("bluetooth", "ble", "rf", "discovery"),
            ),
            Topic(
                key="mobile_security",
                title="Mobile Device Security",
                capability_class="config_assessment",
                summary=(
                    "BYOD/cohort policy, MDM enrollment, containerization and "
                    "app-permission posture for authorized corporate estates. "
                    "Findings cover policy gaps, not personal devices."
                ),
                defensive="MDM/UEM baselines; managed app catalogs.",
                keywords=("mobile", "byod", "mdm", "device policy"),
            ),
        ),
    ),
    KnowledgeDomain(
        key="attack_defense",
        number=12,
        title="Attack & Defense (Purple Team)",
        objective=(
            "Connect authorized attack modeling with detection engineering: "
            "simulate, detect, investigate, validate, remediate, retest."
        ),
        topics=(
            Topic(
                key="attack_models",
                title="Attack Models & Technique Mapping",
                capability_class="info",
                summary=(
                    "Map authorized assessment activity to technique "
                    "categories (recon, initial access, execution, persistence, "
                    "C2, exfiltration) so results are comparable across teams."
                ),
                defensive="Technique coverage matrices guide detection investment.",
                keywords=("att&ck", "techniques", "tactics", "mapping"),
            ),
            Topic(
                key="detection_validation",
                title="Detection Validation",
                capability_class="config_assessment",
                summary=(
                    "Execute controlled technique simulations against "
                    "authorized segments, then verify whether alerts fired — "
                    "producing coverage gaps as findings."
                ),
                defensive="Purple-team loop: simulate -> detect -> close gaps.",
                keywords=("purple team", "detection", "validation", "coverage"),
            ),
            Topic(
                key="incident_workflow",
                title="Incident Response Integration",
                capability_class="info",
                summary=(
                    "Incident lifecycle: preparation, identification, "
                    "containment, eradication, recovery, lessons learned. The "
                    "case workspace models IR investigations with timeline "
                    "reconstruction."
                ),
                defensive="IR playbooks, tabletop exercises, metrics.",
                keywords=("incident response", "ir", "containment", "playbook"),
            ),
            Topic(
                key="dos_analysis",
                title="Denial-of-Service Exposure Analysis",
                capability_class="config_assessment",
                summary=(
                    "Review bandwidth/amplification exposure, rate limiting, "
                    "connection-table behavior and upstream filtering for "
                    "authorized properties. Load/DoS simulation only with "
                    "provider coordination and written approval."
                ),
                defensive="Rate limiting, anycast/CDN absorption, upstream scrubbing.",
                keywords=("dos", "ddos", "amplification", "rate limit"),
            ),
            Topic(
                key="memory_safety",
                title="Memory-Safety Defect Classes",
                capability_class="info",
                summary=(
                    "Buffer overflows, heap spraying and related memory-safety "
                    "classes: how they work, how mitigations (ASLR, DEP/NX, "
                    "stack canaries) change exploitability, and how results "
                    "are reported as design findings."
                ),
                defensive="Compiler hardening, memory-safe languages, patch cadence.",
                keywords=("buffer overflow", "heap", "aslr", "dep", "memory safety"),
            ),
        ),
    ),
    KnowledgeDomain(
        key="cryptography",
        number=13,
        title="Cryptography",
        objective=(
            "Assess cryptographic posture: algorithm strength, certificate "
            "health, protocol configuration — as configuration findings, not "
            "key cracking."
        ),
        topics=(
            Topic(
                key="algorithms",
                title="Symmetric, Asymmetric & Hashing",
                capability_class="info",
                summary=(
                    "AES/ChaCha, RSA/ECC, SHA-2/3 families; classical broken "
                    "algorithms (DES, RC4, MD5 for security) as finding "
                    "categories."
                ),
                defensive="Algorithm agility; approved-algorithm policy.",
                keywords=("aes", "rsa", "sha256", "md5", "rc4"),
            ),
            Topic(
                key="certificates",
                title="Certificates & PKI Health",
                capability_class="config_assessment",
                summary=(
                    "Certificate validity, chain issues, weak signature "
                    "algorithms, expiry, SAN review — integrated with "
                    "certificate intelligence collection."
                ),
                defensive="Automated cert lifecycle; CT monitoring.",
                keywords=("pki", "x509", "certificate", "expiry", "chain"),
            ),
            Topic(
                key="tls_posture",
                title="TLS/SSH Protocol Posture",
                capability_class="config_assessment",
                summary=(
                    "Protocol versions, cipher suites, renegotiation and "
                    "handshake configuration as assessed configuration — "
                    "weak suites (SSLv3, TLS1.0/1.1, NULL/EXPORT) are findings."
                ),
                defensive="Modern TLS baselines; SSH hardening.",
                keywords=("tls", "ssl", "cipher", "ssh", "handshake"),
            ),
            Topic(
                key="key_management",
                title="Key Management & Storage",
                capability_class="info",
                summary=(
                    "Key lifecycle, rotation, storage and secrets hygiene; "
                    "exposed keys detected during assessment are handled "
                    "through the redaction pipeline."
                ),
                defensive="KMS/HSM usage; secret scanning in CI.",
                keywords=("key management", "rotation", "secrets", "kms"),
            ),
        ),
    ),
    KnowledgeDomain(
        key="security_architecture",
        number=14,
        title="Security Architecture & Design",
        objective=(
            "Evaluate security design: identity models, segmentation, hardening "
            "baselines and monitoring architecture."
        ),
        topics=(
            Topic(
                key="identity_architecture",
                title="Identity & Access Architecture",
                capability_class="info",
                summary=(
                    "Authentication/authorization models, directory design, "
                    "least privilege, MFA placement — assessed through the "
                    "identity intelligence engine."
                ),
                defensive="Zero-trust identity baselines.",
                keywords=("iam", "mfa", "directory", "least privilege"),
            ),
            Topic(
                key="segmentation",
                title="Network Segmentation & Zoning",
                capability_class="network_mapping",
                summary=(
                    "VLAN/zone design, DMZ placement, east-west controls — "
                    "validated through authorized mapping and path analysis."
                ),
                defensive="Micro-segmentation limits blast radius.",
                keywords=("segmentation", "vlan", "dmz", "zoning"),
            ),
            Topic(
                key="hardening",
                title="System Hardening & Baselines",
                capability_class="config_assessment",
                summary=(
                    "Configuration baselines for hosts/services; drift "
                    "detection against approved baselines produces "
                    "compliance findings."
                ),
                defensive="CIS-style baselines; automated drift detection.",
                keywords=("hardening", "baseline", "cis", "drift"),
            ),
            Topic(
                key="monitoring_arch",
                title="Logging & Monitoring Architecture",
                capability_class="info",
                summary=(
                    "Log sources, retention, SIEM architecture, detection "
                    "coverage — evaluated as part of defensive findings."
                ),
                defensive="Central logging; integrity-protected audit trails.",
                keywords=("siem", "logging", "monitoring", "retention"),
            ),
        ),
    ),
    KnowledgeDomain(
        key="cloud_iot",
        number=15,
        title="Cloud Computing & IoT",
        objective=(
            "Assess cloud tenancy configuration and IoT/embedded device "
            "exposure within authorized boundaries."
        ),
        topics=(
            Topic(
                key="cloud_models",
                title="Cloud Service & Deployment Models",
                capability_class="info",
                summary=(
                    "IaaS/PaaS/SaaS and responsibility-split model: which "
                    "controls belong to provider vs tenant — the basis of "
                    "cloud assessment scope."
                ),
                defensive="Shared-responsibility clarity prevents gaps.",
                keywords=("iaas", "paas", "saas", "shared responsibility"),
            ),
            Topic(
                key="cloud_iam_storage",
                title="Cloud IAM & Storage Exposure",
                capability_class="config_assessment",
                summary=(
                    "Authorized cloud inventory: identities, roles, policies, "
                    "storage ACLs, public bucket exposure — findings require "
                    "cloud-side evidence."
                ),
                defensive="CSPM posture, bucket lockdown, role minimization.",
                keywords=("cloud iam", "bucket", "cspm", "exposure"),
            ),
            Topic(
                key="containers",
                title="Containers & Kubernetes Posture",
                capability_class="config_assessment",
                summary=(
                    "Image hygiene, runtime config, RBAC, secrets exposure "
                    "indicators, namespace isolation as assessed posture."
                ),
                defensive="Admission controls, least-privilege service accounts.",
                keywords=("docker", "kubernetes", "image", "rbac", "secrets"),
            ),
            Topic(
                key="iot_security",
                title="IoT & Embedded Device Security",
                capability_class="active_recon",
                summary=(
                    "Device inventory, default credentials, firmware/version "
                    "exposure and network placement of IoT assets in "
                    "authorized environments."
                ),
                defensive="Device segregation, firmware updates, vendor patching.",
                keywords=("iot", "firmware", "default credentials", "embedded"),
            ),
            Topic(
                key="ot_security",
                title="OT/ICS & the Purdue Model",
                capability_class="config_assessment",
                summary=(
                    "Operational-technology zones per the Purdue levels: "
                    "IT/OT boundary enforcement, unidirectional gateways and "
                    "asset safety constraints. OT assessments are "
                    "observation-first; no active probing without explicit "
                    "safety authorization."
                ),
                defensive="Zone-conduits, Purdue layering, safety-instrumented review.",
                keywords=("ot", "ics", "scada", "purdue", "conduit"),
            ),
        ),
    ),
)


def list_domains() -> list[dict]:
    """List all domains with topic counts (for CLI/help/LLM context)."""
    return [
        {
            "number": d.number,
            "key": d.key,
            "title": d.title,
            "topics": len(d.topics),
            "objective": d.objective,
        }
        for d in DOMAINS
    ]


def find_domain(key: str) -> KnowledgeDomain | None:
    key = key.strip().lower().replace("-", "_")
    for d in DOMAINS:
        if d.key == key or str(d.number) == key:
            return d
    return None


def search(query: str) -> list[tuple[KnowledgeDomain, Topic]]:
    """Keyword search across domains and topics (case-insensitive)."""
    q = query.strip().lower()
    if not q:
        return []
    terms = q.split()
    results: list[tuple[KnowledgeDomain, Topic]] = []
    for d in DOMAINS:
        for t in d.topics:
            haystack = " ".join(
                [d.key, d.title, d.objective, t.key, t.title, t.summary,
                 t.defensive, " ".join(t.keywords)]
            ).lower()
            if all(term in haystack for term in terms):
                results.append((d, t))
    return results


def planner_context(domain_keys: list[str] | None = None) -> dict:
    """Compact structured context for the LLM planner.

    Returns domains with their topics as capability summaries. This is the
    machine-readable knowledge contract: the planner selects capability
    classes from here; policy/risk engines decide whether they may run.
    """
    selected = DOMAINS
    if domain_keys:
        found = [find_domain(k) for k in domain_keys]
        selected = tuple(d for d in found if d is not None)
    return {
        "schema_version": 1,
        "domains": [
            {
                "key": d.key,
                "number": d.number,
                "title": d.title,
                "objective": d.objective,
                "topics": [
                    {
                        "key": t.key,
                        "title": t.title,
                        "capability_class": t.capability_class,
                        "summary": t.summary,
                        "defensive": t.defensive,
                        "keywords": list(t.keywords),
                    }
                    for t in d.topics
                ],
            }
            for d in selected
        ],
        "rule": (
            "Topics describe WHAT a capability means. Authorization, scope and "
            "policy decide WHETHER it may run. No topic implies authorization."
        ),
    }
