"""Deep techniques matrix for every knowledge domain.

For each domain: the techniques an authorized assessment uses, the standard
Kali tooling that provides them, the countermeasure a defender should deploy,
and the authorization gates the policy engine must enforce.

Original reference content authored for Rebel Profiler. Technique taxonomy
mirrors public curriculum coverage (CEH v13 chapter ordering) without
reproducing any external text. Presence here never implies authorization —
the policy engine decides that.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    key: str
    name: str
    capability_class: str          # maps to security/risk.py classes
    kali_tools: tuple[str, ...]    # standard Kali providers
    countermeasure: str            # defensive control that detects/prevents
    notes: str = ""                # extra planner guidance


@dataclass(frozen=True)
class DomainTechniques:
    domain_key: str
    techniques: tuple[Technique, ...]


TECHNIQUES: tuple[DomainTechniques, ...] = (
    DomainTechniques(
        domain_key="ethical_hacking",
        techniques=(
            Technique(
                key="engagement_setup",
                name="Engagement setup & rules of engagement",
                capability_class="info",
                kali_tools=(),
                countermeasure="Maintain RoE docs; train staff to verify tester identity.",
                notes="Always the first step: no RoE, no operations.",
            ),
            Technique(
                key="kill_chain_mapping",
                name="Kill-chain stage mapping",
                capability_class="info",
                kali_tools=(),
                countermeasure="Map detections to each stage; find uncovered stages.",
            ),
            Technique(
                key="scope_reconciliation",
                name="Scope reconciliation & asset ownership check",
                capability_class="info",
                kali_tools=(),
                countermeasure="Keep asset inventories current to avoid scope disputes.",
            ),
        ),
    ),
    DomainTechniques(
        domain_key="networking",
        techniques=(
            Technique(
                key="dns_record_analysis",
                name="DNS record analysis (A/AAAA/MX/NS/TXT/PTR/CAA/SOA)",
                capability_class="passive_recon",
                kali_tools=("dig", "dnsrecon", "dnsenum"),
                countermeasure="Minimize DNS exposure; review zone contents for leakage.",
            ),
            Technique(
                key="subnet_enumeration",
                name="CIDR subnet enumeration & range planning",
                capability_class="discovery",
                kali_tools=("nmap",),
                countermeasure="Segment networks; monitor for range-wide sweeps.",
            ),
            Technique(
                key="path_analysis",
                name="Traceroute / TTL path analysis",
                capability_class="network_mapping",
                kali_tools=("traceroute", "mtr"),
                countermeasure="ICMP rate limiting; egress filtering.",
            ),
            Technique(
                key="protocol_behavior",
                name="Protocol behavior profiling (ARP/DHCP/ICMP/TCP handshake)",
                capability_class="discovery",
                kali_tools=("tcpdump", "wireshark"),
                countermeasure="Protocol-aware monitoring (DHCP snooping, RA guard).",
            ),
            Technique(
                key="tcp_state_analysis",
                name="TCP state-machine analysis (handshake, RST, window)",
                capability_class="info",
                kali_tools=("tcpdump", "wireshark", "ss"),
                countermeasure="Stateful inspection plus TCP-state telemetry for scan detection.",
                notes="Distinguishing filtered (silence) from closed (RST) prevents the "
                      "single most common false finding in port reports.",
            ),
            Technique(
                key="dns_wire_analysis",
                name="DNS resolution-path & record-semantics analysis",
                capability_class="passive_recon",
                kali_tools=("dig", "dnswalk", "dnsutils"),
                countermeasure="DNSSEC signing, CAA records, resolver audit logging.",
            ),
            Technique(
                key="dnssec_validation",
                name="DNSSEC chain-of-trust validation",
                capability_class="passive_recon",
                kali_tools=("dig +dnssec", "delv", "drill"),
                countermeasure="Sign zones and monitor for unsigned delegation drift.",
            ),
            Technique(
                key="tls_handshake_audit",
                name="TLS handshake & certificate-chain audit",
                capability_class="config_assessment",
                kali_tools=("openssl s_client", "sslscan", "testssl.sh"),
                countermeasure="Modern TLS baseline, HSTS preload, automated certificate lifecycle.",
                notes="Judge versions AND cipher suites AND chain together, not in isolation.",
            ),
            Technique(
                key="http_protocol_audit",
                name="HTTP protocol-semantics & proxy-normalization audit",
                capability_class="web_assessment",
                kali_tools=("curl", "httpx", "h2c probe"),
                countermeasure="Strict framing validation at the edge; strip untrusted hop-by-hop headers.",
                notes="Where two components disagree about framing is where smuggling-style defects live.",
            ),
            Technique(
                key="nat_boundary_mapping",
                name="NAT/firewall boundary interpretation (VIP & DNAT mapping)",
                capability_class="network_mapping",
                kali_tools=("nmap", "traceroute", "curl"),
                countermeasure="Consistent deny behaviour; documented VIP/DNAT inventory.",
            ),
            Technique(
                key="ipv6_surface_check",
                name="IPv6 / dual-stack surface check (SLAAC, NDP)",
                capability_class="discovery",
                kali_tools=("nmap -6", "fping -6", "ndisc6"),
                countermeasure="RA Guard, DHCPv6 snooping, IPv6 ACL parity with IPv4.",
                notes="The v6 path is frequently the unmonitored twin of a well-defended v4 path.",
            ),
        ),
    ),
    DomainTechniques(
        domain_key="security_foundations",
        techniques=(
            Technique(
                key="impact_scoring",
                name="CIA impact scoring of findings",
                capability_class="info",
                kali_tools=(),
                countermeasure="Express risk in business terms for prioritization.",
            ),
            Technique(
                key="attack_surface_mapping",
                name="Attack-surface mapping from inventory",
                capability_class="info",
                kali_tools=(),
                countermeasure="Reduce surface: close ports, retire services.",
            ),
            Technique(
                key="control_gap_analysis",
                name="Control gap analysis (prevent/detect/correct)",
                capability_class="info",
                kali_tools=(),
                countermeasure="Defense-in-depth review against control catalog.",
            ),
        ),
    ),
    DomainTechniques(
        domain_key="footprinting",
        techniques=(
            Technique(
                key="whois_collection",
                name="WHOIS/registry record collection",
                capability_class="passive_recon",
                kali_tools=("whois",),
                countermeasure="Registry privacy protection; review public records.",
            ),
            Technique(
                key="ct_log_review",
                name="Certificate transparency log review",
                capability_class="passive_recon",
                kali_tools=("certctl",),
                countermeasure="Monitor CT logs for rogue certs on your domains.",
            ),
            Technique(
                key="web_archive_review",
                name="Web archive & cached-content review",
                capability_class="passive_recon",
                kali_tools=("waybackurls",),
                countermeasure="Remove sensitive content from public pages/archives.",
            ),
            Technique(
                key="email_format_discovery",
                name="Email format & identifier discovery",
                capability_class="passive_recon",
                kali_tools=("theharvester",),
                countermeasure="DMARC p=reject; limit published contact patterns.",
            ),
            Technique(
                key="google_dorking",
                name="Search-engine dorking for exposure",
                capability_class="passive_recon",
                kali_tools=("lynx", "curl"),
                countermeasure="Robots hygiene; remove indexed sensitive paths.",
            ),
        ),
    ),
    DomainTechniques(
        domain_key="scanning",
        techniques=(
            Technique(
                key="icmp_sweep",
                name="ICMP/ARP live-host sweep",
                capability_class="discovery",
                kali_tools=("nmap", "arp-scan", "fping"),
                countermeasure="Sweep detection at NIDS; ICMP rate limits.",
            ),
            Technique(
                key="tcp_connect_scan",
                name="TCP connect scan",
                capability_class="discovery",
                kali_tools=("nmap",),
                countermeasure="Port-scan detection; connection-rate anomalies.",
            ),
            Technique(
                key="syn_scan",
                name="SYN (half-open) scan",
                capability_class="discovery",
                kali_tools=("nmap",),
                countermeasure="SYN-flood heuristics surface scanning activity.",
            ),
            Technique(
                key="udp_scan",
                name="UDP service scan (slow, needs patience)",
                capability_class="discovery",
                kali_tools=("nmap", "udp-proto-scanner"),
                countermeasure="Monitor ICMP-port-unreachable rates.",
            ),
            Technique(
                key="service_version_detection",
                name="Service/version detection probes",
                capability_class="discovery",
                kali_tools=("nmap",),
                countermeasure="Standardized banners; limit version leakage.",
            ),
            Technique(
                key="os_fingerprinting_tcp_ip",
                name="OS fingerprinting (TCP/IP stack signatures)",
                capability_class="discovery",
                kali_tools=("nmap", "p0f"),
                countermeasure="Stack tuning reduces signature fidelity.",
            ),
            Technique(
                key="spoof_decoy_awareness",
                name="Decoy/IDLE-scan awareness (detection side)",
                capability_class="info",
                kali_tools=(),
                countermeasure="Correlate scan sources; flag spoofed proxies.",
                notes="Modeled for detection only; framework never spoofs.",
            ),
        ),
    ),
    DomainTechniques(
        domain_key="enumeration",
        techniques=(
            Technique(
                key="netbios_enum",
                name="NetBIOS name/service enumeration",
                capability_class="network_mapping",
                kali_tools=("nbtscan",),
                countermeasure="Restrict NetBIOS; filter 137-139 at boundaries.",
            ),
            Technique(
                key="smb_share_enum",
                name="SMB share & session enumeration",
                capability_class="network_mapping",
                kali_tools=("enum4linux-ng", "smbclient", "crackmapexec"),
                countermeasure="Disable null sessions; audit share ACLs.",
            ),
            Technique(
                key="snmp_enum",
                name="SNMP MIB walk (v1/v2c default communities)",
                capability_class="network_mapping",
                kali_tools=("snmpwalk", "snmpcheck"),
                countermeasure="SNMPv3 + ACLs; remove default communities.",
            ),
            Technique(
                key="ldap_enum",
                name="LDAP directory enumeration",
                capability_class="network_mapping",
                kali_tools=("ldapsearch",),
                countermeasure="Anonymous binds off; directory hardening.",
            ),
            Technique(
                key="nfs_export_enum",
                name="NFS export listing",
                capability_class="network_mapping",
                kali_tools=("showmount",),
                countermeasure="Restrict export ACLs; avoid world-readable exports.",
            ),
            Technique(
                key="smtp_user_enum",
                name="SMTP user verification (VRFY/EXPN)",
                capability_class="network_mapping",
                kali_tools=("smtp-user-enum",),
                countermeasure="Disable VRFY/EXPN; rate-limit recipients.",
            ),
            Technique(
                key="dns_axfr_test",
                name="DNS zone transfer (AXFR) misconfiguration test",
                capability_class="network_mapping",
                kali_tools=("dnsenum", "dnsrecon"),
                countermeasure="Restrict transfers to secondaries only.",
            ),
            Technique(
                key="rpc_endpoint_enum",
                name="RPC endpoint & service enumeration",
                capability_class="network_mapping",
                kali_tools=("rpcinfo", "nmap"),
                countermeasure="Filter portmapper/endpoint mapper exposure at boundaries.",
            ),
            Technique(
                key="web_surface_enum",
                name="Web-surface enumeration (dirs, endpoints, tech)",
                capability_class="network_mapping",
                kali_tools=("httpx", "dirb", "whatweb"),
                countermeasure="Disable directory listing; remove admin exposure.",
            ),
        ),
    ),
    DomainTechniques(
        domain_key="system_hacking",
        techniques=(
            Technique(
                key="password_audit_online",
                name="Online password audit (designated test accounts)",
                capability_class="intrusive_testing",
                kali_tools=("hydra", "medusa"),
                countermeasure="Lockout policy, MFA, credential-stuffing alerts.",
                notes="Rate-limited; designated accounts only; approval-gated.",
            ),
            Technique(
                key="offline_hash_audit",
                name="Offline hash audit of owned samples (lab)",
                capability_class="config_assessment",
                kali_tools=("john", "hashcat"),
                countermeasure="Modern hashing (bcrypt/argon2), salting, pepper.",
                notes="Owned/lab hashes only; demonstrates policy weakness.",
            ),
            Technique(
                key="suid_sudo_review",
                name="SUID/sudo misconfiguration review",
                capability_class="vuln_validation",
                kali_tools=("find", "sudo -l", "linpeas"),
                countermeasure="Least privilege; audit sudoers; patch cadence.",
            ),
            Technique(
                key="writable_path_review",
                name="Writable service path / DLL placement review",
                capability_class="vuln_validation",
                kali_tools=("icacls", "accesschk"),
                countermeasure="Service path hardening; ACL reviews.",
            ),
            Technique(
                key="keylogger_concept",
                name="Keylogger concept (detection engineering view)",
                capability_class="info",
                kali_tools=(),
                countermeasure="Endpoint DLP; detect API hooking patterns.",
                notes="Detection modeling only; never deployed by this framework.",
            ),
            Technique(
                key="session_hijack_risk",
                name="Session hijack risk analysis",
                capability_class="info",
                kali_tools=(),
                countermeasure="Secure cookies, TLS, rotation on privilege change.",
            ),
            Technique(
                key="kerberoast_audit",
                name="Kerberoastable account audit (configured lab)",
                capability_class="config_assessment",
                kali_tools=("impacket-GetUserSPNs",),
                countermeasure="Managed service accounts; long random SPN passwords.",
                notes="Runs only against designated lab/test domains.",
            ),
            Technique(
                key="rainbow_table_concept",
                name="Rainbow-table exposure concept",
                capability_class="info",
                kali_tools=(),
                countermeasure="Per-user salts; modern slow KDFs (bcrypt/Argon2).",
            ),
            Technique(
                key="pivot_path_review",
                name="Pivot path review (post-exploitation mapping)",
                capability_class="info",
                kali_tools=(),
                countermeasure="Segmentation; jump-host controls; credential tiering.",
                notes="Modeled for detection design; pivoting is never performed.",
            ),
            Technique(
                key="client_side_surface",
                name="Client-side attack surface review",
                capability_class="info",
                kali_tools=(),
                countermeasure="Patch cadence; browser/mail hardening; EDR coverage.",
            ),
        ),
    ),
    DomainTechniques(
        domain_key="malware",
        techniques=(
            Technique(
                key="static_hashing",
                name="Static hashing & fuzzy hashing of artifacts",
                capability_class="config_assessment",
                kali_tools=("md5sum", "sha256sum", "ssdeep"),
                countermeasure="Hash-based blocklisting; YARA rule deployment.",
            ),
            Technique(
                key="strings_ioc_pull",
                name="Strings/IOC extraction from binaries",
                capability_class="config_assessment",
                kali_tools=("strings", "floss"),
                countermeasure="Quarantine-first handling of suspicious files.",
            ),
            Technique(
                key="packer_detection",
                name="Packer/protector identification",
                capability_class="config_assessment",
                kali_tools=("peid", "diec"),
                countermeasure="Treat packed binaries as untrusted by default.",
            ),
            Technique(
                key="sandbox_reference",
                name="Sandbox detonation reference workflow",
                capability_class="config_assessment",
                kali_tools=("cape", "cuckoo"),
                countermeasure="Isolated detonation infra; behavioral detections.",
                notes="Reference workflow only; detonation is external infra.",
            ),
            Technique(
                key="ransomware_behavior",
                name="Ransomware behavior model (detection focus)",
                capability_class="info",
                kali_tools=(),
                countermeasure="Backup hygiene; mass-file-change alerts; canaries.",
            ),
            Technique(
                key="ioc_lifecycle",
                name="IOC lifecycle management (new→validated→stale)",
                capability_class="osint",
                kali_tools=("misp",),
                countermeasure="Feed SIEM; retire stale indicators promptly.",
            ),
            Technique(
                key="fileless_indicator_review",
                name="Fileless-malware indicator review",
                capability_class="config_assessment",
                kali_tools=("osquery", "sysmon"),
                countermeasure="PowerShell/script logging; AMSI; memory scanning.",
            ),
            Technique(
                key="dropper_chain_analysis",
                name="Dropper/c2 infrastructure chain analysis",
                capability_class="osint",
                kali_tools=("virustotal (authorized)", "misp"),
                countermeasure="Sinkhole/block C2 domains; registrar takedowns.",
            ),
        ),
    ),
    DomainTechniques(
        domain_key="sniffing",
        techniques=(
            Technique(
                key="authorized_capture",
                name="Authorized capture on owned segments (SPAN/tap)",
                capability_class="network_mapping",
                kali_tools=("tcpdump", "wireshark"),
                countermeasure="Detect unauthorized promiscuous interfaces.",
            ),
            Technique(
                key="cleartext_audit",
                name="Cleartext credential exposure audit",
                capability_class="config_assessment",
                kali_tools=("tcpdump", "wireshark"),
                countermeasure="TLS everywhere; retire Telnet/FTP/HTTP auth.",
            ),
            Technique(
                key="arp_spoof_lab",
                name="ARP spoofing validation (isolated lab only)",
                capability_class="vuln_validation",
                kali_tools=("arpspoof", "ettercap"),
                countermeasure="Dynamic ARP inspection; port security.",
                notes="Isolated lab segments only; approval-gated.",
            ),
            Technique(
                key="dns_spoof_lab",
                name="DNS spoofing validation (isolated lab only)",
                capability_class="vuln_validation",
                kali_tools=("dnsspoof",),
                countermeasure="DNSSEC; resolver ACLs.",
                notes="Isolated lab segments only.",
            ),
            Technique(
                key="sslstrip_risk",
                name="SSL-stripping risk assessment",
                capability_class="info",
                kali_tools=(),
                countermeasure="HSTS with preload; HTTPS-only cookies.",
            ),
            Technique(
                key="rogue_dhcp_detection",
                name="Rogue DHCP / starvation detection",
                capability_class="config_assessment",
                kali_tools=("dhcpig (lab only)",),
                countermeasure="DHCP snooping; lease anomaly alerting.",
                notes="Detection/audit focus; active starvation is lab-only.",
            ),
        ),
    ),
    DomainTechniques(
        domain_key="social_engineering",
        techniques=(
            Technique(
                key="pretext_library",
                name="Pretext taxonomy for authorized simulations",
                capability_class="info",
                kali_tools=(),
                countermeasure="Verify-identity culture; reporting drills.",
            ),
            Technique(
                key="phishing_sim_email",
                name="Consented phishing simulation (email)",
                capability_class="intrusive_testing",
                kali_tools=("gophish",),
                countermeasure="Awareness metrics; report-button workflow.",
                notes="Written approval, designated recipients, no credential capture.",
            ),
            Technique(
                key="phishing_sim_sms",
                name="Consented smishing simulation",
                capability_class="intrusive_testing",
                kali_tools=("setoolkit",),
                countermeasure="Mobile awareness training; number verification.",
                notes="Same consent constraints as email sims.",
            ),
            Technique(
                key="lookalike_domain_hunt",
                name="Look-alike domain discovery",
                capability_class="osint",
                kali_tools=("dnstwist",),
                countermeasure="Brand monitoring; defensive registrations.",
            ),
            Technique(
                key="insider_risk_model",
                name="Insider risk indicators (passive model)",
                capability_class="info",
                kali_tools=(),
                countermeasure="Least privilege; UEBA baselines.",
                notes="Privacy-respecting: aggregates only, never surveillance.",
            ),
            Technique(
                key="web_clone_detection",
                name="Cloned/typosquat web property detection",
                capability_class="osint",
                kali_tools=("dnstwist",),
                countermeasure="Brand monitoring; CT-log watch; rapid takedown.",
            ),
            Technique(
                key="vishing_sim",
                name="Consented vishing simulation (helpdesk resilience)",
                capability_class="intrusive_testing",
                kali_tools=(),
                countermeasure="Callback verification procedure; caller-ID education.",
                notes="Written consent, scripted pretexts, no real credentials.",
            ),
        ),
    ),
    DomainTechniques(
        domain_key="wireless",
        techniques=(
            Technique(
                key="ap_survey",
                name="AP/SSID/channel survey",
                capability_class="active_recon",
                kali_tools=("airodump-ng", "kismet"),
                countermeasure="WIDS/WIPS; rogue AP detection.",
                notes="Designated interfaces; RF legal review required.",
            ),
            Technique(
                key="handshake_capture_lab",
                name="WPA handshake validation (owned lab AP)",
                capability_class="exploit_validation",
                kali_tools=("airodump-ng", "aircrack-ng"),
                countermeasure="SAE/WPA3, 802.1X, strong passphrases, PMF.",
                notes="Lab/owned APs only; approval-gated.",
            ),
            Technique(
                key="wps_audit",
                name="WPS presence audit",
                capability_class="config_assessment",
                kali_tools=("reaver", "bully"),
                countermeasure="Disable WPS entirely.",
            ),
            Technique(
                key="bt_device_discovery",
                name="Bluetooth device discovery/classification",
                capability_class="active_recon",
                kali_tools=("btscanner", "bluelog"),
                countermeasure="Disable unused radios; pairing policy.",
            ),
            Technique(
                key="deauth_detection",
                name="Deauth frame monitoring (detection focus)",
                capability_class="info",
                kali_tools=(),
                countermeasure="802.11w protected management frames.",
                notes="Framework monitors/detects; never injects deauth frames.",
            ),
            Technique(
                key="bt_attack_surface",
                name="Bluetooth attack-surface awareness (bluejack/snarf/bug)",
                capability_class="info",
                kali_tools=(),
                countermeasure="Disable discoverable mode; firmware updates; pairing policy.",
            ),
        ),
    ),
    DomainTechniques(
        domain_key="attack_defense",
        techniques=(
            Technique(
                key="technique_mapping",
                name="Assessment activity → technique mapping",
                capability_class="info",
                kali_tools=(),
                countermeasure="Coverage matrices guide detection investment.",
            ),
            Technique(
                key="detection_validation",
                name="Controlled technique simulation + alert verification",
                capability_class="config_assessment",
                kali_tools=("atomic-red-team", "caldera"),
                countermeasure="Purple-team loop closes coverage gaps.",
            ),
            Technique(
                key="log_source_audit",
                name="Log source & retention audit",
                capability_class="info",
                kali_tools=(),
                countermeasure="Central logging with integrity protection.",
            ),
            Technique(
                key="ir_tabletop",
                name="IR readiness tabletop scenario design",
                capability_class="info",
                kali_tools=(),
                countermeasure="Rehearsed playbooks reduce response time.",
            ),
            Technique(
                key="dos_exposure_review",
                name="DoS exposure & rate-limit review (no active flooding)",
                capability_class="config_assessment",
                kali_tools=(),
                countermeasure="Rate limiting; CDN/anycast absorption; upstream scrubbing.",
                notes="Never flood without provider coordination and written approval.",
            ),
            Technique(
                key="lateral_movement_mapping",
                name="Lateral-movement path mapping (detection design)",
                capability_class="info",
                kali_tools=(),
                countermeasure="Segmentation; tiered admin; credential guard.",
                notes="Modeled on paper/evidence; movement is never performed.",
            ),
            Technique(
                key="web_header_audit",
                name="Web security-header & protection audit",
                capability_class="web_assessment",
                kali_tools=("curl", "httpx"),
                countermeasure="CSP, HSTS, X-Frame-Options, WAF rules.",
            ),
            Technique(
                key="cvss_vector_scoring",
                name="CVSS vector construction with environmental overrides",
                capability_class="info",
                kali_tools=(),
                countermeasure="Record environmental metrics so scores match the estate.",
                notes="CVSS is an input to prioritisation, never the verdict.",
            ),
            Technique(
                key="vulnerability_lifecycle_tracking",
                name="Vulnerability lifecycle & patch-latency tracking",
                capability_class="info",
                kali_tools=(),
                countermeasure="Patch SLAs by severity; measure and publish patch latency.",
                notes="The zero-day window is closed by compensating controls, not hope.",
            ),
            Technique(
                key="coordinated_disclosure",
                name="Coordinated disclosure workflow (report → CVE → advisory)",
                capability_class="info",
                kali_tools=(),
                countermeasure="Publish security.txt, staff triage, credit reporters.",
                notes="Minimal reproducible proof mattering more than volume is the "
                      "whole point; weaponised tooling is never included.",
            ),
            Technique(
                key="bounty_scope_discipline",
                name="Bounty scope & rules compliance discipline",
                capability_class="info",
                kali_tools=(),
                countermeasure="Keep program scope and per-asset instructions unambiguous.",
                notes="Rate limits, no DoS, no data exfiltration, minimal touch — the "
                      "program's own rules are the authorisation boundary.",
            ),
            Technique(
                key="poc_minimization",
                name="Minimal reproducible proof construction",
                capability_class="info",
                kali_tools=(),
                countermeasure="Triagers reproduce faster, so fixes ship sooner.",
                notes="Demonstrate the defect; do not build a weapon. If impact is "
                      "unproven, say so explicitly.",
            ),
            Technique(
                key="patch_diff_analysis",
                name="Patch-diff analysis for defect-class discovery",
                capability_class="config_assessment",
                kali_tools=("diff", "strings", "objdump"),
                countermeasure="Deploy on an SLA; audit sibling components for the same class.",
                notes="Defensive research: once patched, the diff is public and the "
                      "attacker's cost drops sharply.",
            ),
        ),
    ),
    DomainTechniques(
        domain_key="cryptography",
        techniques=(
            Technique(
                key="tls_scan",
                name="TLS version/cipher scan",
                capability_class="config_assessment",
                kali_tools=("sslscan", "testssl.sh", "nmap --script ssl-enum-ciphers"),
                countermeasure="Modern TLS baseline; disable legacy suites.",
            ),
            Technique(
                key="cert_health",
                name="Certificate chain/expiry/SAN health check",
                capability_class="config_assessment",
                kali_tools=("openssl",),
                countermeasure="Automated lifecycle; CT monitoring.",
            ),
            Technique(
                key="weak_algo_hunt",
                name="Weak algorithm usage hunt (MD5/RC4/DES/SHA1)",
                capability_class="config_assessment",
                kali_tools=("grep", "openscap"),
                countermeasure="Approved-algorithm policy; crypto agility.",
            ),
            Technique(
                key="ssh_posture",
                name="SSH configuration posture review",
                capability_class="config_assessment",
                kali_tools=("ssh-audit",),
                countermeasure="Disable SSH-1/weak KEX; key hygiene.",
            ),
            Technique(
                key="wep_legacy_check",
                name="Legacy WEP/TKIP presence check",
                capability_class="config_assessment",
                kali_tools=("airodump-ng",),
                countermeasure="Retire legacy encryption modes.",
            ),
            Technique(
                key="hash_crack_lab",
                name="Hash strength demonstration (owned samples, lab)",
                capability_class="config_assessment",
                kali_tools=("hashcat", "john"),
                countermeasure="Argon2/bcrypt; password policy review.",
                notes="Demonstrates policy weakness; lab-only.",
            ),
        ),
    ),
    DomainTechniques(
        domain_key="security_architecture",
        techniques=(
            Technique(
                key="iam_review",
                name="IAM & least-privilege review",
                capability_class="info",
                kali_tools=(),
                countermeasure="Zero-trust identity baselines; access recertification.",
            ),
            Technique(
                key="segmentation_validation",
                name="Segmentation validation via path analysis",
                capability_class="network_mapping",
                kali_tools=("nmap", "traceroute"),
                countermeasure="Micro-segmentation; east-west controls.",
            ),
            Technique(
                key="baseline_drift",
                name="Configuration baseline drift check",
                capability_class="config_assessment",
                kali_tools=("lynis", "openscap"),
                countermeasure="CIS baselines; automated drift alerting.",
            ),
            Technique(
                key="siem_source_review",
                name="SIEM source coverage review",
                capability_class="info",
                kali_tools=(),
                countermeasure="Coverage map: every asset emits to SIEM.",
            ),
            Technique(
                key="data_classification_review",
                name="Data classification & handling review",
                capability_class="info",
                kali_tools=(),
                countermeasure="Label data; enforce handling per classification.",
            ),
            Technique(
                key="security_model_check",
                name="Security-model alignment check (BLP/Biba/Clark-Wilson)",
                capability_class="info",
                kali_tools=(),
                countermeasure="Match controls to the model the design claims.",
            ),
            Technique(
                key="zero_trust_review",
                name="Zero-trust posture review",
                capability_class="info",
                kali_tools=(),
                countermeasure="Verify explicitly, least privilege, assume breach.",
            ),
        ),
    ),
    DomainTechniques(
        domain_key="cloud_iot",
        techniques=(
            Technique(
                key="cloud_inventory",
                name="Cloud asset inventory (authorized)",
                capability_class="config_assessment",
                kali_tools=("scoutsuite", "prowler"),
                countermeasure="CSPM; asset tagging discipline.",
            ),
            Technique(
                key="bucket_exposure",
                name="Storage/bucket exposure check",
                capability_class="config_assessment",
                kali_tools=("cloudsploit",),
                countermeasure="Block public access; bucket policies review.",
            ),
            Technique(
                key="iam_policy_review",
                name="Cloud IAM policy review (wildcards, privilege spread)",
                capability_class="config_assessment",
                kali_tools=("pmapper",),
                countermeasure="Role minimization; permission boundaries.",
            ),
            Technique(
                key="container_audit",
                name="Container/K8s posture audit",
                capability_class="config_assessment",
                kali_tools=("trivy", "kube-bench"),
                countermeasure="Admission control; least-privilege service accounts.",
            ),
            Technique(
                key="iot_device_inventory",
                name="IoT device inventory & default-credential check",
                capability_class="active_recon",
                kali_tools=("nmap", "shodan (authorized)"),
                countermeasure="Device segregation; firmware updates.",
            ),
            Technique(
                key="firmware_exposure",
                name="Firmware/version exposure review",
                capability_class="config_assessment",
                kali_tools=("binwalk",),
                countermeasure="Patch program; hide version banners.",
            ),
            Technique(
                key="ot_zone_review",
                name="OT/ICS zone-conduit review (Purdue model)",
                capability_class="config_assessment",
                kali_tools=(),
                countermeasure="Purdue layering; unidirectional gateways at IT/OT boundary.",
                notes="Observation-first; no active probing without safety authorization.",
            ),
            Technique(
                key="cloud_threat_review",
                name="Cloud threat surface review (breach/credential/insider)",
                capability_class="config_assessment",
                kali_tools=("scoutsuite",),
                countermeasure="CSPM alerts; anomaly detection; access reviews.",
            ),
        ),
    ),
)


def techniques_for_domain(domain_key: str) -> tuple[Technique, ...]:
    key = domain_key.strip().lower().replace("-", "_")
    for dt in TECHNIQUES:
        if dt.domain_key == key:
            return dt.techniques
    return ()


def all_techniques() -> list[tuple[str, Technique]]:
    return [(dt.domain_key, t) for dt in TECHNIQUES for t in dt.techniques]


def find_technique(technique_key: str) -> tuple[str, Technique] | None:
    key = technique_key.strip().lower()
    for dt in TECHNIQUES:
        for t in dt.techniques:
            if t.key == key:
                return dt.domain_key, t
    return None


def techniques_context(domain_keys: list[str] | None = None) -> dict:
    """Machine-readable technique matrix for the LLM planner."""
    selected = TECHNIQUES
    if domain_keys:
        wanted = {k.strip().lower().replace("-", "_") for k in domain_keys}
        selected = tuple(dt for dt in TECHNIQUES if dt.domain_key in wanted)
    return {
        "schema_version": 1,
        "domains": [
            {
                "domain": dt.domain_key,
                "techniques": [
                    {
                        "key": t.key,
                        "name": t.name,
                        "capability_class": t.capability_class,
                        "kali_tools": list(t.kali_tools),
                        "countermeasure": t.countermeasure,
                        "notes": t.notes,
                    }
                    for t in dt.techniques
                ],
            }
            for dt in selected
        ],
        "rule": (
            "Techniques describe HOW a capability is performed and defended. "
            "Authorization gates still apply: scope + policy decide whether "
            "any technique runs."
        ),
    }
