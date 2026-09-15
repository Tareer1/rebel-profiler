"""Glossary: canonical definitions for LLM interpretation.

Short, precise, original definitions. The planner uses these to interpret
operator language ("check for open shares" → smb_share_enum territory) and
to phrase findings consistently. Definitions describe concepts; they never
grant authorization.
"""

from __future__ import annotations

GLOSSARY: tuple[tuple[str, str], ...] = (
    ("scope", "The explicit set of targets a case may touch. Enforced fail-closed: anything not positively authorized is blocked."),
    ("reconnaissance", "Collecting information about targets. Passive recon avoids touching target infrastructure; active recon interacts with it and is risk-gated higher."),
    ("footprinting", "Systematic passive collection of an organization's public footprint: domains, DNS, certificates, registries, archives."),
    ("osint", "Open-source intelligence: information from publicly available sources, retained with source, time and confidence."),
    ("enumeration", "Extracting structured listings (users, shares, exports, records) from authorized systems."),
    ("port scan", "Probing authorized hosts to list open/closed/filtered ports and services. Port states always carry method, time and evidence."),
    ("banner grabbing", "Reading service banners to infer software and versions. Probabilistic; presented with confidence, never as certainty."),
    ("fingerprinting", "Inferring OS or service identity from protocol signatures. Confidence-scored by definition."),
    ("axfr", "A DNS zone transfer. Being available to unauthorized clients is a classic misconfiguration finding."),
    ("bell lapadula", "A confidentiality-focused security model: no read up, no write down."),
    ("biba", "An integrity-focused security model: no read down, no write up."),
    ("bluejacking", "Sending unsolicited messages to a Bluetooth device. Annoyance, not data theft."),
    ("bluesnarfing", "Unauthorized access to data on a Bluetooth device. A real confidentiality breach."),
    ("buffer overflow", "Writing past a memory buffer's bounds to corrupt execution. Mitigated by ASLR, DEP/NX and canaries."),
    ("byod", "Bring your own device: personal hardware touching corporate data under a policy."),
    ("null session", "An unauthenticated SMB/NetBIOS session. Its availability is a finding."),
    ("snmp community", "A shared SNMP v1/v2c string. Default communities ('public'/'private') are findings."),
    ("privilege escalation", "Gaining rights beyond those assigned, via misconfiguration. In this framework: a validation category, authorized and evidence-backed."),
    ("suid", "A file permission bit executing with file-owner rights. SUID binaries are reviewed for misconfiguration."),
    ("lateral movement", "Pivoting between systems after initial access. Modeled for detection validation, never performed."),
    ("persistence", "Techniques that survive reboots/logouts. Modeled for detection engineering; never deployed by this framework."),
    ("exfiltration", "Moving data out of an environment. Mapped as egress-path risk using synthetic data only."),
    ("ioc", "Indicator of compromise: an artifact (hash, IP, domain, mutex) associated with malicious activity, managed through a lifecycle."),
    ("yara", "A pattern-matching language for identifying malware families and artifacts."),
    ("sandboxing", "Detonating suspicious files in isolated infrastructure to observe behavior. Detonation is external infra, never the workstation."),
    ("packer", "Software that compresses/encrypts binaries to evade analysis. Presence is itself a signal."),
    ("mitm", "Man-in-the-middle: on-path interception of communication. Risk assessed via configuration review; active tests are lab-only."),
    ("arp spoofing", "Forging ARP replies to intercept LAN traffic. Validated only on isolated lab segments."),
    ("hsts", "HTTP Strict Transport Security: forces HTTPS. Its absence is a web posture finding."),
    ("hping", "A packet-crafting tool for custom probes and edge-filter validation."),
    ("masscan", "An extremely fast port scanner. Requires strict rate limits even in scope."),
    ("openvas", "Open-source vulnerability scanner. Findings are potential until validated."),
    ("nessus", "A commercial vulnerability scanner. Same rule: scan output is potential, not confirmed."),
    ("metasploit", "An exploitation framework. In this framework it is a validation tool for lab targets only."),
    ("sslstrip", "Downgrading HTTPS to HTTP during interception. Defeated by HSTS."),
    ("tailgating", "Following an authorized person through a door without credentials. A physical SE vector."),
    ("quid pro quo", "A social engineering trade: help or gift in exchange for access or credentials."),
    ("baiting", "Leaving infected or tempting devices/media to be plugged in. Simulations use inert media."),
    ("pretexting", "Inventing a scenario to obtain information or access. Governed by RoE in simulations."),
    ("identity theft", "Impersonating a real person using their exposed identifiers."),
    ("bpf", "Berkeley Packet Filter: the capture-filter language used by tcpdump/Wireshark."),
    ("lateral movement", "Moving between systems after initial access. Mapped for detection design, never performed."),
    ("heap spraying", "Filling heap memory with controlled content to raise exploit reliability. A design-defense concern."),
    ("bell lapadula model", "See: bell lapadula. Confidentiality model used in architecture review."),
    ("clark wilson", "An integrity model built on well-formed transactions and separation of duties."),
    ("state machine model", "A security model where system states and transitions are proven safe."),
    ("n tier", "Multi-layer application design (web/app/data tiers) that shapes assessment boundaries."),
    ("rest", "REpresentational State Transfer: the API style behind most cloud service interfaces."),
    ("smishing", "Phishing over SMS. Simulated only with consent and designated recipients."),
    ("vishing", "Phishing over voice calls. Simulated only with consent and scripted pretexts."),
    ("certificate authority", "An entity issuing signed certificates. Health and trust chains are assessed."),
    ("self-signed", "A certificate signed by its own key. Fine internally, a finding on public endpoints."),
    ("pgp", "Pretty Good Privacy: end-to-end signed/encrypted email. S/MIME is its X.509 counterpart."),
    ("disk encryption", "Full-volume encryption protecting data at rest from offline access."),
    ("nonrepudiation", "A property where an action's origin cannot be denied, via signatures/audit."),
    ("hybrid cryptosystem", "Asymmetric key exchange protecting symmetric session data — how TLS works."),
    ("elliptic curve", "ECC: strong security with smaller keys, common in modern TLS and IoT."),
    ("weak algorithm", "A cryptographic primitive considered broken or deprecated (MD5, RC4, DES, SHA-1, SSLv3, TLS 1.0/1.1)."),
    ("pki", "Public key infrastructure: certificates, chains, trust stores. Health checks detect expiry/chain issues."),
    ("parkerian hexad", "Six information-security facets: confidentiality, integrity, availability, possession, authenticity, utility."),
    ("purdue model", "A layered reference model for industrial networks separating IT from OT zones."),
    ("port mirroring", "Switch copying traffic to an analysis port (SPAN). The authorized way to capture."),
    ("wep", "Broken Wi-Fi encryption. Presence is a direct critical finding."),
    ("zero trust", "A design stance: verify explicitly, least privilege, assume breach. No implicit network trust."),
    ("siem", "Security information and event management: central log correlation and alerting."),
    ("soar", "Security orchestration, automation and response: playbooks that execute on SIEM signals."),
    ("epp", "Exploit protection: OS-level mitigations (DEP, ASLR, CFG) raising exploit cost."),
    ("iocs of compromise", "(Deprecated alias) see IOC: indicator of compromise."),
    ("ot", "Operational technology: systems controlling physical processes. Safety first, always."),
    ("pfs", "Perfect forward secrecy: session keys stay safe even if the long-term key leaks."),
    ("bcp", "Business continuity planning: keeping essential functions running during disruption."),
    ("dr", "Disaster recovery: restoring IT after disruption, with defined RTO/RPO targets."),
    ("grid computing", "Distributed resource pooling across organizations; conceptual ancestor of cloud."),
    ("fog computing", "Compute placed between edge devices and cloud, reducing latency for IoT."),
    ("wpa2", "Wi-Fi Protected Access 2. Handshake validation occurs only on owned lab APs."),
    ("wpa3/sae", "Modern Wi-Fi authentication. Its presence is a positive posture signal."),
    ("rogue ap", "An unauthorized access point. Detection is defensive; surveys find them."),
    ("rainbow table", "A precomputed hash-reversal structure. Defeated by per-user salts and slow KDFs."),
    ("ransomware", "Malware encrypting data for extortion. Defense: offline backups, canaries, egress control."),
    ("deauth", "A management frame forcing clients off Wi-Fi. This framework only monitors for it; it never injects."),
    ("defense in breadth", "Securing every layer of the stack, not just the perimeter; complements defense in depth."),
    ("dhcp starvation", "Exhausting a DHCP pool so attacker-controlled leases dominate. Detect via snooping."),
    ("dropper", "Malware whose job is installing a payload. The dropper and payload often have separate infrastructure."),
    ("edr", "Endpoint detection and response: telemetry-driven endpoint monitoring with response actions."),
    ("fileless malware", "Malware living in memory and native interpreters, leaving few disk artifacts."),
    ("fuzzing", "Feeding malformed input to software to find robustness defects. Authorized, rate-limited only."),
    ("kerberoasting", "Requesting service tickets to crack service-account passwords offline. Detect via ticket anomaly monitoring."),
    ("living off the land", "Attacking with native admin tools (LOLBAS). Detection relies on command-line auditing."),
    ("phishing simulation", "A consented, approved simulation measuring employee resilience. Never collects real credentials; results feed awareness, not punishment."),
    ("pretext", "The fabricated scenario in a social-engineering simulation. Governed by RoE and approval."),
    ("lookalike domain", "A domain registered to imitate a brand (typosquatting, homoglyphs). Found via passive intelligence."),
    ("purple team", "Joint attack/defense exercise: simulate techniques, verify detections, close gaps."),
    ("kill chain", "Staged attack progression model used to organize assessments and map detection coverage."),
    ("att&ck", "A public knowledge base of adversary tactics and techniques, used for coverage mapping."),
    ("cve", "Common Vulnerabilities and Exposures identifier. A database match is *potential*; validation needs contextual evidence."),
    ("cwe", "Common Weakness Enumeration: the *class* of defect (e.g. CWE-79 XSS, CWE-319 cleartext transmission). CVE identifies one instance; CWE names the pattern to fix everywhere."),
    ("zero-day", "A vulnerability with no vendor fix available yet. The term describes the defender's position (zero days of warning), not the defect's severity."),
    ("zero-day window", "The interval between a defect being exploited and a fix being deployable. It is closed with compensating controls: virtual patching, feature shutdown, reachability reduction and targeted detection."),
    ("cvss", "Common Vulnerability Scoring System: base, threat and environmental metric groups producing a 0-10 score and a vector string. An input to prioritisation, never the verdict — the same CVE scores differently per estate."),
    ("epss", "Exploit Prediction Scoring System: an estimate of the probability a vulnerability will be exploited in the wild. Complements CVSS severity with likelihood."),
    ("coordinated disclosure", "Agreeing a disclosure timeline with the owner: minimal reproducible proof, a fix window (90 days is the norm, extensions for complexity), then a coordinated advisory. Users need a patch to exist before a roadmap to the defect does."),
    ("safe harbor", "A program's commitment not to pursue legal action against researchers who stay within the published scope and rules. Its boundaries are exactly the program's stated instructions."),
    ("in scope", "An asset a program explicitly authorises for testing. Anything not positively listed is out of scope — the same fail-closed rule the scope engine enforces."),
    ("out of scope", "An asset, class of issue or technique a program excludes. Exclusions always win over broad in-scope rules."),
    ("poc", "Proof of concept: the minimal reproducible demonstration that a defect is real. It proves the issue; it is not a weapon, and it never touches data beyond what the demonstration requires."),
    ("patch diffing", "Comparing pre- and post-fix code or binaries to identify the defect class that was fixed. Standard defensive research: the resulting knowledge is what to hunt for in your own estate."),
    ("exploitability", "Whether a defect is actually reachable and triggerable given the mitigation stack. 'The code is buggy' and 'the system is exploitable' are different statements."),
    ("mitigation stack", "The layered exploit protections in a modern platform: ASLR, DEP/NX, stack canaries, CFG/CFI, sandboxing and memory-safe languages. Each removes a class of primitive, not one bug."),
    ("severity", "The impact rating a finding carries, derived from the defect class, reachability and demonstrated impact. In this framework it is advisory: the receiving program's own taxonomy governs payout."),
    ("triage", "The owner's process of validating, de-duplicating and prioritising a report. Fast triage is bought with clear preconditions, minimal steps and the exact request/response that proves the issue."),
    ("shared responsibility", "The cloud split of controls between provider and tenant. Assessment scope is the tenant side."),
    ("cspm", "Cloud security posture management: continuous configuration assessment of cloud tenancy."),
    ("least privilege", "Granting only the rights required. The core IAM review criterion."),
    ("defense in depth", "Layered controls so single failures are survivable."),
    ("chain of custody", "The documented, hash-linked history of evidence handling, proving integrity."),
    ("provenance", "Where an observation came from: source, method, time. Every observation carries it."),
    ("confidence", "A 0–1 score expressing how much evidence supports an observation. Unknowns stay unknown."),
    ("case isolation", "Cases share nothing: separate databases, evidence stores and scopes."),
    ("dry run", "Planning execution without executing: shows exact argv and policy outcome."),
    ("approval gate", "A policy checkpoint requiring explicit human approval before high-risk execution."),
    ("fail closed", "Defaulting to denial when authorization cannot be positively established."),
)


def _normalize(term: str) -> str:
    return " ".join(term.strip().lower().replace("-", "_").replace("_", " ").split())


def _compact(text: str) -> str:
    """Lowercase with separators removed, so 'wifi' matches 'Wi-Fi'."""
    return text.lower().replace("-", "").replace("_", "").replace(" ", "")


def lookup(term: str) -> str | None:
    t = _normalize(term)
    for name, definition in GLOSSARY:
        if name == t:
            return definition
    return None


def search_terms(query: str) -> list[tuple[str, str]]:
    q = query.strip().lower()
    if not q:
        return []
    q_compact = _compact(q)
    return [
        (n, d)
        for n, d in GLOSSARY
        if q in n
        or q in d.lower()
        or (q_compact and (q_compact in _compact(n) or q_compact in _compact(d)))
    ]


def glossary_context() -> dict:
    return {
        "schema_version": 1,
        "terms": [{"term": n, "definition": d} for n, d in GLOSSARY],
        "rule": (
            "Definitions are for interpretation and reporting. They never "
            "authorize anything."
        ),
    }
