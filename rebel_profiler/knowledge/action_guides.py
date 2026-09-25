"""Action guides: the executable how-to for every action the broker can run.

The action contract tells the planner WHAT actions exist; this registry
teaches it HOW to use each one well — written for a small LLM that must
plan without guessing:

  * when to use an action (trigger conditions, in operator language),
  * what target shape each action expects (exact string format),
  * which params are worth setting and what they mean,
  * a literal example ActionRequest (JSON-ready),
  * what claims come back and how to read them,
  * which actions naturally follow (so a session chains into an outcome).

Consistency rule enforced by tests: every guide's action name, capability
class, params and example must match the LIVE AdapterRegistry contract.
A guide for a nonexistent action is a hard error — knowledge may drift
toward the code, never away from it.

Nothing here executes anything and nothing here authorizes anything:
scope + policy still decide at run time.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ActionGuide:
    """Operator-grade how-to for one executable action."""

    action: str                      # must equal adapter.name
    capability_class: str            # must equal adapter.capability_class
    when: tuple[str, ...]            # trigger conditions ("use when …")
    target_shape: str                # exact expected target string format
    target_example: str              # a valid example target
    params: tuple[tuple[str, str], ...] = ()   # (name, meaning/default hint)
    example: dict = field(default_factory=dict)  # literal example ActionRequest
    output_claims: tuple[str, ...] = ()  # claim kinds the parser emits
    reads_output: str = ""           # how to interpret the result
    next_steps: tuple[str, ...] = ()     # actions that naturally follow


_ACTION_GUIDES: tuple[ActionGuide, ...] = (
    # ------------------------------------------------------ passive recon
    ActionGuide(
        action="passive-dns",
        capability_class="passive_recon",
        when=("You need the current DNS records (A, AAAA, MX, NS, TXT, CAA) "
              "of a domain already in scope.",
              "Start every domain investigation here — it is read-only and fast."),
        target_shape="a single hostname or domain (no scheme, no path)",
        target_example="example.com",
        params=(("record_type", "A | AAAA | MX | NS | TXT | CAA — default A"),),
        example={"action": "passive-dns", "target": "example.com",
                 "params": {"record_type": "MX"}},
        output_claims=("dns_record",),
        reads_output=("Each record becomes a claim on the subject. Absence of a "
                      "record type is a valid answer, not an error."),
        next_steps=("whois-lookup", "cert-transparency", "subfinder-enum"),
    ),
    ActionGuide(
        action="dns-lookup",
        capability_class="passive_recon",
        when=("You need a quick resolver answer for one host (e.g. the IP a "
              "hostname points to right now).",
              "Use after surface mapping to confirm a host still resolves."),
        target_shape="a single hostname",
        target_example="host.example.com",
        example={"action": "dns-lookup", "target": "host.example.com"},
        output_claims=("ip",),
        reads_output="The resolved address becomes an ip claim bound to the subject.",
        next_steps=("passive-dns", "httpx-probe"),
    ),
    ActionGuide(
        action="dork-search",
        capability_class="passive_recon",
        when=("You want search-engine surface: exposed files, open directories, "
              "login portals, bucket listings for the domain.",
              "Uses NAMED dork templates only — pick a dork key, never free text."),
        target_shape="a registrable domain",
        target_example="example.com",
        params=(("engine", "REQUIRED: google | duckduckgo | ahmia"),
                ("dork", "REQUIRED: a named dork key from `knowledge search dork`"),
                ("tld", "optional site: tld suffix, e.g. co.in")),
        example={"action": "dork-search", "target": "example.com",
                 "params": {"engine": "duckduckgo", "dork": "excel"}},
        output_claims=("search_hit", "hostname"),
        reads_output=("Hit URLs become search_hit claims; on-domain hosts also "
                      "become hostname claims. Engine markup is untrusted data."),
        next_steps=("wayback-urls", "js-intel"),
    ),
    ActionGuide(
        action="dns-enum",
        capability_class="passive_recon",
        when=("You need a wide DNS record sweep of a domain INCLUDING a zone-"
              "transfer (AXFR) misconfiguration check (dnsrecon std mode)."),
        target_shape="a registrable domain",
        target_example="example.com",
        example={"action": "dns-enum", "target": "example.com"},
        output_claims=("dns_soa", "dns_ns", "dns_mx", "dns_a", "dns_txt"),
        reads_output=("Record lines become typed dns_* claims; a successful AXFR "
                      "would be a critical finding — its absence is normal."),
        next_steps=("whois-lookup", "cert-transparency"),
    ),
    ActionGuide(
        action="whois-lookup",
        capability_class="passive_recon",
        when=("You need registration facts: registrar, creation/expiry dates, "
              "name servers, registrant org.",
              "Freshly registered or soon-expiring domains are reportable context."),
        target_shape="a registrable domain (not a subdomain, not a URL)",
        target_example="example.com",
        example={"action": "whois-lookup", "target": "example.com"},
        output_claims=("registrar", "created", "expires", "nameserver"),
        reads_output=("Registrar/date fields become typed claims; unrelated WHOIS "
                      "lines are ignored, never guessed."),
        next_steps=("cert-transparency", "subfinder-enum"),
    ),
    ActionGuide(
        action="cert-transparency",
        capability_class="passive_recon",
        when=("You want subdomains and hostnames the organization got TLS "
              "certificates for — historic visibility without touching the target.",
              "One of the highest-yield passive subdomain sources; run it early."),
        target_shape="a registrable domain",
        target_example="example.com",
        example={"action": "cert-transparency", "target": "example.com"},
        output_claims=("hostname",),
        reads_output=("Each logged DNS-name becomes a hostname claim; dedupe "
                      "against earlier sources happens automatically."),
        next_steps=("httpx-probe", "subfinder-enum"),
    ),
    ActionGuide(
        action="subfinder-enum",
        capability_class="passive_recon",
        when=("You need the passive subdomain surface of a domain from public "
              "datasets (fast, target untouched).",
              "Pair with cert-transparency for the widest passive coverage."),
        target_shape="a registrable domain",
        target_example="example.com",
        params=(("timeout", "seconds per source query, e.g. 30"),
                ("limit", "max overall runtime minutes, e.g. 5")),
        example={"action": "subfinder-enum", "target": "example.com"},
        output_claims=("hostname",),
        reads_output=("Every FQDN inside the queried domain becomes a hostname "
                      "claim; out-of-scope noise from sources is filtered."),
        next_steps=("httpx-probe", "known-urls"),
    ),
    ActionGuide(
        action="subdomain-enum",
        capability_class="passive_recon",
        when=("amass passive enumeration — a second, deeper passive source; "
              "run when subfinder coverage seems thin."),
        target_shape="a registrable domain",
        target_example="example.com",
        params=(("timeout", "seconds per query, e.g. 30"),),
        example={"action": "subdomain-enum", "target": "example.com"},
        output_claims=("hostname",),
        reads_output="One FQDN per line, in-scope only, becomes hostname claims.",
        next_steps=("httpx-probe", "known-urls"),
    ),
    ActionGuide(
        action="wayback-urls",
        capability_class="passive_recon",
        when=("You want historical URLs and parameters the target exposed in "
              "the past (old endpoints, admin panels, forgotten APIs).",
              "Archive-side only: the target is never contacted."),
        target_shape="a hostname (subdomains are included by the archive)",
        target_example="h1.example.com",
        params=(("limit", "max URLs, e.g. 500"),),
        example={"action": "wayback-urls", "target": "h1.example.com",
                 "params": {"limit": "500"}},
        output_claims=("wayback_url",),
        reads_output=("URLs on the queried host become wayback_url claims; "
                      "interesting paths (admin, api, backup) feed the probe action."),
        next_steps=("probe", "js-intel", "httpx-probe"),
    ),
    ActionGuide(
        action="email-osint",
        capability_class="passive_recon",
        when=("You need the public email/identity surface of a domain "
              "(breach-context awareness, phishing-simulation scoping)."),
        target_shape="a registrable domain",
        target_example="example.com",
        example={"action": "email-osint", "target": "example.com"},
        output_claims=("email", "hostname"),
        reads_output="Emails on the domain become email claims with the source score attached.",
        next_steps=("passive-dns",),
    ),
    ActionGuide(
        action="js-intel",
        capability_class="passive_recon",
        when=("A JavaScript bundle URL is known (from a page, wayback, or "
              "katana-crawl) — mine it for API routes, cloud hosts and "
              "key/secret candidates.",
              "The single highest-yield action on modern JS-heavy apps."),
        target_shape="a full https URL of a .js asset",
        target_example="https://js.example.com/app.main.js",
        example={"action": "js-intel",
                 "target": "https://js.example.com/app.main.js"},
        output_claims=("js_endpoint", "js_cloud", "js_key_candidate"),
        reads_output=("Endpoint paths, cloud storage hosts and key-shaped "
                      "strings become claims ranked by severity in `intel hunt`."),
        next_steps=("probe", "cert-transparency"),
    ),
    ActionGuide(
        action="known-urls",
        capability_class="passive_recon",
        when=("You want known URLs from archives AND alienvault sources for a "
              "domain (gau) — wider than wayback-urls, still passive."),
        target_shape="a registrable domain",
        target_example="example.com",
        params=(("limit", "max URLs, e.g. 1000"),),
        example={"action": "known-urls", "target": "example.com"},
        output_claims=("wayback_url",),
        reads_output="Same shape as wayback-urls; treat as archive knowledge.",
        next_steps=("probe", "httpx-probe"),
    ),
    # ------------------------------------------------------ discovery
    ActionGuide(
        action="host-discovery",
        capability_class="discovery",
        when=("An IP range is explicitly in scope and you need to know which "
              "hosts are alive before deeper scans.",
              "Never propose for single-host scopes — nothing to discover."),
        target_shape="a CIDR range or single IP that exists as a scope entry",
        target_example="192.0.2.0/24",
        params=(("mode", "discover | list — default discover"),),
        example={"action": "host-discovery", "target": "192.0.2.0/24",
                 "params": {"mode": "discover"}},
        output_claims=("host_state",),
        reads_output="Per-host up/down/filtered state; only live hosts need port scans.",
        next_steps=("port-scan",),
    ),
    ActionGuide(
        action="port-scan",
        capability_class="discovery",
        when=("A host is in scope and you need its open TCP ports.",
              "Prefer a short port list first (22,80,443) to stay polite; "
              "widen only if needed."),
        target_shape="a single hostname or IP in scope",
        target_example="h1.example.com",
        params=(("ports", "comma-separated list, e.g. 22,80,443"),),
        example={"action": "port-scan", "target": "h1.example.com",
                 "params": {"ports": "22,80,443"}},
        output_claims=("port",),
        reads_output=("Open ports become port claims; the exposure map binds "
                      "services to them automatically."),
        next_steps=("service-detect", "os-fingerprint"),
    ),
    ActionGuide(
        action="service-detect",
        capability_class="active_recon",
        when=("Open ports are known and you need service/version fingerprints "
              "to reason about exposure."),
        target_shape="a single hostname or IP in scope",
        target_example="h1.example.com",
        params=(("ports", "comma-separated list, e.g. 22,80,443"),),
        example={"action": "service-detect", "target": "h1.example.com",
                 "params": {"ports": "22,80,443"}},
        output_claims=("service", "product", "version"),
        reads_output=("Banner-based product/version claims; shared products "
                      "across hosts surface as lateral hints in `surface exposure`."),
        next_steps=("os-fingerprint", "tls-posture"),
    ),
    ActionGuide(
        action="os-fingerprint",
        capability_class="active_recon",
        when=("TCP-stack OS hints are needed for a scoped host — low confidence "
              "by nature, treat as context, never as fact."),
        target_shape="a single hostname or IP in scope",
        target_example="h1.example.com",
        example={"action": "os-fingerprint", "target": "h1.example.com"},
        output_claims=("os_guess",),
        reads_output="An os_guess claim with explicit low confidence — never report it as fact.",
        next_steps=("service-detect",),
    ),
    # ------------------------------------------------------ web assessment
    ActionGuide(
        action="httpx-probe",
        capability_class="discovery",
        when=("You need live-host confirmation: is the site up, what title, "
              "status code, technologies, which IP. (Adapter declares this "
              "discovery — a liveness probe on one in-scope host.)",
              "The natural next step after any subdomain enumeration."),
        target_shape="hostname[:port] in scope",
        target_example="example.com",
        params=(("timeout", "per-request seconds, default 10"),),
        example={"action": "httpx-probe", "target": "example.com"},
        output_claims=("httpx_status", "httpx_title", "httpx_tech", "ip"),
        reads_output=("A 200 with a title means the host is live web surface; "
                      "tech names inform what to test next."),
        next_steps=("web-crawl", "js-intel", "header-audit"),
    ),
    ActionGuide(
        action="katana-crawl",
        capability_class="active_recon",   # mirrors KatanaAdapter exactly
        when=("You need the endpoint surface of an in-scope web origin: "
              "links, JS bundles, API paths (depth-capped crawler).",
              "Confirm the origin allows crawling in the program rules."),
        target_shape="a full http(s) URL in scope",
        target_example="https://js.example.com/",
        params=(("depth", "1..5 crawl depth — default 2; keep small"),
                ("timeout", "per-request seconds, default 15")),
        example={"action": "katana-crawl", "target": "https://js.example.com/",
                 "params": {"depth": "2"}},
        output_claims=("wayback_url",),
        reads_output=("Discovered in-scope URLs become wayback_url claims; "
                      "JS bundles found here should each go through js-intel."),
        next_steps=("js-intel", "web-crawl"),
    ),
    ActionGuide(
        action="web-crawl",
        capability_class="web_assessment",
        when=("You need the live HTTP surface of one in-scope host: status, "
              "title, technologies across specific ports (httpx).",
              "Use for a quick multi-port liveness+tech sweep after discovery."),
        target_shape="a single hostname in scope (no scheme, no path)",
        target_example="h1.example.com",
        params=(("ports", "comma-separated ports to probe, e.g. 80,443,8080"),
                ("threads", "concurrency, small number e.g. 10"),
                ("tech_detect", "include technology detection: yes|no")),
        example={"action": "web-crawl", "target": "h1.example.com",
                 "params": {"ports": "80,443"}},
        output_claims=("web_url", "tech"),
        reads_output=("Each live port yields URL/title/status claims; tech "
                      "names inform which misconfigurations to hunt next. "
                      "For the full security-header/cookie/TLS audit use the "
                      "`intel crawl` CLI on the origin instead."),
        next_steps=("header-audit", "js-intel"),
    ),
    ActionGuide(
        action="header-audit",
        capability_class="web_assessment",
        when=("You need the security-header verdict for ONE page quickly "
              "(CSP, HSTS, XFO, cookie flags) without a crawl."),
        target_shape="a full http(s) URL in scope",
        target_example="https://h1.example.com/login",
        example={"action": "header-audit", "target": "https://h1.example.com/login"},
        output_claims=("header_finding",),
        reads_output="Missing/weak headers become per-header findings with the exact name.",
        next_steps=("web-crawl",),
    ),
    ActionGuide(
        action="dir-enum",
        capability_class="web_assessment",
        when=("You need directory/file enumeration on an in-scope origin with "
              "a wordlist (ffuf) — active; keep rate limits in mind."),
        target_shape="a full http(s) URL in scope",
        target_example="https://h1.example.com/",
        params=(("wordlist", "path to an existing wordlist file"),
                ("extensions", "comma-separated, e.g. php,html,txt"),
                ("threads", "small number, e.g. 10")),
        example={"action": "dir-enum", "target": "https://h1.example.com/",
                 "params": {"extensions": "php,html,txt"}},
        output_claims=("web_path",),
        reads_output="Each discovered path + status becomes a web_path claim.",
        next_steps=("probe", "js-intel"),
    ),
    ActionGuide(
        action="tech-fingerprint",
        capability_class="web_assessment",
        when=("You need the technology stack of one in-scope site (whatweb) — "
              "informs which misconfigurations to look for."),
        target_shape="a full http(s) URL in scope",
        target_example="https://h1.example.com/",
        example={"action": "tech-fingerprint", "target": "https://h1.example.com/"},
        output_claims=("tech",),
        reads_output="Plugin=value pairs (framework, server, CMS) become tech claims.",
        next_steps=("header-audit", "waf-detect"),
    ),
    ActionGuide(
        action="waf-detect",
        capability_class="web_assessment",
        when=("Before active testing you need to know whether a WAF sits in "
              "front of the origin (wafw00f) — shapes expectations for probes."),
        target_shape="a full http(s) URL in scope",
        target_example="https://h1.example.com/",
        example={"action": "waf-detect", "target": "https://h1.example.com/"},
        output_claims=("waf",),
        reads_output=("A named WAF means active testing will be rate-limited/"
                      "challenged; a 'none detected' result is also recorded."),
        next_steps=("header-audit", "probe"),
    ),
    ActionGuide(
        action="tls-posture",
        capability_class="web_assessment",
        when=("You need the TLS configuration verdict of an in-scope HTTPS "
              "origin: protocol versions, weak ciphers, certificate health."),
        target_shape="hostname[:port] in scope",
        target_example="h1.example.com",
        params=(("port", "default 443"),),
        example={"action": "tls-posture", "target": "h1.example.com"},
        output_claims=("tls_protocol", "tls_cipher", "cert_finding"),
        reads_output=("Legacy protocol/weak-cipher lines are the reportable "
                      "findings; a clean TLSv1.3-only result is a pass."),
        next_steps=("web-crawl",),
    ),
    ActionGuide(
        action="param-hunt",
        capability_class="active_recon",
        when=("An endpoint exists but documented parameters are unknown — "
              "arjun discovers hidden HTTP parameters (active, rate-limited)."),
        target_shape="a full http(s) URL in scope",
        target_example="https://h1.example.com/api/search",
        params=(("timeout", "seconds, default 20"),),
        example={"action": "param-hunt", "target": "https://h1.example.com/api/search"},
        output_claims=("param",),
        reads_output="Discovered parameter names become param claims on the subject.",
        next_steps=("probe",),
    ),
    # ------------------------------------------------------ validation
    ActionGuide(
        action="nuclei-scan",
        capability_class="vuln_validation",
        when=("Known endpoints are mapped and you want template-based "
              "vulnerability checks (known CVE paths, misconfigurations, "
              "exposed panels) with severity filtering.",
              "Rate-limited by the adapter; info noise is filtered by default."),
        target_shape="a full http(s) URL in scope",
        target_example="https://h1.example.com/",
        params=(("severity", "csv of info|low|medium|high|critical — "
                 "default low,medium,high,critical"),
                ("timeout", "per-request seconds, default 30")),
        example={"action": "nuclei-scan", "target": "https://h1.example.com/",
                 "params": {"severity": "medium,high,critical"}},
        output_claims=("nuclei_finding", "nuclei_detail"),
        reads_output=("Each template hit names the vulnerability class + host + "
                      "severity; verify notable hits with probe before reporting."),
        next_steps=("probe",),
    ),
    ActionGuide(
        action="probe",
        capability_class="vuln_validation",
        when=("A specific candidate finding (missing auth, open bucket, "
              "reflected param) needs one verification request with a real, "
              "stored response.",
              "ALWAYS approval-gated: the operator must approve before dispatch."),
        target_shape="a full http(s) URL in scope (the exact endpoint to verify)",
        target_example="https://h1.example.com/api/user/1",
        params=(("method", "GET | POST | HEAD … — default GET"),
                ("data", "request body for POST/PUT (form or JSON payload)"),
                ("header", "an extra request header, 'Name: value'"),
                ("timeout", "seconds, e.g. 15")),
        example={"action": "probe", "target": "https://h1.example.com/api/user/1",
                 "params": {"method": "GET"}},
        output_claims=("probe_result",),
        reads_output=("status + response shape prove or refute the candidate; "
                      "the raw response is hash-chained evidence."),
        next_steps=("bounty assess (CLI)", "report (CLI)"),
    ),
    ActionGuide(
        action="vuln-correlate",
        capability_class="vuln_validation",
        when=("You want collected claims cross-checked into candidate "
              "vulnerability classes before writing the report."),
        target_shape="case subject (domain or host) in scope, or the case root domain",
        target_example="example.com",
        example={"action": "vuln-correlate", "target": "example.com"},
        output_claims=("correlation",),
        reads_output="Each correlation pairs observed conditions with a class + confidence.",
        next_steps=("probe",),
    ),
    # ------------------------------------------------------ network mapping
    ActionGuide(
        action="smb-enum",
        capability_class="network_mapping",
        when=("A Windows host in scope exposes 445/tcp — enumerate shares, "
              "sessions, users (enum4linux-ng) for misconfiguration findings."),
        target_shape="an IP or hostname in scope",
        target_example="192.0.2.10",
        example={"action": "smb-enum", "target": "192.0.2.10"},
        output_claims=("smb_share", "smb_session"),
        reads_output="Null-session reachability or open shares are reportable misconfigurations.",
        next_steps=("service-detect",),
    ),
    ActionGuide(
        action="route-analysis",
        capability_class="network_mapping",
        when=("You need the hop path to an in-scope host for segmentation "
              "review (traceroute) — passive on the target."),
        target_shape="a hostname or IP in scope",
        target_example="h1.example.com",
        example={"action": "route-analysis", "target": "h1.example.com"},
        output_claims=("route_hop",),
        reads_output="Hops reveal filtering boundaries; treat unresponsive hops as unknown.",
        next_steps=("port-scan",),
    ),
    # ------------------------------------------------------ tool exec
    ActionGuide(
        action="exec-tool",
        capability_class="active_recon",
        when=("A vetted Kali binary (nmap, dig, whois, sslscan, enum4linux-ng, "
              "…) is needed with flags inside its whitelist — the general "
              "escape-free tool runner.",
              "Prefer the dedicated action when one exists; use exec-tool for "
              "flag combinations the dedicated actions do not expose."),
        target_shape="the validated host/URL argument the tool expects",
        target_example="h1.example.com",
        params=(("tool", "whitelisted binary name, e.g. nmap"),
                ("args", "extra flags INSIDE the tool's whitelist, e.g. -sV"),
                ("note", "why this tool run is needed — stored with the audit")),
        example={"action": "exec-tool", "target": "h1.example.com",
                 "params": {"tool": "nmap", "note": "top-port sweep"}},
        output_claims=("tool_output",),
        reads_output="Output parses through the wrapped tool's natural parser (e.g. nmap → port/service claims).",
        next_steps=("service-detect", "tls-posture"),
    ),
    ActionGuide(
        action="echo",
        capability_class="info",
        when=("Smoke-testing the broker chain itself (gates → evidence → "
              "audit) without touching any target infrastructure."),
        target_shape="any short string",
        target_example="broker-selftest",
        example={"action": "echo", "target": "broker-selftest"},
        output_claims=(),
        reads_output="Round-trips the payload; useful in verification sessions only.",
        next_steps=(),
    ),
    # ------------------------------------------------------ wireless (authorized site)
    ActionGuide(
        action="wlan-survey",
        capability_class="wireless_observation",
        when=("You need the RF picture of an AUTHORIZED site: APs, channels, "
              "encryption posture, associated clients (airodump-ng listen-only).",
              "Rogue-AP hunting and legacy-encryption (WEP/TKIP) detection "
              "start here. Requires a monitor-mode interface."),
        target_shape="the site label the survey belongs to (any short slug; "
                     "the interface comes from params)",
        target_example="office-floor-2",
        params=(("interface", "REQUIRED: monitor-mode interface, e.g. wlan0mon"),
                ("duration", "capture seconds 60–3600, default 120"),
                ("channel", "optional: lock one channel 1–196 instead of hopping"),
                ("band", "optional: a | b | g | n | abg | bg")),
        example={"action": "wlan-survey", "target": "office-floor-2",
                 "params": {"interface": "wlan0mon", "duration": "300"}},
        output_claims=("ap", "wifi_security", "wireless_sta"),
        reads_output=("Each AP becomes an ap claim (BSSID, channel, ESSID); "
                      "encryption posture becomes wifi_security; client MACs "
                      "become wireless_sta with association only — probe SSID "
                      "privacy is preserved, probes are never recorded."),
        next_steps=("wlan-ap-audit",),
    ),
    ActionGuide(
        action="wlan-monitor",
        capability_class="wireless_monitor",
        when=("You need an interface switched into (or out of) monitor mode "
              "before a survey — airmon-ng start/stop."),
        target_shape="the site label or machine tag the interface belongs to",
        target_example="operator-laptop",
        params=(("interface", "REQUIRED: the wireless interface, e.g. wlan0"),
                ("stop", "set to return the interface to managed mode")),
        example={"action": "wlan-monitor", "target": "operator-laptop",
                 "params": {"interface": "wlan0"}},
        output_claims=(),
        reads_output=("State change on the OPERATOR'S OWN machine only — never "
                      "a target. Approval-gated by policy; nothing here "
                      "transmits toward any other device."),
        next_steps=("wlan-survey",),
    ),
    ActionGuide(
        action="wlan-ap-audit",
        capability_class="passive_recon",
        when=("You want the encryption-posture summary of an already-captured "
              "survey without touching the RF environment again — offline "
              "analysis of the case's own evidence."),
        target_shape="the site label used for the original survey",
        target_example="office-floor-2",
        example={"action": "wlan-ap-audit", "target": "office-floor-2"},
        output_claims=("wifi_security",),
        reads_output=("Pure offline analysis: WEP/TKIP/open APs surface as "
                      "reportable posture findings; nothing is transmitted."),
        next_steps=("header-audit",),
    ),
    ActionGuide(
        action="nikto-scan",
        capability_class="web_assessment",
        when=("You need a broad misconfiguration sweep of one web origin — "
              "dangerous default files, outdated software, risky methods.",
              "Run after tech-fingerprint confirms a classic web server; "
              "it is an active scan, so keep it for authorized origins only."),
        target_shape="a single hostname (no scheme, no path); port via params",
        target_example="h1.lab.example.test",
        params=(("port", "1-65535, default 443"),
                ("ssl", "1 to force https; omit for http"),
                ("timeout", "5-120 seconds per request, default 30")),
        example={"action": "nikto-scan", "target": "h1.lab.example.test",
                 "params": {"port": "443", "ssl": "1"}},
        output_claims=("nikto_finding", "nikto_reference"),
        reads_output=("Each CSV row becomes one misconfiguration finding; the "
                      "reference column carries the OSVDB/CVE pointer. Nikto "
                      "noise (items-tested summary) never becomes a claim."),
        next_steps=("nuclei-scan", "exploit-lookup", "header-audit"),
    ),
    ActionGuide(
        action="wpscan-audit",
        capability_class="web_assessment",
        when=("The target is WordPress (whatweb reported WordPress) and you "
              "need core/plugin/theme version exposure and vulnerable "
              "component checks — WITHOUT any brute force."),
        target_shape="a full URL of the WordPress root (scheme included)",
        target_example="https://wp.lab.example.test",
        params=(("enumerate", "comma list of vp|vt|cb|dbe — vulnerable "
                 "plugins/themes, config backups, db exports; default vp,vt"),
                ("timeout", "10-300 seconds per request, default 60")),
        example={"action": "wpscan-audit", "target": "https://wp.lab.example.test",
                 "params": {"enumerate": "vp,vt"}},
        output_claims=("wp_finding", "wp_info"),
        reads_output=("(!) alert lines become wp_finding claims; (i) info lines "
                      "become wp_info context. Password attacks and aggressive "
                      "enumeration are NOT offered by this adapter."),
        next_steps=("exploit-lookup", "nuclei-scan"),
    ),
    ActionGuide(
        action="exploit-lookup",
        capability_class="passive_recon",
        when=("You want to know whether published exploit-db entries exist "
              "for a product+version already fingerprinted — a pure OFFLINE "
              "database query on this machine; the target is never contacted."),
        target_shape="a short search query: product and version, e.g. 'nginx 1.18'",
        target_example="nginx 1.18",
        params=(("exclude", "comma-separated words to filter out noise"),),
        example={"action": "exploit-lookup", "target": "nginx 1.18"},
        output_claims=("exploit_candidate",),
        reads_output=("Each EDB result becomes one exploit_candidate claim with "
                      "its id. Publication is NOT exploitability — verify with "
                      "gated actions before reporting anything."),
        next_steps=("nuclei-scan", "probe"),
    ),
    ActionGuide(
        action="packet-capture",
        capability_class="network_mapping",
        when=("You need to observe which cleartext protocols actually flow on "
              "the operator's OWN segment (segmentation review, plaintext "
              "audit). Listen-only: capture receives, it never transmits."),
        target_shape="a site/segment label (recorded; the capture is local)",
        target_example="office-floor-2",
        params=(("interface", "REQUIRED: the operator's own interface, e.g. eth0"),
                ("filter", "named BPF filter: arp|icmp|tcp|udp|port 53|port 80|port 443|port 445|broadcast"),
                ("count", "1-5000 packets, default 200")),
        example={"action": "packet-capture", "target": "office-floor-2",
                 "params": {"interface": "eth0", "filter": "tcp", "count": "200"}},
        output_claims=("capture_summary",),
        reads_output=("Protocol AGGREGATES only (packet counts per proto:port) — "
                      "no addresses of bystanders, no payloads. Free-form BPF "
                      "filters are refused by the whitelist."),
        next_steps=("service-detect", "port-scan"),
    ),
    ActionGuide(
        action="host-audit",
        capability_class="config_assessment",
        when=("You want the hardening baseline of the OPERATOR'S OWN machine "
              "(blue-team): lynis audit with findings as defensive guidance. "
              "The tool audits where it runs — the target is never contacted."),
        target_shape="a label for the machine itself (informational, not passed to the binary)",
        target_example="operator-laptop",
        example={"action": "host-audit", "target": "operator-laptop"},
        output_claims=("hardening_suggestion",),
        reads_output=("Each lynis suggestion becomes one hardening_suggestion "
                      "claim with its test id — apply it, re-run, verify."),
        next_steps=("exec-tool",),
    ),
)

_GUIDES: dict[str, ActionGuide] = {g.action: g for g in _ACTION_GUIDES}


def all_action_guides() -> tuple[ActionGuide, ...]:
    return _ACTION_GUIDES


def find_action_guide(action: str) -> ActionGuide | None:
    return _GUIDES.get(str(action).strip().lower())


def action_guides_context() -> dict:
    """Machine-readable bundle: one guide per live executable action."""
    from ..execution.broker import AdapterRegistry

    registry = AdapterRegistry()
    live = {a.name: a for a in registry.list()}
    guides = []
    for name, adapter in sorted(live.items()):
        g = _GUIDES.get(name)
        if g is None:
            guides.append({
                "action": name,
                "capability_class": adapter.capability_class,
                "covered": False,
                "contract_only": True,
                "target_shape": "(see adapter manifest)",
                "example": {"action": name, "target": "<in-scope target>"},
            })
            continue
        guides.append({
            "action": name,
            "capability_class": g.capability_class,
            "covered": True,
            "when": list(g.when),
            "target_shape": g.target_shape,
            "target_example": g.target_example,
            "params": [{"name": n, "meaning": m} for n, m in g.params],
            "example": dict(g.example),
            "output_claims": list(g.output_claims),
            "reads_output": g.reads_output,
            "next_steps": list(g.next_steps),
        })
    return {
        "schema_version": 1,
        "actions": guides,
        "covered": sum(1 for g in guides if g.get("covered")),
        "total": len(guides),
        "rule": (
            "Follow the example's exact target shape; the broker refuses "
            "malformed targets and undeclared params. Every request still "
            "passes scope + policy gates — a guide never authorizes."
        ),
    }


def coverage_report() -> dict:
    """Consistency verdict: guides vs the live registry, both directions."""
    from ..execution.broker import AdapterRegistry

    registry = AdapterRegistry()
    live = set(registry.names())
    guided = set(_GUIDES)
    return {
        "live_actions": len(live),
        "guided_actions": len(guided),
        "covered": len(live & guided),
        "missing_guides": sorted(live - guided),
        "stale_guides": sorted(guided - live),
        "complete": not (live - guided) and not (guided - live),
    }
