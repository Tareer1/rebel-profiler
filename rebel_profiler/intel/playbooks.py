"""Hunt playbooks: named, versioned multi-step hunt recipes.

A playbook is a REVIEWED recipe — an ordered list of gated actions that a
hunt should run against one in-scope target. Playbooks are data, never code:

  * every step's ``action`` must exist in the live AdapterRegistry
    (validated mechanically, the same discipline as ``vulncov``);
  * every param key must be in that adapter's ``allowed_params``;
  * expansion produces plan ENTRIES (action + params + why) — the actual
    execution still goes through the broker's six gates, so a playbook can
    never grant more reach than the operator's scope allows.

Discovery order for ``load_playbooks``: the built-in tuple first, then
``<data_dir>/playbooks/*.json`` — an operator can add site-specific recipes
without touching the code. Malformed playbook files are rejected with
structured reasons (deterministic parser discipline), never half-loaded.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from ..core.errors import UsageError

_SCHEMA_VERSION = 1
_NAME = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
_KNOWN_KEYS = {"schema_version", "name", "version", "description",
               "author", "tags", "steps"}


@dataclass(frozen=True)
class PlaybookStep:
    rank: int
    action: str
    params: dict
    why: str


@dataclass(frozen=True)
class Playbook:
    name: str
    version: str
    description: str
    author: str
    tags: tuple[str, ...]
    steps: tuple[PlaybookStep, ...]
    source: str = "builtin"

    def as_dict(self) -> dict:
        return {
            "name": self.name, "version": self.version,
            "description": self.description, "author": self.author,
            "tags": list(self.tags), "source": self.source,
            "steps": [{"rank": s.rank, "action": s.action,
                       "params": s.params, "why": s.why}
                      for s in self.steps],
        }


def _parse_playbook(raw, source: str = "builtin") -> Playbook:
    """Validate one playbook dict against the schema. Raises UsageError."""
    if not isinstance(raw, dict):
        raise UsageError("A playbook must be a JSON object",
                         reason=f"got {type(raw).__name__}", source=source)
    unknown = sorted(set(raw) - _KNOWN_KEYS)
    if unknown:
        raise UsageError(f"Unknown playbook key(s): {', '.join(unknown)}",
                         reason="Keep the schema: name/version/description/"
                                "author/tags/steps", source=source)
    name = str(raw.get("name", ""))
    if not _NAME.match(name):
        raise UsageError(f"Bad playbook name: {name!r}",
                         reason="lowercase letters, digits and dashes; "
                                "2–41 chars, starts with a letter",
                         source=source)
    steps_raw = raw.get("steps")
    if not isinstance(steps_raw, list) or not steps_raw:
        raise UsageError(f"Playbook '{name}' has no steps",
                         reason="steps must be a non-empty array",
                         source=source)
    if len(steps_raw) > 24:
        raise UsageError(f"Playbook '{name}' has too many steps "
                         f"({len(steps_raw)} > 24)",
                         reason="A playbook is a focused recipe, not a plan dump",
                         source=source)
    steps: list[PlaybookStep] = []
    for i, st in enumerate(steps_raw, 1):
        if not isinstance(st, dict):
            raise UsageError(f"Step {i} of '{name}' is not an object",
                             source=source)
        action = str(st.get("action", ""))
        why = str(st.get("why", "")).strip()
        params = st.get("params") or {}
        if not action:
            raise UsageError(f"Step {i} of '{name}' has no action",
                             source=source)
        if not why:
            raise UsageError(f"Step {i} of '{name}' has no 'why'",
                             reason="A reviewed recipe explains every step",
                             source=source)
        if not isinstance(params, dict):
            raise UsageError(f"Step {i} of '{name}': params must be an object",
                             source=source)
        params = {str(k): str(v) for k, v in params.items()}
        steps.append(PlaybookStep(rank=i, action=action,
                                  params=params, why=why))
    return Playbook(
        name=name, version=str(raw.get("version", "1")),
        description=str(raw.get("description", "")),
        author=str(raw.get("author", "")),
        tags=tuple(str(t) for t in raw.get("tags", [])),
        steps=tuple(steps), source=source)


def builtin_playbooks() -> tuple[Playbook, ...]:
    """The shipped, reviewed recipes. Order: broad → focused."""
    def pb(name, version, desc, author, tags, steps):
        return _parse_playbook({
            "schema_version": _SCHEMA_VERSION, "name": name,
            "version": version, "description": desc, "author": author,
            "tags": tags,
            "steps": [{"rank": i, "action": a, "params": p, "why": w}
                      for i, (a, p, w) in enumerate(steps, 1)],
        })

    return (
        pb("quick-surface", "1", "Fast external surface read of one host",
           "rebel-profiler core", ["recon", "fast"], [
               ("dns-lookup", {}, "resolve the host before anything touches it"),
               ("passive-dns", {}, "passive DNS history: aliases and neighbours"),
               ("whois-lookup", {}, "registration data anchors the target"),
               ("cert-transparency", {}, "certificate log: sibling hosts and SANs"),
               ("httpx-probe", {}, "which resolved hosts answer HTTP(S)"),
           ]),
        pb("web-audit", "1", "Scope-enforced web posture audit for one host",
           "rebel-profiler core", ["web", "headers"], [
               ("header-audit", {"scheme": "https"},
                "security headers and cookie flags first — cheapest signal"),
               ("tls-posture", {},
                "protocol and cipher posture; legacy TLS is a downgrade path"),
               ("web-crawl", {},
                "bounded crawl: forms, links and cleartext credential posts"),
               ("tech-fingerprint", {},
                "technologies and versions feed the known-CVE correlation"),
           ]),
        pb("js-secrets", "1", "Client-side JS intel: endpoints, keys, clouds",
           "rebel-profiler core", ["js", "secrets"], [
               ("js-intel", {}, "mine shipped JS for API routes, keys, S3/Firebase hosts"),
               ("wayback-urls", {}, "historical URLs that still resolve"),
               ("known-urls", {}, "public URL datasets: forgotten endpoints"),
               ("param-hunt", {}, "parameter discovery on the mined endpoints"),
           ]),
        pb("dns-health", "1", "DNS misconfiguration and takeover prerequisites",
           "rebel-profiler core", ["dns", "takeover"], [
               ("dns-enum", {}, "records, NS and mail surface"),
               ("subdomain-enum", {}, "enumerate the host's subdomain tree"),
               ("subfinder-enum", {}, "passive subdomain sources add breadth"),
               ("httpx-probe", {},
                "NXDOMAIN/CNAME answers flag dangling takeover candidates"),
           ]),
        pb("lan-inventory", "1", "Own-LAN device inventory sweep (admin/authorized use)",
           "rebel-profiler core", ["lan", "inventory"], [
               ("host-discovery", {},
                "ping sweep: every live host becomes a lan_device claim with MAC/vendor"),
               ("port-scan", {"ports": "22,80,443,8080"},
                "management and web surfaces on the found devices"),
           ]),
        pb("wifi-posture", "1", "Authorized-site Wi-Fi posture audit (listen-only)",
           "rebel-profiler core", ["wireless", "wifi"], [
               ("wlan-monitor", {},
                "bring the operator's OWN interface into monitor mode (approval-gated)"),
               ("wlan-survey", {"duration": "300"},
                "bounded RF survey: APs, channels, encryption posture, associations"),
               ("wlan-monitor", {"stop": "1"},
                "restore managed mode — the machine goes back to normal"),
               ("wlan-ap-audit", {},
                "offline posture summary: WEP/TKIP/open APs become findings"),
           ]),
        pb("web-deep-audit", "1", "Deep web assessment: misconfig, CMS, published exploits",
           "rebel-profiler core", ["web", "misconfig", "cms"], [
               ("tech-fingerprint", {},
                "identify the stack first — CMS detection decides the wpscan step"),
               ("nikto-scan", {"port": "443", "ssl": "1"},
                "server misconfiguration sweep: defaults, outdated software, methods"),
               ("wpscan-audit", {},
                "WordPress exposure (harmless no-op when the origin is not WP)"),
               ("exploit-lookup", {},
                "offline EDB correlation for the fingerprinted product+version"),
               ("nuclei-scan", {"severity": "medium,high,critical"},
                "template validation of what the sweep actually flagged"),
           ]),
        pb("own-box-baseline", "1", "Operator's own machine hardening baseline (blue-team)",
           "rebel-profiler core", ["hardening", "defense"], [
               ("host-audit", {},
                "lynis baseline of THIS box: every suggestion is a hardening claim"),
               ("packet-capture", {"interface": "eth0", "filter": "tcp", "count": "300"},
                "protocol aggregates on the own segment: cleartext stands out"),
           ]),
        pb("binary-triage", "1", "Static binary triage (offline RE, analysis-only)",
           "rebel-profiler core", ["reverse_engineering", "malware"], [
               ("binary-info", {},
                "identity card: format, architecture, linked libraries (pass "
                "the sample path as target)"),
               ("checksec", {},
                "exploit-mitigation posture: NX/PIE/canary/RELRO states"),
               ("string-dump", {},
                "pattern-classified IOC candidates: URLs, IPs, domains, paths"),
               ("symbol-dump", {},
                "imports & exports: socket/execve/dlopen-class hints"),
               ("disasm", {"section": ".text"},
                "read the calls in the focus section — bytes as data, never run"),
           ]),
        pb("web-exposure", "1",
           "Origin exposure checks: CORS, GraphQL surface, disclosure contact",
           "rebel-profiler core", ["web", "cors", "graphql"], [
               ("cors-check", {},
                "foreign-Origin probe: reflected ACAO + credentials = reportable"),
               ("graphql-introspection", {"path": "/graphql"},
                "is the schema publicly readable? one minimal __schema probe"),
               ("security-txt", {},
                "disclosure posture: where should researchers report?"),
               ("header-audit", {},
                "header verdict for the same origin — pairs with the CORS result"),
           ]),
        pb("email-spoofing", "1",
           "Domain spoofing posture via DNS (no mail is ever sent)",
           "rebel-profiler core", ["email", "phishing", "dns"], [
               ("email-spoof", {},
                "SPF/DMARC posture: p=none or absent records = spoofable"),
               ("email-osint", {},
                "who the exposed personnel are — pairs with the spoofing posture"),
           ]),
    )


def load_playbooks(data_dir: str | Path | None = None) -> tuple[Playbook, ...]:
    """Built-ins + operator recipes from ``<data_dir>/playbooks/*.json``.

    A malformed operator file raises a structured error naming the file —
    it is never silently skipped (deterministic parser discipline).
    """
    out = list(builtin_playbooks())
    if data_dir is None:
        return tuple(out)
    pdir = Path(data_dir) / "playbooks"
    if not pdir.is_dir():
        return tuple(out)
    for path in sorted(pdir.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise UsageError(f"Playbook {path.name} is not valid JSON",
                             reason=str(exc),
                             action="Fix or remove the file, then re-run.")
        out.append(_parse_playbook(raw, source=str(path)))
    return tuple(out)


def get_playbook(name: str, data_dir: str | Path | None = None) -> Playbook:
    for p in load_playbooks(data_dir):
        if p.name == name:
            return p
    raise UsageError(
        f"Unknown playbook '{name}'",
        reason="Playbooks are named recipes; list them with 'intel playbook list'.",
        action="intel playbook list")


def validate_playbook(pb: Playbook) -> dict:
    """Mechanical honesty check against the live AdapterRegistry.

    Returns a report dict; steps whose action/params cannot possibly run are
    listed as invalid with the reason. The playbook still expands only valid
    steps — a recipe that drifted from the registry is REPORTED, never
    silently trusted.
    """
    from ..execution.broker import AdapterRegistry

    registry = AdapterRegistry()
    problems: list[dict] = []
    valid: list[PlaybookStep] = []
    for st in pb.steps:
        adapter = registry.get(st.action)
        if adapter is None:
            problems.append({"rank": st.rank, "action": st.action,
                             "problem": "no such adapter"})
            continue
        bad_params = sorted(set(st.params) - set(adapter.allowed_params))
        if bad_params:
            problems.append({"rank": st.rank, "action": st.action,
                             "problem": f"params not allowed: {', '.join(bad_params)}"})
            continue
        valid.append(st)
    return {
        "schema_version": _SCHEMA_VERSION,
        "playbook": pb.name,
        "version": pb.version,
        "valid_steps": len(valid),
        "problems": problems,
        "healthy": not problems,
    }


def expand_playbook(pb: Playbook, target: str) -> dict:
    """Expand a validated playbook into gated plan entries for ONE target.

    Expansion is pure planning: the entries are what a plan WOULD run. The
    broker's six gates decide everything at execution time — a playbook
    cannot add reach, it only pre-writes intent.
    """
    v = validate_playbook(pb)
    bad_ranks = {p["rank"] for p in v["problems"]}
    entries = [
        {"rank": st.rank, "action": st.action, "params": dict(st.params),
         "target": target, "why": st.why}
        for st in pb.steps
        if st.rank not in bad_ranks
    ]
    return {
        "schema_version": _SCHEMA_VERSION,
        "playbook": pb.name,
        "version": pb.version,
        "target": target,
        "entries": entries,
        "validation": v,
        "note": ("Expansion is a plan, not execution — every entry still "
                 "passes the broker's six gates against the live scope."),
    }
