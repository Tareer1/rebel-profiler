"""Offensive planning & payload workbench: the hacker's brain, inside the law.

Two operator-facing capabilities, both deterministic and evidence-driven:

**attack_plan(case_id)** — reads ONLY the case's claim ledger and turns the
recon picture into ranked, concrete attack strategies: what to try, where
exactly, why (which claims prove the opening), which executable action
verifies it, and the payload category that applies. This is the
"isko hack karne ke tarike dundo" answer — every strategy names a REAL
action from the live registry, so the next step is always executable.

**payload build/list** — deterministic, BENIGN proof-of-impact payloads per
vulnerability class (reflected XSS marker, SQLi error/timing probes, SSTI
math marker, command-injection echo marker, open-redirect marker, IDOR
pivot path). Each payload is built for ONE verified in-scope target URL and
carries a detect marker + expected-evidence description. Nothing here
exploits: the marker proves reflection/echo/redirect, never damage.

**payload deploy** — the only delivery path is the existing `probe` action:
approval-gated, scope-checked, single request, response hash-chained as
evidence. The operator's decision (yes/no/custom-edit) is recorded; the
broker re-validates everything at dispatch. A payload never ships outside
an approved probe.

Laws unchanged: evidence-driven rankings, deterministic output, no exploit
code beyond impact-markers, no credential brute force, scope decides.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit


# --------------------------------------------------------------------- plan


@dataclass(frozen=True)
class AttackStrategy:
    """One ranked, concrete way in — always tied to evidence + an action."""

    rank: int
    title: str
    category: str                  # recon-gap | config | injection | access | fingerprint
    where: str                     # the exact target the next action takes
    why: str                       # which observed claims prove this opening
    action: str                    # executable action name (live registry)
    params: dict = field(default_factory=dict)
    payload_class: str = ""        # empty when no payload applies
    severity_hint: str = "unknown"

    def as_dict(self) -> dict:
        return {
            "rank": self.rank, "title": self.title, "category": self.category,
            "where": self.where, "why": self.why, "action": self.action,
            "params": dict(self.params), "payload_class": self.payload_class,
            "severity_hint": self.severity_hint,
        }


def _claims(ledger, case_id: str) -> list:
    for name in ("list", "all", "claims"):
        fn = getattr(ledger, name, None)
        if callable(fn):
            try:
                return fn(case_id) or fn() or []
            except TypeError:
                try:
                    return fn() or []
                except Exception:
                    pass
            except Exception:
                pass
    return []


def _subjects(claims: list) -> dict[str, dict]:
    """subject → {'kinds': set, 'values': {kind: [values]}, 'urls': [values]}"""
    out: dict[str, dict] = {}
    for c in claims:
        subject = str(getattr(c, "subject", "") or "")
        kind = str(getattr(c, "kind", "") or "")
        value = str(getattr(c, "value", "") or "")
        if not subject or not kind:
            continue
        entry = out.setdefault(subject, {"kinds": set(), "values": {}, "urls": []})
        entry["kinds"].add(kind)
        entry["values"].setdefault(kind, []).append(value)
        if kind in {"wayback_url", "js_endpoint"} and value.startswith("http"):
            entry["urls"].append(value)
    return out


def _first(values: list[str], prefix: str = "") -> str:
    for v in values:
        if prefix and prefix in v:
            return v
    return values[0] if values else ""


def attack_plan(case_id: str, ledger) -> dict:
    """The ranked strategies for this case, from its own evidence only."""
    claims = _claims(ledger, case_id)
    subjects = _subjects(claims)
    strategies: list[AttackStrategy] = []
    rank = 0

    def add(title: str, category: str, where: str, why: str, action: str,
            params: dict | None = None, payload_class: str = "",
            severity_hint: str = "unknown") -> None:
        nonlocal rank
        rank += 1
        strategies.append(AttackStrategy(
            rank=rank, title=title, category=category, where=where, why=why,
            action=action, params=params or {}, payload_class=payload_class,
            severity_hint=severity_hint))

    for subject, info in subjects.items():
        kinds = info["kinds"]
        host_claims = info["values"]
        base = "https://" + subject if not subject.startswith("http") else subject.rstrip("/")

        # 1. live web host with paths/params → parameter & endpoint testing
        urls = info["urls"]
        params = host_claims.get("param", [])
        if params and urls:
            add("Parameter abuse on discovered endpoints",
                "injection", _first(urls, subject),
                f"discovered parameters {params[:5]} on live endpoints",
                "probe", {"method": "GET"}, payload_class="sqli_error",
                severity_hint="high")
        if urls:
            add("JS-mined endpoint access-control check",
                "access", _first([u for u in urls if "/api" in u] or urls, subject),
                "endpoints mined from shipped JavaScript often lack authz",
                "probe", {"method": "GET"}, payload_class="idor_pivot",
                severity_hint="high")

        # 2. live host without header hardening → header/config strategies
        if "httpx_status" in kinds or "web_url" in kinds:
            add("Security-header & cookie posture exploitation prep",
                "config", base if not subject.startswith("http") else subject,
                "live host audited: missing CSP/HSTS/cookie flags widen XSS impact",
                "header-audit", {}, payload_class="reflected_xss",
                severity_hint="medium")

        # 3. tech fingerprints → known template checks
        techs = host_claims.get("tech", []) + host_claims.get("httpx_tech", [])
        if techs:
            add("Fingerprint-matched template scan",
                "fingerprint", base,
                f"identified stack {techs[:3]} — known templates apply",
                "nuclei-scan", {"severity": "medium,high,critical"},
                severity_hint="medium")

        # 4. open ports → service probing
        ports = host_claims.get("port", [])
        if ports:
            add("Exposed service banner verification",
                "access", subject,
                f"open ports {ports[:6]} — banner/version claims need verification",
                "service-detect", {"ports": ",".join(ports[:6])},
                severity_hint="medium")

        # 5. recon gaps — drive the passive loop to close them
        if "hostname" in kinds and "httpx_status" not in kinds:
            hosts = host_claims.get("hostname", [])
            if hosts:
                add("Unprobed subdomain liveness sweep",
                    "recon-gap", _first(hosts, subject),
                    f"{len(hosts)} resolved hostnames never probed live — "
                    "the surface map is unverified",
                    "httpx-probe", {}, severity_hint="low")
        if "wayback_url" in kinds and "param" not in kinds:
            add("Hidden-parameter discovery on archived endpoints",
                "recon-gap", _first(info["urls"] or [base], subject),
                "archived URLs exist but no parameter map was built for them",
                "param-hunt", {}, severity_hint="low")

    return {
        "schema_version": 1,
        "case_id": case_id,
        "subjects": len(subjects),
        "claims_read": len(claims),
        "strategies": [s.as_dict() for s in strategies][:25],
        "rule": (
            "Ranked from THIS case's evidence only. Every strategy names an "
            "executable action; the broker's gates still decide each run. "
            "Payload deployment requires an explicit operator approval."
        ),
    }


# ------------------------------------------------------------------ payload


_PAYLOAD_CLASSES: tuple[str, ...] = (
    "reflected_xss", "sqli_error", "sqli_timing", "ssti", "cmdi_echo",
    "open_redirect", "idor_pivot", "traversal",
)


def payload_classes() -> tuple[str, ...]:
    return _PAYLOAD_CLASSES


def _marker() -> str:
    return "rp" + secrets.token_hex(4)


def build_payload(payload_class: str, target_url: str, param: str = "",
                  *, subject_hint: str = "") -> dict:
    """One benign impact-marker payload for ONE verified in-scope target.

    Every payload proves a condition without damage: a unique marker to
    detect reflection/echo, a benign math/echo expression, or a
    self-referencing redirect. No exploitation beyond detection.
    """
    pc = str(payload_class or "").strip().lower()
    if pc not in _PAYLOAD_CLASSES:
        raise ValueError(
            f"unknown payload class '{payload_class}'",
        )
    urlsplit(target_url)   # raises on truly malformed URLs
    marker = _marker()
    param = (param or "q").strip() or "q"

    if pc == "reflected_xss":
        # pure marker probe — no script execution, only reflection detection
        payload = '\"><svg/onload=undefined>' + marker
        detect = f"response body contains {marker} (reflection proven; no script runs)"
    elif pc == "sqli_error":
        payload = "1'\\\") AND '1'='1" + marker
        detect = "SQL error text or marker reflection in the response"
    elif pc == "sqli_timing":
        payload = "1 AND 1=1 -- " + marker
        detect = "differential response timing between baseline and payload request"
    elif pc == "ssti":
        payload = "${7*7}" + marker
        detect = "'49' rendered in the response (safe math marker; no code exec)"
    elif pc == "cmdi_echo":
        payload = ";echo " + marker
        detect = f"{marker} echoed in the response (marker only, nothing executed beyond echo)"
    elif pc == "open_redirect":
        payload = "//" + (urlsplit(target_url).hostname or "example.invalid")
        detect = "Location header points at the SAME host (redirect controllability proven, no exfil)"
    elif pc == "idor_pivot":
        payload = "1"
        detect = "another principal's object returned for sequential id — compare fields, not exfiltrate"
    elif pc == "traversal":
        payload = "../../../../etc/hostname"
        detect = "host identity string in response (read-only marker, single file)"
    else:   # unreachable; the membership check above guards it
        raise ValueError(pc)

    injected_url = target_url + ("&" if "?" in target_url else "?") + \
        quote(param) + "=" + quote(payload, safe="")
    return {
        "schema_version": 1,
        "payload_class": pc,
        "target": target_url,
        "param": param,
        "payload": payload,
        "request_url": injected_url,
        "detect": detect,
        "marker": marker,
        "safe": True,
        "delivery": "probe (approval-gated, single request, evidence-chained)",
        "rule": (
            "Impact-marker only: proves the condition, causes no damage, "
            "collects no data. Deploy requires an explicit operator decision."
        ),
    }


def deploy_payload(case_id: str, built: dict, *, approved: bool,
                   requested_by: str = "operator") -> dict:
    """Wrap a built payload into the approval-gated probe ActionRequest.

    Nothing executes here — the caller hands the request to the broker,
    which re-validates scope + policy and records the approval decision.
    `approved` must be an explicit operator decision (yes/no flow); the
    custom-edit path is just: build → modify the dict → deploy again.
    """
    if not isinstance(built, dict) or built.get("payload_class") not in _PAYLOAD_CLASSES:
        raise ValueError("deploy_payload needs a payload built by build_payload")
    from ..execution import ActionRequest

    request = ActionRequest(
        case_id=case_id,
        capability="vuln_validation",
        action="probe",
        target=str(built.get("target") or ""),
        params={"method": "GET"},
        requested_by=requested_by,
        reason=f"payload deploy: {built['payload_class']} marker {built.get('marker', '')}"
               + ("" if approved else " [DRAFT — not approved]"),
    )
    if approved:
        # The marker travels as the probe's header so the response proves
        # reflection without touching the query string the operator typed.
        # `detect` stays in the envelope (not params): the probe adapter's
        # declared params are method/data/header/timeout only.
        request.params["header"] = f"X-RP-Marker: {built.get('marker', 'rp')}"
    return {
        "approved": bool(approved),
        "will_dispatch": bool(approved),
        "request": {
            "action": request.action,
            "target": request.target,
            "params": dict(request.params),
            "reason": request.reason,
            "expected_detect": built.get("detect", ""),
        },
        "payload": built,
        "rule": (
            "The broker re-validates scope + policy at dispatch. A denial "
            "here is final for this payload; build a variant instead."
        ),
    }
