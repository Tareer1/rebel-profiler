"""Triage: rank a case's claims into a probe-ready queue.

The hunt (and every collection action) drops claims into the ledger; this
module is the bridge between "collected" and "worth a manual PoC". It reads
the ledger, ranks what a bounty hunter would look at first, and — because a
suggestion without provenance is just a rumour — every candidate carries the
*whole chain*: which tool produced it, which source scored it, which evidence
record holds the raw bytes, and what the exact next probe request is.

Ordering (highest first):

1. secret-shaped values (``*_secret`` claim kinds) — leak = finding
2. object-storage endpoints (S3/Azure/GCS URLs) — data exposure
3. other absolute URLs found in code — undocumented surface
4. API path templates — IDOR/authz probe targets
5. cloud hosts — asset map
6. everything else, demoted further when the observation is stale

Pure ranking over provenance: nothing here touches the network or the
target. The probe itself stays operator-owned — ``probe_suggest`` turns a
candidate into a queued high-risk action, never an automatic one.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field, replace

# Stale observations are worth less: recon data ages like milk.
_FRESH_DAYS = 14.0
_DECAY_FLOOR = 0.4

# Probe-score bonuses by value shape — the bounty-hunter's own priors,
# written down so they apply the same way every time.
_BONUS_STORAGE = 0.9      # s3/amazonaws/azure/blob/gcs URLs
_BONUS_URL = 0.55         # absolute http(s) URLs found in shipped code
_BONUS_API_PATH = 0.35    # /api/... style templates
_BONUS_HOST = 0.25        # bare hosts
_BONUS_OTHER = 0.1


@dataclass(frozen=True)
class Provenance:
    """The full evidence chain for one ranked candidate."""

    case_id: str
    subject: str
    kind: str
    value: str
    source: str
    method: str
    observed_at: float
    evidence_id: str | None
    notes: str
    confidence: float
    corroboration: int = field(default=0)

    def as_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "subject": self.subject,
            "kind": self.kind,
            "value": self.value,
            "source": self.source,
            "method": self.method,
            "observed_at": self.observed_at,
            "evidence_id": self.evidence_id,
            "notes": self.notes,
            "confidence": round(self.confidence, 4),
            "corroboration": self.corroboration,
        }


def _decay(observed_at: float, now: float) -> float:
    age_days = max(0.0, (now - observed_at) / 86400.0)
    if age_days <= _FRESH_DAYS:
        return 1.0
    factor = 1.0 - (age_days - _FRESH_DAYS) / 365.0
    return max(_DECAY_FLOOR, factor)


def _is_secret_kind(kind: str) -> bool:
    """Secret-shaped claim kinds: ``*_secret`` and namespaced forms like
    ``js_secret:google_api_key`` that the hunter writes into the ledger."""
    return kind.endswith("_secret") or ":secret" in kind or \
        kind.startswith("js_secret")


def _shape_bonus(kind: str, value: str) -> float:
    lowered = value.lower()
    storage = (".s3.amazonaws.com", ".blob.core.windows.net",
               "storage.googleapis.com")
    if _is_secret_kind(kind):
        return 1.0
    if any(host in lowered for host in storage):
        return _BONUS_STORAGE
    if lowered.startswith(("http://", "https://")):
        return _BONUS_URL
    if "/api/" in lowered or kind in ("api_path", "js_endpoint"):
        return _BONUS_API_PATH
    if kind.endswith("host"):
        return _BONUS_HOST
    return _BONUS_OTHER


_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*\.)[A-Za-z]{2,}$")


def _probe_url(value: str, subject: str) -> str:
    """The exact request target a probe would hit, or '' when unclear."""
    v = value.strip()
    # Hunt claims join seed-url and path with a space: "https://host /api/x"
    if " " in v:
        head, tail = v.split(" ", 1)
        if head.lower().startswith(("http://", "https://")) and tail.startswith("/"):
            return (head.rstrip("/") + tail)[:300]
    if v.lower().startswith(("http://", "https://")):
        return v[:300]
    if v.startswith("/"):
        base = subject if subject.startswith(("http://", "https://")) \
            else f"https://{subject}"
        return (base.rstrip("/") + v)[:300]
    # Bare hostnames (s3 buckets, cloud hosts stored scheme-less) get a
    # scheme so the suggestion is runnable. Tokens/keys (underscores, no
    # dot-shape) deliberately do NOT match — no fake probe URLs.
    if _HOST_RE.match(v):
        return f"https://{v}"[:300]
    return ""


def _probe_reason(score: float, kind: str, value: str) -> str:
    if _is_secret_kind(kind):
        return ("secret-shaped value found in shipped code — verify "
                "out-of-band first; a live key is revoke+rotate, not a probe")
    if _shape_bonus(kind, value) == _BONUS_STORAGE:
        return "object-storage URL — check anonymous read/list ACLs"
    if value.lower().startswith(("http://", "https://")):
        return ("absolute URL shipped in client code — undocumented surface; "
                "compare auth surface against the official API")
    if "/api/" in value.lower() or kind == "api_path":
        return ("API route template — probe with/without auth tokens for "
                "IDOR/authz gaps")
    if kind.endswith("host"):
        return "cloud host in the asset map — enumerate for forgotten apps"
    return "secondary candidate — corroboration may raise its rank"


def triage(case_id: str, ledger, *, limit: int = 10,
           subject: str | None = None) -> dict:
    """Rank ledger claims for *case_id* into a probe-ready queue.

    ``ledger`` is a :class:`~rebel_profiler.intel.claims.ClaimLedger`;
    provenance is copied out so the caller never mutates store state.
    """
    now = time.time()
    wanted_subject = (subject or "").strip().lower()
    candidates: list[dict] = []
    for claim in ledger.list(case_id):
        if wanted_subject and claim.subject != wanted_subject:
            continue
        prov = Provenance(
            case_id=claim.case_id,
            subject=claim.subject,
            kind=claim.kind,
            value=claim.value,
            source=claim.source,
            method=claim.method,
            observed_at=claim.observed_at,
            evidence_id=claim.evidence_id,
            notes=claim.notes,
            confidence=claim.confidence,
            corroboration=max(0, len(claim.corroborated_by)
                              if hasattr(claim, "corroborated_by") else 0),
        )
        bonus = _shape_bonus(claim.kind, claim.value)
        score = round(min(1.0, claim.confidence * _decay(claim.observed_at, now)
                          + bonus * 0.5), 4)
        # secrets surface raw; every other candidate carries the ready URL
        candidates.append({
            "score": score,
            "priority": 1 if bonus >= 0.9 else 2 if bonus >= 0.35 else 3,
            "probe_url": _probe_url(claim.value, claim.subject),
            "probe_reason": _probe_reason(score, claim.kind, claim.value),
            "provenance": prov.as_dict(),
        })
    candidates.sort(key=lambda c: (-c["score"], c["provenance"]["value"]))
    trimmed = candidates[:max(1, limit)]
    return {
        "schema_version": 1,
        "case_id": case_id,
        "subject": wanted_subject or None,
        "count": len(trimmed),
        "total_considered": len(candidates),
        "candidates": trimmed,
    }


__all__ = ["Provenance", "triage", "replace"]
