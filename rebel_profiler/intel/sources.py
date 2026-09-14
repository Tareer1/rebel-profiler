"""OSINT source registry with reliability / freshness / independence scoring.

Every observation entering the system carries a source reference. A source is
scored deterministically — never by the LLM — using a two-axis admiralty-style
model extended with independence (PDF 5):

  * reliability  — how trustworthy the source *type* is (primary registry,
                   authoritative protocol answer, aggregator, crowd, unknown)
  * freshness    — how recently the data was observed (decay with age)
  * independence — whether the source shares infrastructure with other sources

The composite score is a plain weighted mean of the three axes. Scoring is a
pure function: same inputs, same score, versioned and auditable.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

RELIABILITY_GRADES: dict[str, int] = {
    # A: primary/authoritative (registry of record, protocol answer from the
    # authoritative server itself)
    "a1": 5,
    # B: authoritative aggregator or signed/verified feed
    "b2": 4,
    # C: reputable aggregator without verification guarantees
    "c3": 3,
    # D: crowd-sourced / user-contributed
    "d4": 2,
    # E: unknown or unattributable
    "e5": 1,
}

_FRESHNESS_HALF_LIFE_DAYS = 30.0

_WEIGHTS = {"reliability": 0.5, "freshness": 0.3, "independence": 0.2}


@dataclass(frozen=True)
class Source:
    """A named intelligence source with a declared reliability grade."""

    key: str
    kind: str                      # e.g. "whois", "dns", "ct_log", "crowd"
    grade: str                     # key into RELIABILITY_GRADES
    independence: float = 1.0      # 1.0 = fully independent, 0.0 = fully shared
    operator: str = ""             # who runs it, for the record
    notes: str = ""

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "kind": self.kind,
            "grade": self.grade,
            "independence": self.independence,
            "operator": self.operator,
            "notes": self.notes,
        }


def _freshness_score(age_days: float) -> float:
    """Exponential decay: 1.0 now, 0.5 after the half-life, approaching 0."""
    if age_days <= 0:
        return 1.0
    return 0.5 ** (age_days / _FRESHNESS_HALF_LIFE_DAYS)


def score_source(
    source: Source,
    *,
    observed_at: float | None = None,
    now: float | None = None,
) -> dict:
    """Deterministically score a source observation.

    Returns the three axis scores (0..1) plus the composite and the inputs,
    so the score can be audited later.
    """
    if source.grade not in RELIABILITY_GRADES:
        raise ValueError(f"Unknown reliability grade '{source.grade}'")
    now_ts = time.time() if now is None else now
    obs_ts = now_ts if observed_at is None else observed_at
    age_days = max(0.0, (now_ts - obs_ts) / 86400.0)

    reliability = RELIABILITY_GRADES[source.grade] / 5.0
    freshness = _freshness_score(age_days)
    independence = min(1.0, max(0.0, source.independence))

    composite = (
        _WEIGHTS["reliability"] * reliability
        + _WEIGHTS["freshness"] * freshness
        + _WEIGHTS["independence"] * independence
    )
    return {
        "source": source.key,
        "grade": source.grade,
        "age_days": round(age_days, 3),
        "reliability": round(reliability, 4),
        "freshness": round(freshness, 4),
        "independence": round(independence, 4),
        "composite": round(composite, 4),
        "scoring_version": "1",
    }


DEFAULT_SOURCES: tuple[Source, ...] = (
    Source("whois.iana", "whois", "a1", 1.0, "IANA", "registry of record for TLDs"),
    Source("whois.registrar", "whois", "b2", 1.0, "registrar of record", ""),
    Source("dns.authoritative", "dns", "a1", 1.0, "zone owner", "protocol answer from authoritative server"),
    Source("dns.resolver", "dns", "b2", 0.8, "recursive resolver", "cached answers possible"),
    Source("ct.logs", "ct_log", "a1", 1.0, "public CT operators", "append-only logs"),
    Source("passive_dns.farsight", "passive_dns", "b2", 1.0, "Farsight/DNSDB-style", "historical observation"),
    Source("aggregator.shodan", "aggregator", "c3", 1.0, "third party", "scan archive, may be stale"),
    Source("aggregator.censys", "aggregator", "c3", 1.0, "third party", "scan archive, may be stale"),
    Source("crowd.urlhaus", "crowd", "d4", 0.9, "community", "user-contributed"),
    Source("scan.nmap", "scan", "a1", 1.0, "local scan", "protocol answer from the target itself"),
    Source("scan.tool", "scan", "b2", 1.0, "whitelisted tool", "exec-tool run through the broker"),
    Source("unknown", "unknown", "e5", 0.5, "", "unattributed content"),
)


class SourceRegistry:
    """Registry of known sources; unknown source keys fail conservative."""

    def __init__(self, sources: tuple[Source, ...] = DEFAULT_SOURCES) -> None:
        self._sources: dict[str, Source] = {s.key: s for s in sources}

    def register(self, source: Source) -> None:
        if source.grade not in RELIABILITY_GRADES:
            raise ValueError(f"Unknown reliability grade '{source.grade}'")
        self._sources[source.key] = source

    def get(self, key: str) -> Source | None:
        return self._sources.get(key)

    def require(self, key: str) -> Source:
        source = self._sources.get(key)
        if source is None:
            # Unknown source behaves like grade E — data still enters, but
            # scored at the bottom and flagged as unattributed.
            return Source(key, "unknown", "e5", 0.5, "", "auto-registered unknown source")
        return source

    def list(self) -> list[Source]:
        return [self._sources[k] for k in sorted(self._sources)]


def source_contract() -> dict:
    """Machine-readable scoring contract for the planner/docs."""
    return {
        "schema_version": 1,
        "scoring_version": "1",
        "grades": RELIABILITY_GRADES,
        "weights": _WEIGHTS,
        "freshness_half_life_days": _FRESHNESS_HALF_LIFE_DAYS,
        "rule": (
            "Scores are deterministic. The LLM may weigh claims using these "
            "scores; it may never assign or alter them."
        ),
    }
