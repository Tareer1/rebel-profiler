"""Cross-domain fusion (PDF 9).

Multiple capabilities observe the same world through different channels —
DNS, certificates, WHOIS, port scans, web audits. Fusion joins those views
per subject into one consistent picture:

  * **Subject profiles** — every (case, subject) gets a fused profile keyed
    by *attribute* (claim kind) rather than by observing domain, so ``dns``
    and ``ct`` observations of the same host unify into one record with
    per-source support listed.
  * **Cross-domain corroboration** — independent sources agreeing on the same
    (attribute, value) fuse into one entry whose confidence is combined with
    a noisy-OR (independence-aware): two 0.6 observations fuse to 0.84, not
    1.2. Corroborated entries outrank single-source ones.
  * **Cross-domain contradiction engine** — differing values for the same
    attribute are surfaced as fusion conflicts with every supporting source
    on each side, never silently dropped. Both sides stay in the ledger.

Fusion is a deterministic view over claims — it executes nothing and
authorizes nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .claims import Claim, ClaimLedger

# Kinds that never participate in value-contradiction detection (they are
# naturally multi-valued).
MULTI_VALUED_KINDS = {"port", "service", "product", "version", "hostname",
                      "nameserver", "mx", "cname", "certificate", "web_finding",
                      "txt", "caa", "ipv6", "ptr", "soa_contact"}


def noisy_or(confidences: list[float]) -> float:
    """Independence-aware confidence combination (bounded 0..1)."""
    if not confidences:
        return 0.0
    product = 1.0
    for c in confidences:
        product *= 1.0 - min(1.0, max(0.0, c))
    return round(1.0 - product, 4)


@dataclass(frozen=True)
class FusionConflict:
    """Two or more differing values for one single-valued attribute."""

    subject: str
    attribute: str
    winner_value: str
    winner_sources: tuple[str, ...]
    loser_value: str
    loser_sources: tuple[str, ...]
    winner_confidence: float
    loser_confidence: float

    def as_dict(self) -> dict:
        return {
            "subject": self.subject,
            "attribute": self.attribute,
            "winner": {"value": self.winner_value,
                       "sources": list(self.winner_sources),
                       "confidence": round(self.winner_confidence, 4)},
            "loser": {"value": self.loser_value,
                      "sources": list(self.loser_sources),
                      "confidence": round(self.loser_confidence, 4)},
        }


@dataclass
class FusedAttribute:
    """One attribute of a subject with all supporting values fused."""

    attribute: str
    values: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"attribute": self.attribute, "values": self.values}


@dataclass
class SubjectProfile:
    """Fused cross-domain profile for one subject."""

    subject: str
    attributes: dict[str, FusedAttribute] = field(default_factory=dict)
    conflicts: list[FusionConflict] = field(default_factory=list)
    domains_seen: set[str] = field(default_factory=set)

    def as_dict(self) -> dict:
        return {
            "subject": self.subject,
            "domains": sorted(self.domains_seen),
            "attributes": {
                key: attr.as_dict() for key, attr in sorted(self.attributes.items())
            },
            "conflicts": [c.as_dict() for c in self.conflicts],
        }


class FusionEngine:
    """Fuses claims from all observing domains into subject profiles."""

    def __init__(self, ledger: ClaimLedger, case_id: str) -> None:
        self.ledger = ledger
        self.case_id = case_id

    def fuse(self) -> dict[str, SubjectProfile]:
        """Build fused profiles for every subject in the case."""
        claims = [
            c for c in self.ledger.list(self.case_id)
            if c.state in {"open", "corroborated"}
        ]
        profiles: dict[str, SubjectProfile] = {}

        for claim in claims:
            profile = profiles.setdefault(claim.subject, SubjectProfile(subject=claim.subject))
            profile.domains_seen.add(_domain_of(claim))
            attr = profile.attributes.setdefault(claim.kind, FusedAttribute(attribute=claim.kind))
            self._fuse_value(attr, claim)

        for profile in profiles.values():
            profile.conflicts = self._detect_conflicts(profile)
        return profiles

    def _fuse_value(self, attr: FusedAttribute, claim: Claim) -> None:
        low_value = claim.value.strip().lower()
        for entry in attr.values:
            if entry["value"].lower() == low_value:
                entry["claims"].append(claim.id)
                if claim.source not in entry["sources"]:
                    entry["sources"].append(claim.source)
                entry["confidence"] = noisy_or(
                    [entry["confidence"], claim.confidence]
                )
                entry["corroborated"] = len(entry["sources"]) > 1
                return
        attr.values.append({
            "value": claim.value,
            "sources": [claim.source],
            "claims": [claim.id],
            "confidence": claim.confidence,
            "corroborated": False,
            "state": claim.state,
            "evidence_ids": [claim.evidence_id] if claim.evidence_id else [],
        })

    def _detect_conflicts(self, profile: SubjectProfile) -> list[FusionConflict]:
        conflicts: list[FusionConflict] = []
        for attribute, attr in profile.attributes.items():
            if attribute in MULTI_VALUED_KINDS or len(attr.values) < 2:
                continue
            ranked = sorted(attr.values, key=lambda v: -v["confidence"])
            winner = ranked[0]
            for loser in ranked[1:]:
                conflicts.append(FusionConflict(
                    subject=profile.subject,
                    attribute=attribute,
                    winner_value=winner["value"],
                    winner_sources=tuple(winner["sources"]),
                    loser_value=loser["value"],
                    loser_sources=tuple(loser["sources"]),
                    winner_confidence=winner["confidence"],
                    loser_confidence=loser["confidence"],
                ))
        return conflicts

    def report(self) -> dict:
        """Machine-readable fusion report for the whole case."""
        profiles = self.fuse()
        all_conflicts = [c for p in profiles.values() for c in p.conflicts]
        return {
            "schema_version": 1,
            "case_id": self.case_id,
            "subjects": {key: p.as_dict() for key, p in sorted(profiles.items())},
            "stats": {
                "subjects": len(profiles),
                "fused_values": sum(
                    1 for p in profiles.values()
                    for attr in p.attributes.values() for _ in attr.values
                ),
                "cross_domain_subjects": sum(
                    1 for p in profiles.values() if len(p.domains_seen) > 1
                ),
                "conflicts": len(all_conflicts),
            },
            "conflicts": [c.as_dict() for c in all_conflicts],
        }


def _domain_of(claim: Claim) -> str:
    """Coarse observing-domain label: source first, then method.

    Source is the primary signal (crowd vs registrar vs scan). The method is
    only consulted when the source alone is ambiguous.
    """
    source = claim.source.lower()
    if source.startswith("dns."):
        return "dns"
    if source.startswith("ct.") or "cert" in source:
        return "certificates"
    if source.startswith("whois."):
        return "whois"
    if source.startswith("scan."):
        return "scanning" if "nmap" in source or "web" not in source else "web"
    if source.startswith("crowd."):
        return "crowd"
    if source.startswith("aggregator."):
        return "aggregator"
    if "dns" in claim.method:
        return "dns"
    if "whois" in claim.method:
        return "whois"
    if "web" in claim.method:
        return "web"
    if "scan" in claim.method or "port" in claim.method:
        return "scanning"
    return source or claim.method or "unknown"
