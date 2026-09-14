"""Claim ledger: confidence propagation and contradiction handling.

A *claim* is a statement about the world with provenance — it is not a fact
until corroborated. The ledger stores claims with:

  * a deterministic confidence score derived from source scoring,
  * provenance (source key, method, observation time, evidence linkage),
  * lifecycle state (open → corroborated / contradicted / stale),
  * contradiction detection between mutually exclusive claims.

Confidence is a *computed* property of evidence quality, never an LLM
opinion. Corroboration from independent sources raises confidence; a
higher-scored contradicting claim demotes the loser to ``contradicted``.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

from .sources import SourceRegistry, score_source

CLAIM_STATES = ("open", "corroborated", "contradicted", "stale")

# Confidence thresholds for the lifecycle decision.
_CORROBORATE_THRESHOLD = 0.75


@dataclass
class Claim:
    """One provenance-carrying statement about a subject."""

    id: str
    case_id: str
    subject: str                    # canonical target/entity the claim is about
    kind: str                       # e.g. "hostname", "ip", "tech", "whois_field"
    value: str                      # the asserted value
    source: str
    method: str
    observed_at: float
    confidence: float               # 0..1, deterministic
    evidence_id: str | None = None
    state: str = "open"
    corroborated_by: list[str] = field(default_factory=list)
    notes: str = ""

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "subject": self.subject,
            "kind": self.kind,
            "value": self.value,
            "source": self.source,
            "method": self.method,
            "observed_at": self.observed_at,
            "confidence": round(self.confidence, 4),
            "evidence_id": self.evidence_id,
            "state": self.state,
            "corroborated_by": list(self.corroborated_by),
            "notes": self.notes,
        }


@dataclass(frozen=True)
class Conflict:
    """A detected contradiction between two claims."""

    winner_id: str
    loser_id: str
    reason: str

    def as_dict(self) -> dict:
        return {"winner": self.winner_id, "loser": self.loser_id, "reason": self.reason}


def fuse_conflicts(existing: Claim, incoming: Claim) -> Conflict | None:
    """Detect a contradiction between two claims on the same (subject, kind).

    Mutually exclusive kinds: a host has exactly one A-style identity value.
    When values differ, the higher-confidence claim wins; the loser is marked
    ``contradicted`` (kept — never deleted, per the evidence law).
    """
    if existing.subject != incoming.subject or existing.kind != incoming.kind:
        return None
    if existing.value.strip().lower() == incoming.value.strip().lower():
        return None
    if incoming.confidence > existing.confidence:
        return Conflict(incoming.id, existing.id,
                        "incoming claim has higher confidence")
    return Conflict(existing.id, incoming.id,
                    "existing claim has higher confidence")


class ClaimLedger:
    """In-memory + optional SQLite-backed claim store."""

    def __init__(self, registry: SourceRegistry | None = None) -> None:
        self._registry = registry or SourceRegistry()
        self._claims: dict[str, Claim] = {}
        self._conflicts: list[Conflict] = []

    # -- creation -----------------------------------------------------------

    def add(
        self,
        case_id: str,
        *,
        subject: str,
        kind: str,
        value: str,
        source: str,
        method: str = "",
        observed_at: float | None = None,
        evidence_id: str | None = None,
        notes: str = "",
    ) -> Claim:
        """Register a claim; confidence comes from source scoring."""
        src = self._registry.require(source)
        now = time.time()
        obs = now if observed_at is None else observed_at
        scored = score_source(src, observed_at=obs, now=now)
        claim = Claim(
            id=f"cl_{uuid.uuid4().hex[:12]}",
            case_id=case_id,
            subject=subject.strip().lower(),
            kind=kind,
            value=value,
            source=source,
            method=method,
            observed_at=obs,
            confidence=scored["composite"],
            evidence_id=evidence_id,
            notes=notes,
        )
        self._claims[claim.id] = claim
        self._apply_lifecycle(claim)
        return claim

    # -- lifecycle -----------------------------------------------------------

    def _apply_lifecycle(self, new_claim: Claim) -> None:
        """Re-evaluate corroboration/contradiction for the affected group."""
        group = [
            c for c in self._claims.values()
            if c.case_id == new_claim.case_id
            and c.subject == new_claim.subject
            and c.kind == new_claim.kind
        ]
        # group corroboration: same value from independent sources
        for claim in group:
            if claim.state == "contradicted":
                continue
            supporters = [
                c for c in group
                if c.value.strip().lower() == claim.value.strip().lower()
                and c.id != claim.id
            ]
            if supporters:
                claim.state = "corroborated"
                for s in supporters:
                    if s.source not in claim.corroborated_by:
                        claim.corroborated_by.append(s.source)
        # contradiction: differing values — loser demoted. Cross-domain
        # differences stay live for the fusion engine to surface; the ledger
        # only demotes when both sides come from the same observing domain.
        from .fusion import _domain_of  # local import: fusion imports claims

        for claim in group:
            if claim.state == "contradicted":
                continue
            for other in group:
                if other.id == claim.id or other.state == "contradicted":
                    continue
                if _domain_of(claim) != _domain_of(other):
                    continue  # cross-domain difference → fusion conflict, not demotion
                conflict = fuse_conflicts(claim, other)
                if conflict is None:
                    continue
                loser = self._claims.get(conflict.loser_id)
                winner = self._claims.get(conflict.winner_id)
                if loser is not None and winner is not None:
                    # demote only the strictly weaker side; skip if already handled
                    if (winner.confidence > loser.confidence
                            and loser.state != "contradicted"):
                        loser.state = "contradicted"
                        self._conflicts.append(conflict)

    def get(self, claim_id: str) -> Claim | None:
        return self._claims.get(claim_id)

    @classmethod
    def load_from_db(
        cls,
        db,
        case_id: str,
        registry: SourceRegistry | None = None,
    ) -> "ClaimLedger":
        """Hydrate a ledger from persisted claims (migration v2 table).

        Note: conflict *events* are not persisted; contradiction state lives
        on the claims themselves, so loaded ledgers keep states intact.
        """
        ledger = cls(registry)
        for row in db.claims_for(case_id):
            claim = Claim(
                id=row["id"],
                case_id=row["case_id"],
                subject=row["subject"],
                kind=row["kind"],
                value=row["value"],
                source=row["source"],
                method=row["method"],
                observed_at=row["observed_at"],
                confidence=row["confidence"],
                evidence_id=row["evidence_id"],
                state=row["state"],
                notes=row["notes"],
            )
            ledger._claims[claim.id] = claim
        return ledger

    def for_subject(self, case_id: str, subject: str) -> list[Claim]:
        subject = subject.strip().lower()
        return sorted(
            (c for c in self._claims.values()
             if c.case_id == case_id and c.subject == subject),
            key=lambda c: (c.kind, -c.confidence),
        )

    def list(self, case_id: str | None = None) -> list[Claim]:
        claims = [c for c in self._claims.values() if case_id is None or c.case_id == case_id]
        return sorted(claims, key=lambda c: (c.subject, c.kind, -c.confidence))

    def conflicts(self, case_id: str | None = None) -> list[Conflict]:
        return [c for c in self._conflicts if case_id is None
                or (self._claims.get(c.winner_id) or self._claims.get(c.loser_id)).case_id == case_id]

    # -- profile ---------------------------------------------------------------

    def profile(self, case_id: str, subject: str) -> dict:
        """Confidence-weighted profile view for one subject.

        Only claims in states open/corroborated contribute; contradicted
        claims are listed but excluded from the weighted value set.
        """
        claims = self.for_subject(case_id, subject)
        active = [c for c in claims if c.state in {"open", "corroborated"}]
        by_kind: dict[str, dict] = {}
        for claim in active:
            slot = by_kind.setdefault(claim.kind, {"values": [], "total_weight": 0.0})
            slot["values"].append((claim.value, round(claim.confidence, 4)))
            slot["total_weight"] += claim.confidence
        best: dict[str, dict] = {}
        for kind, slot in by_kind.items():
            top_value, top_conf = max(slot["values"], key=lambda pair: pair[1])
            best[kind] = {
                "value": top_value,
                "confidence": top_conf,
                "corroborated": any(
                    c.state == "corroborated" for c in active if c.kind == kind
                ),
                "alternatives": sorted({v for v, _ in slot["values"]} - {top_value}),
            }
        return {
            "subject": subject,
            "claims_total": len(claims),
            "active": len(active),
            "contradicted": len(claims) - len(active),
            "attributes": best,
        }

    def mark_stale(self, claim_id: str) -> None:
        claim = self._claims.get(claim_id)
        if claim is None:
            raise KeyError(f"unknown claim {claim_id}")
        claim.state = "stale"
