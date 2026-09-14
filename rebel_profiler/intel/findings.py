"""Findings & report generation.

Turns a case's claim ledger into a human-readable + machine-readable report.
Only claims that are ``corroborated`` (independently supported) or at least
``open`` with meaningful confidence become findings; ``contradicted`` claims
are surfaced explicitly as unresolved conflicts, and ``stale`` claims are
excluded. Every finding keeps its provenance (source, method, evidence id) —
the report inherits the evidence law: no evidence, no claim.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .claims import Claim, ClaimLedger

# Confidence below this is reported but flagged as low-confidence context.
_LOW_CONFIDENCE = 0.35

_MIN_CONFIDENCE = 0.2


@dataclass(frozen=True)
class Finding:
    """One reportable statement backed by at least one live claim."""

    subject: str
    kind: str
    value: str
    confidence: float
    state: str
    corroborated_by: tuple[str, ...]
    claim_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    source: str
    method: str
    observed_at: float

    def as_dict(self) -> dict:
        return {
            "subject": self.subject,
            "kind": self.kind,
            "value": self.value,
            "confidence": round(self.confidence, 4),
            "state": self.state,
            "corroborated_by": list(self.corroborated_by),
            "claim_ids": list(self.claim_ids),
            "evidence_ids": list(self.evidence_ids),
            "source": self.source,
            "method": self.method,
            "observed_at": self.observed_at,
        }


@dataclass
class CaseReport:
    """Structured report for one case."""

    case_id: str
    generated_at: float
    findings: list[Finding] = field(default_factory=list)
    conflicts: list[dict] = field(default_factory=list)
    low_confidence: list[Finding] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "schema_version": 1,
            "case_id": self.case_id,
            "generated_at": self.generated_at,
            "stats": self.stats,
            "findings": [f.as_dict() for f in self.findings],
            "low_confidence": [f.as_dict() for f in self.low_confidence],
            "conflicts": list(self.conflicts),
        }

    def render_human(self) -> str:
        lines = [
            f"Case report — {self.case_id}",
            f"generated : {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(self.generated_at))}",
            f"findings  : {len(self.findings)}"
            f" (+{len(self.low_confidence)} low-confidence,"
            f" {len(self.conflicts)} unresolved conflict(s))",
            "",
        ]
        if not self.findings and not self.low_confidence:
            lines.append("  No reportable findings yet — collect more evidence.")
        for finding in self.findings:
            support = (
                f" corroborated by {', '.join(finding.corroborated_by)}"
                if finding.corroborated_by else ""
            )
            lines.append(
                f"  [{finding.state:>12}] {finding.subject} {finding.kind}:"
                f" {finding.value}  (conf={finding.confidence:.2f},"
                f" evidence={finding.evidence_ids[0] if finding.evidence_ids else '-'}{support})"
            )
        if self.low_confidence:
            lines.append("")
            lines.append("  Low confidence (context only, not findings):")
            for finding in self.low_confidence:
                lines.append(
                    f"  [{finding.state:>12}] {finding.subject} {finding.kind}:"
                    f" {finding.value}  (conf={finding.confidence:.2f})"
                )
        if self.conflicts:
            lines.append("")
            lines.append("  Unresolved conflicts (claims kept, never deleted):")
            for conflict in self.conflicts:
                lines.append(f"  - {conflict['reason']}: winner {conflict['winner'][:14]}…"
                             f" vs loser {conflict['loser'][:14]}…")
        lines.append("")
        lines.append("  Every finding above is backed by hash-chained evidence;")
        lines.append("  verify anytime with: rebel-profiler evidence verify <case-id>")
        return "\n".join(lines)


def build_findings(ledger: ClaimLedger, case_id: str) -> tuple[list[Finding], list[Finding]]:
    """Group live claims into findings, split into main vs low-confidence.

    Grouping rule: one finding per (subject, kind) using the highest-live
    confidence value; corroboration propagates from member claims. Contradicted
    claims never become findings — they surface as conflicts instead.
    """
    claims = [
        c for c in ledger.list(case_id)
        if c.state in {"open", "corroborated"} and c.confidence >= _MIN_CONFIDENCE
    ]
    groups: dict[tuple[str, str], list[Claim]] = {}
    for claim in claims:
        groups.setdefault((claim.subject, claim.kind), []).append(claim)

    findings: list[Finding] = []
    low: list[Finding] = []
    for (subject, kind), members in sorted(groups.items()):
        top = max(members, key=lambda c: (c.confidence, c.observed_at))
        corroborated_by = tuple(
            sorted({src for m in members for src in m.corroborated_by})
        )
        state = "corroborated" if corroborated_by or any(
            m.state == "corroborated" for m in members
        ) else top.state
        finding = Finding(
            subject=subject,
            kind=kind,
            value=top.value,
            confidence=top.confidence,
            state=state,
            corroborated_by=corroborated_by,
            claim_ids=tuple(m.id for m in members),
            evidence_ids=tuple(
                sorted({m.evidence_id for m in members if m.evidence_id})
            ),
            source=top.source,
            method=top.method,
            observed_at=top.observed_at,
        )
        if finding.confidence < _LOW_CONFIDENCE:
            low.append(finding)
        else:
            findings.append(finding)
    return findings, low


def generate_report(ledger: ClaimLedger, case_id: str) -> CaseReport:
    """Build the full report: findings + conflicts + stats."""
    findings, low = build_findings(ledger, case_id)
    conflicts = [c.as_dict() for c in ledger.conflicts(case_id)]
    all_claims = ledger.list(case_id)
    states: dict[str, int] = {}
    for claim in all_claims:
        states[claim.state] = states.get(claim.state, 0) + 1
    return CaseReport(
        case_id=case_id,
        generated_at=time.time(),
        findings=findings,
        conflicts=conflicts,
        low_confidence=low,
        stats={
            "claims_total": len(all_claims),
            "claims_by_state": states,
            "findings": len(findings),
            "low_confidence": len(low),
            "conflicts": len(conflicts),
        },
    )
