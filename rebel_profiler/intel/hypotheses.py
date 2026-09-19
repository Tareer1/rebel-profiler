"""Hypotheses, findings and the analyst workflow (Phase 4, PDF 4/11).

An investigation is hypothesis-driven: the operator (or the LLM, proposing)
states a *testable* claim about the case — "host X runs a vulnerable
version", "subdomain Y is administered by the same registrar" — with
explicit, deterministic acceptance criteria. The engine then checks the
claim against the evidence ledger:

  * ``exists``    — a live claim of kind K on subject S with value V
  * ``min_confidence`` — the best matching claim's confidence ≥ threshold
  * ``corroborated``   — the claim is corroborated by ≥ N independent sources
  * ``absent``    — no live claim matches (supports refutation work)

Evaluation is a pure deterministic function over the ledger — the LLM may
state hypotheses and propose criteria; it can never decide the outcome.
Every evaluation stores its result snapshot (matched claims, evidence ids)
so reports can show exactly why a hypothesis was supported or refuted.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

from ..core.errors import EXIT_USAGE, RPError
from .claims import ClaimLedger


class HypothesisError(RPError):
    """Raised for malformed hypothesis criteria (renders as a usage error)."""

    exit_code = EXIT_USAGE
    title = "Hypothesis error"


@dataclass(frozen=True)
class Criterion:
    """One deterministic acceptance criterion."""

    kind: str                    # exists | min_confidence | corroborated | absent
    subject: str = ""
    claim_kind: str = ""
    value: str = ""
    threshold: float = 0.0
    count: int = 1

    def as_dict(self) -> dict:
        return {
            "kind": self.kind, "subject": self.subject,
            "claim_kind": self.claim_kind, "value": self.value,
            "threshold": self.threshold, "count": self.count,
        }


@dataclass
class Hypothesis:
    """A testable statement with explicit acceptance criteria."""

    id: str
    case_id: str
    statement: str
    criteria: list[Criterion]
    status: str = "open"          # open | supported | refuted | untestable
    rationale: str = ""
    result: dict = field(default_factory=dict)
    created_at: float = 0.0
    updated_at: float = 0.0

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "statement": self.statement,
            "status": self.status,
            "rationale": self.rationale,
            "criteria": [c.as_dict() for c in self.criteria],
            "result": self.result,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def parse_criteria(items: list[dict]) -> list[Criterion]:
    """Validate and normalize raw criterion dicts (fail closed on junk)."""
    allowed = {"exists", "min_confidence", "corroborated", "absent"}
    criteria: list[Criterion] = []
    for item in items:
        if not isinstance(item, dict) or item.get("kind") not in allowed:
            raise HypothesisError(
                f"Unknown criterion kind '{(item or {}).get('kind') if isinstance(item, dict) else type(item).__name__}'"
            )
        kind = item["kind"]
        if kind in {"exists", "min_confidence", "corroborated", "absent"} \
                and not item.get("subject") and kind != "absent":
            raise HypothesisError(f"Criterion '{kind}' requires 'subject'")
        criteria.append(Criterion(
            kind=kind,
            subject=str(item.get("subject", "")).strip().lower(),
            claim_kind=str(item.get("claim_kind", "")).strip().lower(),
            value=str(item.get("value", "")).strip().lower(),
            threshold=float(item.get("threshold", 0.0)),
            count=max(1, int(item.get("count", 1))),
        ))
    return criteria


class HypothesisEngine:
    """Persists hypotheses in the case DB and evaluates them deterministically."""

    def __init__(self, db, ledger: ClaimLedger) -> None:
        self._db = db
        self.ledger = ledger

    def add(
        self,
        case_id: str,
        statement: str,
        criteria: list[dict],
        *,
        rationale: str = "",
    ) -> Hypothesis:
        if not statement.strip():
            raise HypothesisError("Hypothesis statement must not be empty")
        parsed = parse_criteria(criteria)
        if not parsed:
            raise HypothesisError("A hypothesis needs at least one criterion")
        hyp_id = f"hyp_{uuid.uuid4().hex[:12]}"
        now = time.time()
        self._db.add_hypothesis(
            hyp_id, case_id, statement=statement.strip(), rationale=rationale,
            criteria=[c.as_dict() for c in parsed], created_at=now,
        )
        return Hypothesis(
            id=hyp_id, case_id=case_id, statement=statement.strip(),
            criteria=parsed, rationale=rationale, created_at=now, updated_at=now,
        )

    def get(self, hyp_id: str) -> Hypothesis:
        row = self._db.get_hypothesis(hyp_id)
        if row is None:
            raise HypothesisError(f"Hypothesis '{hyp_id}' not found")
        return self._row_to_hypothesis(row)

    def list(self, case_id: str) -> list[Hypothesis]:
        return [self._row_to_hypothesis(r) for r in self._db.hypotheses_for(case_id)]

    def evaluate(self, hyp_id: str) -> Hypothesis:
        """Run all criteria; persist status + result snapshot."""
        hyp = self.get(hyp_id)
        claims = self.ledger.list(hyp.case_id)
        live = [c for c in claims if c.state in {"open", "corroborated"}]

        checks: list[dict] = []
        untestable = False
        for crit in hyp.criteria:
            check = self._check(crit, live)
            checks.append(check)
            if check["verdict"] == "untestable":
                untestable = True

        if untestable:
            status = "untestable"
        elif all(c["verdict"] == "pass" for c in checks):
            status = "supported"
        else:
            status = "refuted"

        result = {
            "evaluated_at": time.time(),
            "status": status,
            "checks": checks,
            "live_claims_considered": len(live),
        }
        self._db.set_hypothesis_status(hyp_id, status)
        self._db.set_hypothesis_result(hyp_id, result)
        hyp.status = status
        hyp.result = result
        hyp.updated_at = time.time()
        return hyp

    # -- criterion evaluation ------------------------------------------------

    def _check(self, crit: Criterion, live) -> dict:
        matched = [
            c for c in live
            if (not crit.subject or c.subject == crit.subject)
            and (not crit.claim_kind or c.kind == crit.claim_kind)
            and (not crit.value or c.value.strip().lower() == crit.value)
        ]
        best_conf = max((c.confidence for c in matched), default=0.0)
        sources = {c.source for c in matched}

        check: dict = {"criterion": crit.as_dict(), "matched": len(matched),
                       "best_confidence": round(best_conf, 4),
                       "sources": sorted(sources),
                       "claim_ids": [c.id for c in matched][:10],
                       "evidence_ids": sorted({c.evidence_id for c in matched if c.evidence_id})[:10]}

        if crit.kind == "exists":
            check["verdict"] = "pass" if matched else "fail"
        elif crit.kind == "min_confidence":
            check["verdict"] = "pass" if best_conf >= crit.threshold else "fail"
            check["threshold"] = crit.threshold
        elif crit.kind == "corroborated":
            corroborated = sum(
                1 for c in matched
                if c.state == "corroborated" or len({c2.source for c2 in matched
                                                     if c2.value == c.value}) > 1
            )
            check["verdict"] = "pass" if corroborated >= crit.count else "fail"
            check["corroborated"] = corroborated
        elif crit.kind == "absent":
            check["verdict"] = "pass" if not matched else "fail"
        return check

    @staticmethod
    def _row_to_hypothesis(row) -> Hypothesis:
        import json

        return Hypothesis(
            id=row["id"],
            case_id=row["case_id"],
            statement=row["statement"],
            criteria=[
                Criterion(**item) for item in json.loads(row["criteria_json"])
            ],
            status=row["status"],
            rationale=row["rationale"],
            result=json.loads(row["result_json"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


def render_human(hypotheses: list[Hypothesis]) -> str:
    lines = [f"{len(hypotheses)} hypothesis(um)"]
    for h in hypotheses:
        lines.append(f"  [{h.status:>11}] {h.id}  {h.statement}")
        for check in h.result.get("checks", []):
            crit = check["criterion"]
            lines.append(
                f"      - {crit['kind']}: {check['verdict']}"
                f" (matched={check['matched']}, conf={check['best_confidence']})"
            )
    return "\n".join(lines)
