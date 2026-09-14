"""Policy engine: the mandatory authorization gate.

Policy decisions are deterministic and machine readable. The LLM can propose
actions; it can never decide them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .risk import RiskAssessment


class PolicyOutcome(str, Enum):
    ALLOW = "allow"
    ALLOW_WITH_CONFIRMATION = "allow_with_confirmation"
    ALLOW_WITH_APPROVAL = "allow_with_approval"
    DENY = "deny"


_RISK_TO_OUTCOME = {
    "low": PolicyOutcome.ALLOW,
    "moderate": PolicyOutcome.ALLOW_WITH_CONFIRMATION,
    "high": PolicyOutcome.ALLOW_WITH_APPROVAL,
    "critical": PolicyOutcome.DENY,
}


@dataclass
class PolicyDecision:
    outcome: PolicyOutcome
    risk: RiskAssessment
    policy_version: str
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return self.outcome is not PolicyOutcome.DENY

    def as_dict(self) -> dict:
        return {
            "outcome": self.outcome.value,
            "risk": self.risk.as_dict(),
            "policy_version": self.policy_version,
            "reasons": list(self.reasons),
        }


class PolicyEngine:
    """Evaluates capability + scope status + risk into a policy decision."""

    version = "1"

    def __init__(self, mapping: dict[str, PolicyOutcome] | None = None) -> None:
        # A deployment may override the default risk -> outcome mapping; a
        # mapping can only make outcomes MORE restrictive, never weaker.
        self._mapping = dict(_RISK_TO_OUTCOME)
        if mapping:
            for level, outcome in mapping.items():
                default_index = list(PolicyOutcome).index(self._mapping[level])
                new_index = list(PolicyOutcome).index(outcome)
                if new_index > default_index:
                    self._mapping[level] = outcome

    def evaluate(
        self,
        *,
        scope_status: str,
        risk: RiskAssessment,
        operator_role: str = "operator",
        approval_required_capability: bool = False,
    ) -> PolicyDecision:
        reasons: list[str] = []
        if scope_status != "in_scope":
            return PolicyDecision(
                outcome=PolicyOutcome.DENY,
                risk=risk,
                policy_version=self.version,
                reasons=(f"scope_status={scope_status}",),
            )
        outcome = self._mapping[risk.level]
        if outcome is PolicyOutcome.ALLOW and approval_required_capability:
            outcome = PolicyOutcome.ALLOW_WITH_APPROVAL
            reasons.append("capability_requires_approval")
        if outcome is PolicyOutcome.ALLOW_WITH_APPROVAL and operator_role == "viewer":
            return PolicyDecision(
                outcome=PolicyOutcome.DENY,
                risk=risk,
                policy_version=self.version,
                reasons=("role=viewer cannot execute risk-gated capabilities",) + tuple(reasons),
            )
        reasons.append(f"risk={risk.level}")
        return PolicyDecision(
            outcome=outcome,
            risk=risk,
            policy_version=self.version,
            reasons=tuple(reasons),
        )
