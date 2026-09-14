"""Security and policy primitives: scope, risk, authorization decisions.

The policy layer is deliberately independent of the LLM. Reasoning may
recommend; only this layer decides.
"""

from .policy import PolicyDecision, PolicyEngine, PolicyOutcome
from .risk import RISK_LEVELS, RiskEngine, classify_risk
from .scope import Scope, ScopeEngine, ScopeEntry, ScopeStatus

__all__ = [
    "PolicyDecision",
    "PolicyEngine",
    "PolicyOutcome",
    "RISK_LEVELS",
    "RiskEngine",
    "Scope",
    "ScopeEngine",
    "ScopeEntry",
    "ScopeStatus",
    "classify_risk",
]
