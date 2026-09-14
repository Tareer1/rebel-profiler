"""Risk classification.

Risk must be independent of LLM opinion: it is derived from the capability
definition plus target/environment context using versioned rules.
"""

from __future__ import annotations

from dataclasses import dataclass

RISK_LEVELS = ("low", "moderate", "high", "critical")

# Capability classes ordered from least to most invasive.
_CAPABILITY_RISK = {
    "info": "low",
    "passive_recon": "low",
    "osint": "low",
    "discovery": "moderate",
    "network_mapping": "moderate",
    "web_assessment": "moderate",
    "config_assessment": "moderate",
    "active_recon": "high",
    "vuln_validation": "high",
    "intrusive_testing": "high",
    "exploit_validation": "critical",
    "destructive": "critical",
}


@dataclass(frozen=True)
class RiskAssessment:
    level: str
    capability_class: str
    factors: tuple[str, ...]

    def as_dict(self) -> dict:
        return {"level": self.level, "capability_class": self.capability_class, "factors": list(self.factors)}


class RiskEngine:
    """Deterministic, versioned risk classification."""

    version = "1"

    def classify(self, capability_class: str, *, target_type: str = "", environment: str = "") -> RiskAssessment:
        factors: list[str] = []
        level = _CAPABILITY_RISK.get(capability_class.lower())
        if level is None:
            # Unknown capability class fails conservative (deny-by-default).
            return RiskAssessment(
                level="critical",
                capability_class=capability_class,
                factors=("unknown_capability_class",),
            )
        factors.append(f"capability_class={capability_class}")
        if target_type.lower() in {"production", "customer", " regulated", "regulated"}:
            if level in {"moderate", "high"}:
                level = "critical"
                factors.append("production_target_escalation")
        if environment.lower() == "air_gapped":
            factors.append("air_gapped_environment")
        return RiskAssessment(level=level, capability_class=capability_class, factors=tuple(factors))


def classify_risk(capability_class: str, **kwargs) -> RiskAssessment:
    """Convenience wrapper around :class:`RiskEngine`."""
    return RiskEngine().classify(capability_class, **kwargs)
