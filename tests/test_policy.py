"""Risk + policy engine tests: deterministic, LLM-independent decisions."""

from __future__ import annotations

import pytest

from rebel_profiler.security.policy import PolicyEngine, PolicyOutcome
from rebel_profiler.security.risk import RiskEngine, classify_risk


class TestRisk:
    def test_known_classes(self):
        engine = RiskEngine()
        assert engine.classify("info").level == "low"
        assert engine.classify("passive_recon").level == "low"
        assert engine.classify("discovery").level == "moderate"
        assert engine.classify("active_recon").level == "high"
        assert engine.classify("exploit_validation").level == "critical"

    def test_unknown_class_fails_conservative(self):
        assessment = RiskEngine().classify("definitely_not_real")
        assert assessment.level == "critical"
        assert "unknown_capability_class" in assessment.factors

    def test_production_escalation(self):
        engine = RiskEngine()
        normal = engine.classify("discovery", target_type="lab")
        escalated = engine.classify("discovery", target_type="production")
        assert normal.level == "moderate"
        assert escalated.level == "critical"
        assert "production_target_escalation" in escalated.factors

    def test_wrapper(self):
        assert classify_risk("info").level == "low"


class TestPolicy:
    def test_low_risk_allows(self):
        risk = RiskEngine().classify("info")
        decision = PolicyEngine().evaluate(scope_status="in_scope", risk=risk)
        assert decision.outcome is PolicyOutcome.ALLOW
        assert decision.allowed

    def test_moderate_requires_confirmation(self):
        risk = RiskEngine().classify("discovery")
        decision = PolicyEngine().evaluate(scope_status="in_scope", risk=risk)
        assert decision.outcome is PolicyOutcome.ALLOW_WITH_CONFIRMATION

    def test_high_requires_approval(self):
        risk = RiskEngine().classify("active_recon")
        decision = PolicyEngine().evaluate(scope_status="in_scope", risk=risk)
        assert decision.outcome is PolicyOutcome.ALLOW_WITH_APPROVAL

    def test_critical_denies(self):
        risk = RiskEngine().classify("exploit_validation")
        decision = PolicyEngine().evaluate(scope_status="in_scope", risk=risk)
        assert decision.outcome is PolicyOutcome.DENY
        assert not decision.allowed

    def test_out_of_scope_denies_everything(self):
        risk = RiskEngine().classify("info")
        decision = PolicyEngine().evaluate(scope_status="out_of_scope", risk=risk)
        assert decision.outcome is PolicyOutcome.DENY

    def test_viewer_role_cannot_run_gated_capabilities(self):
        risk = RiskEngine().classify("active_recon")
        decision = PolicyEngine().evaluate(scope_status="in_scope", risk=risk, operator_role="viewer")
        assert decision.outcome is PolicyOutcome.DENY

    def test_overrides_can_only_tighten(self):
        engine = PolicyEngine(mapping={"low": PolicyOutcome.ALLOW_WITH_APPROVAL})
        risk = RiskEngine().classify("info")
        decision = engine.evaluate(scope_status="in_scope", risk=risk)
        assert decision.outcome is PolicyOutcome.ALLOW_WITH_APPROVAL

    def test_decisions_are_deterministic(self):
        risk = RiskEngine().classify("discovery")
        engine = PolicyEngine()
        results = {engine.evaluate(scope_status="in_scope", risk=risk).outcome for _ in range(5)}
        assert results == {PolicyOutcome.ALLOW_WITH_CONFIRMATION}
