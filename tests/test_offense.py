"""Tests for the offense plane: attack plans + payload workbench + deploy gating.

Offline discipline: plans rank from a hand-built ledger, payloads are built
and checked for their benign-marker contract, and the deploy path is verified
up to (not including) broker dispatch — the approval decision belongs to the
operator, and the gates re-validate at dispatch time.
"""

from __future__ import annotations

import pytest

from rebel_profiler.execution.broker import AdapterRegistry
from rebel_profiler.intel.claims import ClaimLedger, SourceRegistry
from rebel_profiler.intel.offense import (
    attack_plan,
    build_payload,
    deploy_payload,
    payload_classes,
)


# ---------------------------------------------------------------- helpers

def _ledger_with(rows: list[tuple[str, str, str]]) -> ClaimLedger:
    """rows of (subject, kind, value) on one case."""
    ledger = ClaimLedger(SourceRegistry())
    for subject, kind, value in rows:
        ledger.add("c1", subject=subject, kind=kind, value=value,
                   source="test", method="test")
    return ledger


# ---------------------------------------------------------------- plans

class TestAttackPlan:
    def test_empty_ledger_yields_no_strategies(self):
        plan = attack_plan("c1", ClaimLedger(SourceRegistry()))
        assert plan["strategies"] == []
        assert plan["claims_read"] == 0

    def test_live_host_yields_config_strategy(self):
        ledger = _ledger_with([("h1.test", "httpx_status", "h1.test:200")])
        plan = attack_plan("c1", ledger)
        cats = {s["category"] for s in plan["strategies"]}
        assert "config" in cats
        for s in plan["strategies"]:
            assert s["where"], "every strategy names its target"

    def test_params_plus_urls_yield_injection_strategy(self, tmp_path):
        ledger = _ledger_with([
            ("h1.test", "wayback_url", "https://h1.test/search"),
            ("h1.test", "param", "q"),
        ])
        plan = attack_plan("c1", ledger)
        inj = [s for s in plan["strategies"] if s["category"] == "injection"]
        assert inj and inj[0]["payload_class"] == "sqli_error"

    def test_every_strategy_names_a_live_action(self):
        ledger = _ledger_with([
            ("h1.test", "httpx_status", "h1.test:200"),
            ("h1.test", "wayback_url", "https://h1.test/a"),
            ("h1.test", "param", "q"),
            ("h1.test", "tech", "nginx"),
            ("h1.test", "port", "443"),
            ("other.test", "hostname", "other.test"),
        ])
        registry = AdapterRegistry()
        plan = attack_plan("c1", ledger)
        assert plan["strategies"], "evidence above must produce strategies"
        for s in plan["strategies"]:
            assert registry.get(s["action"]) is not None, (
                f"strategy '{s['title']}' names non-executable action")

    def test_unprobed_hostnames_yield_recon_gap(self):
        ledger = _ledger_with([("x.test", "hostname", "a.x.test")])
        plan = attack_plan("c1", ledger)
        gaps = [s for s in plan["strategies"] if s["category"] == "recon-gap"]
        assert gaps and gaps[0]["action"] == "httpx-probe"


# ---------------------------------------------------------------- payloads

class TestPayloadBuild:
    def test_unknown_class_raises(self):
        with pytest.raises(ValueError):
            build_payload("rm_rf", "https://h1.test/")

    @pytest.mark.parametrize("pc", payload_classes())
    def test_every_class_builds_with_marker_and_detect(self, pc):
        built = build_payload(pc, "https://h1.test/x")
        assert built["payload_class"] == pc
        assert built["marker"].startswith("rp")
        assert built["detect"], f"{pc} must say what proves the condition"
        assert built["safe"] is True
        assert built["delivery"].startswith("probe")

    def test_reflection_marker_is_injected_into_url(self):
        built = build_payload("reflected_xss", "https://h1.test/s", "q")
        assert built["marker"] in built["request_url"]

    def test_redirect_payload_is_self_referencing(self):
        built = build_payload("open_redirect", "https://h1.test/r", "url")
        assert "//h1.test" in built["payload"]

    def test_markers_are_unique(self):
        a = build_payload("ssti", "https://h1.test/x")["marker"]
        b = build_payload("ssti", "https://h1.test/x")["marker"]
        assert a != b

    def test_no_exploit_weight_in_payloads(self):
        """Markers prove conditions; they never carry functional weight."""
        for pc in payload_classes():
            built = build_payload(pc, "https://h1.test/x")
            text = built["payload"].lower()
            assert "exec" not in text or pc == "cmdi_echo"
            assert "curl" not in text and "wget" not in text
            assert "nc " not in text and "/bin/sh" not in text


# ---------------------------------------------------------------- deploy

class TestDeployGating:
    def test_draft_does_not_dispatch(self):
        built = build_payload("ssti", "https://h1.test/x")
        draft = deploy_payload("c1", built, approved=False)
        assert draft["approved"] is False
        assert draft["will_dispatch"] is False
        assert "[DRAFT" in draft["request"]["reason"]

    def test_approval_wraps_probe_request(self):
        built = build_payload("ssti", "https://h1.test/x")
        deployment = deploy_payload("c1", built, approved=True)
        assert deployment["will_dispatch"] is True
        req = deployment["request"]
        assert req["action"] == "probe"
        assert "X-RP-Marker" in req["params"]["header"]

    def test_deploy_rejects_foreign_payloads(self):
        with pytest.raises(ValueError):
            deploy_payload("c1", {"payload_class": "not-mine"}, approved=True)

    def test_deploy_declines_outside_scope_text(self):
        built = build_payload("ssti", "https://h1.test/x")
        deployment = deploy_payload("c1", built, approved=False)
        assert "not approved" in deployment["request"]["reason"]
