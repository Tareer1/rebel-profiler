"""Tests for the action-guide knowledge layer (100% executable coverage).

The registry must mirror the LIVE AdapterRegistry in both directions: a
guide for a nonexistent action is stale knowledge, a live action without a
guide is a planning hole for a small LLM. The prompts that reach a model
must embed the guides, because names alone teach nothing.
"""

from __future__ import annotations

import json

import pytest

from rebel_profiler.execution.broker import AdapterRegistry
from rebel_profiler.knowledge.action_guides import (
    action_guides_context,
    all_action_guides,
    coverage_report,
    find_action_guide,
)


class TestCoverage:
    def test_every_live_action_has_a_guide(self):
        report = coverage_report()
        assert report["missing_guides"] == [], (
            "live actions without a guide are planning holes: "
            f"{report['missing_guides']}")
        assert report["complete"] is True

    def test_no_stale_guides(self):
        report = coverage_report()
        assert report["stale_guides"] == [], (
            "guides for nonexistent actions are stale knowledge: "
            f"{report['stale_guides']}")

    def test_registry_names_agree_with_guides(self):
        live = set(AdapterRegistry().names())
        guided = {g.action for g in all_action_guides()}
        assert live == guided


class TestGuideContent:
    """Every guide must be complete enough to plan from without guessing."""

    def test_every_guide_has_when_target_example(self):
        for guide in all_action_guides():
            assert guide.when, f"{guide.action}: missing when"
            assert guide.target_shape, f"{guide.action}: missing target_shape"
            assert guide.target_example, f"{guide.action}: missing example"
            assert guide.reads_output, f"{guide.action}: missing reads_output"

    def test_examples_match_declared_contracts(self):
        """The embedded example must be proposable as-is: right params only."""
        registry = AdapterRegistry()
        for guide in all_action_guides():
            adapter = registry.get(guide.action)
            assert adapter is not None
            example = guide.example or {}
            assert example.get("action") == guide.action
            for param in (example.get("params") or {}):
                assert param in adapter.allowed_params, (
                    f"{guide.action}: example param '{param}' is not declared")
            required = set(adapter.required_params)
            supplied = set((example.get("params") or {}))
            assert required <= supplied, (
                f"{guide.action}: example omits required params "
                f"{required - supplied}")

    def test_capability_class_matches_adapter(self):
        registry = AdapterRegistry()
        for guide in all_action_guides():
            adapter = registry.get(guide.action)
            assert guide.capability_class == adapter.capability_class

    def test_next_steps_point_at_live_actions(self):
        registry = AdapterRegistry()
        for guide in all_action_guides():
            for nxt in guide.next_steps:
                if nxt.endswith(") (CLI)"):
                    continue  # CLI surface step, not an adapter action
                assert registry.get(nxt) is not None or "(" in nxt, (
                    f"{guide.action}: next step '{nxt}' is not executable")

    def test_find_guide_case_insensitive(self):
        assert find_action_guide("PORT-SCAN") is not None
        assert find_action_guide("no-such-action") is None


class TestContextBundle:
    def test_bundle_is_complete_and_flagged(self):
        bundle = action_guides_context()
        assert bundle["covered"] == bundle["total"]
        assert bundle["total"] == len(AdapterRegistry().names())
        assert all(a.get("covered") for a in bundle["actions"])

    def test_bundle_examples_are_json_clean(self):
        bundle = action_guides_context()
        for action in bundle["actions"]:
            json.dumps(action)   # must serialize for prompt embedding


class TestPromptEmbedding:
    def test_planner_prompt_embeds_guides(self):
        from rebel_profiler.agent import PlannerView
        from rebel_profiler.llm.planner import build_plan_prompt

        view = PlannerView("c1", "map example.com", AdapterRegistry())
        prompt = build_plan_prompt(view)
        assert "use_when" in prompt
        assert "target_shape" in prompt
        assert "follow_with" in prompt
        # a concrete guide's shape text must reach the model
        scan = find_action_guide("port-scan")
        assert scan.target_shape in prompt

    def test_hermes_tool_schema_embeds_guides(self):
        from rebel_profiler.llm.hermes import build_system_prompt, tool_schema

        tools = tool_schema(AdapterRegistry())
        prompt = build_system_prompt(tools)
        guide = find_action_guide("whois-lookup")
        assert guide.when[0].split(",")[0][:30] in prompt
        schema = [t for t in tools
                  if t["function"]["name"] == "whois-lookup"][0]
        target = schema["function"]["parameters"]["properties"]["target"]
        assert "domain" in target["description"]

    def test_planner_still_requires_known_actions(self):
        """Guides enrich the prompt; they never widen the parse gate."""
        from rebel_profiler.llm.planner import parse_proposals

        with pytest.raises(Exception):
            parse_proposals(
                '[{"action": "not-a-real-action", "target": "x.test"}]',
                registry=AdapterRegistry())
