"""Knowledge layer tests: domain coverage, tool matrix, planner context."""

from __future__ import annotations

from rebel_profiler.knowledge import (
    capability_classes,
    find_domain,
    list_domains,
    planner_context,
    planner_tool_context,
    search,
    tools_for_domain,
)


def test_sixteen_domains_present():
    """Domains 1-15 mirror the curriculum; 16 is the RE plane (added v1.6)."""
    domains = list_domains()
    assert len(domains) == 16
    numbers = [d["number"] for d in domains]
    assert numbers == list(range(1, 17))


def test_domain_lookup_by_key_and_number():
    assert find_domain("cryptography").number == 13
    assert find_domain("13").title == "Cryptography"
    assert find_domain("CLOUD-IOT") is not None
    assert find_domain("does-not-exist") is None


def test_every_topic_has_capability_and_summary():
    for d in planner_context()["domains"]:
        for t in d["topics"]:
            assert t["capability_class"]
            assert len(t["summary"]) > 40
            assert t["keywords"]


def test_search_matches_keywords():
    results = search("zone transfer")
    assert any(t.key == "nfs_smtp_dns_enum" for _d, t in results)


def test_search_empty_is_empty():
    assert search("") == []


def test_tool_matrix_groups():
    classes = capability_classes()
    assert "passive_recon" in classes
    assert "discovery" in classes
    assert "exploit_validation" in classes
    ctx = planner_tool_context()
    assert ctx["groups"] and "authorization" in ctx["rule"].lower() or "authorization" in ctx["rule"]


def test_tools_mapped_to_domain():
    tools = tools_for_domain("scanning")
    names = {t.name for t in tools}
    assert "host-discovery" in names
    assert "port-scan" in names


def test_tools_for_unknown_domain_empty():
    assert tools_for_domain("no-such-domain") == ()


def test_planner_context_rule_mentions_authorization():
    rule = planner_context()["rule"]
    assert "authorization" in rule.lower()


def test_planner_context_subset():
    subset = planner_context(["scanning", "enumeration"])
    assert len(subset["domains"]) == 2
