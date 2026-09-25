"""Deep knowledge layer tests: techniques, playbooks, glossary, deep context."""

from __future__ import annotations

import pytest

from rebel_profiler.knowledge import (
    GLOSSARY,
    PLAYBOOKS,
    TECHNIQUES,
    all_techniques,
    deep_planner_context,
    find_playbook,
    find_technique,
    glossary_context,
    lookup,
    playbooks_context,
    playbooks_for_domain,
    search_terms,
    techniques_context,
    techniques_for_domain,
)
from rebel_profiler.cli.main import main


class TestTechniques:
    def test_all_fifteen_domains_covered(self):
        domain_keys = {dt.domain_key for dt in TECHNIQUES}
        assert len(domain_keys) == 16

    def test_every_technique_has_fields(self):
        for _domain, t in all_techniques():
            assert t.key and t.name
            assert t.capability_class in {
                "info", "passive_recon", "osint", "discovery", "network_mapping",
                "web_assessment", "config_assessment", "active_recon",
                "binary_analysis", "vuln_validation", "intrusive_testing",
                "exploit_validation", "destructive",
            }
            assert len(t.countermeasure) > 10

    def test_tools_are_kali_realistic(self):
        for _domain, t in all_techniques():
            for tool in t.kali_tools:
                assert tool == tool.strip()
                assert len(tool) > 1

    def test_lookup_by_key(self):
        found = find_technique("syn_scan")
        assert found is not None
        domain, technique = found
        assert domain == "scanning"
        assert "nmap" in technique.kali_tools

    def test_lookup_unknown_returns_none(self):
        assert find_technique("no_such_technique") is None

    def test_techniques_for_domain(self):
        tools = {t.key for t in techniques_for_domain("enumeration")}
        assert "smb_share_enum" in tools
        assert "dns_axfr_test" in tools

    def test_techniques_for_unknown_domain_empty(self):
        assert techniques_for_domain("nope") == ()

    def test_techniques_context_rule_mentions_gates(self):
        rule = techniques_context()["rule"]
        assert "gates" in rule.lower() or "authorization" in rule.lower()

    def test_techniques_context_subset(self):
        ctx = techniques_context(["scanning"])
        assert len(ctx["domains"]) == 1

    def test_no_destructive_techniques_offered(self):
        """Intrusive/critical techniques must carry explicit constraints."""
        for _domain, t in all_techniques():
            if t.capability_class in {"exploit_validation", "intrusive_testing"}:
                notes = t.notes.lower()
                assert any(w in notes for w in ("lab", "approval", "designated", "consent")), t.key


class TestPlaybooks:
    def test_playbooks_exist(self):
        assert len(PLAYBOOKS) >= 6

    def test_steps_are_ordered_from_one(self):
        for pb in PLAYBOOKS:
            orders = [s.order for s in pb.steps]
            assert orders == list(range(1, len(orders) + 1))

    def test_first_step_is_authorization(self):
        for pb in PLAYBOOKS:
            first = pb.steps[0]
            assert first.capability_class == "info"
            assert "confirm" in first.title.lower() or "approval" in first.title.lower() \
                or "authorization" in first.title.lower() or "sign-off" in first.description.lower()

    def test_find_playbook(self):
        pb = find_playbook("authorized_recon")
        assert pb is not None
        assert pb.steps[0].order == 1

    def test_find_playbook_normalizes(self):
        assert find_playbook("authorized-recon") is not None

    def test_playbooks_for_domain(self):
        pbs = playbooks_for_domain("wireless")
        assert any(p.key == "lab_wireless" for p in pbs)

    def test_playbooks_context_structure(self):
        ctx = playbooks_context()
        assert ctx["playbooks"]
        assert "gates" in ctx["rule"].lower()

    def test_no_step_skips_gates(self):
        """Every step must reference a capability class the broker gates."""
        valid = {
            "info", "passive_recon", "osint", "discovery", "network_mapping",
            "web_assessment", "config_assessment", "active_recon",
            "binary_analysis", "vuln_validation", "intrusive_testing",
            "exploit_validation",
        }
        for pb in PLAYBOOKS:
            for s in pb.steps:
                assert s.capability_class in valid, (pb.key, s.order)


class TestGlossary:
    def test_size(self):
        assert len(GLOSSARY) >= 45

    def test_lookup_exact(self):
        assert "fail closed" in lookup("fail closed").lower() or "denial" in lookup("fail closed").lower()

    def test_lookup_normalizes_underscores(self):
        assert lookup("fail_closed") == lookup("fail closed")

    def test_lookup_normalizes_hyphens(self):
        assert lookup("kill-chain") == lookup("kill chain")

    def test_lookup_case_insensitive(self):
        assert lookup("KILL CHAIN") is not None

    def test_lookup_unknown(self):
        assert lookup("zzz_not_a_term") is None

    def test_search_terms(self):
        results = search_terms("wifi")
        assert any(n == "wep" for n, _d in results)

    def test_search_empty(self):
        assert search_terms("") == []

    def test_definitions_never_authorize(self):
        for _n, d in GLOSSARY:
            assert "you may" not in d.lower()
            assert "is allowed to run" not in d.lower()

    def test_glossary_context(self):
        ctx = glossary_context()
        assert ctx["terms"] and "never" in ctx["rule"]


class TestDeepPlannerContext:
    def test_schema_v3_complete(self):
        ctx = deep_planner_context()
        assert ctx["schema_version"] == 3
        assert len(ctx["domains"]) == 16
        assert len(ctx["tool_matrix"]) == 10
        assert len(ctx["techniques"]) == 16
        assert ctx["playbooks"]
        assert len(ctx["glossary"]) >= 45
        # action guides: every live action must be covered in the bundle
        from rebel_profiler.execution.broker import AdapterRegistry

        guides = {g["action"] for g in ctx["action_guides"]}
        assert guides == set(AdapterRegistry().names())
        assert all(g.get("covered") for g in ctx["action_guides"])


class TestExpandedCoverage:
    """Coverage parity with the CEH v13 curriculum blueprint (original content)."""

    def test_new_topics_present(self):
        from rebel_profiler.knowledge import find_domain
        expected = {
            "networking": {"cloud_services"},
            "security_foundations": {"parkerian_hexad", "security_operations"},
            "footprinting": {"social_osint"},
            "scanning": {"packet_crafting", "scan_evasion"},
            "enumeration": {"rpc_web_enum"},
            "system_hacking": {"exploit_research", "fuzzing", "lotl"},
            "social_engineering": {"physical_se"},
            "wireless": {"mobile_security"},
            "attack_defense": {"dos_analysis", "memory_safety"},
            "cloud_iot": {"ot_security"},
        }
        for domain_key, topic_keys in expected.items():
            d = find_domain(domain_key)
            assert d is not None, domain_key
            have = {t.key for t in d.topics}
            missing = topic_keys - have
            assert not missing, (domain_key, missing)

    def test_new_techniques_present(self):
        for key in (
            "rpc_endpoint_enum", "web_surface_enum", "kerberoast_audit",
            "rainbow_table_concept", "pivot_path_review", "client_side_surface",
            "fileless_indicator_review", "dropper_chain_analysis",
            "rogue_dhcp_detection", "web_clone_detection", "vishing_sim",
            "bt_attack_surface", "dos_exposure_review", "lateral_movement_mapping",
            "web_header_audit", "data_classification_review", "security_model_check",
            "zero_trust_review", "ot_zone_review", "cloud_threat_review",
        ):
            assert find_technique(key) is not None, key

    def test_new_playbooks_present(self):
        for key in ("full_assessment", "vuln_triage", "sniffing_audit",
                    "physical_se_review", "dos_resilience"):
            pb = find_playbook(key)
            assert pb is not None, key
            assert pb.steps[0].capability_class == "info"

    def test_new_glossary_terms(self):
        for term in ("purdue model", "zero trust", "kerberoasting",
                     "living off the land", "buffer overflow", "fileless malware"):
            assert lookup(term) is not None, term

    def test_tool_matrix_new_tools(self):
        from rebel_profiler.knowledge import tools_for_domain
        names = {t.name for t in tools_for_domain("scanning")}
        assert "packet-craft" in names
        web = {t.name for t in tools_for_domain("enumeration")}
        assert {"web-dir-enum", "tech-fingerprint"} <= web

    def test_subset_domains(self):
        ctx = deep_planner_context(["scanning", "enumeration"])
        assert len(ctx["domains"]) == 2
        assert len(ctx["techniques"]) == 2

    def test_rules_mention_authorization(self):
        rules = " ".join(deep_planner_context()["rules"]).lower()
        assert "authoriz" in rules
        assert "evidence" in rules

    def test_glossary_is_dict(self):
        ctx = deep_planner_context()
        assert ctx["glossary"]["scope"]
        assert isinstance(ctx["glossary"]["scope"], str)


class TestKnowledgeCLI:
    def test_techniques_listing(self, capsys):
        assert main(["knowledge", "techniques", "enumeration"]) == 0
        assert "smb_share_enum" in capsys.readouterr().out

    def test_technique_detail(self, capsys):
        assert main(["knowledge", "techniques", "scanning", "--technique", "syn_scan"]) == 0
        assert "nmap" in capsys.readouterr().out

    def test_techniques_unknown_domain(self, capsys):
        rc = main(["knowledge", "techniques", "nope", "-o", "json"])
        assert rc != 0

    def test_playbook_listing(self, capsys):
        assert main(["knowledge", "playbook"]) == 0
        assert "authorized_recon" in capsys.readouterr().out

    def test_playbook_detail(self, capsys):
        assert main(["knowledge", "playbook", "web_posture"]) == 0
        assert "TLS" in capsys.readouterr().out

    def test_glossary_lookup(self, capsys):
        assert main(["knowledge", "glossary", "scope"]) == 0
        assert "fail-closed" in capsys.readouterr().out.lower() or "explicit" in capsys.readouterr().out.lower()

    def test_glossary_all(self, capsys):
        assert main(["knowledge", "glossary"]) == 0
        assert "kill chain" in capsys.readouterr().out

    def test_deep_context_json(self, capsys):
        assert main(["knowledge", "deep-context", "-o", "json"]) == 0
        import json

        payload = json.loads(capsys.readouterr().out)
        assert payload["schema_version"] == 3
        assert len(payload["domains"]) == 16
        assert payload["action_guides"]

    @pytest.fixture(autouse=True)
    def _isolate(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
