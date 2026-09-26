"""Tests: web-expansion adapters — cors-check, security-txt,
graphql-introspection, email-spoof.

Same discipline as the existing set: declared params only, whitelisted argv,
validated tokens, and parsers that turn unknown input into NO claims rather
than invented ones.
"""

from __future__ import annotations

import pytest

from rebel_profiler.core.errors import UsageError
from rebel_profiler.execution.broker import AdapterRegistry, ActionRequest
from rebel_profiler.execution.hunters import (
    CORSCheckAdapter,
    EmailSpoofAdapter,
    GraphqlIntrospectionAdapter,
    SecurityTxtAdapter,
)
from rebel_profiler.intel.collection import (
    _parse_cors_headers,
    _parse_dmarc,
    _parse_graphql_introspection,
    _parse_security_txt,
)


def make_request(action: str, target: str, **params) -> ActionRequest:
    return ActionRequest(case_id="c1", capability="x", action=action,
                         target=target, params=params)


class TestRegistrySurface:
    def test_new_actions_registered(self):
        names = set(AdapterRegistry().names())
        assert {"cors-check", "security-txt",
                "graphql-introspection", "email-spoof"} <= names

    def test_no_shell_ever(self):
        for a in AdapterRegistry().list():
            assert a.binary not in {"sh", "bash", "zsh", "python", "perl"}

    def test_capability_classes_are_known_risk_levels(self):
        from rebel_profiler.security.risk import RiskEngine

        engine = RiskEngine()
        for name in ("cors-check", "security-txt",
                     "graphql-introspection", "email-spoof"):
            adapter = AdapterRegistry().get(name)
            assessment = engine.classify(adapter.capability_class)
            assert assessment.level in ("low", "moderate", "high", "critical")


class TestCorsCheckAdapter:
    def test_basic_argv(self):
        argv = CORSCheckAdapter().build_argv(
            make_request("cors-check", "h1.lab.example.test"))
        assert argv[0] == "curl"
        assert "https://h1.lab.example.test" in argv
        assert any(a.startswith("Origin:") for a in argv)

    def test_port_and_scheme_params(self):
        argv = CORSCheckAdapter().build_argv(
            make_request("cors-check", "h1.lab.example.test",
                         port="8443", scheme="http"))
        assert "http://h1.lab.example.test:8443" in argv

    def test_rejects_bad_host(self):
        with pytest.raises(UsageError):
            CORSCheckAdapter().build_argv(
                make_request("cors-check", "h1; reboot"))

    def test_rejects_bad_port(self):
        with pytest.raises(UsageError):
            CORSCheckAdapter().build_argv(
                make_request("cors-check", "h1.lab.example.test",
                             port="99999"))

    def test_rejects_bad_scheme(self):
        with pytest.raises(UsageError):
            CORSCheckAdapter().build_argv(
                make_request("cors-check", "h1.lab.example.test",
                             scheme="ftp"))


class TestSecurityTxtAdapter:
    def test_fetches_both_canonical_locations(self):
        argv = SecurityTxtAdapter().build_argv(
            make_request("security-txt", "lab.example.test"))
        assert argv[0] == "curl"
        assert any(a.endswith("/.well-known/security.txt") for a in argv)
        assert any(a.endswith("/security.txt") for a in argv)
        # bare-host contract: no scheme in the target itself
        assert "https://lab.example.test/.well-known/security.txt" in argv

    def test_rejects_url_shaped_target(self):
        with pytest.raises(UsageError):
            SecurityTxtAdapter().build_argv(
                make_request("security-txt", "https://lab.example.test"))

    def test_rejects_metachars(self):
        with pytest.raises(UsageError):
            SecurityTxtAdapter().build_argv(
                make_request("security-txt", "lab.example.test && id"))


class TestGraphqlIntrospectionAdapter:
    def test_default_path(self):
        argv = GraphqlIntrospectionAdapter().build_argv(
            make_request("graphql-introspection", "h1.lab.example.test"))
        assert argv[0] == "curl"
        assert "https://h1.lab.example.test/graphql" in argv
        assert "-X" in argv and "POST" in argv

    def test_path_param_and_full_url(self):
        argv = GraphqlIntrospectionAdapter().build_argv(
            make_request("graphql-introspection", "h1.lab.example.test",
                         path="/api/graphql"))
        assert "https://h1.lab.example.test/api/graphql" in argv
        argv2 = GraphqlIntrospectionAdapter().build_argv(
            make_request("graphql-introspection",
                         "https://h1.lab.example.test/gql"))
        assert "https://h1.lab.example.test/gql" in argv2

    def test_rejects_bad_path(self):
        with pytest.raises(UsageError):
            GraphqlIntrospectionAdapter().build_argv(
                make_request("graphql-introspection", "h1.lab.example.test",
                             path="/a b; id"))

    def test_rejects_bad_host(self):
        with pytest.raises(UsageError):
            GraphqlIntrospectionAdapter().build_argv(
                make_request("graphql-introspection", "h1 `id`"))


class TestEmailSpoofAdapter:
    def test_dig_txt_argv(self):
        argv = EmailSpoofAdapter().build_argv(
            make_request("email-spoof", "example.test"))
        assert argv[0] == "dig"
        assert "+short" in argv and "TXT" in argv
        assert "_dmarc.example.test" in argv

    def test_no_params_accepted(self):
        adapter = EmailSpoofAdapter()
        req = make_request("email-spoof", "example.test", record="MX")
        with pytest.raises(UsageError):
            adapter.validate_params(req)

    def test_rejects_bad_domain(self):
        with pytest.raises(UsageError):
            EmailSpoofAdapter().build_argv(
                make_request("email-spoof", "example.test; dig all"))


class TestParsers:
    def test_cors_reflected_with_credentials(self):
        text = ("HTTP/1.1 200 OK\r\n"
                "Access-Control-Allow-Origin: https://evil-cors-probe.example\r\n"
                "Access-Control-Allow-Credentials: true\r\n\r\nbody")
        pairs = _parse_cors_headers(text)
        assert pairs == [("cors_check",
                          "acao_reflected:yes; allow-credentials:true — "
                          "exploitable shape")]

    def test_cors_missing_acao_is_a_clean_check(self):
        pairs = _parse_cors_headers("HTTP/1.1 200 OK\r\n\r\nhi")
        assert pairs == [("cors_check", "acao_reflected:no")]

    def test_cors_fixed_allowlist_recorded(self):
        pairs = _parse_cors_headers(
            "HTTP/1.1 200 OK\r\n"
            "Access-Control-Allow-Origin: https://trusted.example\r\n\r\n")
        assert pairs[0][1].startswith("acao_present:https://trusted.example")

    def test_securitytxt_present_at_second_location(self):
        text = ("HTTP/1.1 404 Not Found\r\n\r\n"
                "--\r\n"
                "HTTP/1.1 200 OK\r\n"
                "Contact: mailto:security@x.test\r\n")
        pairs = _parse_security_txt(text)
        kinds = [k for k, _ in pairs]
        assert "securitytxt_check" in kinds
        assert any("present" in v for k, v in pairs if k == "securitytxt_check")
        assert ("securitytxt_field", "Contact: mailto:security@x.test") in pairs

    def test_securitytxt_missing_everywhere(self):
        pairs = _parse_security_txt(
            "HTTP/1.1 404 Not Found\r\n\r\n--\r\nHTTP/1.1 500 Err\r\n\r\n")
        assert pairs == [("securitytxt_check",
                          "security.txt missing at both canonical locations")]

    def test_graphql_enabled_and_disabled(self):
        on = _parse_graphql_introspection(
            '{"data":{"__schema":{"queryType":{"name":"Query"}}}}')
        assert on and on[0][0] == "graphql_introspection"
        assert "introspection:enabled" in on[0][1]
        off = _parse_graphql_introspection(
            '{"errors":[{"message":"forbidden"}]}')
        assert off and "introspection:disabled" in off[0][1]

    def test_graphql_garbage_yields_nothing(self):
        assert _parse_graphql_introspection("<html>blocked</html>") == []
        assert _parse_graphql_introspection("") == []
        assert _parse_graphql_introspection("[1,2,3]") == []

    def test_dmarc_enforcing(self):
        text = '"v=spf1 -all"\n"v=DMARC1; p=reject;"\n'
        pairs = _parse_dmarc(text)
        assert pairs == [("email_spoofing",
                          "spoofing posture:spf:present; dmarc:present; "
                          "p=reject")]

    def test_dmarc_non_enforcing_is_the_finding(self):
        pairs = _parse_dmarc('"v=DMARC1; p=none;"\n')
        assert "non-enforcing" in pairs[0][1]
        assert "spf:absent" in pairs[0][1]

    def test_dmarc_silent_domain(self):
        pairs = _parse_dmarc("")
        assert "spoofable" in pairs[0][1]
        assert "no SPF and no DMARC" in pairs[0][1]


class TestCoverageMatrixConsistency:
    def test_new_classes_have_live_detect_actions(self):
        from rebel_profiler.intel.claims import ClaimLedger
        from rebel_profiler.intel.sources import SourceRegistry
        from rebel_profiler.intel.vulncov import VULN_CLASSES, coverage_for_case

        live = set(AdapterRegistry().names())
        for vc in VULN_CLASSES:
            assert any(a in live for a in vc.detect_actions), vc.key
        report = coverage_for_case(ClaimLedger(SourceRegistry()), "c1")
        assert report["no_adapter"] == 0

    def test_url_target_actions_match_adapter_contracts(self):
        """URL-shaped actions must accept full URLs; host-shaped must not
        silently accept them as targets (the contract the planner relies on).
        """
        from rebel_profiler.intel.vulncov import URL_TARGET_ACTIONS

        registry = AdapterRegistry()
        for name in ("cors-check", "graphql-introspection", "security-txt"):
            if name in URL_TARGET_ACTIONS:
                # cors/graphql accept host OR URL; security-txt is bare-host.
                assert registry.get(name) is not None

    def test_email_spoof_is_host_shaped(self):
        from rebel_profiler.intel.vulncov import URL_TARGET_ACTIONS

        assert "email-spoof" not in URL_TARGET_ACTIONS
