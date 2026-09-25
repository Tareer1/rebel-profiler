"""Tests: Kali tool expansion — nikto, wpscan, searchsploit, tcpdump, lynis.

Every new adapter obeys the same discipline as the existing set: declared
params only, whitelisted argv, validated tokens, and parsers that turn
unknown input into NO claims rather than invented ones.
"""

from __future__ import annotations

import pytest

from rebel_profiler.core.errors import UsageError
from rebel_profiler.execution.broker import AdapterRegistry, ActionRequest
from rebel_profiler.execution.hunters import (
    LynisAuditAdapter,
    NiktoAdapter,
    SearchsploitAdapter,
    TcpdumpCaptureAdapter,
    WpscanAdapter,
)
from rebel_profiler.intel.collection import (
    _parse_lynis,
    _parse_nikto_csv,
    _parse_searchsploit_json,
    _parse_tcpdump_summary,
    _parse_wpscan_text,
)


def make_request(action: str, target: str, **params) -> ActionRequest:
    return ActionRequest(case_id="c1", capability="x", action=action,
                         target=target, params=params)


class TestRegistrySurface:
    def test_new_actions_registered(self):
        names = set(AdapterRegistry().names())
        assert {"nikto-scan", "wpscan-audit", "exploit-lookup",
                "packet-capture", "host-audit"} <= names

    def test_no_shell_ever(self):
        """No new adapter introduces a shell binary."""
        for a in AdapterRegistry().list():
            assert a.binary not in {"sh", "bash", "zsh", "python", "perl"}

    def test_capability_classes_are_known_risk_levels(self):
        from rebel_profiler.security.risk import RiskEngine

        engine = RiskEngine()
        for name in ("nikto-scan", "wpscan-audit", "exploit-lookup",
                     "packet-capture", "host-audit"):
            adapter = AdapterRegistry().get(name)
            assessment = engine.classify(adapter.capability_class)
            assert assessment.level in ("low", "moderate", "high", "critical")


class TestNiktoAdapter:
    def test_basic_argv(self):
        argv = NiktoAdapter().build_argv(
            make_request("nikto-scan", "h1.lab.example.test", port="443", ssl="1"))
        assert argv[0] == "nikto"
        assert "-h" in argv and "h1.lab.example.test" in argv
        assert "-Format" in argv and "csv" in argv
        assert "-ssl" in argv

    def test_rejects_bad_host(self):
        with pytest.raises(UsageError):
            NiktoAdapter().build_argv(
                make_request("nikto-scan", "h1; reboot"))

    def test_rejects_bad_port(self):
        with pytest.raises(UsageError):
            NiktoAdapter().build_argv(
                make_request("nikto-scan", "h1.lab.example.test", port="99999"))

    def test_unknown_param_fails_at_the_broker(self):
        """Param gating lives in Adapter.validate_params (broker gate 2)."""
        adapter = NiktoAdapter()
        req = make_request("nikto-scan", "h1.lab.example.test", tuning="x")
        with pytest.raises(UsageError):
            adapter.validate_params(req)


class TestWpscanAdapter:
    def test_basic_argv(self):
        argv = WpscanAdapter().build_argv(
            make_request("wpscan-audit", "https://wp.lab.example.test"))
        assert argv[0] == "wpscan"
        assert "--url" in argv and "https://wp.lab.example.test" in argv
        assert "--enumerate" in argv and "vp,vt" in argv

    def test_rejects_bare_host(self):
        with pytest.raises(UsageError):
            WpscanAdapter().build_argv(
                make_request("wpscan-audit", "wp.lab.example.test"))

    def test_rejects_bad_enum(self):
        with pytest.raises(UsageError):
            WpscanAdapter().build_argv(
                make_request("wpscan-audit", "https://wp.lab.example.test",
                             enumerate="passwords"))


class TestSearchsploitAdapter:
    def test_basic_argv(self):
        argv = SearchsploitAdapter().build_argv(
            make_request("exploit-lookup", "nginx 1.18"))
        assert argv[0] == "searchsploit"
        assert "--json" in argv and "nginx 1.18" in argv

    def test_rejects_metachars(self):
        with pytest.raises(UsageError):
            SearchsploitAdapter().build_argv(
                make_request("exploit-lookup", "nginx; cat /etc/passwd"))


class TestTcpdumpAdapter:
    def test_requires_interface(self):
        argv = TcpdumpCaptureAdapter().build_argv(
            make_request("packet-capture", "office-floor-2",
                         interface="eth0", filter="tcp", count="200"))
        assert argv[0] == "tcpdump"
        assert "-i" in argv and "eth0" in argv
        assert "-c" in argv and "200" in argv

    def test_missing_interface_is_usage_error(self):
        with pytest.raises(UsageError):
            TcpdumpCaptureAdapter().build_argv(
                make_request("packet-capture", "office-floor-2"))

    def test_free_form_bpf_refused(self):
        with pytest.raises(UsageError):
            TcpdumpCaptureAdapter().build_argv(
                make_request("packet-capture", "office-floor-2",
                             interface="eth0", filter="host 10.0.0.9"))

    def test_count_bounded(self):
        with pytest.raises(UsageError):
            TcpdumpCaptureAdapter().build_argv(
                make_request("packet-capture", "office-floor-2",
                             interface="eth0", count="99999"))


class TestLynisAdapter:
    def test_fixed_argv(self):
        argv = LynisAuditAdapter().build_argv(
            make_request("host-audit", "operator-laptop"))
        assert argv[:3] == ["lynis", "audit", "system"]
        assert "--no-log" in argv

    def test_no_params_accepted(self):
        adapter = LynisAuditAdapter()
        req = make_request("host-audit", "operator-laptop", extra="x")
        with pytest.raises(UsageError):
            adapter.validate_params(req)


class TestParsers:
    def test_nikto_csv_skips_summary_rows(self):
        csv_text = ('"1","OSVDB-3092","/admin/: This might be interesting",'
                    '"GET","/admin/","10.0.0.1","h1",\n'
                    '"2","Items tested","x","GET","","","",""\n')
        pairs = _parse_nikto_csv(csv_text)
        kinds = {k for k, _ in pairs}
        assert "nikto_finding" in kinds
        assert all("Items tested" not in v for _, v in pairs)

    def test_nikto_garbage_yields_nothing(self):
        assert _parse_nikto_csv("not csv at all\n\n") == []

    def test_wpscan_levels(self):
        text = ("[i] WordPress version 6.4 identified\n"
                "[!] 2 vulnerabilities associated with wordpress 6.4\n")
        pairs = _parse_wpscan_text(text)
        assert ("wp_info", "WordPress version 6.4 identified") in pairs
        assert any(k == "wp_finding" for k, _ in pairs)

    def test_searchsploit_dedupes_and_caps(self):
        import json as j
        rows = [{"Title": f"Product - issue {i}", "EDB-ID": str(10000 + i)}
                for i in range(60)]
        pairs = _parse_searchsploit_json(j.dumps({"RESULTS_EXPLOIT": rows}))
        assert len(pairs) <= 40
        assert any("EDB-10000" in v for _, v in pairs)

    def test_searchsploit_malformed_yields_nothing(self):
        assert _parse_searchsploit_json("{broken json") == []
        assert _parse_searchsploit_json('{"RESULTS_EXPLOIT": "nope"}') == []

    def test_tcpdump_aggregates_protocols_no_addresses(self):
        text = ("IP 10.0.0.1.53022 > 10.0.0.2.443: tcp 0\n"
                "IP 10.0.0.1.53022 > 10.0.0.2.443: tcp 0\n"
                "IP 10.0.0.3.5353 > 224.0.0.251.5353: udp 42\n"
                "10.0.0.1 > 10.0.0.2: ICMP echo reply\n")
        pairs = _parse_tcpdump_summary(text)
        values = {v for _, v in pairs}
        assert "packets tcp:443=2" in values
        assert "packets udp:5353=1" in values
        assert "packets icmp=1" in values
        # privacy: no IP address ever appears in a claim value
        for _, v in pairs:
            assert "10.0.0." not in v

    def test_lynis_suggestions(self):
        text = ("suggestion[]LYN-ACCT-001|Accounts|Set password expiry on user accounts\n"
                "banner lines that are not suggestions stay out\n")
        pairs = _parse_lynis(text)
        assert ("hardening_suggestion",
                "LYN-ACCT-001: Set password expiry on user accounts") in pairs
        assert all("banner" not in v for _, v in pairs)


class TestCoverageMatrixConsistency:
    def test_new_classes_have_live_detect_actions(self):
        """The matrix cannot drift from what the tool executes."""
        from rebel_profiler.intel.vulncov import VULN_CLASSES, coverage_for_case
        from rebel_profiler.intel.claims import ClaimLedger
        from rebel_profiler.intel.sources import SourceRegistry

        live = set(AdapterRegistry().names())
        for vc in VULN_CLASSES:
            assert any(a in live for a in vc.detect_actions), vc.key
        ledger = ClaimLedger(SourceRegistry())
        report = coverage_for_case(ledger, "c1")
        assert report["no_adapter"] == 0

    def test_guide_contract_complete(self):
        report = __import__(
            "rebel_profiler.knowledge.action_guides",
            fromlist=["coverage_report"]).coverage_report()
        assert report["complete"] is True
