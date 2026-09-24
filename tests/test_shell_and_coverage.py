"""Tests for the sci-fi shell, the vuln-coverage matrix, and the new
header-audit / tls-posture parsers.

Offline discipline: the shell is exercised through its helpers and a
piped-loop run against a temp workspace; the coverage matrix ranks from a
hand-built ledger; parsers get recorded tool-output shapes only.
"""

from __future__ import annotations

import json

import pytest

from rebel_profiler.cli.shell import GLYPHS, _help, _prompt, _run_cli
from rebel_profiler.execution.broker import AdapterRegistry
from rebel_profiler.intel.collection import _parse_header_head, _parse_sslscan
from rebel_profiler.intel.claims import ClaimLedger, SourceRegistry
from rebel_profiler.intel.vulncov import (
    VULN_CLASSES,
    coverage_for_case,
    vuln_classes,
)


# ---------------------------------------------------------------- shell

class TestShell:
    def test_help_lists_console_map(self):
        text = _help()
        assert ":plan" in text and ":cover" in text and ":case" in text

    def test_prompt_carries_case(self):
        prompt = _prompt("abc123")
        assert "abc123" in prompt and "◈" in prompt and "❯" in prompt

    def test_cli_dispatch_runs_real_command(self, capsys):
        code = _run_cli(["adapters"])
        assert code == 0
        assert "nuclei-scan" in capsys.readouterr().out

    def test_glyphs_available(self):
        assert GLYPHS["shield"] and GLYPHS["ok"]

    def test_shell_command_registered(self):
        from rebel_profiler.cli.main import build_parser

        parser = build_parser()
        args = parser.parse_args(["shell", "--data-dir", "/tmp/rp-shell-test"])
        assert args.group == "shell"


# ---------------------------------------------------------------- coverage

def _ledger(rows: list[tuple[str, str, str]]) -> ClaimLedger:
    ledger = ClaimLedger(SourceRegistry())
    for subject, kind, value in rows:
        ledger.add("c1", subject=subject, kind=kind, value=value,
                   source="test", method="header-audit")
    return ledger


class TestVulnCoverage:
    def test_classes_have_live_actions(self):
        registry = AdapterRegistry()
        for vc in VULN_CLASSES:
            assert vc.detect_actions, f"{vc.key}: no detection path"
            assert any(a in registry.names() for a in vc.detect_actions), (
                f"{vc.key}: no detect action is executable")

    def test_payload_classes_exist(self):
        from rebel_profiler.intel.offense import payload_classes

        for vc in VULN_CLASSES:
            if vc.payload_class:
                assert vc.payload_class in payload_classes(), (
                    f"{vc.key}: payload class {vc.payload_class} not buildable")

    def test_case_uses_method_for_probed(self):
        ledger = _ledger([("h1.test", "header_obs", "x-frame-options: DENY")])
        report = coverage_for_case(ledger, "c1")
        by_class = {r["class"]: r for r in report["classes"]}
        assert by_class["headers"]["status"] == "covered"
        assert by_class["sqli"]["status"] == "available"

    def test_empty_ledger_means_nothing_covered(self):
        report = coverage_for_case(ClaimLedger(SourceRegistry()), "c1")
        assert report["covered"] == 0
        assert report["no_adapter"] == 0   # every class has some live action

    def test_matrix_is_honest(self):
        report = coverage_for_case(ClaimLedger(SourceRegistry()), "c1")
        assert report["covered"] + report["available"] + report["no_adapter"] \
            == report["total"] == len(vuln_classes())


# ---------------------------------------------------------------- parsers

class TestHeaderAuditParser:
    def test_security_headers_and_cookie_flags(self):
        out = ("HTTP/2 302 \n"
               "location: https://h1.test/en\n"
               "strict-transport-security: max-age=15552000\n"
               "server: cloudflare\n"
               "set-cookie: SID=abc123; HttpOnly; SameSite=Lax; Path=/\n"
               "set-cookie: LOCALE=en; Path=/\n")
        pairs = _parse_header_head(out)
        headers = [v for k, v in pairs if k == "header_obs"]
        cookies = [v for k, v in pairs if k == "cookie_flag"]
        assert "location: https://h1.test/en" in headers
        assert "strict-transport-security: max-age=15552000" in headers
        assert any(v.startswith("SID:") and "httponly" in v for v in cookies)
        assert any(v.startswith("LOCALE:") and "no security flags" in v
                   for v in cookies)
        # the secret cookie VALUE must never appear
        assert not any("abc123" in v for _, v in pairs)

    def test_garbage_is_empty(self):
        assert _parse_header_head("nothing useful here") == []


class TestSslscanParser:
    def test_protocols_and_vuln_marker(self):
        out = ("SSLv2     disabled\n"
               "TLSv1.0   enabled\n"
               "TLSv1.3   enabled\n"
               "  Heartbleed:\n"
               "TLSv1.3 not vulnerable to heartbleed\n"
               "Heartbleed: VULNERABLE\n")
        pairs = _parse_sslscan(out)
        values = [v for _, v in pairs]
        assert "tlsv1.0 enabled (legacy — downgrade risk)" in values
        assert "tlsv1.3 enabled" in values
        assert any("VULNERABLE" in v for v in values)
        # the 'not vulnerable' noise line is never a claim
        assert not any("not vulnerable" in v for v in values)

    def test_disabled_protocols_are_not_findings(self):
        out = "SSLv2     disabled\nSSLv3     disabled\n"
        assert _parse_sslscan(out) == []
