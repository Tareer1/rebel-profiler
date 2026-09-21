"""New recon adapters (v1.5): argv contracts + output parsing."""

from __future__ import annotations

import pytest

from rebel_profiler.core.errors import UsageError
from rebel_profiler.execution.adapters import (
    DnsEnumAdapter,
    DirEnumAdapter,
    EmailOsintAdapter,
    SubdomainEnumAdapter,
    TechFingerprintAdapter,
    WafDetectAdapter,
)
from rebel_profiler.execution.broker import ActionRequest


def _req(action: str, target: str, **params) -> ActionRequest:
    return ActionRequest(case_id="c1", capability="passive_recon",
                         action=action, target=target, params=params)


class TestArgvContracts:
    def test_subdomain_enum_passive_only(self):
        argv = SubdomainEnumAdapter().build_argv(
            _req("subdomain-enum", "example.test", timeout="5"))
        assert argv[:2] == ["amass", "enum"]
        assert "-passive" in argv            # never active probing
        assert "-d" in argv and "example.test" in argv

    def test_email_osint_bounded(self):
        argv = EmailOsintAdapter().build_argv(
            _req("email-osint", "example.test", limit="50"))
        assert argv[0] == "theHarvester"
        assert "-l" in argv and "50" in argv

    def test_email_osint_rejects_bad_limit(self):
        with pytest.raises(UsageError):
            EmailOsintAdapter().build_argv(
                _req("email-osint", "example.test", limit="; rm -rf"))

    def test_dir_enum_whitelists_wordlist(self):
        argv = DirEnumAdapter().build_argv(
            _req("dir-enum", "https://app.example.test/"))
        assert argv[0] == "ffuf"
        assert "-of" in argv and "json" in argv
        # small.txt by default (polite on slow targets); -ac calibrates
        # against soft-404 hosts that answer 200 for every path.
        assert any("dirb/small.txt" in a for a in argv)
        assert "-ac" in argv

    def test_dir_enum_rejects_metachar_wordlist(self):
        with pytest.raises(UsageError):
            DirEnumAdapter().build_argv(
                _req("dir-enum", "https://app.example.test/",
                     wordlist="/tmp/x; rm -rf /"))

    def test_tech_fingerprint_and_waf_are_plain(self):
        w = TechFingerprintAdapter().build_argv(
            _req("tech-fingerprint", "https://app.example.test/"))
        assert w[0] == "whatweb" and "--color=never" in w
        f = WafDetectAdapter().build_argv(
            _req("waf-detect", "https://app.example.test/"))
        assert f[0] == "wafw00f"

    def test_dns_enum_fixed_mode_list(self):
        argv = DnsEnumAdapter().build_argv(
            _req("dns-enum", "example.test"))
        assert argv[0] == "dnsrecon" and "-t" in argv

    def test_targets_are_validated(self):
        for adapter, action, bad in (
            (SubdomainEnumAdapter(), "subdomain-enum", "bad host; id"),
            (EmailOsintAdapter(), "email-osint", "not a domain"),
            (TechFingerprintAdapter(), "tech-fingerprint",
             "https://x.test/$(id)"),
        ):
            with pytest.raises(UsageError):
                adapter.build_argv(_req(action, bad))


class TestParsers:
    def test_subdomain_lines_only_in_scope_domain(self, monkeypatch):
        from rebel_profiler.intel.collection import _parse_subdomain_lines
        out = ("www.example.test\n"
               "blog.example.test\n"
               "evil.other.test\n"
               "example.test\n")
        pairs = _parse_subdomain_lines(out, "example.test")
        hosts = [v for k, v in pairs]
        assert "www.example.test" in hosts and "example.test" in hosts
        assert "evil.other.test" not in hosts

    def test_harvester_emails_and_hosts(self):
        from rebel_profiler.intel.collection import _parse_harvester
        out = ("[*] Emails found: 2\n"
               "webmaster@hplovecraft.com\n"
               "admin@other.org\n"
               "[*] Hosts found: 1\n"
               "www.hplovecraft.com\n")
        pairs = _parse_harvester(out, "hplovecraft.com")
        kinds = {k for k, _ in pairs}
        assert "email" in kinds and "hostname" in kinds

    def test_ffuf_json_with_ansi_prefix(self):
        from rebel_profiler.intel.collection import _parse_ffuf
        raw = ('\r\x1b[2K frame [Status: 200]\n'
               '{"commandline":"ffuf","results":['
               '{"input":{"FUZZ":"about"},"status":301,'
               '"url":"https://x.test/about"}]}')
        assert _parse_ffuf(raw) == [("web_path", "/about [301]")]

    def test_ffuf_garbage_is_empty(self):
        from rebel_profiler.intel.collection import _parse_ffuf
        assert _parse_ffuf("no json here") == []

    def test_whatweb_plugins(self):
        from rebel_profiler.intel.collection import _parse_whatweb
        out = ("https://x.test/ [200 OK] ASP_NET[4.0.30319], "
               "HTTPServer[Microsoft-IIS/8.5], Title[Hello]")
        pairs = _parse_whatweb(out)
        values = [v for k, v in pairs if k == "tech"]
        assert any(v.startswith("ASP_NET=") for v in values)
        assert any(v.startswith("HTTPServer=") for v in values)

    def test_dnsrecon_records(self):
        from rebel_profiler.intel.collection import _parse_dnsrecon
        out = ("[INFO]\t SOA ns1.example.test 192.0.2.1\n"
               "[INFO]\t NS ns2.example.test 192.0.2.2\n"
               "[INFO]\t MX mail.example.test 10\n")
        pairs = _parse_dnsrecon(out)
        kinds = {k for k, _ in pairs}
        assert {"dns_soa", "dns_ns", "dns_mx"} <= kinds

    def test_wafw00f_detected_and_none(self):
        from rebel_profiler.intel.collection import _parse_wafw00f
        assert _parse_wafw00f(
            "[+] The site https://x.test is behind Cloudflare WAF.") == [
            ("waf", "Cloudflare")]
        assert _parse_wafw00f(
            "No WAF detected on https://x.test") == [("waf", "none detected")]
        assert _parse_wafw00f("generic banner only") == []
