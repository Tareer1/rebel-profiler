"""Extended adapter tests: argv contracts, validation, no raw shell."""

from __future__ import annotations

import pytest

from rebel_profiler.core.errors import UsageError
from rebel_profiler.execution import (
    ActionRequest,
    AdapterRegistry,
    CertTransparencyAdapter,
    HeaderAuditAdapter,
    HttpProbeAdapter,
    NucleiAdapter,
    SmbEnumAdapter,
    TlsPostureAdapter,
    TracerouteAdapter,
    WhoisAdapter,
)


def make_request(**overrides) -> ActionRequest:
    base = dict(
        case_id="case1",
        capability="passive_recon",
        action="whois-lookup",
        target="lab.example.test",
        params={},
    )
    base.update(overrides)
    return ActionRequest(**base)


class TestRegistry:
    def test_extended_adapters_registered(self):
        registry = AdapterRegistry()
        names = set(registry.names())
        expected = {
            "whois-lookup", "cert-transparency", "tls-posture", "web-crawl",
            "header-audit", "smb-enum", "route-analysis", "vuln-correlate",
        }
        assert expected <= names

    def test_builtin_only_mode(self):
        registry = AdapterRegistry(include_extended=False)
        assert set(registry.names()) == {"echo", "dns-lookup", "host-discovery"}

    def test_no_duplicate_names(self):
        registry = AdapterRegistry()
        assert len(registry.names()) == len(set(registry.names()))


class TestWhoisAdapter:
    def test_basic_argv(self):
        argv = WhoisAdapter().build_argv(make_request())
        assert argv == ["whois", "lab.example.test"]

    def test_rejects_injection_target(self):
        with pytest.raises(UsageError):
            WhoisAdapter().build_argv(
                make_request(target="example.test; rm -rf /")
            )


class TestCertTransparencyAdapter:
    def test_basic_argv(self):
        argv = CertTransparencyAdapter().build_argv(
            make_request(action="cert-transparency", params={"limit": "50"})
        )
        assert argv[0] == "curl"
        assert "crt.sh" in argv[-1]
        assert "lab.example.test" in argv[-1]
        assert "limit=50" in argv[-1]

    def test_rejects_bad_limit(self):
        with pytest.raises(UsageError):
            CertTransparencyAdapter().build_argv(
                make_request(action="cert-transparency", params={"limit": "50; x"})
            )


class TestTlsPostureAdapter:
    def test_basic_argv(self):
        argv = TlsPostureAdapter().build_argv(
            make_request(action="tls-posture", capability="web_assessment",
                         target="host1.lab.example.test", params={"port": "8443"})
        )
        assert argv[0] == "sslscan"
        assert "host1.lab.example.test:8443" in argv

    def test_rejects_out_of_range_port(self):
        with pytest.raises(UsageError):
            TlsPostureAdapter().build_argv(
                make_request(action="tls-posture", capability="web_assessment",
                             target="host1.lab.example.test", params={"port": "99999"})
            )


class TestHttpProbeAdapter:
    def test_basic_argv(self):
        argv = HttpProbeAdapter().build_argv(
            make_request(action="web-crawl", capability="web_assessment",
                         target="host1.lab.example.test",
                         params={"tech_detect": True, "threads": "10"})
        )
        assert argv[0] == "httpx"
        assert "-tech-detect" in argv
        assert "10" in argv


class TestHeaderAuditAdapter:
    def test_basic_argv(self):
        argv = HeaderAuditAdapter().build_argv(
            make_request(action="header-audit", capability="web_assessment",
                         target="host1.lab.example.test")
        )
        assert argv[0] == "curl"
        assert "https://host1.lab.example.test" in argv


class TestSmbEnumAdapter:
    def test_basic_argv(self):
        argv = SmbEnumAdapter().build_argv(
            make_request(action="smb-enum", capability="network_mapping",
                         target="host1.lab.example.test",
                         params={"shares": True})
        )
        assert argv[0] == "enum4linux-ng"
        assert "-S" in argv
        assert "-A" in argv


class TestTracerouteAdapter:
    def test_basic_argv(self):
        argv = TracerouteAdapter().build_argv(
            make_request(action="route-analysis", capability="network_mapping",
                         target="host1.lab.example.test", params={"max_hops": "15"})
        )
        assert argv[0] == "traceroute"
        assert "15" in argv


class TestNucleiAdapter:
    def test_basic_argv(self):
        argv = NucleiAdapter().build_argv(
            make_request(action="vuln-correlate", capability="vuln_validation",
                         target="https://host1.lab.example.test",
                         params={"severity": "high,critical"})
        )
        assert argv[0] == "nuclei"
        assert "high,critical" in argv

    def test_rejects_bad_severity(self):
        with pytest.raises(UsageError):
            NucleiAdapter().build_argv(
                make_request(action="vuln-correlate", capability="vuln_validation",
                             target="https://host1.lab.example.test",
                             params={"severity": "whatever"})
            )

    def test_rejects_non_url_target(self):
        with pytest.raises(UsageError):
            NucleiAdapter().build_argv(
                make_request(action="vuln-correlate", capability="vuln_validation",
                             target="host1.lab.example.test")
            )


class TestNoShellMetacharacters:
    """No adapter may emit shell metacharacters into argv."""

    @pytest.mark.parametrize(
        "action,capability,target,params",
        [
            ("whois-lookup", "passive_recon", "x.test; cat /etc/passwd", {}),
            ("cert-transparency", "passive_recon", "x.test", {"limit": "1 && id"}),
            ("tls-posture", "web_assessment", "x.test", {"port": "443 -oG"}),
            ("web-crawl", "web_assessment", "x.test", {"ports": "80,`id`"}),
            ("header-audit", "web_assessment", "x.test | id", {}),
            ("smb-enum", "network_mapping", "x.test $(id)", {}),
            ("route-analysis", "network_mapping", "x.test\nid", {}),
            ("vuln-correlate", "vuln_validation", "file:///etc/passwd", {}),
        ],
    )
    def test_metacharacters_rejected(self, action, capability, target, params):
        registry = AdapterRegistry()
        adapter = registry.get(action)
        request = make_request(action=action, capability=capability,
                               target=target, params=params)
        with pytest.raises(UsageError):
            adapter.build_argv(request)
