"""Wireless capability tests: adapter argv contracts, CSV parsing, gates.

The wireless adapters must obey the same discipline as every other adapter —
declared params only, whitelisted argv, validated tokens — and the parser
must turn airodump CSV into claims without ever recording client probe SSIDs
(privacy discipline) or inventing rows.
"""

from __future__ import annotations

import pytest

from rebel_profiler.core.errors import UsageError
from rebel_profiler.execution.broker import AdapterRegistry
from rebel_profiler.execution.wireless import (
    WlanApAuditAdapter,
    WlanMonitorAdapter,
    WirelessSurveyAdapter,
    parse_airodump_csv,
)
from rebel_profiler.intel.vulncov import VULN_CLASSES


def make_request(action: str, **overrides) -> "object":
    from rebel_profiler.execution.broker import ActionRequest

    base = dict(
        case_id="case1",
        capability="wireless_observation",
        action=action,
        target="office-floor-2",
        params={},
    )
    base.update(overrides)
    return ActionRequest(**base)


class TestWirelessRegistry:
    def test_wireless_adapters_registered(self):
        names = set(AdapterRegistry().names())
        assert {"wlan-survey", "wlan-monitor", "wlan-ap-audit"} <= names

    def test_no_duplicate_names(self):
        registry = AdapterRegistry()
        assert len(registry.names()) == len(set(registry.names()))


class TestSurveyAdapter:
    def test_basic_argv(self):
        req = make_request("wlan-survey", params={"interface": "wlan0mon"})
        argv = WirelessSurveyAdapter().build_argv(req)
        assert argv[0] == "airodump-ng"
        assert "wlan0mon" in argv
        # write prefix is a fixed literal, never user-controlled
        assert "-w" in argv and "rp_survey" in argv

    def test_channel_lock(self):
        req = make_request(
            "wlan-survey", params={"interface": "wlan0mon", "channel": "6"})
        argv = WirelessSurveyAdapter().build_argv(req)
        assert "-c" in argv

    def test_rejects_bad_interface(self):
        req = make_request(
            "wlan-survey", params={"interface": "wlan0; rm -rf /"})
        with pytest.raises(UsageError):
            WirelessSurveyAdapter().build_argv(req)

    def test_rejects_missing_interface(self):
        with pytest.raises(UsageError):
            WirelessSurveyAdapter().build_argv(make_request("wlan-survey"))

    def test_rejects_out_of_range_duration(self):
        req = make_request(
            "wlan-survey", params={"interface": "wlan0mon", "duration": "99999"})
        with pytest.raises(UsageError):
            WirelessSurveyAdapter().build_argv(req)

    def test_rejects_unknown_band(self):
        req = make_request(
            "wlan-survey",
            params={"interface": "wlan0mon", "band": "xyz"})
        with pytest.raises(UsageError):
            WirelessSurveyAdapter().build_argv(req)


class TestMonitorAdapter:
    def test_start_argv(self):
        req = make_request("wlan-monitor",
                           capability="wireless_monitor",
                           params={"interface": "wlan0"})
        argv = WlanMonitorAdapter().build_argv(req)
        assert argv == ["airmon-ng", "start", "wlan0"]

    def test_stop_argv(self):
        req = make_request("wlan-monitor",
                           capability="wireless_monitor",
                           params={"interface": "wlan0mon", "stop": "1"})
        argv = WlanMonitorAdapter().build_argv(req)
        assert argv == ["airmon-ng", "stop", "wlan0mon"]

    def test_monitor_is_high_risk(self):
        from rebel_profiler.security.risk import RiskEngine

        assert RiskEngine().classify("wireless_monitor").level == "high"

    def test_survey_is_moderate_risk(self):
        from rebel_profiler.security.risk import RiskEngine

        assert RiskEngine().classify("wireless_observation").level == "moderate"


class TestApAuditAdapter:
    def test_offline_marker(self):
        argv = WlanApAuditAdapter().build_argv(make_request("wlan-ap-audit"))
        assert argv[0] == "echo"
        assert "offline" in argv[-1]


# Minimal but faithful airodump-ng CSV fixture (AP section + client section).
_AIRODUMP_CSV = (
    "BSSID, First time seen, Last time seen, channel, Speed, "
    "Privacy, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
    "AA:BB:CC:DD:EE:01, 2026-09-25 10:00:00, 2026-09-25 10:05:00,  6, 54, "
    "WPA2, -42, 120, 0,   0.  0.  0.  0,  11, LabNet, \n"
    "AA:BB:CC:DD:EE:02, 2026-09-25 10:00:00, 2026-09-25 10:05:00, 11, 54, "
    "WEP, -60, 80, 0,   0.  0.  0.  0,   8, Legacy-Net, \n"
    "\n"
    "Station MAC, First time seen, Last time seen, Power, # packets, "
    "BSSID, Probed ESSIDs\n"
    "11:22:33:44:55:66, 2026-09-25 10:01:00, 2026-09-25 10:04:00, -44, 25, "
    "(not associated) AA:BB:CC:DD:EE:01, CoffeeShop GuestNet\n"
    "22:33:44:55:66:77, 2026-09-25 10:02:00, 2026-09-25 10:05:00, -50, 40, "
    "AA:BB:CC:DD:EE:01, \n"
)


class TestAirodumpCsvParser:
    def test_parses_aps(self):
        pairs = parse_airodump_csv(_AIRODUMP_CSV)
        aps = [v for k, v in pairs if k == "ap"]
        assert any("AA:BB:CC:DD:EE:01" in v and "LabNet" in v for v in aps)
        assert any("AA:BB:CC:DD:EE:02" in v and "Legacy-Net" in v for v in aps)

    def test_parses_security_posture(self):
        pairs = parse_airodump_csv(_AIRODUMP_CSV)
        sec = [v for k, v in pairs if k == "wifi_security"]
        assert any("WEP" in v for v in sec)
        assert any("WPA2" in v for v in sec)

    def test_station_association_recorded(self):
        pairs = parse_airodump_csv(_AIRODUMP_CSV)
        stas = [v for k, v in pairs if k == "wireless_sta"]
        assert any(v.startswith("22:33:44:55:66:77") and
                   "AA:BB:CC:DD:EE:01" in v for v in stas)

    def test_unassociated_station_never_gets_a_false_ap(self):
        pairs = parse_airodump_csv(_AIRODUMP_CSV)
        stas = [v for k, v in pairs if k == "wireless_sta"]
        assert any(v.startswith("11:22:33:44:55:66") and "assoc=none" in v
                   for v in stas)

    def test_probe_ssids_never_recorded(self):
        pairs = parse_airodump_csv(_AIRODUMP_CSV)
        blob = " ".join(v for _, v in pairs)
        assert "CoffeeShop" not in blob
        assert "GuestNet" not in blob

    def test_garbage_yields_nothing(self):
        assert parse_airodump_csv("hello,world\nfoo bar\n") == []
        assert parse_airodump_csv("") == []


class TestCoverageMatrix:
    def test_wireless_rows_have_live_actions(self):
        live = set(AdapterRegistry().names())
        for vc in VULN_CLASSES:
            if vc.key.startswith("wifi_"):
                assert vc.detect_actions, f"{vc.key} has no detect actions"
                assert any(a in live for a in vc.detect_actions), (
                    f"{vc.key}: no live adapter among {vc.detect_actions}")
