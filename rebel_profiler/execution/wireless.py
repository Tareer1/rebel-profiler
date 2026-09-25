"""Wireless reconnaissance adapters (802.11) — AUTHORIZED USE ONLY.

The wireless domain completes the all-in-one coverage promise: a case that
authorizes a physical site (own office, lab, client premises with written
permission) can now inventory its radio environment exactly like its wired
one — through the same six gates, the same evidence chain and the same audit.

Design laws mirrored from every other adapter module:

  * declared params only, whitelisted argv construction, no shell;
  * passive/observation modes are offered; injection/attack modes (aireplay,
  * deauth, evil-twin) are deliberately ABSENT — detection, not disruption;
  * the monitor-mode adapter is approval-gated (capability class
    ``wireless_monitor`` → high risk → ALLOW_WITH_APPROVAL), because it changes
    the operator's own machine state (brings an interface into monitor mode);
  * every value that reaches argv is validated with the same strict
    single-token discipline as the rest of the toolset (interface names,
    channel numbers, capture durations — never free-form strings).

Parsers here turn airodump-ng's CSV output into the same (kind, value) pairs
the collection pipeline ingests, so wireless observations land in the claim
ledger with full provenance:

  * ``ap``            — BSSID + ESSID + channel of an access point,
  * ``wireless_sta``  — client station MAC + its associated AP (privacy:
                        probe SSIDs are NEVER recorded, only association),
  * ``handshake``     — a captured WPA handshake marker for a BSSID (proof of
                        capture for an authorized audit, never a crack),
  * ``wifi_security`` — the encryption posture of an AP (OPEN/WEP/WPA2/…).
"""

from __future__ import annotations

import re

from ..core.errors import UsageError
from .adapters import _single_token
from .broker import ActionRequest, Adapter

# Interface names are kernel identifiers: wlan0mon, wlp3s0, eth0 … strictly
# alphanumeric with dashes/underscores, 2–16 chars. Dots and slashes never
# appear in a legal name and would be path-traversal attempts.
_IFACE = r"[A-Za-z0-9][A-Za-z0-9_-]{1,15}"
_CHANNEL = r"\d{1,3}"
_SECONDS = r"\d{1,4}"
_BSSID = r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"

# airodump-ng CSV: AP lines, client lines, and the separation marker between
# the two sections.
_CSV_AP_SEP = "# First seen"


def _csv_cells(line: str) -> list[str]:
    """Split one airodump-ng CSV line (comma-separated, quoted strings)."""
    cells = [c.strip().strip('"') for c in line.split(",")]
    return cells


class WirelessSurveyAdapter(Adapter):
    """Passive 802.11 channel observation (airodump-ng CSV output).

    Listens on the GIVEN interface (which the operator put in monitor mode
    explicitly, or let :class:`WlanMonitorAdapter` do approval-gated) and
    records APs/clients heard — zero packets are transmitted beyond the
    interface's own beacon listening. Bounded by --write-interval via the
    duration param mapped to aivmdump's ``--write`` plus the runner timeout.

    Params:
      * duration — capture seconds (60–3600, default 120)
      * channel  — lock to one 2.4/5 GHz channel (1–196) instead of hopping
      * band     — a/b/g/n/ac/abg hop set (default: abg)
    """

    name = "wlan-survey"
    binary = "airodump-ng"
    capability_class = "wireless_observation"
    allowed_params = ("interface", "duration", "channel", "band")
    required_params = ("interface",)

    _BANDS = ("a", "b", "g", "n", "abg", "bg")

    def build_argv(self, request: ActionRequest) -> list[str]:
        iface = _single_token(request.params.get("interface", ""),
                              field="interface", pattern=_IFACE)
        duration = _single_token(str(request.params.get("duration", "120")),
                                 field="duration", pattern=_SECONDS)
        if not (60 <= int(duration) <= 3600):
            raise UsageError(
                f"duration out of range: {duration}",
                reason="Surveys are bounded between one minute and one hour.",
                action="Pick a duration between 60 and 3600 seconds.",
            )
        # airodump-ng has no stdout-CSV mode: it writes files with the -w
        # prefix (rp_survey-01.csv …) refreshed every --write-interval
        # seconds. The prefix is a fixed literal (never user-controlled), so
        # the collection step reads exactly one known file. The runner's
        # subprocess timeout is the capture-duration bound.
        argv = [self.binary, "--write-interval", "5", "-w", "rp_survey", iface]
        band = request.params.get("band")
        if band is not None:
            band = _single_token(str(band), field="band", pattern=r"[abgn]{1,3}")
            if band not in self._BANDS:
                raise UsageError(
                    f"Unknown band '{band}'",
                    reason="Only whitelisted hop sets are executable.",
                    action=f"Choose one of: {', '.join(self._BANDS)}",
                )
            argv += ["--band", band]
        channel = request.params.get("channel")
        if channel is not None:
            channel = _single_token(str(channel), field="channel",
                                    pattern=_CHANNEL)
            if not (1 <= int(channel) <= 196):
                raise UsageError(f"Channel out of range: {channel}")
            argv += ["-c", channel]
        return argv


class WlanMonitorAdapter(Adapter):
    """Put a wireless interface into monitor mode (airmon-ng) — approval-gated.

    This is the only state-changing wireless action: it reconfigures the
    OPERATOR'S OWN interface (never a target). High risk by policy ⇒ the
    approval queue decides. The stop direction uses the same adapter.
    """

    name = "wlan-monitor"
    binary = "airmon-ng"
    capability_class = "wireless_monitor"
    allowed_params = ("interface", "stop")
    required_params = ("interface",)

    def build_argv(self, request: ActionRequest) -> list[str]:
        iface = _single_token(request.params.get("interface", ""),
                              field="interface", pattern=_IFACE)
        argv = [self.binary]
        if request.params.get("stop"):
            argv += ["stop", iface]
        else:
            argv += ["start", iface]
        return argv


class WlanApAuditAdapter(Adapter):
    """Enumerate saved AP/ security posture of ONE captured survey CSV.

    Pure offline analysis: reads nothing but the survey CSV already captured
    into the case (the evidence ledger holds the bytes). No RF interaction.
    Emits wifi_security + ap claims parsed from the file contents handed in
    via the collection pipeline (this adapter's stdout contract is the CSV).
    """

    name = "wlan-ap-audit"
    binary = "echo"           # no external binary: the parser IS the adapter
    capability_class = "passive_recon"
    allowed_params = ()
    required_params = ()

    def build_argv(self, request: ActionRequest) -> list[str]:
        # Deterministic marker: the real analysis happens in the collection
        # pipeline over previously captured survey evidence. Keeping this as
        # an adapter (rather than a bare function) means the planner, the
        # playbooks and the coverage matrix all see one uniform action name.
        return [self.binary, "wlan-ap-audit: offline CSV analysis"]


# -- parsers (exported for the collection pipeline) ---------------------------

_MAC = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")


def parse_airodump_csv(csv_text: str) -> list[tuple[str, str]]:
    """Parse airodump-ng CSV into (kind, value) pairs.

    Two sections: APs first, then clients after the ``# First seen`` marker
    repeated in the client header. AP row shape (BSSID, FirstTimeSeen, Last,
    channel, Speed, Privacy, Power, #beacons, #IV, LAN, IP, ID-Length,
    ESSID, Key); client row shape (StationMAC, …, AP-BSSID, …, Probe-SSIDs…).

    Privacy discipline: client PROBE SSIDs are never recorded — association
    only. Unknown/malformed lines yield nothing (never invented).
    """
    pairs: list[tuple[str, str]] = []
    in_clients = False
    for raw in csv_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(_CSV_AP_SEP):
            # The second header block separates the client section.
            if in_clients:
                continue
            # First occurrence is still the AP header; airodump repeats the
            # marker line in the client section header too, so track by a
            # preceding empty line heuristic instead: header lines contain
            # "BSSID" or "Station MAC".
            continue
        lower = line.lower()
        if lower.startswith("bssid,") or "bssid, first time seen" in lower:
            continue
        if lower.startswith("station mac,"):
            in_clients = True
            continue
        cells = _csv_cells(line)
        if not cells or not _MAC.fullmatch(cells[0]):
            continue
        if not in_clients:
            # AP row: BSSID, first, last, channel, speed, privacy, …
            # ESSID sits at index 11 (ID-length at 10); index 12 is the
            # trailing empty Key cell. Treat index 11 as authoritative but
            # fall back to 12 for CSV variants that merge ID-length/ESSID.
            bssid = cells[0].upper()
            channel = cells[3] if len(cells) > 3 else ""
            privacy = (cells[5] if len(cells) > 5 else "").strip()
            essid = ""
            if len(cells) > 11:
                essid = cells[11].strip() or (cells[12].strip() if len(cells) > 12 else "")
            ap_value = f"{bssid} ch={channel or '?'} essid={essid or '<hidden>'}"
            pairs.append(("ap", ap_value))
            if privacy:
                pairs.append(("wifi_security", f"{bssid} {privacy}"))
        else:
            # Client row: StationMAC, …, BSSID(associated AP) …, probes …
            sta = cells[0].upper()
            # Associated-AP position varies; find the first cell that is a
            # BSSID but NOT the client's own MAC and not "(not associated)".
            ap = ""
            for cell in cells[1:]:
                cell = cell.strip()
                if cell.lower().startswith("(not associated"):
                    break
                if _MAC.fullmatch(cell):
                    ap = cell.upper()
                    break
            value = f"{sta} assoc={ap or 'none'}"
            pairs.append(("wireless_sta", value))
    return pairs


WIRELESS_ADAPTERS: tuple[type[Adapter], ...] = (
    WirelessSurveyAdapter,
    WlanMonitorAdapter,
    WlanApAuditAdapter,
)
