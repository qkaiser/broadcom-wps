#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "scapy",
# ]
# ///
"""Safely fingerprint Broadcom WPS Monitor versus hostapd over 802.11."""

from __future__ import annotations

import argparse
import json
import queue
import re
import secrets
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import replace as dataclass_replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol, Self

from scapy.arch.common import compile_filter
from scapy.layers.dot11 import (
    Dot11,
    Dot11AssoReq,
    Dot11AssoResp,
    Dot11Auth,
    Dot11Deauth,
    Dot11Disas,
    Dot11Elt,
    Dot11ProbeReq,
    RadioTap,
)
from scapy.layers.l2 import LLC, SNAP
from scapy.packet import Packet, Raw
from scapy.sendrecv import AsyncSniffer, sendp
from scapy.utils import PcapWriter

BROADCOM_IE_PREFIX = bytes.fromhex("00101802")
WPS_IE_PREFIX = b"\x00\x50\xf2\x04"
FIXED_WPS_UUID = bytes.fromhex("000102030405060708090a0b0c0d0ebb")
WPS_TEXT_ATTRIBUTES = {
    0x1011: "device_name",
    0x1021: "vendor",
    0x1023: "model",
    0x1024: "model_number",
    0x1042: "serial_number",
}
DEFAULT_CHANNELS = tuple(range(1, 14))
DEFAULT_DWELL = 0.45
DEFAULT_RESPONSE_TIMEOUT = 10.0
RETRANSMIT_INTERVAL = 1.0
MAC_FRAGMENT_SIZE = 500
PARTIAL_SESSION_RELEASE_DELAY = 60.0
WFA_IDENTITY = b"WFA-SimpleConfig-Enrollee-1-0"
WPS_VENDOR = b"\x00\x37\x2a"
WPS_VENDOR_TYPE = b"\x00\x00\x00\x01"
WPS_ASSOCIATION_IE = WPS_IE_PREFIX + b"\x10\x4a\x00\x01\x10" + b"\x10\x3a\x00\x01\x01"
WSC_START = 0x01
WSC_MESSAGE = 0x04
WSC_FRAGMENT_ACK = 0x06
LENGTH_FIELD = 0x02
MORE_FRAGMENTS = 0x01
ETH_P_PAE = 0x888E

# RSN (802.11i) suite selectors used to build a station-side RSN element that a
# PMF-capable AP will accept for a plain (non-SAE) WPS enrollee association.
RSN_OUI = b"\x00\x0f\xac"
RSN_CIPHER_TKIP = RSN_OUI + b"\x02"
RSN_CIPHER_CCMP = RSN_OUI + b"\x04"
RSN_AKM_PSK = RSN_OUI + b"\x02"
RSN_AKM_PSK_SHA256 = RSN_OUI + b"\x06"
# RSN Capabilities: MFPC (bit 7, 0x0080) capable but NOT MFPR (bit 6, 0x0040)
# required, so the AP permits the association while the station advertises PMF
# support. Echoing the AP's MFPR=1 while doing open auth is what gets rejected.
RSN_CAPS_MFPC = 0x0080
RSN_CAPS_MFPR = 0x0040


class FingerprintError(RuntimeError):
    """Operator-visible environmental or RF failure."""


class StationStateLost(FingerprintError):
    """The target explicitly discarded the generated station state."""

    def __init__(self, action: str, reason: int) -> None:
        self.action = action
        self.reason = reason
        super().__init__(
            f"target {action} station while waiting for EAP (reason={reason})"
        )


class Assessment(StrEnum):
    """Public, evidence-graded assessment values."""

    PATCHED_HOSTAPD = "PATCHED_HOSTAPD"
    LIKELY_VULNERABLE = "LIKELY_VULNERABLE"
    NO_BROADCOM_FINGERPRINT = "NO_BROADCOM_FINGERPRINT"
    INCONCLUSIVE = "INCONCLUSIVE"


class ResponseKind(StrEnum):
    """Normalized response to one bounded first fragment."""

    ACK = "ACK"
    REJECTED = "REJECTED"
    SILENCE = "SILENCE"
    ERROR = "ERROR"


@dataclass(frozen=True)
class FingerprintResult:
    """Fields presented in the stable human report."""

    ssid: str
    bssid: str
    channel: int | str
    vendor: str = "Unknown"
    model: str = "Unknown"
    assessment: Assessment = Assessment.INCONCLUSIVE
    implementation: str = "INCONCLUSIVE"
    target_health: str = "UNKNOWN"
    broadcom_evidence: tuple[str, ...] = ()
    outcomes: tuple[TransactionOutcome, ...] = ()
    warning: str | None = None


@dataclass(frozen=True)
class TransactionOutcome:
    """Externally observable result of one isolated first-fragment session."""

    response: ResponseKind
    cleanup_sent: bool
    recovered: bool | None
    detail: str = ""


class FingerprintBackend(Protocol):
    """Narrow RF seam used by the safe orchestration and offline tests."""

    def probe_first_fragment(
        self,
        target: Observation,
        total_length: int,
        payload: bytes,
        *,
        recover: bool = True,
    ) -> TransactionOutcome: ...


@dataclass(frozen=True)
class Observation:
    """One normalized beacon or probe-response observation."""

    ssid: str
    bssid: str
    channel: int
    rssi_dbm: int
    vendor: str = "Unknown"
    model: str = "Unknown"
    model_number: str = "Unknown"
    device_name: str = "Unknown"
    serial_number: str = "Unknown"
    wps_advertised: bool = False
    broadcom_evidence: tuple[str, ...] = ()
    rates: bytes = b"\x82\x84\x8b\x96\x24\x30\x48\x6c"
    extended_rates: bytes = b""
    rsn: bytes | None = None
    wpa: bytes | None = None

    @property
    def broadcom_detected(self) -> bool:
        return bool(self.broadcom_evidence)


def _information_elements(packet: Packet):
    element = packet.getlayer(Dot11Elt)
    for _index in range(512):
        if element is None:
            return
        try:
            contents = bytes(element.info)
            declared = len(contents) if element.len is None else int(element.len)
            if 0 <= declared <= len(contents):
                yield int(element.ID), contents[:declared]
        except (AttributeError, TypeError, ValueError):
            pass
        element = element.payload.getlayer(Dot11Elt)


def _parse_wps_attributes(data: bytes) -> tuple[dict[str, str], set[str]]:
    identity: dict[str, str] = {}
    evidence: set[str] = set()
    offset = 0
    while offset + 4 <= len(data):
        kind = int.from_bytes(data[offset : offset + 2], "big")
        length = int.from_bytes(data[offset + 2 : offset + 4], "big")
        offset += 4
        end = offset + length
        if end > len(data):
            break
        value = data[offset:end]
        offset = end
        name = WPS_TEXT_ATTRIBUTES.get(kind)
        if name is not None:
            rendered = value.rstrip(b"\x00").decode("utf-8", errors="replace").strip()
            if rendered:
                identity[name] = rendered
        if kind in {0x1047, 0x1048} and value == FIXED_WPS_UUID:
            evidence.add("broadcom_fixed_wps_uuid")
    characteristic = sum(
        (
            identity.get("vendor", "").casefold() == "broadcom",
            identity.get("model", "").casefold() in {"broadcom", "broadcomap"},
            identity.get("model_number") in {"1234", "123456"},
            identity.get("device_name", "").casefold() == "broadcomap",
        )
    )
    if characteristic >= 2:
        evidence.add("broadcom_wps_identity_defaults")
    return identity, evidence


def parse_advertisement(
    packet: Packet,
    *,
    channel_hint: int,
) -> Observation | None:
    """Parse a beacon/probe response without trusting malformed IE lengths."""

    try:
        dot11 = packet[Dot11]
        if int(dot11.type) != 0 or int(dot11.subtype) not in {5, 8}:
            return None
        bssid = str(dot11.addr3 or dot11.addr2 or "").lower()
    except (IndexError, TypeError, ValueError):
        return None
    if len(bssid.split(":")) != 6:
        return None

    ssid: str | None = None
    channel = channel_hint
    identity: dict[str, str] = {}
    evidence: set[str] = set()
    wps_advertised = False
    rates = b"\x82\x84\x8b\x96\x24\x30\x48\x6c"
    extended_rates = b""
    rsn: bytes | None = None
    wpa: bytes | None = None
    for element_id, contents in _information_elements(packet):
        if element_id == 0 and ssid is None:
            ssid = contents.decode("utf-8", errors="replace")
        elif element_id in {3, 61} and contents:
            channel = contents[0]
        elif element_id == 1:
            rates = contents
        elif element_id == 50:
            extended_rates = contents
        elif element_id == 48:
            rsn = contents
        elif element_id == 221:
            if len(contents) == 9 and contents.startswith(BROADCOM_IE_PREFIX):
                evidence.add("broadcom_proprietary_ie")
            if contents.startswith(WPS_IE_PREFIX):
                wps_advertised = True
                parsed, wps_evidence = _parse_wps_attributes(
                    contents[len(WPS_IE_PREFIX) :]
                )
                identity.update(parsed)
                evidence.update(wps_evidence)
            elif contents.startswith(b"\x00\x50\xf2\x01"):
                wpa = contents
    if ssid is None:
        return None
    try:
        signal: Any = packet[RadioTap].dBm_AntSignal
        rssi = int(signal) if signal is not None else -127
    except (AttributeError, IndexError, TypeError, ValueError):
        rssi = -127
    return Observation(
        ssid=ssid,
        bssid=bssid,
        channel=channel,
        rssi_dbm=rssi,
        vendor=identity.get("vendor", "Unknown"),
        model=identity.get("model", "Unknown"),
        model_number=identity.get("model_number", "Unknown"),
        device_name=identity.get("device_name", "Unknown"),
        serial_number=identity.get("serial_number", "Unknown"),
        wps_advertised=wps_advertised,
        broadcom_evidence=tuple(sorted(evidence)),
        rates=rates,
        extended_rates=extended_rates,
        rsn=rsn,
        wpa=wpa,
    )


def select_target(observations: list[Observation], ssid: str) -> Observation:
    """Select the strongest exact-SSID BSSID with a deterministic tie break."""

    matches = [item for item in observations if item.ssid == ssid]
    if not matches:
        raise ValueError(f"SSID {ssid!r} was not observed")
    return min(matches, key=lambda item: (-item.rssi_dbm, item.bssid))


def decide_assessment(
    broadcom_detected: bool,
    differential: ResponseKind,
    *,
    cleaned_up: bool,
) -> Assessment:
    """Map an explicit implementation response to an assessment.

    ``cleaned_up`` is retained in the internal API so callers cannot accidentally
    omit the transaction health result.  Cleanup affects target health, not the
    meaning of an explicit differential response.
    """

    if differential is ResponseKind.REJECTED:
        return Assessment.LIKELY_VULNERABLE
    if differential is ResponseKind.ACK:
        return (
            Assessment.PATCHED_HOSTAPD
            if broadcom_detected
            else Assessment.NO_BROADCOM_FINGERPRINT
        )
    return Assessment.INCONCLUSIVE


def fingerprint_target(
    target: Observation,
    backend: FingerprintBackend,
) -> FingerprintResult:
    """Run one bounded differential without sending a continuation fragment."""

    if not target.wps_advertised:
        return FingerprintResult(
            target.ssid,
            target.bssid,
            target.channel,
            target.vendor,
            target.model,
            broadcom_evidence=target.broadcom_evidence,
            warning="selected AP does not advertise WPS",
        )
    # WPS entry already proves that the selected AP accepted this station and
    # reached its Expanded state.  A separate benign fragment used to repeat
    # that liveness check, but it left Broadcom's AP-global reassembly state
    # occupied until its timeout.  A zero declared length also makes Broadcom's
    # bounds check reject before a nonzero reassembly length can remain latched.
    # The implementation-family distinction only needs this explicit, bounded
    # first-fragment response.
    differential = backend.probe_first_fragment(
        target,
        0,
        b"",
        recover=False,
    )
    outcomes = (differential,)
    cleaned_up = differential.cleanup_sent
    assessment = decide_assessment(
        target.broadcom_detected,
        differential.response,
        cleaned_up=cleaned_up,
    )
    implementation = (
        "BROADCOM_WPS_MONITOR"
        if differential.response is ResponseKind.REJECTED
        else "HOSTAPD"
        if differential.response is ResponseKind.ACK
        else "INCONCLUSIVE"
    )
    target_health = (
        "DEGRADED"
        if not cleaned_up
        else "UNKNOWN"
        if assessment is Assessment.INCONCLUSIVE
        else "HEALTHY"
    )
    warning = None
    if assessment is Assessment.INCONCLUSIVE:
        warning = differential.detail or None
    if assessment is not Assessment.INCONCLUSIVE and not cleaned_up:
        cleanup_warning = "implementation response was explicit, but cleanup failed"
        warning = (
            f"{cleanup_warning}: {differential.detail}"
            if differential.detail
            else cleanup_warning
        )
    return FingerprintResult(
        target.ssid,
        target.bssid,
        target.channel,
        target.vendor,
        target.model,
        assessment,
        implementation,
        target_health,
        target.broadcom_evidence,
        outcomes,
        warning,
    )


def format_human_report(
    result: FingerprintResult,
    json_path: Path,
    pcap_path: Path,
) -> str:
    """Render the documented, intentionally compact terminal report."""

    return "\n".join(
        (
            f"SSID:       {result.ssid}",
            f"BSSID:      {result.bssid}",
            f"Channel:    {result.channel}",
            f"Vendor:     {result.vendor or 'Unknown'}",
            f"Model:      {result.model or 'Unknown'}",
            f"Assessment: {result.assessment}",
            f"JSON:       {json_path.resolve()}",
            f"PCAP:       {pcap_path.resolve()}",
        )
    )


def write_result_json(
    result: FingerprintResult,
    json_path: Path,
    pcap_path: Path,
) -> None:
    """Atomically write the stable machine-readable assessment."""

    stages = ("differential",)
    document = {
        "schema": "artemisia-broadcom-fingerprint/2",
        "schema_version": 2,
        "completed_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "target": {
            "ssid": result.ssid,
            "bssid": result.bssid,
            "channel": result.channel,
            "wps_identity": {
                "vendor": result.vendor or "Unknown",
                "model": result.model or "Unknown",
            },
        },
        "broadcom_sdk": {
            "detected": bool(result.broadcom_evidence)
            or result.implementation == "BROADCOM_WPS_MONITOR",
            "evidence": list(result.broadcom_evidence),
        },
        "implementation": result.implementation,
        "assessment": result.assessment,
        "target_health": result.target_health,
        "warning": result.warning,
        "transactions": [
            {
                "stage": stages[index] if index < len(stages) else f"step-{index + 1}",
                "response": outcome.response,
                "cleanup_sent": outcome.cleanup_sent,
                "fresh_wps_entry": outcome.recovered,
                "detail": outcome.detail,
            }
            for index, outcome in enumerate(result.outcomes)
        ],
        "artifacts": {
            "json": str(json_path.resolve()),
            "pcap": str(pcap_path.resolve()),
        },
        "claim_boundary": (
            "Implementation-family fingerprint only; no continuation fragment, "
            "memory access, or exploit verification was attempted."
        ),
    }
    temporary = json_path.with_suffix(json_path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(json_path)


@dataclass(frozen=True)
class MonitorState:
    """State which must survive a completed or interrupted run."""

    channel: int | None


def _run_iw(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as error:
        raise FingerprintError("iw is required for channel control") from error


def inspect_monitor_interface(interface: str) -> MonitorState:
    """Require one up monitor-mode interface and retain its channel."""

    if not re.fullmatch(r"[A-Za-z0-9_.-]+", interface):
        raise FingerprintError("interface name contains unsupported characters")
    result = _run_iw(["iw", "dev", interface, "info"])
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "interface not found"
        raise FingerprintError(f"cannot inspect interface {interface}: {detail}")
    type_match = re.search(r"^\s*type\s+(\S+)", result.stdout, re.MULTILINE)
    if type_match is None or type_match.group(1) != "monitor":
        raise FingerprintError(f"interface {interface} must already be in monitor mode")
    try:
        flags = int(
            Path(f"/sys/class/net/{interface}/flags")
            .read_text(encoding="ascii")
            .strip(),
            16,
        )
    except (OSError, ValueError) as error:
        raise FingerprintError(
            f"cannot determine link state for {interface}"
        ) from error
    if not flags & 1:
        raise FingerprintError(f"interface {interface} is down")
    channel_match = re.search(r"^\s*channel\s+(\d+)\b", result.stdout, re.MULTILINE)
    return MonitorState(
        channel=int(channel_match.group(1)) if channel_match is not None else None
    )


def set_channel(interface: str, channel: int) -> None:
    result = _run_iw(["iw", "dev", interface, "set", "channel", str(channel)])
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "command rejected"
        raise FingerprintError(f"cannot select channel {channel}: {detail}")


def random_station() -> str:
    octets = bytearray(secrets.token_bytes(6))
    octets[0] = (octets[0] | 0x02) & 0xFE
    return octets.hex(":")


# 802.11 data rates, in 500 kbit/s units. A rates element may also carry BSS
# membership selectors (HT/VHT PHY, SAE hash-to-element), which set the same
# high bit as a basic rate but are not rates and must not be transmitted at.
_DATA_RATES = frozenset({2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108})
_DEFAULT_RATE_MBPS = 1.0


def _lowest_basic_rate(target: Observation | None) -> float:
    """Return the rate to transmit at, in Mbps.

    Management frames belong at a basic rate: the BSSBasicRateSet is what every
    station in the BSS is required to decode. Rates carry the set in their high
    bit, so the lowest marked entry is the safe choice. Without a target yet, or
    for an advertisement that marks nothing, fall back to 1 Mbps DSSS.
    """

    if target is None:
        return _DEFAULT_RATE_MBPS
    basic = [
        value & 0x7F
        for value in target.rates + target.extended_rates
        if value & 0x80 and (value & 0x7F) in _DATA_RATES
    ]
    if not basic:
        return _DEFAULT_RATE_MBPS
    return min(basic) / 2


def _radiotap(target: Observation | None = None) -> Packet:
    """Pin the transmit rate rather than leaving it to the driver.

    A bare ``RadioTap()`` sets ``present=0``, so mac80211 chooses the rate and
    the frame can go out at a modulation the target does not answer.
    """

    return RadioTap(present="Rate", Rate=_lowest_basic_rate(target))


def _wildcard_probe(station: str) -> Packet:
    return (
        _radiotap()
        / Dot11(
            type=0,
            subtype=4,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=station,
            addr3="ff:ff:ff:ff:ff:ff",
        )
        / Dot11ProbeReq()
        / Dot11Elt(ID="SSID", info=b"")
        / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
        / Dot11Elt(ID="ESRates", info=b"\x30\x48\x60\x6c")
    )


def _directed_probe(station: str, target: Observation) -> Packet:
    return (
        _radiotap(target)
        / Dot11(
            type=0,
            subtype=4,
            addr1=target.bssid,
            addr2=station,
            addr3=target.bssid,
        )
        / Dot11ProbeReq()
        / Dot11Elt(ID="SSID", info=target.ssid.encode("utf-8"))
        / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96")
    )


def _merge_observation(left: Observation, right: Observation) -> Observation:
    """Combine repeated advertisements without losing richer WPS metadata."""

    def richer(primary: str, secondary: str) -> str:
        return primary if primary != "Unknown" else secondary

    strongest, other = (
        (left, right) if left.rssi_dbm >= right.rssi_dbm else (right, left)
    )
    return Observation(
        ssid=left.ssid,
        bssid=left.bssid,
        channel=strongest.channel,
        rssi_dbm=max(left.rssi_dbm, right.rssi_dbm),
        vendor=richer(right.vendor, left.vendor),
        model=richer(right.model, left.model),
        model_number=richer(right.model_number, left.model_number),
        device_name=richer(right.device_name, left.device_name),
        serial_number=richer(right.serial_number, left.serial_number),
        wps_advertised=left.wps_advertised or right.wps_advertised,
        broadcom_evidence=tuple(
            sorted(set(left.broadcom_evidence) | set(right.broadcom_evidence))
        ),
        rates=strongest.rates or other.rates,
        extended_rates=strongest.extended_rates or other.extended_rates,
        rsn=strongest.rsn if strongest.rsn is not None else other.rsn,
        wpa=strongest.wpa if strongest.wpa is not None else other.wpa,
    )


class LiveDiscovery:
    """Continuous 2.4 GHz discovery with capture limited to the requested SSID."""

    def __init__(
        self,
        interface: str,
        pcap: PcapWriter,
        *,
        dwell: float = DEFAULT_DWELL,
    ) -> None:
        self.interface = interface
        self.pcap = pcap
        self.dwell = dwell
        self.station = random_station()
        self._pcap_lock = threading.Lock()

    def _write(self, packet: Packet) -> None:
        with self._pcap_lock:
            self.pcap.write(packet)

    def scan_sweep(self, ssid: str) -> list[Observation]:
        matches: dict[str, Observation] = {}
        usable_channels = 0
        for channel in DEFAULT_CHANNELS:
            try:
                set_channel(self.interface, channel)
            except FingerprintError as error:
                print(f"warning: {error}", file=sys.stderr)
                continue
            usable_channels += 1

            def remember(packet: Packet, selected_channel: int = channel) -> None:
                observed = parse_advertisement(packet, channel_hint=selected_channel)
                if observed is None or observed.ssid != ssid:
                    return
                self._write(packet)
                previous = matches.get(observed.bssid)
                matches[observed.bssid] = (
                    observed
                    if previous is None
                    else _merge_observation(previous, observed)
                )

            sniffer = AsyncSniffer(iface=self.interface, store=False, prn=remember)
            sniffer.start()
            try:
                probe = _wildcard_probe(self.station)
                self._write(probe)
                sendp(probe, iface=self.interface, verbose=False)
                time.sleep(self.dwell)
            finally:
                sniffer.stop()
        if usable_channels == 0:
            raise FingerprintError("none of channels 1-13 could be selected")
        return list(matches.values())

    def revalidate(self, selected: Observation) -> Observation:
        set_channel(self.interface, selected.channel)
        validated: Observation | None = None

        def remember(packet: Packet) -> None:
            nonlocal validated
            observed = parse_advertisement(packet, channel_hint=selected.channel)
            if (
                observed is None
                or observed.ssid != selected.ssid
                or observed.bssid != selected.bssid
                or observed.channel != selected.channel
            ):
                return
            self._write(packet)
            validated = (
                observed
                if validated is None
                else _merge_observation(validated, observed)
            )

        sniffer = AsyncSniffer(iface=self.interface, store=False, prn=remember)
        sniffer.start()
        try:
            probe = _directed_probe(self.station, selected)
            self._write(probe)
            sendp(probe, iface=self.interface, verbose=False)
            time.sleep(max(1.0, self.dwell * 2))
        finally:
            sniffer.stop()
        if validated is None:
            raise FingerprintError(
                "selected SSID/BSSID was not observed during revalidation"
            )
        return _merge_observation(selected, validated)


def _authentication_frame(station: str, target: Observation) -> Packet:
    return (
        _radiotap(target)
        / Dot11(
            type=0,
            subtype=11,
            addr1=target.bssid,
            addr2=station,
            addr3=target.bssid,
        )
        / Dot11Auth(algo=0, seqnum=1, status=0)
    )


def _association_frame(
    station: str,
    target: Observation,
    *,
    minimal: bool,
) -> Packet:
    # Both attempts carry the AP's advertised supported + extended rates so the
    # BSSBasicRateSet check (status 18) is satisfied. The difference is security:
    # the "full" attempt includes a sanitized RSN (PSK/CCMP, PMF-capable), while
    # the "minimal" attempt drops RSN entirely for open/legacy APs.
    rates = target.rates
    frame = (
        _radiotap(target)
        / Dot11(
            type=0,
            subtype=0,
            addr1=target.bssid,
            addr2=station,
            addr3=target.bssid,
        )
        / Dot11AssoReq(cap=0x1114, listen_interval=10)
        / Dot11Elt(ID="SSID", info=target.ssid.encode("utf-8"))
        / Dot11Elt(ID="Rates", info=rates)
    )
    if target.extended_rates:
        frame /= Dot11Elt(ID=50, info=target.extended_rates)
    if not minimal and target.rsn is not None:
        station_rsn = _station_rsn_element(target.rsn)
        if station_rsn is not None:
            frame /= Dot11Elt(ID=48, info=station_rsn)
    if not minimal and target.wpa is not None:
        frame /= Dot11Elt(ID=221, info=target.wpa)
    frame /= Dot11Elt(ID=221, info=WPS_ASSOCIATION_IE)
    return frame


ASSOC_STATUS_MEANINGS = {
    1: "unspecified failure",
    10: "cannot support all requested capabilities",
    12: "association denied, reason outside scope of this standard",
    17: "association denied; AP unable to handle additional stations",
    18: "denied; STA not supporting all BSSBasicRateSet data rates",
    27: "association denied; HT features required but not supported",
    31: "association denied; RSN cipher/AKM policy violation",
    40: "invalid information element",
    41: "invalid group cipher",
    42: "invalid pairwise cipher",
    43: "invalid AKMP (authentication/key management)",
    45: "invalid RSN capabilities",
    46: "cipher suite rejected per security policy",
    53: "invalid PMKID",
    77: "unsupported finite cyclic group (SAE)",
}


def _assoc_status_meaning(status: int) -> str:
    return ASSOC_STATUS_MEANINGS.get(status, "see IEEE 802.11 status code table")


def _station_rsn_element(ap_rsn: bytes | None) -> bytes | None:
    """Derive a station-side RSN element the AP will accept for open-auth WPS.

    The AP's advertised RSN is parsed for its group and pairwise ciphers, but the
    AKM list is reduced to PSK (the only key-management a plain WPS enrollee can
    satisfy) and the RSN Capabilities are rewritten so PMF is advertised as
    *capable* (MFPC) but not *required* (MFPR clear). Echoing the AP's RSN
    verbatim keeps SAE/MFPR, which a non-SAE station cannot honor, and the AP
    answers the association with status 18/43.
    """

    group_cipher = RSN_CIPHER_CCMP
    pairwise = [RSN_CIPHER_CCMP]
    akm_has_psk_sha256 = False

    if ap_rsn is not None:
        try:
            # Layout: version(2) group(4) pcount(2) pairwise[...] acount(2) akm[...]
            offset = 2
            group_cipher = ap_rsn[offset : offset + 4] or group_cipher
            offset += 4
            pcount = int.from_bytes(ap_rsn[offset : offset + 2], "little")
            offset += 2
            advertised_pairwise = [
                ap_rsn[offset + i * 4 : offset + i * 4 + 4] for i in range(pcount)
            ]
            offset += pcount * 4
            acount = int.from_bytes(ap_rsn[offset : offset + 2], "little")
            offset += 2
            advertised_akm = [
                ap_rsn[offset + i * 4 : offset + i * 4 + 4] for i in range(acount)
            ]
            # Prefer CCMP; fall back to whatever pairwise cipher the AP offered.
            if advertised_pairwise:
                pairwise = (
                    [RSN_CIPHER_CCMP]
                    if RSN_CIPHER_CCMP in advertised_pairwise
                    else advertised_pairwise[:1]
                )
            akm_has_psk_sha256 = RSN_AKM_PSK_SHA256 in advertised_akm
        except (IndexError, ValueError):
            group_cipher = RSN_CIPHER_CCMP
            pairwise = [RSN_CIPHER_CCMP]

    # When the AP mandates PMF, PSK-SHA256 is the correct AKM; otherwise plain PSK.
    akm = RSN_AKM_PSK_SHA256 if akm_has_psk_sha256 else RSN_AKM_PSK

    body = b"\x01\x00"  # RSN version 1
    body += group_cipher
    body += len(pairwise).to_bytes(2, "little") + b"".join(pairwise)
    body += (1).to_bytes(2, "little") + akm
    body += RSN_CAPS_MFPC.to_bytes(2, "little")  # MFPC set, MFPR clear
    return body


def _station_data_frame(
    station: str,
    target: Observation,
    eapol: bytes,
) -> Packet:
    return (
        _radiotap(target)
        / Dot11(
            type=2,
            subtype=0,
            FCfield=0x01,
            addr1=target.bssid,
            addr2=station,
            addr3=target.bssid,
        )
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0, code=ETH_P_PAE)
        / Raw(eapol)
    )


def _deauthentication_frame(station: str, target: Observation) -> Packet:
    return (
        _radiotap(target)
        / Dot11(
            type=0,
            subtype=12,
            addr1=target.bssid,
            addr2=station,
            addr3=target.bssid,
        )
        / Dot11Deauth(reason=3)
    )


def _ethernet_eapol(eapol: bytes) -> bytes:
    return bytes(12) + b"\x88\x8e" + eapol


def _eapol_start() -> bytes:
    return _ethernet_eapol(b"\x02\x01\x00\x00")


def _eapol_eap(eap: bytes) -> bytes:
    return _ethernet_eapol(b"\x01\x00" + len(eap).to_bytes(2, "big") + eap)


def _identity_response(identifier: int) -> bytes:
    length = 5 + len(WFA_IDENTITY)
    eap = bytes((2, identifier)) + length.to_bytes(2, "big") + b"\x01" + WFA_IDENTITY
    return _eapol_eap(eap)


def _wps_response(identifier: int, flags: int, data: bytes) -> bytes:
    length = 14 + len(data)
    eap = (
        bytes((2, identifier))
        + length.to_bytes(2, "big")
        + b"\xfe"
        + WPS_VENDOR
        + WPS_VENDOR_TYPE
        + bytes((WSC_MESSAGE, flags))
        + data
    )
    return _eapol_eap(eap)


def _parse_eapol(eapol: bytes) -> tuple[int, int, bytes] | None:
    if len(eapol) < 8 or eapol[1] != 0:
        return None
    eapol_length = int.from_bytes(eapol[2:4], "big")
    eap = eapol[4 : 4 + eapol_length]
    if len(eap) < 4:
        return None
    declared = int.from_bytes(eap[2:4], "big")
    if declared < 4 or len(eap) < declared:
        return None
    return eap[0], eap[1], eap[:declared]


def _parse_ap_eap(
    packet: Packet,
    station: str,
    bssid: str,
) -> tuple[int, int, bytes] | None:
    if not packet.haslayer(Dot11) or not packet.haslayer(SNAP):
        return None
    dot11 = packet[Dot11]
    if (
        str(dot11.addr1 or "").lower() != station.lower()
        or str(dot11.addr2 or "").lower() != bssid.lower()
        or int(packet[SNAP].code) != ETH_P_PAE
    ):
        return None
    return _parse_eapol(bytes(packet[SNAP].payload))


class ScapyFingerprintBackend:
    """Raw monitor-mode transport pinned to one selected BSSID."""

    def __init__(
        self,
        interface: str,
        target: Observation,
        pcap: PcapWriter,
        *,
        response_timeout: float = DEFAULT_RESPONSE_TIMEOUT,
        partial_release_delay: float = PARTIAL_SESSION_RELEASE_DELAY,
        debug_assoc: bool = False,
    ) -> None:
        self.interface = interface
        self.target = target
        self.pcap = pcap
        self.response_timeout = response_timeout
        self.partial_release_delay = partial_release_delay
        self.debug_assoc = debug_assoc
        self.packets: queue.Queue[Packet] = queue.Queue()
        self._pcap_lock = threading.Lock()
        self._seen_eap: dict[str, set[bytes]] = {}
        self._sequences: dict[str, int] = {}
        self._recovered_session: tuple[str, int] | None = None
        self._sniffer: AsyncSniffer | None = None
        self._capture_station: str | None = None

    def __enter__(self) -> Self:
        set_channel(self.interface, self.target.channel)
        self._start_capture()
        return self

    def __exit__(
        self,
        _kind: type[BaseException] | None,
        _value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        recovered_session = self._recovered_session
        self._recovered_session = None
        if recovered_session is not None:
            try:
                self._deauthenticate(recovered_session[0])
            except Exception:  # noqa: BLE001, S110 - capture shutdown still required
                pass
        self._stop_capture()

    def _start_capture(self) -> None:
        if self._sniffer is not None:
            raise FingerprintError("capture is already running")
        # ``_receive`` already drops every frame outside this exchange, but only after
        # scapy has dissected it, and dissecting 802.11 is the cost on a weak host: on
        # a WiFi Pineapple Mk7 (MIPS 24KEc, 385 BogoMIPS) a callback that reaches the
        # Dot11 layer keeps up with 4 to 6 frames per second, whatever the filter.
        # Matching the BSSID alone does not get under that, because every frame of
        # every other client of the BSS carries it in one of the three address fields:
        # 6.3 frames per second measured on an idle home AP, which saturates the budget
        # and leaves the capture seconds behind the air. Pairing it with the station
        # address identifies the exchange exactly, and the same channel then delivers
        # 0 frames per second while idle.
        #
        # Address fields are named one by one rather than with ``wlan host``, whose
        # expansion is frame-type dependent: on a from-DS data frame it tests addr3 and
        # addr1 and never addr2, which is the field ``_parse_ap_eap`` keys on, and it
        # rejects control frames before examining any address.
        bssid = self.target.bssid
        station = self._capture_station
        capture_filter = (
            f"(wlan addr1 {bssid} or wlan addr2 {bssid} or wlan addr3 {bssid})"
        )
        if station is None:
            # No station is in play yet, so drop the beacons at least.
            capture_filter += " and not (type mgt and subtype beacon)"
        else:
            capture_filter += f" and (wlan addr1 {station} or wlan addr2 {station})"
        kwargs: dict[str, str] = {}
        try:
            # Validate here, in this thread. AsyncSniffer builds its socket inside
            # the sniffing thread and stores the failure in ``exception``, so
            # ``start()`` returns cleanly and a rejected filter would otherwise leave
            # a live object with a dead thread and no capture at all.
            compile_filter(capture_filter, iface=self.interface)
        except Exception:  # noqa: BLE001, S110 - an unfiltered capture still works
            pass
        else:
            kwargs["filter"] = capture_filter
        sniffer = AsyncSniffer(
            iface=self.interface,
            store=False,
            prn=self._receive,
            **kwargs,
        )
        self._sniffer = sniffer
        try:
            sniffer.start()
            time.sleep(0.15)
        except Exception:
            self._sniffer = None
            raise

    def _stop_capture(self) -> None:
        sniffer = self._sniffer
        self._sniffer = None
        if sniffer is None:
            return
        try:
            sniffer.stop()
        except Exception:  # noqa: BLE001, S110 - capture may already be stopped
            pass

    def _wait_for_partial_release(self, delay: float) -> None:
        """Quiesce capture across AP-global partial-reassembly timeouts."""

        self._stop_capture()
        time.sleep(delay)
        set_channel(self.interface, self.target.channel)
        self._start_capture()

    def _retune_capture(self, station: str) -> None:
        """Narrow the kernel filter to one station, restarting the sniffer if needed."""

        wanted = station.lower()
        if self._capture_station == wanted and self._sniffer is not None:
            return
        self._stop_capture()
        self._capture_station = wanted
        self._start_capture()

    def _write(self, packet: Packet) -> None:
        with self._pcap_lock:
            self.pcap.write(packet)

    def _receive(self, packet: Packet) -> None:
        if not packet.haslayer(Dot11):
            return
        dot11 = packet[Dot11]
        addresses = {
            str(dot11.addr1 or "").lower(),
            str(dot11.addr2 or "").lower(),
            str(dot11.addr3 or "").lower(),
        }
        if self.target.bssid not in addresses:
            return
        self._write(packet)
        self.packets.put(packet)

    def _transmit(self, packet: Packet) -> None:
        dot11 = packet.getlayer(Dot11)
        if dot11 is None:
            raise FingerprintError("refusing to transmit a non-802.11 frame")
        addresses = {
            str(dot11.addr1 or "").lower(),
            str(dot11.addr3 or "").lower(),
        }
        if self.target.bssid not in addresses:
            raise FingerprintError("refusing to transmit outside the pinned BSSID")
        station = str(dot11.addr2 or "").lower()
        sequence = self._sequences.setdefault(station, secrets.randbelow(0x1000))
        dot11.SC = sequence << 4
        self._sequences[station] = (sequence + 1) & 0xFFF
        payload = bytes(dot11.payload)
        if len(payload) > MAC_FRAGMENT_SIZE:
            header = dot11.copy()
            header.remove_payload()
            fragments: list[Packet] = []
            for offset in range(0, len(payload), MAC_FRAGMENT_SIZE):
                chunk = payload[offset : offset + MAC_FRAGMENT_SIZE]
                fragment_header = header.copy()
                flags = int(fragment_header.FCfield)
                if offset + len(chunk) < len(payload):
                    flags |= 0x04
                else:
                    flags &= ~0x04
                fragment_header.FCfield = flags
                fragment_header.SC = (sequence << 4) | (offset // MAC_FRAGMENT_SIZE)
                fragments.append(_radiotap(self.target) / fragment_header / Raw(chunk))
            with self._pcap_lock:
                for fragment in fragments:
                    self.pcap.write(fragment)
            sendp(
                fragments,
                iface=self.interface,
                count=1,
                inter=0.002,
                verbose=False,
            )
            return
        self._write(packet)
        sendp(packet, iface=self.interface, count=1, verbose=False)

    def _wait_for(
        self,
        predicate: Callable[[Packet], bool],
        timeout: float,
    ) -> Packet:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                packet = self.packets.get(
                    timeout=max(0.01, deadline - time.monotonic())
                )
            except queue.Empty as error:
                raise TimeoutError("timed out waiting for an RF response") from error
            if predicate(packet):
                return packet
        raise TimeoutError("timed out waiting for a matching RF response")

    def _reset_station(self, station: str) -> None:
        self._seen_eap.pop(station.lower(), None)
        self._retune_capture(station)
        while True:
            try:
                self.packets.get_nowait()
            except queue.Empty:
                return

    def _debug_assoc(self, message: str) -> None:
        if self.debug_assoc:
            print(f"[assoc] {message}", file=sys.stderr)

    def _associate(self, station: str, deadline: float) -> None:
        seen_association_responses: set[int] = set()

        def remaining(limit: float) -> float:
            available = deadline - time.monotonic()
            if available <= 0:
                raise TimeoutError("association deadline expired")
            return min(limit, available)

        def is_new_association_response(packet: Packet) -> bool:
            if (
                not packet.haslayer(Dot11AssoResp)
                or str(packet[Dot11].addr1 or "").lower() != station
                or str(packet[Dot11].addr2 or "").lower() != self.target.bssid
            ):
                return False
            sequence = int(packet[Dot11].SC) >> 4
            if sequence in seen_association_responses:
                return False
            seen_association_responses.add(sequence)
            return True

        for attempt in range(3):
            self._transmit(_authentication_frame(station, self.target))
            try:
                auth = self._wait_for(
                    lambda packet: (
                        packet.haslayer(Dot11Auth)
                        and str(packet[Dot11].addr1 or "").lower() == station
                        and str(packet[Dot11].addr2 or "").lower() == self.target.bssid
                    ),
                    remaining(1.5),
                )
            except TimeoutError:
                self._debug_assoc(
                    f"attempt {attempt + 1}: no authentication response "
                    f"(station {station} may be filtered or off-channel)"
                )
                continue
            if int(auth[Dot11Auth].status) != 0:
                raise FingerprintError(
                    f"authentication rejected with status {int(auth[Dot11Auth].status)}"
                )
            self._debug_assoc(f"attempt {attempt + 1}: authentication accepted")
            for minimal in (False, True):
                self._transmit(
                    _association_frame(station, self.target, minimal=minimal)
                )
                try:
                    response = self._wait_for(
                        is_new_association_response,
                        remaining(2.0),
                    )
                except TimeoutError:
                    self._debug_assoc(
                        f"attempt {attempt + 1} ({'minimal' if minimal else 'full'}): "
                        "no association response"
                    )
                    continue
                status = int(response[Dot11AssoResp].status)
                if status == 0:
                    self._debug_assoc(
                        f"attempt {attempt + 1} "
                        f"({'minimal' if minimal else 'full'}): association accepted"
                    )
                    return
                self._debug_assoc(
                    f"attempt {attempt + 1} ({'minimal' if minimal else 'full'}): "
                    f"association rejected with status {status} "
                    f"({_assoc_status_meaning(status)})"
                )
        raise FingerprintError("could not authenticate and associate selected target")

    def _send_eapol(self, station: str, ethernet_record: bytes) -> None:
        if len(ethernet_record) < 18 or ethernet_record[12:14] != b"\x88\x8e":
            raise ValueError("only Ethernet-shaped EAPOL records are accepted")
        self._transmit(_station_data_frame(station, self.target, ethernet_record[14:]))

    def _wait_eap(
        self,
        station: str,
        timeout: float,
        *,
        accept_repeated: bool,
    ) -> tuple[int, int, bytes]:
        def wanted(packet: Packet) -> bool:
            if (
                packet.haslayer(Dot11Deauth) or packet.haslayer(Dot11Disas)
            ) and packet.haslayer(Dot11):
                return (
                    str(packet[Dot11].addr1 or "").lower() == station
                    and str(packet[Dot11].addr2 or "").lower() == self.target.bssid
                )
            parsed = _parse_ap_eap(packet, station, self.target.bssid)
            if parsed is None:
                return False
            eap = parsed[2]
            seen = self._seen_eap.setdefault(station.lower(), set())
            if not accept_repeated and eap in seen:
                return False
            seen.add(eap)
            return True

        packet = self._wait_for(wanted, timeout)
        if packet.haslayer(Dot11Deauth):
            raise StationStateLost("deauthenticated", int(packet[Dot11Deauth].reason))
        if packet.haslayer(Dot11Disas):
            raise StationStateLost("disassociated", int(packet[Dot11Disas].reason))
        parsed = _parse_ap_eap(packet, station, self.target.bssid)
        assert parsed is not None
        return parsed

    def _start_wps(self, station: str) -> int:
        self._reset_station(station)
        deadline = time.monotonic() + self.response_timeout
        self._associate(station, deadline)
        self._send_eapol(station, _eapol_start())
        last_identity: int | None = None
        association_recovered = False
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                code, identifier, eap = self._wait_eap(
                    station,
                    min(RETRANSMIT_INTERVAL, remaining),
                    accept_repeated=True,
                )
            except StationStateLost as error:
                retryable = (
                    not association_recovered
                    and error.action == "deauthenticated"
                    and error.reason == 7
                    and time.monotonic() < deadline
                )
                if not retryable:
                    raise
                association_recovered = True
                self._reset_station(station)
                self._associate(station, deadline)
                last_identity = None
                self._send_eapol(station, _eapol_start())
                continue
            except TimeoutError:
                if last_identity is None:
                    self._send_eapol(station, _eapol_start())
                else:
                    self._send_eapol(station, _identity_response(last_identity))
                continue
            if code == 1 and len(eap) >= 5 and eap[4] == 1:
                last_identity = identifier
                self._send_eapol(station, _identity_response(identifier))
                continue
            if code == 1 and len(eap) >= 14 and eap[4] == 0xFE:
                if eap[12] == WSC_START:
                    return identifier
                continue
            raise FingerprintError(
                f"unexpected EAP during WPS entry: code={code} len={len(eap)}"
            )
        raise FingerprintError("WPS entry timed out before an Expanded request")

    def _deauthenticate(self, station: str) -> None:
        frame = _deauthentication_frame(station, self.target)
        for _attempt in range(3):
            self._transmit(frame.copy())
            time.sleep(0.04)

    def _recover(self) -> tuple[bool, str]:
        failures: list[str] = []
        for _attempt in range(2):
            station = random_station()
            try:
                identifier = self._start_wps(station)
                self._recovered_session = (station, identifier)
                return True, ""
            except Exception as error:  # noqa: BLE001 - retain recovery evidence
                failures.append(f"{type(error).__name__}: {error}")
                try:
                    self._deauthenticate(station)
                except Exception:  # noqa: BLE001, S110 - original failure retained
                    pass
        return False, "; ".join(failures)

    def probe_first_fragment(
        self,
        target: Observation,
        total_length: int,
        payload: bytes,
        *,
        recover: bool = True,
    ) -> TransactionOutcome:
        if target.bssid != self.target.bssid:
            raise FingerprintError("backend target changed after BSSID pinning")
        if not 0 <= total_length <= 0xFFFF or len(payload) > total_length:
            raise ValueError("first fragment exceeds its declared total")
        recovered_session = getattr(self, "_recovered_session", None)
        if recovered_session is None:
            station = random_station()
            identifier: int | None = None
        else:
            station, identifier = recovered_session
            self._recovered_session = None
        response = ResponseKind.ERROR
        detail = ""
        cleanup_sent = False
        try:
            if identifier is None:
                identifier = self._start_wps(station)
            data = total_length.to_bytes(2, "big") + payload
            request = _wps_response(
                identifier,
                LENGTH_FIELD | MORE_FRAGMENTS,
                data,
            )
            deadline = time.monotonic() + self.response_timeout
            while True:
                self._send_eapol(station, request)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("fragment response deadline expired")
                try:
                    code, _identifier, eap = self._wait_eap(
                        station,
                        min(RETRANSMIT_INTERVAL, remaining),
                        accept_repeated=False,
                    )
                    break
                except TimeoutError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(
                            "fragment response deadline expired"
                        ) from None
            if code == 4:
                response = ResponseKind.REJECTED
            elif code == 1 and len(eap) >= 14 and eap[12] == WSC_FRAGMENT_ACK:
                response = ResponseKind.ACK
            else:
                detail = f"unexpected response code={code} len={len(eap)}"
        except TimeoutError as error:
            response = ResponseKind.SILENCE
            detail = str(error)
        except StationStateLost as error:
            if error.action == "deauthenticated" and error.reason == 0:
                response = ResponseKind.REJECTED
                detail = "target rejected first fragment by deauthentication (reason=0)"
            else:
                detail = f"{type(error).__name__}: {error}"
        except Exception as error:  # noqa: BLE001 - RF ambiguity is an outcome
            detail = f"{type(error).__name__}: {error}"
        try:
            self._deauthenticate(station)
            cleanup_sent = True
        except Exception as error:  # noqa: BLE001 - retain cleanup evidence
            detail = f"{detail + '; ' if detail else ''}cleanup failed: {error}"
        if not recover:
            return TransactionOutcome(response, cleanup_sent, None, detail)
        if (
            response in {ResponseKind.ACK, ResponseKind.REJECTED}
            and cleanup_sent
            and self.partial_release_delay > 0
        ):
            try:
                self._wait_for_partial_release(self.partial_release_delay)
            except Exception as error:  # noqa: BLE001 - retain recovery evidence
                detail = (
                    f"{detail + '; ' if detail else ''}"
                    f"capture restart after partial release failed: {error}"
                )
                return TransactionOutcome(response, cleanup_sent, False, detail)
        recovered, recovery_detail = self._recover()
        if recovery_detail:
            detail = f"{detail + '; ' if detail else ''}{recovery_detail}"
        return TransactionOutcome(response, cleanup_sent, recovered, detail)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Safely fingerprint Broadcom WPS Monitor versus hostapd for one SSID."
        )
    )
    parser.add_argument("--interface", required=True, help="existing monitor interface")
    parser.add_argument("--ssid", required=True, help="exact SSID to locate")
    parser.add_argument(
        "--debug-assoc",
        action="store_true",
        help="log 802.11 authentication/association status codes to stderr",
    )
    return parser


def _artifact_directory(root: Path) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    path = (root / f"broadcom-fingerprint-{stamp}").resolve()
    try:
        path.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        raise FingerprintError(
            f"cannot create evidence directory under {root}: {error}"
        ) from error
    return path


def _append_warning(result: FingerprintResult, warning: str) -> FingerprintResult:
    combined = f"{result.warning}; {warning}" if result.warning else warning
    return dataclass_replace(result, warning=combined)


def run_live(
    interface: str,
    ssid: str,
    *,
    output_root: Path | None = None,
    debug_assoc: bool = False,
) -> int:
    try:
        encoded_ssid = ssid.encode("utf-8")
    except UnicodeEncodeError as error:
        raise FingerprintError("SSID must be valid UTF-8") from error
    if not encoded_ssid or len(encoded_ssid) > 32:
        raise FingerprintError("SSID must encode to 1..32 UTF-8 bytes")
    root = Path.cwd() if output_root is None else output_root
    evidence_dir = _artifact_directory(root)
    json_path = evidence_dir / "result.json"
    pcap_path = evidence_dir / "traffic.pcap"
    writer = PcapWriter(str(pcap_path), linktype=127, sync=True)
    state: MonitorState | None = None
    target: Observation | None = None
    result: FingerprintResult | None = None
    exit_code = 2
    pending_error: str | None = None
    try:
        state = inspect_monitor_interface(interface)
        discovery = LiveDiscovery(interface, writer)
        sweep = 0
        while target is None:
            sweep += 1
            print(
                f"Scanning channels 1-13 for SSID {ssid!r} (sweep {sweep})...",
                file=sys.stderr,
            )
            observations = discovery.scan_sweep(ssid)
            if observations:
                target = select_target(observations, ssid)
        target = discovery.revalidate(target)
        if target.wps_advertised:
            with ScapyFingerprintBackend(
                interface, target, writer, debug_assoc=debug_assoc
            ) as backend:
                result = fingerprint_target(target, backend)
        else:
            result = FingerprintResult(
                target.ssid,
                target.bssid,
                target.channel,
                target.vendor,
                target.model,
                broadcom_evidence=target.broadcom_evidence,
                warning="selected AP does not advertise WPS",
            )
        exit_code = 1 if result.assessment is Assessment.INCONCLUSIVE else 0
    except KeyboardInterrupt:
        pending_error = "operator interrupted the scan"
        exit_code = 130
    except Exception as error:  # noqa: BLE001 - preserve failure in JSON report
        pending_error = f"{type(error).__name__}: {error}"
        exit_code = 2
    finally:
        restore_error: str | None = None
        if state is not None and state.channel is not None:
            try:
                set_channel(interface, state.channel)
            except Exception as error:  # noqa: BLE001 - restoration is best effort
                restore_error = f"could not restore original channel: {error}"
        writer.close()

    if result is None:
        result = FingerprintResult(
            ssid=ssid,
            bssid=target.bssid if target is not None else "Unknown",
            channel=target.channel if target is not None else "Unknown",
            vendor=target.vendor if target is not None else "Unknown",
            model=target.model if target is not None else "Unknown",
            broadcom_evidence=(target.broadcom_evidence if target is not None else ()),
            target_health="UNKNOWN",
            warning=pending_error,
        )
    elif pending_error:
        result = _append_warning(result, pending_error)
    if restore_error:
        result = _append_warning(result, restore_error)
    write_result_json(result, json_path, pcap_path)
    print(format_human_report(result, json_path, pcap_path))
    if result.warning:
        print(f"Warning: {result.warning}", file=sys.stderr)
    return exit_code


def main(argv: list[str] | None = None) -> int:
    options = build_parser().parse_args(argv)
    try:
        return run_live(options.interface, options.ssid, debug_assoc=options.debug_assoc)
    except FingerprintError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
