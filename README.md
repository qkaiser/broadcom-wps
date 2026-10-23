# Broadcom 802.11 SDK Detection Toolkit

This repository contains two ways to detect the presence of Broadcom's 802.11 implementation on a target router:
1. Statically using YARA rules on extracted firmware
2. Dynamically by running a fingerprinting script against a live access point

The list of affected devices is available at the end of this page. **This list is not exhaustive**. We expect the complete list to contain thousands of different devices, make and models.

## Broadcom WPS Monitor YARA rules

`broadcom_wps_monitor.yar` contains three candidate detectors for ELF32 ARM and
MIPS binaries:

- `BRCM_WPS_Monitor_Generic_ELF` identifies a generic Broadcom WPS Monitor
  binary from independent vendor and protocol strings.
- `BRCM_WPS_Monitor_HAL_Config_ELF` identifies the narrower HAL configuration
  event variant.
- `VULN_BRCM_WPS_EAP_Fragment_Reassembly_ELF` requires the generic component
  evidence plus an ARM or MIPS opcode shape associated with the vulnerable
  fragment-reassembly path.

These rules are triage aids. Compiler changes can evade
opcode patterns, and a patched binary can retain strings or code bytes used by
a candidate detector. Confirm findings against the integrated source or by
manual review of the fragment-length validation and copy sink.

You can find binaries with this command:

```sh
yara -w -r broadcom_wps_monitor.yar extracted_firmware_dir
```

## Broadcom SDK Fingerprinter

Make sure your interface supports monitor mode and enable monitor mode.

> [!TIP]
> **Prevent NetworkManager interference:** Before switching to monitor mode, prevent NetworkManager from managing or resetting the interface:
> ```sh
> sudo nmcli device set <interface> managed no
> ```

Enable monitor mode using the `otherbss control` flags (important: without `otherbss`, drivers such as MediaTek `mt76` / `mt7921` will drop frames from other BSSIDs):

```sh
sudo ip link set dev wlp0s12u1 down
sudo iw dev wlp0s12u1 set monitor otherbss control
sudo ip link set dev wlp0s12u1 up
```

### Quick Verification

Verify that your card is receiving frames in monitor mode with `tcpdump` (set to a channel with known traffic, e.g., channel 1, 3, or 6):

```sh
sudo iw dev wlp0s12u1 set channel 6
sudo tcpdump -i wlp0s12u1 -e -n -c 5 "type mgt subtype beacon"
```

If beacons appear, your adapter is successfully receiving 802.11 frames.

> **Note on hardware:** monitor mode / frame injection is very driver-dependent.
> In testing, the built-in **Intel Dual Band Wireless-AC 7265** (`iwlwifi`)
> accepted `type monitor` but captured **zero** frames (no beacons even with a
> strong signal), so the fingerprinter never locked onto a target. MediaTek chipsets
> — such as **MT7921AU** (USB id `0e8d:7961`, driver `mt7921u`) or **MT7922** (`mt7921e`) —
> work properly when configured with `set monitor otherbss control`. If the script keeps
> sweeping without finding your SSID, check that `otherbss` is enabled and test with `tcpdump`.
> Known-good chipsets for this kind of work include MediaTek `mt76`, Atheros `ath9k_htc`, and Realtek `rtl8812au`.

### Running the Fingerprinter

> [!TIP]
> If `uv` is installed in your user directory (e.g., `~/.local/bin/uv`) and `sudo` reports `uv: command not found`, either run with `sudo env "PATH=$PATH"` or directly invoke the virtual environment's Python:
> ```sh
> sudo .venv/bin/python broadcom_fingerprint.py --interface <interface> --ssid "<SSID>"
> ```
> *(Always wrap the SSID in quotes if it contains spaces or special characters).*

You should see something like this on affected devices:

```sh
sudo uv run --with scapy broadcom_fingerprint.py --interface wlp0s12u1 --ssid VOO-111317
Scanning channels 1-13 for SSID 'VOO-111317' (sweep 1)...
SSID:       VOO-111317
BSSID:      20:0c:c8:16:76:dc
Channel:    1
Vendor:     Netgear
Model:      Netgear
Assessment: LIKELY_VULNERABLE
JSON:       /tmp/broadcom-fingerprint-20261014T203352.732742Z/result.json
PCAP:       /tmp/broadcom-fingerprint-20261014T203352.732742Z/traffic.pcap
```

```
sudo uv run --with scapy broadcom_fingerprint.py --interface wlp0s12u1 --ssid Orange-180cd
Scanning channels 1-13 for SSID 'Orange-180cd' (sweep 1)...
SSID:       Orange-180cd
BSSID:      08:6a:0a:f1:80:d1
Channel:    1
Vendor:     TCG300
Model:      TCG300
Assessment: LIKELY_VULNERABLE
JSON:       /tmp/broadcom-fingerprint-20261014T205813.695480Z/result.json
PCAP:       /tmp/broadcom-fingerprint-20261014T205813.695480Z/traffic.pcap
```

```
sudo uv run --with scapy broadcom_fingerprint.py --interface wlp0s12u1 --ssid WiFi-2.4-4B3C
Scanning channels 1-13 for SSID 'WiFi-2.4-4B3C' (sweep 1)...
SSID:       WiFi-2.4-4B3C
BSSID:      38:35:fb:13:4b:42
Channel:    1
Vendor:     SagemCom
Model:      SagemcomFast5336v_BBOX3
Assessment: LIKELY_VULNERABLE
JSON:       /tmp/broadcom-fingerprint-20261014T205852.234368Z/result.json
PCAP:       /tmp/broadcom-fingerprint-20261014T205852.234368Z/traffic.pcap
```

On patched devices you'll see:

```
sudo uv run --with scapy broadcom_fingerprint.py --interface wlp0s12u1 --ssid MY-AP
Scanning channels 1-13 for SSID 'MY-AP' (sweep 1)...
SSID:       MY-AP
BSSID:      38:35:fb:13:4b:42
Channel:    1
Vendor:     SagemCom
Model:      SagemcomFast5336v_BBOX3
Assessment: PATCHED_HOSTAPD
JSON:       /tmp/broadcom-fingerprint-20261014T205852.234368Z/result.json
PCAP:       /tmp/broadcom-fingerprint-20261014T205852.234368Z/traffic.pcap
```

If your device does not advertise WPS it's not affected and you'll see this:

```
sudo uv run --with scapy broadcom_fingerprint.py --interface wlx00c0ca588c7e --ssid MY-AP
Scanning channels 1-13 for SSID 'MY-AP' (sweep 1)...
SSID:       MY-AP
BSSID:      1c:0b:8b:xx:xx:xx
Channel:    6
Vendor:     Unknown
Model:      Unknown
Assessment: INCONCLUSIVE
JSON:       /tmp/broadcom-fingerprint-20261019T113912.161025Z/result.json
PCAP:       /tmp/broadcom-fingerprint-20261019T113912.161025Z/traffic.pcap
Warning: selected AP does not advertise WPS
```




The fingerprinting script relies on two things:
1. the presence of Broadcom proprietary information elements
2. an implementation quirk that can differentiate between Broadcom's wps_monitor and hostapd

The presence of Broadcom proprietary information element is not a sufficiently
strong signal since it's sometimes added by Broadcom's Linux kernel module
while the user space implementation is not from their SDK. We use that signal
to check if it's Broadcom or not.

If it's a Broadcom AP, we send a zero-length fragmented frame to differentiate
between Broadcom's wps_monitor and hostapd. hostapd sends an ACK while
wps_monitor sends a NACK (in a nutshell).

If we have both signals (Broadcom IE + implementation quirk), we can assess
with a rather high confidence level that you're affected.



## Reporting Affected Devices

You can report affected devices by opening a Pull Request. In your PR, make
sure to provide the vendor, product, version, and optionally the Internet
Service Provider that deploys them. If you identified it statically, please
provide a link to the firmware. If you identified it dynamically, please
provide the PCAP generated by the fingerprinting script.

## Affected Devices

**THIS LIST IS NOT EXHAUSTIVE. YOU MAY BE AFFECTED EVEN IF YOUR DEVICE IS NOT IN THIS LIST.**

The best way to verify that is to get your hands on the firmware, extract it,
and run the YARA rule. If you don't have access to the firmware, you can run
the fingerprinting script using a wireless interface in monitor mode.


| Vendor | Product | Versions  | Confirmed | ISPs |
|--------|---------|-----------|------------|------|
| Actiontec | T3200 | ? | Y | ? |
| ARRIS | ARRIS SURFboard AC1200 | ALL | Y | - |
| ARRIS | BGW210-700 | 1.5.12 | Y | AT&T |
| Arcadyan | VRV9517 | at least up to v6.00.18 | Y | KPN (aka "Experia Box V10A"), SPARK |
| Askey | Speedport W 723V Typ A | ALL | Y | Deutsche Telekom | 
| Askey | TCG3000 | ALL | Y | Orange Belgium, VOO |
| Askey | RTF3505VW | ALL | Y | Movistar / O2 / Telefonica |
| ASUS | DSL-AC87VG Annex B | 1.00.13_build502<br>1.00.14_build508<br>1.05.16_build287<br>1.05.17_build299<br>1.05.18_build305<br>1.05.19_build307 | Y | - |
| ASUS | DSL-AC88U Annex A | 1.10.06_Build591<br>1.10.08_Build593 | Y | - |
| ASUS | DSL-AC88U Annex B | 1.10.06_Build591<br>1.10.08_Build593 | Y | - |
| CastleNET | NetMASTER Infinity 401MP | ALL | Y | Türksat Cablenet |
| CastleNET | NetMASTER CBW-383ZN | ALL | Y | Türksat Cablenet |
| CastleNET | NetMASTER CBW-383Z4 | ALL | Y | Türksat Cablenet |
| CastleNET | NetMASTER CBW-700V | ALL | Y | Türksat Cablenet |
| Cisco | RV110W | ALL | Y | - |
| Cisco | RV130W | ALL | Y | - |
| Cisco | RV215W | ALL | Y | - |
| Cisco | RV340W | ALL | Y | - |
| Cisco | WAP121 | ALL | Y | - |
| Cisco | WAP125 | ALL | Y | - |
| Cisco | WAP150 | ALL | Y | - |
| Cisco | WAP361 | ALL | Y | - |
| Cisco | WAP371 | ALL | Y | - |
| Cisco | WAP571 | ALL | Y | - |
| Cisco | WAP571E | ALL | Y | - |
| Cisco | WAP581 | ALL | Y | - |
| Comtrend | VG8050 | ALL | Y | Movistar / O2 / Telefonica | 
| Comtrend | VR-3031eu | RA41-412VDC-C11_R04 | Y | Vodafone |
| D-Link | DSL-4320L A1 | AU 1.00.14 20151214<br>AU 1.00.15 20160107<br>AU 1.00.16 20160121<br>AU 1.00.19 20160306<br>AU 1.00.20 20160421<br>AU 1.00.21 20160524<br>AU 1.01.00 20160928<br>AU 1.01.02 20161109<br>AU 1.01.05 20170116<br>AU 1.01.11 | Y | - |
| FiberHome | HG6245D | RP2725 | Y | PLDT, Globe (Philippines) |
| Huawei | B310 | ALL | - | - |
| Huawei | B315 | ALL | - | - |
| Huawei | B593 | ALL | - | - |
| Huawei | Speedport W 724V Typ A | ALL | Y | Deutsche Telekom |
| Huawei | Speedport Hybrid | ALL | Y | Deutsche Telekom |
| Huawei | WS880 | ALL | - | - |
| MitraStar | GPT-2541GNAC | ALL | Y | Movistar / O2 / Telefonica |
| Motorola | MD1600 | 1.0.0.6-72 | Y | ? |
| NetComm | NF4V | ALL | Y | Exetel, Harbour ISP, Spintel |
| NetComm | NF10W | ALL | Y | Exetel, Aussie Broadband, Harbour ISP |
| NetComm | NF10WV | ALL | Y | Exetel, Aussie Broadband |
| NetComm | NF8AC | ALL | Y | Activ8me, Mate, SkyMesh, Aussie Broadband |
| NetComm | NF17ACV | ALL | Y | SkyMesh, Aussie Broadband | 
| NetComm | NF18ACV | ALL | Y | Aussie Broadband, Tangerine, Mate, Spintel |
| NetComm | NF18MESH | ALL | Y | Aussie Broadband |
| NetComm | NL19MESH | NC.UR-R6B022.EN_ALG | Y | ? |
| NetComm | NL1901ACV | NC.AU-R6B033.EN | Y | ? |
| Netgear | CG3100 | ALL | Y | Orange Belgium, VOO |
| Netgear | CG3700B | ALL | Y | Orange Belgium, VOO |
| Netgear | D6400 | 1.0.0.102<br>1.0.0.106<br>1.0.0.108<br>1.0.0.114<br>1.0.0.34<br>1.0.0.52<br>1.0.0.88 | Y | - |
| Netgear | D7000 v1 | 1.0.1.84 | Y | - |
| Neuf | NB6 | TODO | Y | SFR | 
| Neuf | NB6VAC | TODO | Y | SFR |
| Nokia | G-140W-H, G-240W-B, G-240W-A, G-240W-C, G-240W-F, G-240W-G, G-240W-J | ? | Y | Telmex, Speedy, ETB, Axtel, lucascell, STC, Du Telecom, Kazakhtelecom, Türk Telecom, Wind, Viettel, Etisalat, GO Telecom, True Internet, Singtel, Vodafone Turkey, Lattelekom, Sky Telecom, Vivacom, Proximus, Orange Ivory Coast, Canalbox Caraibes, Inea |
| Sagemcom | F@ST 2504 / 2504N | 6.14.2a4 | Y | Sky |
| Sagemcom | F@ST 3804 | 7.120a4N_RTC | Y | ? |
| Sagemcom | F@ST 3864 / 3864OP | ALL | Y | Optus |
| Sagemcom | F@ST 4353 | ALL | Y | Belong |
| Sagemcom | F@st 5336 | ALL | Y | Proximus |
| Sagemcom | F@ST 5655 V2 | - | LIKELY | Magyar Telekom |
| Sagemcom | F@ST 5656 | - | LIKELY | Orange Polska, NJU |
| Sagemcom | F@ST 5657 | - | LIKELY | Yoigo |
| Sercomm | Easybox 804 | up to 05.02_5_4_8_1_325_1_21_1_8 at least | Y | Vodafone (DE) |
| Sercomm | Group ONT L3 (253794565) | V1 | LIKELY | Vodafone / Lowi |
| Sercomm | Speedport W 724V Typ C | ? | LIKELY | Deutsche Telekom |
| Sercomm | RT-GM6 | ALL | LIKELY | Rostelecom |
| Sky | SR203 | at least 1.3.8.0.878-2020w47.2 | Y | Sky |
| Sky | SkyHub SR101 | 3.4.5 | Y | Sky |
| Sky | SkyHub SR102 | 2.8.8 | Y | Sky |
| SmartRG | SR630n | 1.0.0.12.ICE | Y | Kölbi / ICE (Costa Rica) |
| Tenda | D301 / N300 | - | - | - |
| TP-Link | Archer C3150 | ALL | Y | Türk Telekom |
| TP-Link | Archer C5400 | ALL | Y | Türk Telekom |
| TP-Link | Archer D9 v1 | 0.9.1_0.1 Build 150826 | Y | - |
| TP-Link | Archer VR2800 | ALL | Y | Türk Telekom |
| TP-Link | Archer VR600 | ALL | Y | Türk Telekom |
| TP-Link | Archer VR900 | ALL | Y | Türk Telekom |
| TP-Link | TD-VG5612 | ALL | Y | MyNetFone, Barefoot, OntheNet |
| TP-Link | VR1600 | ALL | Y | OntheNet, Future Broadband, Internode |
| ZTE | F680 v4 | ALL | Y | MasMovil, ThailandToT, Telkom, Linkstar, Mnc, Viettel, VNPT, SeteTec, EgyptTEData, Ais, MTN, FranceReunicable, RTC, Indosat, MAXCom, EKT, OSP, Moldtelecom, Türk Telekom, TurkNet, AtlantisNet |
| ZTE | 368N | ALL | Y | KPN (device is called "Experia Box v9"), Türk Telekom |
| Zyxel | 6641 | ? | Y | O2 Czech Republic |
| Zyxel | VMG3312-B10A, VMG3312-B10B | ALL | Y | Türk Telekom |
| Zyxel | VMG8924-B30A | ? | Y | O2 Czech Republic |
| Zyxel | VMG1312-B30B | ? | Y | O2 Czech Republic |
| Zyxel | VMG3925-B10C | V5.13(AAVF.18)C0 | Y | AAISP |

## Not Vulnerable (Patched)

These devices were tested dynamically with the fingerprinting script and reported
`PATCHED_HOSTAPD`: they are Broadcom-based but run patched hostapd rather than the
vulnerable `wps_monitor`, so they are **not** affected. Listing them here so others
don't need to re-test the same models.

| Vendor | Product | Assessment | Method |
|--------|---------|------------|--------|
| Sagemcom | F5598T | PATCHED_HOSTAPD | fingerprinting script |
| Sagemcom | F380B | PATCHED_HOSTAPD | fingerprinting script |
| Sky | Q Hub ER110 | PATCHED_HOSTAPD | YARA |
| Sky | Q Hub ER115 | PATCHED_HOSTAPD | YARA |

## Integrations

Projects that vendor or wrap these detectors:

| Project | What it adds |
|---------|--------------|
| [AURIS.net](https://github.com/REGT-URRED/AURIS.net) | Wifite-style 802.11 audit framework (RoE gating, phase engine, offline field bundle) that vendors the fingerprinter and YARA rules, ships an offline affected-device catalog, and exposes `auris broadcom` for catalog lookup, firmware scanning and live fingerprinting. |
