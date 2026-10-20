# Broadcom 802.11 SDK Detection Toolkit

This repository contains two ways to detect the presence of Broadcom's 802.11 implementation on a target router:
1. Statically using YARA rules on extracted firmware
2. Dynamically by running a fingerprinting script against a live access point

The list of affected devices is available at the end of this page. **This list is not exhaustive**. We expect the complete list to contains thousands of different devices, make and models.

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

Make sure your interface supports monitor mode and enable monitor mode:

```
sudo ip link set dev wlp0s12u1 down
sudo iw dev wlp0s12u1 set monitor none
sudo ip link set dev wlp0s12u1 up
```

> **Note on hardware:** monitor mode / frame injection is very driver-dependent.
> In my testing the built-in **Intel Dual Band Wireless-AC 7265** (`iwlwifi`)
> accepted `type monitor` but captured **zero** frames (no beacons even with a
> strong signal), so the fingerprinter never locked onto a target. A USB adapter
> with a MediaTek chipset — **MT7921AU** (USB id `0e8d:7961`, driver `mt7921u`) —
> worked immediately. If the script keeps sweeping without finding your SSID,
> suspect the adapter rather than the target. Known-good chipsets for this kind
> of work include MediaTek `mt76`, Atheros `ath9k_htc`, and Realtek `rtl8812au`.

You should seem something like this on affected devices:

```
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

| Vendor | Product | Versions | Confirmed | ISPs |
|--------|---------|-----------|-----------|------|
| ARRIS | ARRIS SURFboard AC1200 | ALL | Y | - |
| Arcadyan | VRV9517 | at least up to v6.00.18 | Y | KPN (aka "Experia Box V10A"), SPARK |
| Askey | Speedport W 723V Typ A | ALL | Y | Deutsche Telekom |
| Askey | TCG3000 | ALL | Y | Orange Belgium, VOO |
| Askey | RTF3505VW | ALL | Y | Movistar / O2 / Telefonica |
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
| Huawei | B310 | - | ALL | - |
| Huawei | B315 | - | ALL | - |
| Huawei | B593 | - | ALL | - |
| Huawei | Spedport W 724V Typ A | ALL | Y | Deutsche Telekom |
| Huawei | Speedport Hybrid | ALL | Y | Deutsche Telekom |
| Huawei | WS880 | - | ALL | - |
| NetComm | NF4V | ALL | Y | Exetel, Harbour ISP, Spintel |
| NetComm | NF10W | ALL | Y | Exetel, Aussie Broadband, Harbour ISP |
| NetComm | NF10WV | ALL | Y | Exetel, Aussie Broadband |
| NetComm | NF8AC | ALL | Y | Activ8me, Mate, SkyMesh, Aussie Broadband |
| NetComm | NF17ACV | ALL | Y | SkyMesh, Aussie Broadband |
| NetComm | NF18ACV | ALL | Y | Aussie Broadband, Tangerine, Mate, Spintel |
| NetComm | NF18MESH | ALL | Y | Aussie Broadband |
| Netgear | CG3100 | ALL | Y | Orange Belgium, VOO |
| Netgear | CG3700B | ALL | Y | Orange Belgium, VOO |
| Neuf | NB6 | TODO | Y | SFR |
| Neuf | NB6VAC | TODO | Y | SFR |
| Nokia | G-140W-H, G-240W-B, G-240W-A, G-240W-C, G-240W-F, G-240W-G, G-240W-J | ? | Y | Telmex, Speedy, ETB, Axtel, lucascell, STC, Du Telecom, Kazakhtelecom, Türk Telecom, Wind, Viettel, Etisalat, GO Telecom, True Internet, Singtel, Vodafone Turkey, Lattelekom, Sky Telecom, Vivacom, Proximus, Orange Ivory Coast, Canalbox Caraibes, Inea |
| Sagemcom | F@ST 3864 / 3864OP | ALL | Y | Optus |
| Sagemcom | F@ST 4353 | ALL | Y | Belong |
| Sagemcom | F@st 5336 | ALL | Y | Proximus |
| Sagemcom | F@ST 5655 V2 | - | LIKELY | Magyar Telekom |
| Sagemcom | F@ST 2504 / 2504N | 6.14.2a4 | Y | Sky |
| Sercomm | Easybox 804 | up to 05.02_5_4_8_1_325_1_21_1_8 at least | Y | Vodafone (DE) |
| Sercomm | Group ONT L3 (253794565) | V1 | LIKELY | Vodafone / Lowi |
| Sercomm | Speedport W 724V Typ C | ? | LIKELY | Deutsche Telekom |
| Sky | SR203 | at least 1.3.8.0.878-2020w47.2 | Y | Sky |
| Sky | SkyHub SR101 | 3.4.5 | Y | Sky |
| Sky | SkyHub SR102 | 2.8.8 | Y | Sky |
| Tenda | D301 / N300 | - | - | - |
| TP-Link | Archer C3150 | ALL | Y | Türk Telekom |
| TP-Link | Archer C5400 | ALL | Y | Türk Telekom |
| TP-Link | Archer VR2800 | ALL | Y | Türk Telekom |
| TP-Link | Archer VR600 | ALL | Y | Türk Telekom |
| TP-Link | Archer VR900 | ALL | Y | Türk Telekom |
| TP-Link | TD-VG5612 | ALL | Y | MyNetFone, Barefoot, OntheNet |
| TP-Link | VR1600 | ALL | Y | OntheNet, Future Broadband, Internode |
| ZTE | F680 v4 | ALL | Y | MasMovil, ThailandToT, Telkom, Linkstar, Mnc, Viettel, VNPT, SeteTec, EgyptTEData, Ais, MTN, FranceReunicable, RTC, Indosat, MAXCom, EKT, Moldtelecom, Türk Telekom, TurkNet, AtlantisNet |
| ZTE | 368N | ALL | Y | KPN (device is called "Experia Box v9"), Türk Telekom |
| Zyxel | VMG3312-B10A, VMG3312-B10B | ALL | Y | Türk Telekom |
| MitraStar | GPT-2541GNAC | ALL | Y | Movistar / O2 / Telefonica |

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

## Inconclusive Results

These devices were tested dynamically with the fingerprinting script, but the result did not establish whether they are vulnerable.

| Vendor | Product | Version | Assessment | Method | ISP |
|--------|---------|---------|------------|--------|-----|
| Sagemcom | FAST 5670 | SGDV20000151 | INCONCLUSIVE | fingerprinting script; WPS not advertised | MásMóvil España |

The access point did not advertise WPS in the captured frames. The test is inconclusive and does not establish whether this model or firmware is vulnerable. SSID and BSSID are omitted for privacy.
