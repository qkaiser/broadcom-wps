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
| Actiontec | C1000A | CAC004-31.30L.95 | Y | CenturyLink |
| Actiontec | C1900A | CAB005-31.30L.96 | Y | CenturyLink |
| Actiontec | C2000A | CAH006-31.30L.95 | Y | CenturyLink |
| Actiontec | C2300A | CAS001-31.165L.11 | Y | CenturyLink |
| Actiontec | C3000A | CAD004-31.165L.13 | Y | CenturyLink |
| Actiontec | Q1000 | QAQ004-31.20L.7 | Y | CenturyLink |
| Actiontec | T3200 | ? | Y | ? |
| Adtran | C424G | CAO001-4.16.011.2 | Y | CenturyLink |
| ARRIS | ARRIS SURFboard AC1200 | ALL | Y | - |
| ARRIS | BGW210-700 | 1.0.24<br>1.0.29<br>1.10.9<br>1.5.11<br>1.5.12<br>1.6.7<br>1.8.18<br>1.9.14<br>1.9.16<br>2.10.4<br>2.10.6<br>2.11.5<br>2.12.4<br>2.15.4<br>2.16.4<br>2.17.4<br>2.17.5<br>2.3.4<br>2.4.4<br>2.5.6<br>2.6.4<br>2.7.1<br>2.7.7<br>2.8.5<br>2.8.7<br>2.9.4 | Y | AT&T |
| Arcadyan | VRV9517 | at least up to v6.00.18 | Y | KPN (aka "Experia Box V10A"), SPARK |
| ARRIS | NVG589 | 11.5.0h0d51<br>11.6.0h0d48<br>9.2.2h0d79 CFEROM | Y | AT&T |
| ARRIS | NVG599 | 11.5.0h0d51<br>11.6.0h0d48<br>9.2.2h0d79 CFEROM<br>9.2.2h0d83 | Y | AT&T |
| Askey | RTV1900VW | 08.06.06 | Y | Swisscom (Internet-Box light) |
| Askey | Speedport W 723V Typ A | 1.01.022<br>ALL | Y | Deutsche Telekom |
| Askey | TCG3000 | ALL | Y | Orange Belgium, VOO |
| Askey | RTF3505VW | ALL | Y | Movistar / O2 / Telefonica |
| ASUS | DSL-AC3100 | 1.10.04_Build460<br>1.10.05_Build502<br>1.10.05_Build503<br>1.10.06_Build585<br>1.10.06_Build591<br>1.10.08_Build593 | Y | - |
| ASUS | DSL-AC68U | 3.0.0.4.382_50302<br>3.0.0.4.384_21128<br>3.0.0.4.384_56087<br>3.0.0.4.384_80766<br>3.0.0.4.384_81140<br>3.0.0.4.384_81727<br>3.0.0.4.384_81981<br>3.0.0.4.386_38287<br>3.0.0.4.386_38832<br>3.0.0.4.386_39648<br>3.0.0.4.386_41995<br>3.0.0.4.386_43252<br>3.0.0.4.386_45662<br>3.0.0.4.386_47534<br>3.0.0.4.386_50117<br>3.0.0.4.386_50120<br>3.0.0.4.386_52006 | Y | - |
| ASUS | DSL-AC68VG | 5.00.04_build248<br>5.00.07_build271<br>5.00.08_build272<br>5.00.09_build274 | Y | - |
| ASUS | DSL-AC87VG Annex B | 1.00.13_build502<br>1.00.14_build508<br>1.05.16_build287<br>1.05.17_build299<br>1.05.18_build305<br>1.05.19_build307 | Y | - |
| ASUS | DSL-AC88U (Annex A/B) | 1.10.04_build460<br>1.10.05-Build502<br>1.10.05_Build503<br>1.10.06_Build585<br>1.10.08_Build593 | Y | - |
| ASUS | DSL-AC88U Annex A | 1.10.06_Build591<br>1.10.08_Build593 | Y | - |
| ASUS | DSL-AC88U Annex B | 1.10.06_Build591<br>1.10.08_Build593 | Y | - |
| ASUS | DSL-AX82U | 3.0.0.4.386.49608<br>3.0.0.4.386_42438<br>3.0.0.4.386_43563<br>3.0.0.4.386_43600<br>3.0.0.4.386_48378<br>3.0.0.4.388_22048<br>3.0.0.4.388_23756<br>3.0.0.4.388_24894<br>3.0.0.4.388_24906<br>3.0.0.4.388_24919<br>3.0.0.4.388_25052<br>3.0.0.4.388_25110 | Y | - |
| ASUS | DSL-N12HP | 1.0.0.16<br>1.0.0.8 | Y | - |
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
| D-Link | DSL-2640B Rev E1 | reve1_206_ALL_multi_20130122 | Y | - |
| D-Link | DSL-2640U | NRU_C4_1.0.10_20110407 | Y | - |
| D-Link | DSL-2641B Rev E1 | reve1_100b04_04142011_ALL_multi_20110414<br>reve1_201_03092012_ALL_multi_20120309<br>reve1_206_ALL_multi_20121204 | Y | - |
| D-Link | DSL-2730B REVT | DSL-2730B-T1-FW-AU_1.00<br>DSL-2730B-T1-FW-AU_2.00<br>DSL-2730B_T1_FW_AU_2.01 | Y | - |
| D-Link | DSL-2730U Rev C1 (ME) | 1.00_B03 | Y | - |
| D-Link | DSL-2740B Rev F1 | revf1_206_ALL_multi_20121126 | Y | - |
| D-Link | DSL-2740B Rev F1 (AU) | 1.00<br>2.00<br>2.01<br>2.03<br>2.04<br>2.07 | Y | - |
| D-Link | DSL-2740BR REVF | DSL2740B_F1_AU_1.00_IPv6<br>DSL2740B_F1_AU_2.00_10132011<br>DSL2740B_F1_AU_2.01_03082012<br>DSL2740B_F1_AU_2.03_06282012<br>DSL2740B_F1_AU_2.04_07262012<br>DSL2740B_F1_AU_2.07_10082012 | Y | - |
| D-Link | DSL-2741B Rev F1 | revf1_100b09_04142011_ALL_multi_20110414<br>revf1_201_03092012_ALL_multi_20120309<br>revf1_206_ALL_multi_20121228 | Y | - |
| D-Link | DSL-2750B Rev D | revd_eu104-1601_ALL_multi_20150722<br>revd_eu105-1521_EU_multi_20180730 | Y | - |
| D-Link | DSL-2750B Rev D1 | revd1_EU102_ALL_multi_20130610<br>revd1_EU102_ALL_multi_20131111<br>revd1_eu104-08032015_ALL_multi_20150803 | Y | - |
| D-Link | DSL-2750B REVB | DSL2750B_B1_AU_1.00_06232011<br>DSL2750B_B1_AU_2.00_12282011<br>DSL2750B_B1_AU_2.01_03012012<br>DSL2750B_B1_AU_2.03_06282012<br>DSL2750B_B1_AU_2.05_08032012<br>DSL2750B_B1_AU_2.07_10082012 | Y | - |
| D-Link | DSL-2750B REVD1 | revd1_eu102-09232014_ALL_multi_20140923 | Y | - |
| D-Link | DSL-2750B REVT | DSl-2750B.T1_Firmware_AU_3.00_20121018<br>DSl-2750B.T1_Firmware_AU_3.01_20130313<br>DSl-2750B.T1_Firmware_AU_3.02_20131211<br>DSl-2750B.T1_Firmware_AU_3.05_20140718<br>DSL-2750B.T1_Firmware_AU_3.06_20141028<br>DSL-2750B.T1_Firmware_AU_3.08_25032015 | Y | - |
| D-Link | DSL-2751 Rev D1 | revd1_EU100_ALL_multi_20130424<br>revd1_EU101-11102014_ALL_multi_20141110<br>revd1_EU101_ALL_multi_20131008 | Y | - |
| D-Link | DSL-2790U Rev A | AU 1.00.14 20151211 R1767 | Y | - |
| D-Link | DSL-2870B REVA | DSL-2870B_FW_upgrade_from_v1.01.24_to_v2.00.00AU_06062013<br>DSL-2870B_FW_v1.01.14_07272012<br>DSL-2870B_FW_v1.01.23_11062012<br>DSL-2870B_FW_v1.01.24_11152012 | Y | - |
| D-Link | DSL-2880AL REVA | DSL-2880AL_A1_AU_1.01_01072014<br>DSL-2880AL_A1_AU_1.01b_03132014<br>DSL-2880AL_A1_AU_2.00_06052014<br>DSL-2880AL_A1_AU_2.01_09112014 | Y | - |
| D-Link | DSL-2890AL Rev A (AU) | AU 1.01.02 20130524<br>AU 1.01.03 20130613<br>AU 1.01.04 20130906<br>AU 1.02.02 20131203<br>AU 1.02.04 20140121<br>AU 1.02.06 20140528<br>AU 1.02.07 20150427<br>AU 1.02.08 20150507<br>AU 1.02.10 20160617 | Y | - |
| D-Link | DSL-2900AL Rev A (AU) | AU 1.00.25 20160329<br>AU 1.00.26 20160426<br>AU 1.01.00 20160905 | Y | - |
| D-Link | DSL-3580L Rev A2 | reva2_eu202-08042015_ALL_multi_20150804 | Y | - |
| D-Link | DSL-3580L REVA2 | reva2_eu201-12192014-1013_ALL_multi_20141219 | Y | - |
| D-Link | DSL-3590L Rev A | reva_eu10012_ALL_multi_20160704 | Y | - |
| D-Link | DSL-4320L A1 | AU 1.00.14 20151214<br>AU 1.00.15 20160107<br>AU 1.00.16 20160121<br>AU 1.00.19 20160306<br>AU 1.00.20 20160421<br>AU 1.00.21 20160524<br>AU 1.01.00 20160928<br>AU 1.01.02 20161109<br>AU 1.01.05 20170116<br>AU 1.01.11 | Y | - |
| D-Link | DSL-4320L REVA | DSL4320L_AU_1.01.11 | Y | - |
| D-Link | DSL-5300 Rev A | AU 1.00<br>AU 1.05<br>AU 1.07 | Y | - |
| D-Link | DSL-G225 Rev J (AU) | AU 1.0.2<br>AU 1.0.3<br>AU 1.0.4<br>AU 1.0.5<br>AU 1.0.6 | Y | - |
| D-Link | DSL-G225 REVJ | VDM206-2-DL-DSL-G225-EE-NoF-U1-R435-20170313.w | Y | - |
| FiberHome | HG6245D | RP2725 | Y | PLDT, Globe (Philippines) |
| Huawei | B310 | ALL | - | - |
| Huawei | B315 | ALL | - | - |
| Huawei | B593 | ALL | - | - |
| Huawei | HG659-13 (Vodacom South Africa) | V100R001C195B021 | Y | Vodacom |
| Huawei | HG8245H | V300R013C10SPC122 | Y | - |
| Huawei | Speedport Hybrid | 050124.04.00.013<br>ALL | Y | Deutsche Telekom |
| Huawei | Speedport W 724V Typ A | ALL | Y | Deutsche Telekom |
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
| Netgear | D6200 | 1.1.00.09<br>1.1.00.14<br>1.1.00.17<br>1.1.00.24<br>1.1.00.36<br>1.1.00.38<br>1.1.00.40 | Y | - |
| Netgear | D6220 | 1.0.0.16<br>1.0.0.28<br>1.0.0.32<br>1.0.0.60<br>1.0.0.72<br>1.0.0.74<br>1.0.0.76<br>1.0.0.80 | Y | - |
| Netgear | D6300 | 1.0.0.16 | Y | - |
| Netgear | D6300 (All regions except NA) | 1.0.0.24 | Y | - |
| Netgear | D6300 (Worldwide except NA and Germany) | 1.0.0.102<br>1.0.0.90 | Y | - |
| Netgear | D6400 | 1.0.0.102<br>1.0.0.106<br>1.0.0.108<br>1.0.0.114<br>1.0.0.34<br>1.0.0.52<br>1.0.0.88 | Y | - |
| Netgear | D7000 | 1.0.0.18 | Y | - |
| Netgear | D7000 v1 | 1.0.1.84 | Y | - |
| Netgear | D8500 | 1.0.3.52 | Y | - |
| Netgear | DGN2200Bv3 (Germany) | 1.1.00.23 | Y | - |
| Netgear | DGN2200Bv4 (Germany) | 1.0.0.109<br>1.0.0.60 | Y | - |
| Netgear | DGN2200v3 (North America) | 1.1.00.21<br>1.1.00.23<br>1.1.00.24 | Y | - |
| Netgear | DGN2200v3 (Worldwide except NA and Germany) | 1.1.00.23<br>1.1.00.24 | Y | - |
| Netgear | DGN2200v4 (All regions except Germany) | 1.0.0.114<br>1.0.0.116<br>1.0.0.118<br>1.0.0.126<br>1.0.0.132<br>1.0.0.24<br>1.0.0.46<br>1.0.0.58<br>1.0.0.76 | Y | - |
| Netgear | DGND3700v2 (North America) | 1.1.00.08<br>1.1.00.17<br>1.1.00.21<br>1.1.00.26 | Y | - |
| Netgear | DGND3700v2 (Worldwide) | 1.1.00.26 | Y | - |
| Netgear | DGND4000 | 1.1.00.15 | Y | - |
| Netgear | DGND4000 (North America) | 1.1.00.10 | Y | - |
| Netgear | WNR3500L | 1.2.2.48 | Y | K-Net |
| Neuf | NB6 | TODO | Y | SFR | 
| Neuf | NB6VAC | 4.0.44d<br>4.0.44f<br>4.0.44i<br>4.0.44j<br>4.0.44k<br>4.0.45<br>4.0.45c<br>4.0.45d<br>4.0.46<br>TODO | Y | RED by SFR<br>SFR |
| Nokia | BGW320-505 | 3.17.5 dnvpnP 021 | Y | AT&T |
| Nokia | G-140W-H | 3FE48077HJIL96_V6 | Y | - |
| Nokia | G-140W-H, G-240W-B, G-240W-A, G-240W-C, G-240W-F, G-240W-G, G-240W-J | ? | Y | Telmex, Speedy, ETB, Axtel, lucascell, STC, Du Telecom, Kazakhtelecom, Türk Telecom, Wind, Viettel, Etisalat, GO Telecom, True Internet, Singtel, Vodafone Turkey, Lattelekom, Sky Telecom, Vivacom, Proximus, Orange Ivory Coast, Canalbox Caraibes, Inea |
| Nokia | G-240W-C | 3FE46322IJHL28_V3 | Y | - |
| Nokia | G-240W-G | 3FE47550HJIL96_V9 | Y | - |
| Sagemcom | F@ST 2504 / 2504N | 6.14.2a4 | Y | Sky |
| Sagemcom | F@st 2704 (Etisalat) | 6.29.3a4N | Y | - |
| Sagemcom | F@ST 3804 | 7.120a4N_RTC | Y | ? |
| Sagemcom | F@ST 3864 / 3864OP | ALL | Y | Optus |
| Sagemcom | F@ST 4353 | ALL | Y | Belong |
| Sagemcom | F@st 5336 | ALL | Y | Proximus |
| Sagemcom | F@st 5350 GV | SG790131200068 (3.12.35)<br>SG790131200312 (3.12.5301)<br>SG790131200412 (3.12.5901) | Y | GVT |
| Sagemcom | F@st 5364 (TalkTalk) | SG4K10001E00t / 6.72.38<br>SG4K10002600t / 6.72.40<br>SG4K10002808t / 6.72.44<br>SG4K10002810t / 6.72.44.11<br>SG4K10002816t / 6.72.44.14 | Y | TalkTalk |
| Sagemcom | F@st 5650 GVT (GPON) | 8.126.1.28 | Y | GVT |
| Sagemcom | F@ST 5655 V2 | - | LIKELY | Magyar Telekom |
| Sagemcom | F@ST 5656 | - | LIKELY | Orange Polska, NJU |
| Sagemcom | F@ST 5657 | - | LIKELY | Yoigo |
| Sagemcom | F@ST5317GV GVT | 6.51.31 | Y | - |
| Sagemcom | F@ST5317GV Vivo | 6.51.28 | Y | - |
| Sagemcom | F@ST5350GV GVT | 3.12.5904 | Y | - |
| Sercomm | Easybox 804 | up to 05.02_5_4_8_1_325_1_21_1_8 at least | Y | Vodafone (DE) |
| Sercomm | Group ONT L3 (253794565) | V1 | LIKELY | Vodafone / Lowi |
| Sercomm | Speedport W 724V Typ C | ? | LIKELY | Deutsche Telekom |
| Sercomm | RT-GM6 | ALL | LIKELY | Rostelecom |
| SFR | NB6VAC | 4.0.44d<br>4.0.44f<br>4.0.44i<br>4.0.44j<br>4.0.44k<br>4.0.45<br>4.0.45c<br>4.0.45d<br>4.0.46 | Y | RED by SFR |
| Sky | SR203 | at least 1.3.8.0.878-2020w47.2 | Y | Sky |
| Sky | SkyHub SR101 | 3.4.5 | Y | Sky |
| Sky | SkyHub SR102 | 2.8.8 | Y | Sky |
| SmartRG | SR630n | 1.0.0.12.ICE | Y | Kölbi / ICE (Costa Rica) |
| Technicolor | C2000T | CTH005-4.12.1.44 | Y | CenturyLink |
| Technicolor | C2100T | CTQ003-4.12.1.78 | Y | CenturyLink |
| Tenda | D151 V2.0 (US) | V50.21.1.5 | Y | - |
| Tenda | D301 / N300 | - | - | - |
| Tenda | D301 V1.0 (US) | 1.2.11.2 | Y | - |
| Tenda | V1200 V1.0 (US) | V53.0.0.4 | Y | - |
| Tenda | V300 v1.0 | V53.0.1.6 | Y | - |
| TP-Link | Archer C3150 | ALL | Y | Türk Telekom |
| TP-Link | Archer C3150 V2 | Archer C3150(US)_V2_160812<br>Archer C3150(US)_V2_170225<br>Archer C3150(US)_V2_170628<br>Archer C3150(US)_V2_170926<br>Archer C3150_V2_170411 | Y | - |
| TP-Link | Archer C5400 | ALL | Y | Türk Telekom |
| TP-Link | Archer D9 v1 | 0.9.1_0.1 Build 150826 | Y | - |
| TP-Link | Archer VR1600v V1 | Archer VR1600v(AU)_V1_2.1.0 Build 260318 | Y | - |
| TP-Link | Archer VR1600v V2 | Archer VR1600v(ANZWISP)_V2_0.1.0 Build 260317 Rel.7757n | Y | - |
| TP-Link | Archer VR2800 | ALL | Y | Türk Telekom |
| TP-Link | Archer VR2800 V1 | (EU) 170809<br>(EU) 201103<br>Archer VR2800(EU)_V1_170110<br>Archer VR2800(EU)_V1_200227<br>Archer VR2800(EU)_V1_210313<br>Archer VR2800(EU)_V1_220120<br>Archer VR2800(EU)_V1_220512<br>Archer_VR2800(EU)_V1_170809<br>Archer_VR2800(EU)_V1_220512<br>Archer_VR2800(EU)V1_200624 beta<br>Archer_VR2800(EU)V1_200708 beta<br>Archer_VR2800(EU)V1_201103 beta<br>Archer_VR2800V1_0.8.0_0.9.1_up_boot(220120)<br>ArcherVR2800(EU)_V1_200710 | Y | - |
| TP-Link | Archer VR400 V2 | (EU) 201104<br>200227<br>201104<br>220126<br>Archer VR400(EU)_V2_170224<br>Archer VR400(EU)_V2_170719<br>Archer VR400(EU)_V2_220126<br>ArcherVR400(EU)_V2_200227<br>ArcherVR400(EU)_V2_200706<br>ArcherVR400(EU)_V2_201104 | Y | - |
| TP-Link | Archer VR600 | ALL | Y | Türk Telekom |
| TP-Link | Archer VR600 V2 | (AU) 200624<br>170504<br>200226<br>Archer VR600(EU)_V2_170504<br>Archer VR600(EU)_V2_200226<br>Archer_VR600(AU)_V2_170302<br>Archer_VR600(AU)_V2_190123<br>Archer_VR600(AU)_V2_200226<br>Archer_VR600(EU)V2_200701 beta<br>Archer_VR600(EU)V2_201104 beta<br>Archer_VR600_AU2.0 beta (2018-02-06)<br>Archer_VR600V2_210409 beta | Y | - |
| TP-Link | Archer VR600v V2 | (EU) 170814<br>(EU) 200624<br>Archer VR600v(EU)_V2_220112 | Y | - |
| TP-Link | Archer VR900 | ALL | Y | Türk Telekom |
| TP-Link | TD-VG5612 | ALL | Y | MyNetFone, Barefoot, OntheNet |
| TP-Link | TD-W9970 V3 | (EU) 200227<br>190419<br>200227<br>221012<br>TD-W9970(EU)_V3.0_190419<br>TD-W9970(EU)_V3_200227<br>TD-W9970_V3_221012_RC | Y | - |
| TP-Link | TD-W9970 V3.0 | (EU) 190419<br>TD-W9970(EU)_V3.0_190419 | Y | - |
| TP-Link | VR1600 | ALL | Y | OntheNet, Future Broadband, Internode |
| ZTE | F680 v4 | ALL | Y | MasMovil, ThailandToT, Telkom, Linkstar, Mnc, Viettel, VNPT, SeteTec, EgyptTEData, Ais, MTN, FranceReunicable, RTC, Indosat, MAXCom, EKT, OSP, Moldtelecom, Türk Telekom, TurkNet, AtlantisNet |
| ZTE | 368N | ALL | Y | KPN (device is called "Experia Box v9"), Türk Telekom |
| ZTE | H168N (HOL) | V1.1.0_GR4T10 | Y | - |
| ZTE | Speedport Entry 2i | OTET11LW4O6P5A | Y | Cosmote |
| ZTE | Speedport Entry 2i (Cosmote) | OTET12LW4O6P5A | Y | - |
| ZTE | ZXHN F660 | V5.2.10P2T29 | Y | VNPT |
| ZTE | ZXHN H168N (HOL variant) | V1.1.0_GR4T11 | Y | - |
| Zyxel | 6641 | ? | Y | O2 Czech Republic |
| Zyxel | AX7501-B1 | V5.17(ABPC.8)C0 | Y | Init7 |
| Zyxel | C1100Z | CZW006-4.16.012.0 | Y | CenturyLink |
| Zyxel | C2100Z | CZQ002-4.16.011.30 | Y | CenturyLink |
| Zyxel | C3000Z | CZD003-4.16.009.47<br>CZD005-4.16.011.0 | Y | CenturyLink |
| Zyxel | Q1000Z | QZZ002-4.4.015.4 | Y | CenturyLink |
| Zyxel | VMG3312-B10A, VMG3312-B10B | ALL | Y | Türk Telekom |
| Zyxel | VMG8924-B30A | ? | Y | O2 Czech Republic |
| Zyxel | VMG1312-B30B | ? | Y | O2 Czech Republic |
| Zyxel | VMG3925-B10C | V5.13(AAVF.18)C0 | Y | AAISP |
| Zyxel | XMG3927-Bx0A WiFi | V513ABQO1b5_D0 | Y | green.ch |

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
