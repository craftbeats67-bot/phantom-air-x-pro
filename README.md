<p align="center"><img src="assets/phantom_team_logo.png" alt="PHANTOM TEAM" width="320"></p>

# PHANTOM AIR X PRO
**Advanced Wi-Fi Security Suite** · POWERED BY PHANTOM TEAM · DEVELOPED BY KRRISH · Instagram: [@mahisec_13](https://instagram.com/mahisec_13) · v1.0 PRO

A defensive Wi-Fi auditing suite for **networks you own or are authorized to test** (home, lab, CTF/practice setups).
UI layout is inspired by Airgeddon; no Airgeddon code or branding is used.

> **Not included on purpose:** password cracking, deauthentication, Evil Twin, WPS attacks, handshake capture, DoS.

## Modules
| # | Module | What it really does |
|---|---|---|
| 01 | Wireless Interface Manager | Lists wireless interfaces, state, MAC, driver, chipset, bands, 802.11 standards, driver-reported modes |
| 02 | Wi-Fi Network Scanner | Standard scan (SSID, BSSID, channel, signal, security), open-network flag, JSON/CSV export |
| 03 | Network Security Analyzer | Rates each observed network (OPEN, WEP, WPA/TKIP, WPA2, WPA3…) with fixes |
| 04 | Signal Analyzer | Live dBm of the connected network, min/avg/max, stability |
| 05 | Channel Information | Networks per channel and 2.4 GHz interference score with a channel recommendation |
| 06 | Authorized Device Inventory | Host discovery on **your private LAN** (max /22), MAC + vendor via OUI |
| 07 | Router Security Audit | Probes your gateway for exposed Telnet/FTP/HTTP-only admin/UPnP/TR-069, banner info |
| 08 | Password Security Analyzer | Local strength check; the password is never saved or sent |
| 09 | Network Monitoring | Live up/down rates, errors, drops, link state |
| 10 | Security Report Generator | TXT + JSON report of this session's real data |
| 11 / 12 | Settings / About | |

## Install
**Kali Linux / Parrot OS**
```bash
git clone https://github.com/craftbeats67-bot/phantom-air-x-pro.git
cd phantom-air-x-pro
chmod +x install.sh && ./install.sh
sudo ./run.sh          # root is needed for `iw` scans and full ARP inventory; nmcli scans work without it
```
**Termux (Android, no root)**
```bash
pkg install -y git
git clone https://github.com/craftbeats67-bot/phantom-air-x-pro.git
cd phantom-air-x-pro && chmod +x install.sh && ./install.sh
./run.sh
```
On Termux always use `./install.sh` and start with `./run.sh` (not `pip install -r requirements.txt` or plain `python main.py`): the tool lives in a virtual environment and `psutil` cannot be built on Android (it is optional).
Termux also needs the **Termux:API** app (F-Droid), Location permission and Location turned on for Wi-Fi scanning.

## Platform limits (honest list)
| Feature | Kali / Parrot | Termux (no root) |
|---|---|---|
| Wi-Fi scan | nmcli (no root) or iw (root) | termux-wifi-scaninfo; security type may show UNKNOWN if Android does not report it |
| Interface details / bands / standards | yes (`iw`) | only basic connection info |
| Signal monitor | yes | yes (Termux:API) |
| Device inventory MACs | yes with sudo | often unavailable on Android 10+ (ARP table is hidden) |
| Network monitor | yes | depends on /proc/net access |
Scans use the normal Wi-Fi scan (like your phone's list). Monitor mode and packet injection are never used.

## Safety
Active actions (06, 07) ask for confirmation, accept only private IPv4 ranges, and never touch neighbouring networks.
Results are limited to what was observed; a clean report does not prove a network is secure.

## Tests
```bash
.venv/bin/python -m unittest discover -s tests -v
```
Parsers (nmcli, iw, Termux:API), analyzer rules, channel scoring, password analyzer, router findings and report generation are unit-tested with sample data.
Live scanning needs real hardware and was not part of automated tests.

## Troubleshooting
- **No wireless interface:** plug in an adapter or attach it to the VM (USB passthrough); check with `iw dev`.
- **nmcli failed / no networks:** `sudo systemctl start NetworkManager`; make sure Wi-Fi is not blocked: `rfkill list`.
- **iw scan "Operation not permitted":** run with `sudo ./run.sh`.
- **Termux scan error / empty:** install Termux:API app, `pkg install termux-api`, grant Location permission, enable Location.
- **Logo missing:** `pip install pillow` (Termux: `pkg install python-pillow`).
- **Module error:** details are in `logs/phantom.log`.

## License
MIT
