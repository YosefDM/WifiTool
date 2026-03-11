# WifiTool — Educational Wi-Fi Security Analysis Suite

A menu-driven terminal application for learning about Wi-Fi security protocols
and vulnerabilities.  It **actually calls the real tools** — aircrack-ng,
hashcat, hcxdumptool, bettercap, wifite2, and the KRACK PoC scripts — rather
than simulating them.

> **Legal notice**: For use in authorized, sandboxed lab environments only.
> Using these tools against any network you do not own or have explicit written
> permission to test is illegal under CFAA, the Computer Misuse Act, and
> equivalent legislation worldwide.

---

## Features

| Menu Option | What it does | Real tool(s) used |
|---|---|---|
| System Setup | List interfaces, enable monitor mode, install tools | `airmon-ng` |
| Network Discovery | Scan for nearby APs and clients | `airodump-ng` |
| WEP Analysis | IV capture + PTW/FMS statistical crack | `airodump-ng`, `aireplay-ng`, `aircrack-ng` |
| WPA/WPA2 Handshake | Capture 4-way handshake, GPU crack | `airodump-ng`, `aireplay-ng`, `hashcat`, `aircrack-ng` |
| PMKID Attack | Clientless WPA2 capture + offline crack | `hcxdumptool`, `hcxpcapngtool`, `hashcat` |
| KRACK Test | CVE-2017-13077+ nonce reinstallation test | `krackattacks-scripts` (vanhoef/krackattacks-scripts) |
| Bettercap | Interactive network monitoring & attack REPL | `bettercap` |
| Wifite2 | Automated WEP/WPA/PMKID/WPS auditing | `wifite` / `wifite2` |
| Protocol Reference | WEP / WPA / WPA2 / WPA3 technical details | — |
| Attack Reference | FMS / KRACK / PMKID / Dragonblood deep-dives | — |
| Legal & Ethics | Responsible use and legal framework | — |

---

## Covered Attack Vectors

- **FMS / PTW** (WEP, 2001/2007) — IV statistical attack cracking WEP keys
- **Beck-Tews** (TKIP, 2008) — Partial TKIP packet decryption
- **4-Way Handshake Dictionary Attack** (WPA/WPA2) — Offline PMK brute-force
- **KRACK** (WPA2, CVE-2017-13077+, 2017) — Nonce reinstallation via MITM
- **PMKID Attack** (WPA2, 2018) — Clientless offline cracking
- **Dragonblood** (WPA3, CVE-2019-9494, 2019) — SAE side-channel + downgrade

---

## Tool Sources (GitHub)

| Tool | GitHub Repository |
|---|---|
| aircrack-ng | https://github.com/aircrack-ng/aircrack-ng |
| hashcat | https://github.com/hashcat/hashcat |
| hcxdumptool | https://github.com/ZerBea/hcxdumptool |
| hcxtools | https://github.com/ZerBea/hcxtools |
| bettercap | https://github.com/bettercap/bettercap |
| wifite2 | https://github.com/derv82/wifite2 |
| krackattacks-scripts | https://github.com/vanhoef/krackattacks-scripts |

---

## Installation

### Windows 11

#### 1. Install Python (if not already installed)

```powershell
winget install Python.Python.3
```

#### 2. Install WifiTool Python dependency

```powershell
pip install rich
# or
pip install -r requirements.txt
```

#### 3. Install available tools (Run PowerShell as Administrator)

```powershell
# hashcat — GPU-accelerated password cracking (fully supported on Windows)
winget install hashcat

# aircrack-ng — CPU-based cracking (partial Windows support; capture requires Linux)
winget install aircrack-ng

# git — needed to clone KRACK test scripts
winget install Git.Git

# bettercap (optional, partial Windows support)
choco install bettercap
```

> **Note:** `hcxdumptool`, `hcxpcapngtool`, `wifite`, and `airmon-ng` are
> **Linux-only** tools.  On Windows, WifiTool detects this automatically and
> marks them as unavailable.  Use WSL (Windows Subsystem for Linux) or a
> Linux VM/live USB for full packet-capture workflows.

#### 4. Run WifiTool

```powershell
# From an Administrator PowerShell (right-click → Run as administrator):
python main.py
```

#### Windows-specific features

| Feature | Windows support |
|---|---|
| Network Discovery | ✔ Native (via `netsh wlan show networks`) |
| hashcat cracking | ✔ Full (GPU-accelerated) |
| aircrack-ng cracking | ✔ CPU mode (for pre-captured files) |
| Monitor mode / packet capture | ✘ Not supported — use WSL or Linux |
| airodump-ng / aireplay-ng | ✘ Linux only |
| hcxdumptool / hcxpcapngtool | ✘ Linux only |
| Wifite2 | ✘ Linux only |
| Protocol & Attack Reference | ✔ Full |
| KRACK test scripts | ⚠ Requires Linux (hostapd/wpa_supplicant) |

---

### Linux / Kali / Ubuntu / Debian

##### 1. Install Python dependency

```bash
pip3 install rich
# or
pip3 install -r requirements.txt
```

#### 2. Install Wi-Fi tools (Kali Linux / Ubuntu / Debian)

```bash
sudo apt-get update
sudo apt-get install -y aircrack-ng hashcat hcxdumptool hcxtools bettercap wifite
```

#### 3. (Optional) Install KRACK test scripts

```bash
git clone https://github.com/vanhoef/krackattacks-scripts /opt/krackattacks-scripts
cd /opt/krackattacks-scripts && pip3 install -r requirements.txt
```

#### 4. (Optional) Install as a command

```bash
pip3 install -e .
# then run:
wifitool
```

---

## Usage

```bash
# Linux/macOS — run directly (recommended: as root for capture operations)
sudo python3 main.py

# Windows — run from an Administrator PowerShell
python main.py

# If installed via pip (any platform)
wifitool          # Linux/macOS
python -m wifi_tool.ui.app  # Windows alternative
```

The tool detects which of the required tools are installed and shows their
status on startup.  Missing tools can be installed from the **System Setup**
menu (requires root).

---

## Architecture

```
wifi_tool/
├── data/
│   ├── protocols.py    # WEP / WPA / WPA2 / WPA3 reference data
│   └── attacks.py      # FMS / KRACK / PMKID / Dragonblood data
├── tools/
│   ├── system.py       # Interface management, monitor mode, tool detection
│   ├── aircrack.py     # airmon-ng / airodump-ng / aireplay-ng / aircrack-ng
│   ├── hashcat_tool.py # hashcat -m 22000 / 22801
│   ├── hcx.py          # hcxdumptool + hcxpcapngtool
│   ├── bettercap.py    # bettercap wifi modules
│   ├── wifite.py       # wifite2 automated auditing
│   └── krack.py        # vanhoef/krackattacks-scripts runner
└── ui/
    ├── app.py          # Menu-driven application (rich terminal UI)
    └── panels.py       # Reusable rich panels and tables
main.py                 # Root entry point
```

---

## References

- Vanhoef, M. & Piessens, F. (2017). *Key Reinstallation Attacks: Forcing Nonce Reuse in WPA2*. ACM CCS 2017. https://krackattacks.com
- Vanhoef, M. & Ronen, E. (2019). *Dragonblood: Analyzing the Dragonfly Handshake of WPA3*. IEEE S&P 2020.
- Fluhrer, S., Mantin, I., & Shamir, A. (2001). *Weaknesses in the Key Scheduling Algorithm of RC4*. SAC 2001.
- Steube, J. (2018). *New attack on WPA/WPA2 using PMKID*. https://hashcat.net/forum/thread-7717.html
- IEEE 802.11-2020 Standard for Wireless LAN
- Wi-Fi Alliance WPA3 Specification v3.0 (2020)