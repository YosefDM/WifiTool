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

## Download the Windows Installer

The easiest way to get started on Windows is to download the pre-built
installer from the [Releases page](https://github.com/YosefDM/WifiTool/releases).

**WifiTool-Setup.exe** bundles everything you need:

| Included component | Version | Purpose |
|---|---|---|
| WifiTool application | 1.0.0 | The tool itself (standalone EXE, no Python needed) |
| aircrack-ng (Windows) | 1.7 | airodump-ng, aireplay-ng, aircrack-ng |
| hashcat | 6.2.6 | GPU-accelerated WPA/WPA2 password cracking |
| Npcap driver | 1.79 | Packet capture + monitor mode (installed silently) |

### Installation steps

1. Download **WifiTool-Setup.exe** from the Releases page.
2. Run the installer — it will request Administrator access (required for
   monitor mode and packet capture).
3. The installer installs Npcap silently and adds aircrack-ng and hashcat to
   your system PATH automatically.
4. Launch **WifiTool** from the Start Menu or the Desktop shortcut.

> **Note**: WifiTool always requires Administrator privileges when capturing
> packets or toggling monitor mode.  Right-click → *Run as administrator* if
> the shortcut doesn't request elevation automatically.

---

## Quick Start — Windows (double-click setup, no installer)

If you prefer to run from source rather than using the installer, two batch
scripts are included:

| Script | Purpose |
|---|---|
| `setup.bat` | **Run once.** Installs Python (via winget if missing), installs `rich` and `scapy`, opens the aircrack-ng and hashcat download pages, optionally installs Git via winget, and opens the Npcap download page. |
| `WifiTool.bat` | **Run every time.** Launches WifiTool; automatically requests Administrator privileges. |

### Steps

1. **Download / clone** this repository to any folder on your PC.
2. **Double-click `setup.bat`** — it will request Administrator access, then
   walk you through each installation step.
3. When prompted, download and install **Npcap** from
   <https://npcap.com/#download> (check *"Support raw 802.11 traffic"*).
4. **Double-click `WifiTool.bat`** to start the tool at any time.

> **Note**: Both scripts self-elevate to Administrator automatically.  If UAC
> prompts you, click *Yes*.

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

> **Easiest way**: use the included `setup.bat` and `WifiTool.bat` scripts
> described in the [Quick Start](#quick-start--windows-double-click-setup)
> section above.  The manual steps below are for reference.

#### 1. Install Python (if not already installed)

```powershell
winget install Python.Python.3
```

#### 2. Install WifiTool dependencies

```powershell
pip install -r requirements.txt
# (installs rich and scapy — scapy powers the Windows-native capture tools)
```

#### 3. Install Npcap (required for monitor mode and packet capture)

Download and install Npcap from **https://npcap.com/#download**.
During installation check **"Support raw 802.11 traffic (monitor mode)"**.

Npcap provides:
- The packet-capture driver used by `airodump-ng.exe` and `aireplay-ng.exe`
- `WlanHelper.exe` — used by WifiTool to enable/disable monitor mode on Windows
  (replaces `airmon-ng`)

#### 4. Install aircrack-ng and optional tools

**aircrack-ng** (includes `airodump-ng.exe` and `aireplay-ng.exe`):
- No winget or Chocolatey package exists for aircrack-ng
- Download the Windows `.zip` from **https://www.aircrack-ng.org/downloads.html**,
  extract it, and add the folder to `PATH`

**hashcat** (GPU-accelerated password cracking):
- No winget package exists for hashcat — it is distributed as a `.7z` archive
  ([hashcat/hashcat#4215](https://github.com/hashcat/hashcat/issues/4215))
- Download from **https://hashcat.net/hashcat/**, extract to a permanent folder,
  and run `hashcat.exe` **from that folder** (hashcat on Windows requires the
  current directory to be its own folder to locate its kernel files)

**git** (needed to clone KRACK test scripts):

```powershell
winget install Git.Git
```

**bettercap** (optional):

```powershell
choco install bettercap
```

#### 5. Run WifiTool

```powershell
# From an Administrator PowerShell (right-click → Run as administrator):
python main.py
```

#### Windows feature availability

| Feature | Windows support |
|---|---|
| Network Discovery (quick) | ✔ Native — `netsh wlan show networks` |
| Network Discovery (full) | ✔ `airodump-ng.exe` + Npcap (monitor mode) |
| Monitor mode enable/disable | ✔ Npcap `WlanHelper.exe` (replaces `airmon-ng`) |
| airodump-ng / aireplay-ng | ✔ Windows aircrack-ng build + Npcap |
| aircrack-ng cracking | ✔ Full |
| hashcat cracking | ✔ Full (GPU-accelerated) |
| hcxdumptool (PMKID capture) | ✔ Python/scapy replacement (pcap_utils) |
| hcxpcapngtool (pcap→hc22000) | ✔ Python/scapy replacement (pcap_utils) |
| bettercap | ✔ Windows build available |
| Wifite2 | ✘ Requires `airmon-ng` (Linux bash script) |
| Protocol & Attack Reference | ✔ Full |
| KRACK test scripts | ⚠ Requires Linux (hostapd/wpa_supplicant) |

> **Note on Wifite2**: Wifite2 internally calls `airmon-ng` (a Linux bash
> script) and cannot run natively on Windows.  WifiTool's individual workflow
> menus replicate the same attack chains using Windows-native tools.

---

### Build the installer from source (Windows)

> **Prerequisites**: Python 3.8+, [Inno Setup 6](https://jrsoftware.org/isinfo.php),
> [7-Zip](https://www.7-zip.org), and an internet connection.

```powershell
# Clone the repo and run the build helper from an Administrator PowerShell:
git clone https://github.com/YosefDM/WifiTool.git
cd WifiTool
powershell -ExecutionPolicy Bypass -File installer\build_installer.ps1
```

The script:
1. Downloads aircrack-ng, hashcat, and the Npcap driver installer into
   `installer\assets\` (skipped automatically on subsequent runs).
2. Runs **PyInstaller** (`WifiTool.spec`) to produce a self-contained EXE at
   `dist\WifiTool\WifiTool.exe`.
3. Runs **Inno Setup** (`installer\WifiTool.iss`) to compile the final
   `installer\Output\WifiTool-Setup.exe`.

The [GitHub Actions workflow](.github/workflows/build-installer.yml) runs the
same steps automatically on every version tag push and attaches the installer
to the GitHub Release.

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