# WifiTool — Project Guide for Claude

## What this project is

WifiTool is a Windows-first Wi-Fi security auditing tool with a customtkinter GUI.
It wraps aircrack-ng, hashcat, bettercap, wifite, and its own Python/Scapy
capture engine into a single attack orchestrator. The user is the sole developer;
Claude does all code changes and creates all PRs.

GitHub: https://github.com/YosefDM/WifiTool

---

## Rules Claude must always follow

- **Never skip `--no-verify`** or bypass hooks. Fix the root cause instead.
- **Always create a new branch** for each fix/feature, push it, open a PR, and
  let the user merge it. After the user says "merged / do the rest", tag the new
  version (e.g. `git tag v1.3.10 && git push origin v1.3.10`).
- The user merges PRs himself and says "do the rest" — that means tag the version.
- Do not add docstrings, refactor, or clean up code that wasn't touched.
- **Before every commit/push, run `gh pr list --state all --limit 20` to check
  which PRs are open vs merged.** Never push new commits onto a branch whose PR
  is already merged — create a new branch instead. Do this check at the start of
  any session where work is continuing from a previous conversation.

### Versioning rules (two separate strings)

| File | When to bump | Format |
|---|---|---|
| `wifi_tool/version.py` | **Every PR** — shown in window title | Dev: add 4th decimal `1.3.9.1`, `1.3.9.2` / Release: bump 3rd `1.3.10` |
| `installer/WifiTool.iss` `MyAppVersion` | **Release PRs only** — triggers installer rebuild (~7 min) | Same as release version e.g. `1.3.10` |

During active development the user runs from source (`WifiTool.bat` → `python main.py`).
Do NOT bump `WifiTool.iss` for dev PRs — only bump it when the user says they are cutting a release.

---

## Current version

Last release: `1.3.9` (installer). Dev build: `1.3.10.2` (running from source).

Version history:
- v1.3.0 — unified attack orchestrator, mask attacks, WEP wordlist fallback
- v1.3.1 — monitor mode enable before wlansvc stop (fixed myGUIDFromString)
- v1.3.2 — tried Npcap device path for airodump-ng (failed, reverted in 1.3.7)
- v1.3.7 — PR #18: friendly name for airodump-ng, font size, Fix WLAN button,
            debug log window, shellexec post-install launch, wlansvc on close
- v1.3.8 — PR #19: Scapy-based handshake capture on Windows (replaces airodump-ng),
            tkfont.Font fix for treeview
- v1.3.9 — PR #20: fix sc.sendp() NPF interface resolution on Windows
- dev builds since v1.3.9 (not yet released as installer):
  - PR #21: WifiTool.bat pulls from GitHub before launching
  - PR #22: fix sc.sniff() NPF interface resolution; version.py added; window title shows version
  - PR #23: show git pull output in WifiTool.bat console
  - PR #24: fix channel never set before Scapy capture; fix PMKID capture timeout; wordlist logging
  - PR #25: fix git pull running as admin (pull before elevation in WifiTool.bat)

---

## Development workflow (no installer rebuild needed)

The user runs from source during development — no installer build between PRs.

```
Double-click WifiTool.bat
  → Pass 1 (normal user): git pull + pip install -r requirements.txt
  → UAC prompt
  → Pass 2 (admin): python main.py
```

Wordlists are copied from the installed version to `wordlists/` in the repo root
(gitignored). `find_default_wordlist()` finds them via `Path(__file__).parent.parent.parent / "wordlists"`.

Only rebuild the installer when the user explicitly says they are cutting a release.

---

## Repository layout

```
WifiTool-main/
├── main.py                        # Entry point: --cli for TUI, else GUI
├── requirements.txt               # customtkinter>=5.2.0, rich>=13.0.0, scapy>=2.5.0
├── WifiTool.bat                   # Dev launcher: git pull (as user) then python main.py (as admin)
├── WifiTool.spec                  # PyInstaller spec (uac_admin=True, console=False)
├── wordlists/                     # gitignored — copied from installed version for dev use
├── installer/
│   ├── WifiTool.iss               # Inno Setup script — defines MyAppVersion
│   ├── build_installer.ps1        # Downloads assets, compiles installer
│   └── assets/                   # aircrack-ng/, hashcat/, npcap-installer.exe,
│                                  # wordlists/wifitool-wordlist-{wpa2,full}.txt
├── wifi_tool/
│   ├── version.py                 # Single source of truth for version string (shown in window title)
│   ├── tools/
│   │   ├── system.py             # IS_WINDOWS, monitor mode, wlansvc, netsh, set_channel_windows
│   │   ├── unified_attack.py     # UnifiedAttacker — the core attack orchestrator
│   │   ├── pcap_utils.py         # Pure-Python Scapy capture + pcap→hc22000 converter
│   │   ├── aircrack.py           # Wrappers: deauth, crack_wpa, check_handshake
│   │   ├── hashcat_tool.py       # Wrappers: convert_pcap, show_cracked
│   │   ├── hcx.py                # hcxdumptool / hcxpcapngtool wrappers
│   │   ├── bettercap.py          # bettercap wrapper
│   │   ├── wifite.py             # wifite wrapper
│   │   └── krack.py              # KRACK vuln assessment
│   ├── ui/
│   │   ├── gui.py                # customtkinter GUI — WifiToolApp class
│   │   ├── app.py                # Rich/terminal TUI fallback
│   │   └── panels.py             # Unused panel helpers
│   └── data/
│       ├── attacks.py            # Attack metadata
│       └── protocols.py          # Protocol metadata
└── .github/workflows/
    └── build-installer.yml       # CI: triggers on v* tags, builds installer
```

---

## Key technical facts

### Windows monitor mode flow (CRITICAL ORDER)

```
1. get_npcap_device_name()      — netsh wlan show interfaces → \Device\NPF_{GUID}
                                   MUST happen before wlansvc is stopped
2. enable_monitor_mode()        — WlanHelper.exe <iface> mode monitor
                                   WlanHelper NEEDS wlansvc running
3. set_channel_windows()        — WlanHelper.exe <iface> channel <N>
                                   Lock adapter to target AP's channel BEFORE stopping wlansvc.
                                   Without this, Scapy sniffs on the wrong channel and captures nothing.
4. kill_interfering_processes() — net stop wlansvc
                                   stops wlansvc AFTER monitor mode and channel are set
5. [capture phase]
6. finally: restart_wlansvc()   — net start wlansvc
                                   MUST happen before WlanHelper restore
7. finally: disable_monitor_mode() — WlanHelper.exe <iface> mode managed
```

Breaking this order causes `SetWlanOperationMode::myGUIDFromString error`.

### Scapy interface resolution on Windows (CRITICAL)

Both `sc.sniff()` and `sc.sendp()` on Windows require a `NetworkInterface` object
from `sc.conf.ifaces`, **not** a raw `\Device\NPF_{GUID}` string. Passing the string
causes `Interface '...' not found !`.

Resolution pattern used in both `pcap_utils.py` and `unified_attack.py`:

```python
iface_obj = npf_string  # fallback
for _obj in sc.conf.ifaces.values():
    _pcap = getattr(_obj, "pcap_name", "") or getattr(_obj, "network_name", "")
    if _pcap and _pcap.lower() == npf_string.lower():
        iface_obj = _obj
        break
# then pass iface_obj to sc.sniff() / sc.sendp()
```

### Two interface variables in UnifiedAttacker

| Variable | Value | Used for |
|---|---|---|
| `self._scapy_iface` | `\Device\NPF_{GUID}` (Windows) or iface name (Linux) | Scapy/pcap_utils capture |
| `self._cap_iface` | friendly name returned by WlanHelper ("Wi-Fi 2") | External tools (airodump-ng, aireplay-ng, bettercap, wifite) |

### Why airodump-ng fails on Windows

airodump-ng calls the WLAN API at startup to enumerate adapters. By the time
capture starts, wlansvc has been stopped. airodump-ng fails with:
`Failed initializing wireless card(s): Wi-Fi 2`
regardless of whether a friendly name or `\Device\NPF_{GUID}` is passed.

**Solution (v1.3.8):** `_phase_handshake_windows()` uses `pcap_utils.capture_pmkid_eapol`
(Scapy + Npcap, no WLAN API dependency) and sends deauth via Scapy instead of
aireplay-ng. Both use `self._scapy_iface`.

### hcxdumptool / hcxpcapngtool replacements

`wifi_tool/tools/pcap_utils.py` provides pure-Python replacements:
- `capture_pmkid_eapol(iface, output_file, bssid_filter, timeout)` — live capture
- `convert_pcap_to_hc22000(input_file, output_file)` — offline conversion

Both use `scapy` + Npcap. Used for PMKID phase and (since v1.3.8) handshake phase on Windows.

### Attack sequence (WPA/WPA2)

```
1. PMKID phase       — Scapy capture (pcap_utils), hashcat -m 22000
2. Handshake phase   — Windows: _phase_handshake_windows() (Scapy + Scapy deauth)
                       Linux:   airodump-ng + aireplay-ng deauth
3. Bettercap phase   — bettercap handshake capture
4. Wifite phase      — wifite2 automated auditor (Linux only)
5. KRACK phase       — KRACK vulnerability assessment (no password)
```

For each phase: hashcat (GPU, wordlist) → aircrack-ng (CPU, wordlist) → hashcat masks.

### Hashcat mask fallbacks (when no wordlist or wordlist exhausted)

```python
("6-digit number",   "?d?d?d?d?d?d"),
("8-digit number",   "?d?d?d?d?d?d?d?d"),
("10-digit number",  "?d?d?d?d?d?d?d?d?d?d"),
("8-char lowercase", "?l?l?l?l?l?l?l?l"),
```

### Wordlists

Two bundled wordlists in `installer/assets/wordlists/`, installed to `{app}\wordlists\`:
- `wifitool-wordlist-wpa2.txt` — 8-63 chars only (WPA2/WPA3 PSK requirement)
- `wifitool-wordlist-full.txt` — unfiltered (WEP and other protocols)

For dev: copy both to `wordlists/` at the repo root (gitignored).
`find_default_wordlist()` → wpa2 list (or rockyou.txt on Linux).
`find_full_wordlist()` → full list (used in `_phase_wep()` dictionary fallback).

### Windows-specific tool notes

- **airmon-ng**: not available on Windows — replaced by WlanHelper.exe (Npcap)
- **hcxdumptool**: not available on Windows — replaced by `pcap_utils.capture_pmkid_eapol`
- **hcxpcapngtool**: not available on Windows — replaced by `pcap_utils.convert_pcap_to_hc22000`
- **wifite**: requires airmon-ng, Linux only
- **hashcat on Windows**: must be run from its own directory (`get_hashcat_dir()` → `cwd`)
- **Npcap WlanHelper**: `C:\Windows\System32\Npcap\WlanHelper.exe`

### wlansvc (WLAN AutoConfig service)

- Must be RUNNING for: `WlanHelper.exe`, `netsh wlan show interfaces`
- Must be STOPPED for: raw 802.11 capture (Npcap, Scapy)
- `kill_interfering_processes()` → `net stop wlansvc` (Windows) or `airmon-ng check kill` (Linux)
- `restart_wlansvc()` → `net start wlansvc`
- Called in: `UnifiedAttacker.run()` finally block + `WifiToolApp._on_close()` + Fix WLAN button

### Error code 50 (ERROR_NOT_SUPPORTED)

If WlanHelper returns "error code = 50" or "not supported", the adapter driver
does not support monitor mode at all. Skip retry, log guidance about using a
dedicated USB adapter (e.g. Alfa AWUS036ACH).

---

## GUI (wifi_tool/ui/gui.py)

Class: `WifiToolApp(ctk.CTk)`

### Layout

- **Toolbar** (row 0): Interface combobox | Scan button | Wordlist entry + Browse
- **Content** (row 1, columnconfigure weight 3:2):
  - Left: `ttk.Treeview` (Nearby Networks) with `Wifi.Treeview` style
  - Right: `CTkTextbox` (Attack Log)
- **Bottom bar** (row 2):
  - "No network selected" label
  - ATTACK button (green, disabled until network selected)
  - STOP button (dark red)
  - Fix WLAN button (amber #4a3000)
  - Indeterminate progress bar
  - Result label (green for success, red for failure)
- **Menu**: View > Debug Log (Ctrl+D)

### Treeview font fix (Windows)

`ttk.Style` ignores `font=("Segoe UI", 12)` tuples on Windows.
Must use `tkfont.Font(family="Segoe UI", size=12)` objects:

```python
import tkinter.font as tkfont
_tree_font = tkfont.Font(family="Segoe UI", size=12)
_heading_font = tkfont.Font(family="Segoe UI", size=12, weight="bold")
style.configure("Wifi.Treeview", font=_tree_font, rowheight=32, ...)
style.configure("Wifi.Treeview.Heading", font=_heading_font, ...)
```

### Debug log window

Accessible via View menu or Ctrl+D. `CTkToplevel` with `CTkTextbox`.
- All log messages are buffered in `self._debug_buffer` (max 20,000 lines)
  with timestamps: `[HH:MM:SS.mmm] LEVEL    message`
- Buffer persists even when window is closed — history visible when reopened
- Clear and Save buttons in button bar

### Thread safety

All log callbacks go through `self._log_queue` (queue.Queue).
`_poll_queue()` drains it on the main thread via `self.after(50, ...)`.
Attack runs on a daemon thread.

### Window close handler

`WM_DELETE_WINDOW` → `_on_close()`:
1. `attacker.stop()` — signals stop event, kills subprocess
2. `attack_thread.join(timeout=5)` — waits for finally block
3. `restart_wlansvc()` — safety net if thread didn't finish

---

## Installer (installer/WifiTool.iss)

- **Version constant**: `#define MyAppVersion "1.3.9"` — only update on release PRs
- **AppId**: `{A9B5C3D2-4E6F-7890-ABCD-EF0123456789}`
- **Output**: `Output/WifiTool-Setup-{version}.exe`
- **Bundled tools**: aircrack-ng (`{app}\tools\aircrack-ng\`), hashcat (`{app}\tools\hashcat\`)
- **Npcap**: runs interactive installer with `/dot11_support=yes`, skipped if already present
- **Post-install launch**: `shellexec` flag → ShellExecute → honours UAC manifest
  (without `shellexec`, CreateProcess would bypass the manifest and run without admin)
- **PATH**: `CurStepChanged(ssPostInstall)` adds aircrack-ng and hashcat dirs to system PATH

### Building

```powershell
powershell -ExecutionPolicy Bypass -File installer\build_installer.ps1
```

CI builds on push to `v*` tags (`.github/workflows/build-installer.yml`).

---

## PyInstaller (WifiTool.spec)

- `uac_admin=True` — requests Administrator elevation on Windows
- `console=False` — GUI app, no console window
- `upx=True` — compressed binary
- Hidden imports: `darkdetect`, `scapy.all`, `scapy.layers.all`, `scapy.layers.dot11`,
  `scapy.layers.l2`, `scapy.layers.eap`, `scapy.sendrecv`, `scapy.utils`
- Data files: `customtkinter` theme JSON/PNG via `collect_data_files("customtkinter")`

---

## Workflow

### Dev PR (most PRs)
1. User reports a bug or requests a feature
2. Claude creates a branch: `fix/something` or `feature/something`
3. Claude implements the fix, bumps **`wifi_tool/version.py`** (4th decimal e.g. `1.3.9.2`), commits, pushes, opens PR
4. User merges — no tagging needed, no installer rebuild

### Release PR (when user says "cut a release")
1. Claude bumps **both** `wifi_tool/version.py` (3rd decimal e.g. `1.3.10`) **and** `installer/WifiTool.iss` `MyAppVersion`
2. User merges and says "do the rest"
3. Claude tags: `git tag v1.3.10 && git push origin v1.3.10`
4. CI builds the installer automatically

---

## Hardware used for testing

- **Adapter**: Alfa AWUS036NH (USB Wi-Fi adapter)
- **OS**: Windows 11 Pro
- **Interface name**: "Wi-Fi 2" (the friendly name returned by WlanHelper and netsh)

---

## Known issues / things to watch for

- **WEP phase on Windows**: `_phase_wep()` still calls airodump-ng, which has the same
  WLAN API init problem as the handshake phase. Consider replacing with Scapy capture
  for WEP too if the user reports it failing.
- **PMKID "No PMKID data captured"**: Expected when no clients are connecting during
  the 60-second capture window. Not a capture failure.
- **Scapy deauth effectiveness**: Scapy deauth frames sent in `_phase_handshake_windows`
  may not work on all adapters in monitor mode. If the user reports no handshakes
  captured, investigate whether deauth is reaching the AP.
- **Code signing**: The installer triggers Windows SmartScreen because it is not code-signed.
  User decided to skip code signing for now.
- **PMKID capture timeout**: `capture_pmkid_eapol()` must always be called with
  `timeout=CAPTURE_SECS`. Without it the sniff thread runs forever and blocks the next phase.
