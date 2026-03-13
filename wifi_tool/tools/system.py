"""System utilities: interface management, monitor mode, tool detection."""

import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple


IS_WINDOWS: bool = platform.system() == "Windows"

# Sentinel value used in TOOL_PACKAGES_WINDOWS for tools that have no
# viable native Windows equivalent.
WINDOWS_NOT_AVAILABLE = "not available on Windows"

# Download URL for Npcap — the Windows packet-capture library required by
# airodump-ng, aireplay-ng, and monitor-mode support.
NPCAP_DOWNLOAD_URL = "https://npcap.com/#download"

# Download URLs for tools that have Windows builds distributed as archives
# (not available as winget or Chocolatey packages).
#
# aircrack-ng ships a Windows .zip from its official site; there is no winget
# package for it (winget only supports .zip/.exe/.msi installers and the
# aircrack-ng zip is not registered in the winget repository).
#
# hashcat ships a Windows .7z archive from its official site; winget does not
# support .7z packages and hashcat is not registered in the winget repository
# (see https://github.com/hashcat/hashcat/issues/4215). Additionally, on
# Windows hashcat must be run from its own directory — it cannot locate its
# kernel files when invoked from a different directory via PATH alone.
AIRCRACK_WINDOWS_DOWNLOAD_URL = "https://www.aircrack-ng.org/downloads.html"
HASHCAT_WINDOWS_DOWNLOAD_URL = "https://hashcat.net/hashcat/"

# Candidate locations for Npcap's WlanHelper.exe (monitor-mode toggling)
_NPCAP_WLANHELPER_PATHS: List[str] = [
    r"C:\Windows\System32\Npcap\WlanHelper.exe",
    r"C:\Program Files\Npcap\WlanHelper.exe",
]

# Maps tool executable name -> apt package to install it from (Linux/macOS)
TOOL_PACKAGES: Dict[str, str] = {
    "airmon-ng": "aircrack-ng",
    "airodump-ng": "aircrack-ng",
    "aireplay-ng": "aircrack-ng",
    "aircrack-ng": "aircrack-ng",
    "hashcat": "hashcat",
    "hcxdumptool": "hcxdumptool",
    "hcxpcapngtool": "hcxtools",
    "bettercap": "bettercap",
    "wifite": "wifite",
    "git": "git",
    "iw": "iw",
}

# Maps tool executable name -> install hint for Windows.
#
# airodump-ng and aireplay-ng are bundled in the official Windows build of
# aircrack-ng and work natively with Npcap.  The Windows build is distributed
# as a .zip from the official site — there is no winget package for it.
#
# hashcat is distributed as a .7z archive from its official site — winget
# does not support .7z packages and hashcat is not in the winget repository
# (see https://github.com/hashcat/hashcat/issues/4215).
#
# airmon-ng is a Linux bash script; on Windows Npcap's WlanHelper.exe is
# used instead to toggle monitor mode (see enable_monitor_mode).
#
# hcxdumptool and hcxpcapngtool have no Windows binaries; WifiTool provides
# its own Python-native replacements (wifi_tool/tools/pcap_utils.py).
#
# wifite is a Python orchestrator that hard-codes calls to airmon-ng which
# does not exist on Windows; it cannot run natively without modification.
#
# iw is a Linux kernel netlink tool; netsh covers the same use-cases on
# Windows and is already used by get_wireless_interfaces().
TOOL_PACKAGES_WINDOWS: Dict[str, str] = {
    "airmon-ng":     WINDOWS_NOT_AVAILABLE,              # replaced by WlanHelper (Npcap)
    "airodump-ng":   AIRCRACK_WINDOWS_DOWNLOAD_URL,      # bundled in Windows aircrack-ng zip
    "aireplay-ng":   AIRCRACK_WINDOWS_DOWNLOAD_URL,      # bundled in Windows aircrack-ng zip
    "aircrack-ng":   AIRCRACK_WINDOWS_DOWNLOAD_URL,      # download .zip from official site
    "hashcat":       HASHCAT_WINDOWS_DOWNLOAD_URL,       # download .7z from official site
    "hcxdumptool":   WINDOWS_NOT_AVAILABLE,              # replaced by pcap_utils (Python)
    "hcxpcapngtool": WINDOWS_NOT_AVAILABLE,              # replaced by pcap_utils (Python)
    "bettercap":     "bettercap",
    "wifite":        WINDOWS_NOT_AVAILABLE,              # requires airmon-ng (Linux only)
    "git":           "Git.Git",
    "iw":            WINDOWS_NOT_AVAILABLE,              # replaced by netsh
}

# GitHub source repos for reference
TOOL_REPOS: Dict[str, str] = {
    "aircrack-ng": "https://github.com/aircrack-ng/aircrack-ng",
    "hashcat": "https://github.com/hashcat/hashcat",
    "hcxdumptool": "https://github.com/ZerBea/hcxdumptool",
    "hcxtools": "https://github.com/ZerBea/hcxtools",
    "bettercap": "https://github.com/bettercap/bettercap",
    "wifite": "https://github.com/derv82/wifite2",
    "krackattacks-scripts": "https://github.com/vanhoef/krackattacks-scripts",
}


def check_tool(name: str) -> bool:
    """Return True if *name* is found on PATH."""
    return shutil.which(name) is not None


def get_all_tool_status() -> Dict[str, bool]:
    """Return a dict of {tool_name: is_installed} for every tracked tool."""
    return {tool: check_tool(tool) for tool in TOOL_PACKAGES}


# ---------------------------------------------------------------------------
# Npcap / WlanHelper helpers (Windows monitor mode)
# ---------------------------------------------------------------------------

def find_npcap_wlanhelper() -> Optional[str]:
    """Return the absolute path to Npcap's ``WlanHelper.exe``, or ``None``.

    WlanHelper is bundled with Npcap and provides monitor-mode toggling on
    Windows, equivalent to ``airmon-ng start / stop`` on Linux.
    Install Npcap from: https://npcap.com/#download
    During installation check "Support raw 802.11 traffic (monitor mode)".
    """
    if not IS_WINDOWS:
        return None
    for p in _NPCAP_WLANHELPER_PATHS:
        if Path(p).is_file():
            return p
    return shutil.which("WlanHelper")


def is_root() -> bool:
    """Return True when running with elevated privileges.

    On Windows this checks for Administrator status; on Unix it checks uid 0.
    """
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def _get_wireless_interfaces_windows() -> List[str]:
    """Return wireless interface names on Windows using ``netsh``."""
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        interfaces: List[str] = []
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("name") and ":" in stripped:
                name = stripped.split(":", 1)[1].strip()
                if name:
                    interfaces.append(name)
        return interfaces
    except Exception:
        return []


def get_wireless_interfaces() -> List[str]:
    """Return a list of wireless interface names detected on the system."""
    if IS_WINDOWS:
        return _get_wireless_interfaces_windows()

    interfaces: List[str] = []

    # Primary method: iw dev
    if shutil.which("iw"):
        try:
            result = subprocess.run(
                ["iw", "dev"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("Interface"):
                    parts = stripped.split()
                    if len(parts) >= 2:
                        interfaces.append(parts[1])
            if interfaces:
                return interfaces
        except Exception:
            pass

    # Fallback: /sys/class/net — check for wireless subdirectory
    net_path = Path("/sys/class/net")
    if net_path.exists():
        for iface in sorted(net_path.iterdir()):
            if (iface / "wireless").exists() or (iface / "phy80211").exists():
                interfaces.append(iface.name)

    return interfaces


def _get_all_interfaces_windows() -> List[str]:
    """Return all network interface names on Windows using ``netsh``."""
    try:
        result = subprocess.run(
            ["netsh", "interface", "show", "interface"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        interfaces: List[str] = []
        for line in result.stdout.splitlines():
            parts = line.split()
            # Lines look like: "Enabled    Connected    Dedicated    Wi-Fi"
            if len(parts) >= 4 and parts[0] in ("Enabled", "Disabled"):
                interfaces.append(" ".join(parts[3:]))
        return interfaces
    except Exception:
        return []


def get_all_interfaces() -> List[str]:
    """Return all network interface names (wired + wireless)."""
    if IS_WINDOWS:
        return _get_all_interfaces_windows()

    try:
        result = subprocess.run(
            ["ip", "link", "show"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        interfaces: List[str] = []
        for line in result.stdout.splitlines():
            if ": " in line and not line.startswith(" "):
                iface = line.split(": ")[1].split("@")[0]
                if iface not in ("lo", ""):
                    interfaces.append(iface)
        return interfaces
    except Exception:
        return []


def get_npcap_device_name(interface_name: str) -> Optional[str]:
    """Return the Npcap device path (\\Device\\NPF_{GUID}) for a Wi-Fi interface.

    airodump-ng and aireplay-ng on Windows require this Npcap path rather
    than the friendly name (e.g. "Wi-Fi") that WlanHelper accepts.
    Must be called while wlansvc is still running (before kill_interfering_processes).
    """
    if not IS_WINDOWS:
        return None
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        current_name: Optional[str] = None
        for line in result.stdout.splitlines():
            s = line.strip()
            low = s.lower()
            # "Name : Wi-Fi" — avoid matching "Network Name (SSID)"
            if low.startswith("name") and ":" in s and "ssid" not in low and "network" not in low:
                current_name = s.split(":", 1)[1].strip()
            elif low.startswith("guid") and ":" in s:
                if current_name and current_name.lower() == interface_name.lower():
                    guid = s.split(":", 1)[1].strip()
                    return rf"\Device\NPF_{{{guid}}}"
    except Exception:
        pass
    return None


def _enable_monitor_mode_windows(interface: str) -> Tuple[bool, str]:
    """Enable monitor mode on Windows using Npcap's WlanHelper.exe."""
    helper = find_npcap_wlanhelper()
    if not helper:
        return False, (
            "Npcap WlanHelper not found.\n"
            f"  Install Npcap from {NPCAP_DOWNLOAD_URL}\n"
            "  During installation check 'Support raw 802.11 traffic (monitor mode)'."
        )
    try:
        result = subprocess.run(
            [helper, interface, "mode", "monitor"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = (result.stdout + result.stderr).strip()
        if result.returncode == 0:
            return True, interface
        return False, output or "WlanHelper returned a non-zero exit code."
    except subprocess.TimeoutExpired:
        return False, "WlanHelper timed out."
    except Exception as exc:
        return False, str(exc)


def _disable_monitor_mode_windows(interface: str) -> Tuple[bool, str]:
    """Disable monitor mode on Windows using Npcap's WlanHelper.exe."""
    helper = find_npcap_wlanhelper()
    if not helper:
        return False, (
            f"Npcap WlanHelper not found. Install Npcap from {NPCAP_DOWNLOAD_URL}."
        )
    try:
        result = subprocess.run(
            [helper, interface, "mode", "managed"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = (result.stdout + result.stderr).strip()
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "WlanHelper timed out."
    except Exception as exc:
        return False, str(exc)


def enable_monitor_mode(interface: str) -> Tuple[bool, str]:
    """Enable monitor mode on *interface*.

    On Windows uses Npcap's ``WlanHelper.exe`` to put the adapter into
    monitor (802.11) mode.  Npcap must be installed with
    "Support raw 802.11 traffic" checked — see https://npcap.com/#download.

    On Linux/macOS uses ``airmon-ng start``.
    Returns (success, monitor_interface_name_or_error_message).
    """
    if IS_WINDOWS:
        return _enable_monitor_mode_windows(interface)
    if not check_tool("airmon-ng"):
        return False, "airmon-ng not found — install aircrack-ng."
    try:
        result = subprocess.run(
            ["airmon-ng", "start", interface],
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = result.stdout + result.stderr

        # Parse the monitor interface name from output lines like:
        #   "monitor mode vif enabled for [...]mon on [phy]; [...]mon"
        for line in output.splitlines():
            low = line.lower()
            if "monitor mode" in low and ("enabled" in low or "already" in low):
                for word in line.split():
                    if word.endswith("mon") and len(word) >= 4:
                        return True, word

        # Fallback: assume conventional naming
        mon_iface = interface + "mon" if not interface.endswith("mon") else interface
        if result.returncode == 0:
            return True, mon_iface
        return False, output.strip()
    except subprocess.TimeoutExpired:
        return False, "airmon-ng timed out."
    except Exception as exc:
        return False, str(exc)


def disable_monitor_mode(interface: str) -> Tuple[bool, str]:
    """Disable monitor mode on *interface*.

    On Windows uses Npcap's ``WlanHelper.exe`` to restore managed mode.
    On Linux/macOS uses ``airmon-ng stop``.
    """
    if IS_WINDOWS:
        return _disable_monitor_mode_windows(interface)
    if not check_tool("airmon-ng"):
        return False, "airmon-ng not found."
    try:
        result = subprocess.run(
            ["airmon-ng", "stop", interface],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return result.returncode == 0, (result.stdout + result.stderr).strip()
    except Exception as exc:
        return False, str(exc)


def restart_wlansvc() -> str:
    """Restart the WLAN AutoConfig service on Windows.

    Call this after capture is complete so that WlanHelper can talk to the
    WLAN API again (it requires wlansvc to be running).
    """
    if not IS_WINDOWS:
        return ""
    try:
        result = subprocess.run(
            ["net", "start", "wlansvc"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return (result.stdout + result.stderr).strip()
    except Exception as exc:
        return str(exc)


def kill_interfering_processes() -> str:
    """Stop processes that interfere with monitor mode.

    On Windows: temporarily stops the WLAN AutoConfig service (wlansvc)
    which holds the adapter in managed mode.  Remember to restart it
    afterwards with ``net start wlansvc``.
    On Linux: uses ``airmon-ng check kill``.
    """
    if IS_WINDOWS:
        try:
            result = subprocess.run(
                ["net", "stop", "wlansvc"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            output = (result.stdout + result.stderr).strip()
            if result.returncode == 0:
                return (
                    output + "\n"
                    "WLAN AutoConfig stopped. Re-enable after capture with: "
                    "net start wlansvc"
                )
            return output
        except Exception as exc:
            return str(exc)
    if not check_tool("airmon-ng"):
        return "airmon-ng not found."
    try:
        result = subprocess.run(
            ["airmon-ng", "check", "kill"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return (result.stdout + result.stderr).strip()
    except Exception as exc:
        return str(exc)


def _install_tool_windows(package: str) -> Tuple[bool, str]:
    """Install *package* on Windows using winget (primary) or chocolatey (fallback).

    If *package* is a URL the tool must be downloaded and installed manually;
    automated installation is not possible and instructions are returned instead.
    """
    if package.startswith("https://"):
        return False, (
            "This tool is not available as a winget or Chocolatey package.\n"
            f"  Download and install the Windows build manually from: {package}"
        )
    if not is_root():
        return False, "Administrator privileges required for installation."
    for mgr, cmd in [
        ("winget", ["winget", "install", "--accept-source-agreements",
                    "--accept-package-agreements", package]),
        ("choco", ["choco", "install", "-y", package]),
    ]:
        if shutil.which(mgr):
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                return result.returncode == 0, (result.stdout + result.stderr).strip()
            except Exception as exc:
                return False, str(exc)
    return (
        False,
        "No supported package manager found. "
        "Install winget (built into Windows 11) or Chocolatey (https://chocolatey.org).",
    )


def install_tool(package: str) -> Tuple[bool, str]:
    """Install *package* using the platform package manager.

    On Windows uses winget or chocolatey; on Linux/macOS uses apt-get.
    If *package* is a URL (tools distributed as archives without a package
    manager entry) installation instructions are returned instead.
    Requires elevated privileges in both cases.
    """
    if IS_WINDOWS:
        return _install_tool_windows(package)
    if not is_root():
        return False, "Root privileges required for installation."
    try:
        result = subprocess.run(
            ["apt-get", "install", "-y", package],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.returncode == 0, (result.stdout + result.stderr).strip()
    except Exception as exc:
        return False, str(exc)


def get_hashcat_dir() -> Optional[str]:
    """Return the directory that contains ``hashcat.exe`` / ``hashcat``, or ``None``.

    On Windows, hashcat must be invoked with its own directory as the working
    directory because it locates its kernel files relative to ``cwd``.  This
    function returns the parent directory of the hashcat executable found on
    PATH so callers can pass it as ``cwd`` to :func:`run_command_live` /
    :func:`stream_command`.

    On Linux/macOS hashcat can be called from any directory, so this returns
    ``None`` on those platforms.
    """
    if not IS_WINDOWS:
        return None
    hashcat_path = shutil.which("hashcat")
    if hashcat_path:
        return str(Path(hashcat_path).parent)
    return None


def run_command_live(
    cmd: List[str],
    timeout: Optional[int] = None,
    cwd: Optional[str] = None,
) -> int:
    """Run *cmd* inheriting the current terminal (stdout/stderr pass-through).

    This is correct for ncurses-based tools like airodump-ng, bettercap, and
    wifite that manage their own screen output.  Returns the exit code.

    *cwd* sets the working directory for the subprocess.  This is required
    when running ``hashcat`` on Windows (use :func:`get_hashcat_dir`).
    """
    return subprocess.call(cmd, timeout=timeout, cwd=cwd)


def stream_command(
    cmd: List[str],
    cwd: Optional[str] = None,
) -> Tuple[int, str]:
    """Run *cmd*, capture all output, and return (returncode, combined_output).

    *cwd* sets the working directory for the subprocess.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            cwd=cwd,
        )
        return result.returncode, (result.stdout + result.stderr)
    except subprocess.TimeoutExpired as exc:
        return 1, f"Command timed out: {exc}"
    except Exception as exc:
        return 1, str(exc)


def scan_networks_windows() -> List[Dict[str, str]]:
    """Scan for nearby Wi-Fi networks on Windows using ``netsh wlan show networks``.

    Returns a list of dicts with keys: SSID, BSSID, Signal, Channel, Auth,
    Cipher, Radio.  Only available on Windows.
    """
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        networks: List[Dict[str, str]] = []
        current: Dict[str, str] = {}
        bssid_idx = 0

        def _after_colon(s: str) -> str:
            """Return the trimmed value after the first colon in *s*."""
            return s.split(":", 1)[1].strip()

        for line in result.stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            upper = stripped.upper()

            # "SSID 1 : MyNetwork" starts a new network block.
            # Guard against matching "BSSID …" lines with the same prefix check.
            if upper.startswith("SSID") and ":" in stripped:
                if current:
                    networks.append(current)
                current = {}
                bssid_idx = 0
                current["SSID"] = _after_colon(stripped)

            elif upper.startswith("BSSID") and ":" in stripped:
                # Only record the first BSSID per SSID block
                if bssid_idx == 0:
                    # _after_colon splits only on the first colon, preserving
                    # the remaining colons that are part of the MAC address.
                    current["BSSID"] = _after_colon(stripped)
                bssid_idx += 1

            elif stripped.lower().startswith("signal") and ":" in stripped:
                if bssid_idx <= 1:
                    current["Signal"] = _after_colon(stripped)

            elif stripped.lower().startswith("radio type") and ":" in stripped:
                if bssid_idx <= 1:
                    current["Radio"] = _after_colon(stripped)

            elif stripped.lower().startswith("channel") and ":" in stripped:
                if bssid_idx <= 1:
                    current["Channel"] = _after_colon(stripped)

            elif stripped.lower().startswith("authentication") and ":" in stripped:
                current["Auth"] = _after_colon(stripped)

            elif stripped.lower().startswith("encryption") and ":" in stripped:
                if "Cipher" not in current:
                    current["Cipher"] = _after_colon(stripped)

        if current:
            networks.append(current)

        return networks
    except Exception:
        return []
