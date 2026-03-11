"""System utilities: interface management, monitor mode, tool detection."""

import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple


IS_WINDOWS: bool = platform.system() == "Windows"

# Sentinel value used in TOOL_PACKAGES_WINDOWS for Linux-only tools
WINDOWS_NOT_AVAILABLE = "not available on Windows"

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

# Maps tool executable name -> winget/chocolatey package name (Windows)
# Tools that are Linux-only are marked with WINDOWS_NOT_AVAILABLE.
TOOL_PACKAGES_WINDOWS: Dict[str, str] = {
    "airmon-ng": WINDOWS_NOT_AVAILABLE,
    "airodump-ng": WINDOWS_NOT_AVAILABLE,
    "aireplay-ng": WINDOWS_NOT_AVAILABLE,
    "aircrack-ng": "aircrack-ng",
    "hashcat": "hashcat",
    "hcxdumptool": WINDOWS_NOT_AVAILABLE,
    "hcxpcapngtool": WINDOWS_NOT_AVAILABLE,
    "bettercap": "bettercap",
    "wifite": WINDOWS_NOT_AVAILABLE,
    "git": "Git.Git",
    "iw": WINDOWS_NOT_AVAILABLE,
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


def enable_monitor_mode(interface: str) -> Tuple[bool, str]:
    """Enable monitor mode on *interface* using airmon-ng.

    Returns (success, monitor_interface_or_error_message).
    Monitor mode is not supported on Windows.
    """
    if IS_WINDOWS:
        return False, (
            "Monitor mode is not supported on Windows. "
            "Use a Linux system or WSL for packet capture operations."
        )
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
    """Disable monitor mode on *interface* using airmon-ng stop.

    Monitor mode is not supported on Windows.
    """
    if IS_WINDOWS:
        return False, (
            "Monitor mode is not supported on Windows. "
            "Use a Linux system or WSL for packet capture operations."
        )
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


def kill_interfering_processes() -> str:
    """Kill processes that interfere with monitor mode (airmon-ng check kill).

    Not applicable on Windows.
    """
    if IS_WINDOWS:
        return "Not applicable on Windows — monitor mode is not supported."
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
    """Install *package* on Windows using winget (primary) or chocolatey (fallback)."""
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


def run_command_live(cmd: List[str], timeout: Optional[int] = None) -> int:
    """Run *cmd* inheriting the current terminal (stdout/stderr pass-through).

    This is correct for ncurses-based tools like airodump-ng, bettercap, and
    wifite that manage their own screen output.  Returns the exit code.
    """
    return subprocess.call(cmd, timeout=timeout)


def stream_command(cmd: List[str]) -> Tuple[int, str]:
    """Run *cmd*, capture all output, and return (returncode, combined_output)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
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
            if upper.startswith("SSID") and not upper.startswith("BSSID") and ":" in stripped:
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
