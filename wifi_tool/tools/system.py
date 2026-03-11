"""System utilities: interface management, monitor mode, tool detection."""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# Maps tool executable name -> apt package to install it from
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
    """Return True when running as root (uid 0)."""
    return os.geteuid() == 0


def get_wireless_interfaces() -> List[str]:
    """Return a list of wireless interface names detected on the system."""
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


def get_all_interfaces() -> List[str]:
    """Return all network interface names (wired + wireless)."""
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
    """
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
    """Disable monitor mode on *interface* using airmon-ng stop."""
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
    """Kill processes that interfere with monitor mode (airmon-ng check kill)."""
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


def install_tool(package: str) -> Tuple[bool, str]:
    """Install *package* via apt-get (requires root)."""
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
