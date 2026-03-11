"""Aircrack-ng suite wrappers.

Wraps: airmon-ng, airodump-ng, aireplay-ng, aircrack-ng
GitHub: https://github.com/aircrack-ng/aircrack-ng
"""

import subprocess
from typing import List, Optional, Tuple

from .system import check_tool, run_command_live


# ---------------------------------------------------------------------------
# Scanning / Capture
# ---------------------------------------------------------------------------

def scan_networks(interface: str, output_prefix: str,
                  channel: Optional[int] = None) -> int:
    """Run airodump-ng to discover nearby networks.

    Runs interactively (ncurses UI).  User presses Ctrl+C to stop.
    Writes CSV + CAP files to *output_prefix*.
    Returns the process exit code.
    """
    if not check_tool("airodump-ng"):
        raise RuntimeError("airodump-ng not found — install aircrack-ng.")
    cmd = [
        "airodump-ng",
        "--write", output_prefix,
        "--output-format", "csv,pcap",
    ]
    if channel is not None:
        cmd += ["-c", str(channel)]
    cmd.append(interface)
    return run_command_live(cmd)


def capture_targeted(interface: str, bssid: str, channel: int,
                     output_prefix: str) -> int:
    """Capture traffic from a specific AP (airodump-ng targeted).

    Runs interactively.  User presses Ctrl+C to stop.
    Returns the process exit code.
    """
    if not check_tool("airodump-ng"):
        raise RuntimeError("airodump-ng not found.")
    cmd = [
        "airodump-ng",
        "-c", str(channel),
        "--bssid", bssid,
        "-w", output_prefix,
        "--output-format", "pcap",
        interface,
    ]
    return run_command_live(cmd)


# ---------------------------------------------------------------------------
# Injection
# ---------------------------------------------------------------------------

def deauth(interface: str, bssid: str,
           client_mac: Optional[str] = None,
           count: int = 5) -> Tuple[bool, str]:
    """Send deauthentication frames to force client reconnection.

    aireplay-ng -0 <count> -a <bssid> [-c <client>] <interface>
    Returns (success, output).
    """
    if not check_tool("aireplay-ng"):
        return False, "aireplay-ng not found — install aircrack-ng."
    cmd = ["aireplay-ng", "-0", str(count), "-a", bssid]
    if client_mac:
        cmd += ["-c", client_mac]
    cmd.append(interface)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.returncode == 0, (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return False, "aireplay-ng timed out."
    except Exception as exc:
        return False, str(exc)


def arp_replay(interface: str, bssid: str) -> int:
    """ARP request replay attack to accelerate IV generation (WEP).

    aireplay-ng -3 -b <bssid> <interface>
    Runs interactively.  User presses Ctrl+C to stop.
    """
    if not check_tool("aireplay-ng"):
        raise RuntimeError("aireplay-ng not found.")
    cmd = ["aireplay-ng", "-3", "-b", bssid, interface]
    return run_command_live(cmd)


def fake_auth(interface: str, bssid: str) -> Tuple[bool, str]:
    """Fake authentication to associate with a WEP AP.

    aireplay-ng -1 0 -a <bssid> <interface>
    """
    if not check_tool("aireplay-ng"):
        return False, "aireplay-ng not found."
    cmd = ["aireplay-ng", "-1", "0", "-a", bssid, interface]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return result.returncode == 0, (result.stdout + result.stderr).strip()
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# Cracking
# ---------------------------------------------------------------------------

def crack_wep(capture_file: str) -> Tuple[bool, str, Optional[str]]:
    """Run aircrack-ng PTW/FMS statistical attack against a WEP capture.

    Returns (success, full_output, key_or_None).
    """
    if not check_tool("aircrack-ng"):
        return False, "aircrack-ng not found.", None
    try:
        result = subprocess.run(
            ["aircrack-ng", "-z", capture_file],
            capture_output=True,
            text=True,
            timeout=180,
        )
        output = (result.stdout + result.stderr)
        key: Optional[str] = None
        for line in output.splitlines():
            if "KEY FOUND" in line.upper():
                start, end = line.find("["), line.find("]")
                if start != -1 and end != -1:
                    key = line[start + 1 : end].strip()
                    break
        return result.returncode == 0, output.strip(), key
    except subprocess.TimeoutExpired:
        return False, "aircrack-ng timed out.", None
    except Exception as exc:
        return False, str(exc), None


def crack_wpa(capture_file: str, wordlist: str,
              bssid: Optional[str] = None,
              ssid: Optional[str] = None) -> Tuple[bool, str, Optional[str]]:
    """Dictionary attack on a WPA/WPA2 handshake using aircrack-ng.

    Returns (success, full_output, passphrase_or_None).
    """
    if not check_tool("aircrack-ng"):
        return False, "aircrack-ng not found.", None
    cmd = ["aircrack-ng", "-w", wordlist]
    if bssid:
        cmd += ["-b", bssid]
    if ssid:
        cmd += ["-e", ssid]
    cmd.append(capture_file)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        output = (result.stdout + result.stderr)
        key: Optional[str] = None
        for line in output.splitlines():
            if "KEY FOUND" in line.upper():
                start, end = line.find("["), line.find("]")
                if start != -1 and end != -1:
                    key = line[start + 1 : end].strip()
                    break
        return result.returncode == 0, output.strip(), key
    except subprocess.TimeoutExpired:
        return False, "aircrack-ng timed out — try a smaller wordlist.", None
    except Exception as exc:
        return False, str(exc), None


def check_handshake(capture_file: str) -> Tuple[bool, str]:
    """Check whether *capture_file* contains a valid WPA 4-way handshake.

    aircrack-ng without a wordlist reports whether a handshake is present.
    Returns (has_handshake, output).
    """
    if not check_tool("aircrack-ng"):
        return False, "aircrack-ng not found."
    try:
        result = subprocess.run(
            ["aircrack-ng", capture_file],
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = (result.stdout + result.stderr)
        has_handshake = "handshake" in output.lower()
        return has_handshake, output.strip()
    except Exception as exc:
        return False, str(exc)


def launch_interactive(args: Optional[List[str]] = None) -> int:
    """Launch aircrack-ng interactively with arbitrary *args*."""
    if not check_tool("aircrack-ng"):
        raise RuntimeError("aircrack-ng not found.")
    cmd = ["aircrack-ng"] + (args or [])
    return run_command_live(cmd)
