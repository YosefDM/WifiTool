"""Hashcat wrapper for WPA2 handshake and PMKID cracking.

GitHub: https://github.com/hashcat/hashcat
"""

import subprocess
from typing import List, Optional, Tuple

from .system import IS_WINDOWS, check_tool, get_hashcat_dir, run_command_live


# ---------------------------------------------------------------------------
# Capture conversion (hcxpcapngtool / pcap_utils fallback)
# ---------------------------------------------------------------------------

def convert_pcap(input_file: str, output_file: str) -> Tuple[bool, str]:
    """Convert a pcap/pcapng capture to hashcat hc22000 format.

    On Linux/macOS uses ``hcxpcapngtool``::

        hcxpcapngtool -o <output_file> <input_file>

    On Windows (when ``hcxpcapngtool`` is not on PATH) uses the pure-Python
    :func:`~wifi_tool.tools.pcap_utils.convert_pcap_to_hc22000` (scapy).

    GitHub (hcxtools): https://github.com/ZerBea/hcxtools
    Returns (success, output).
    """
    if IS_WINDOWS and not check_tool("hcxpcapngtool"):
        from .pcap_utils import convert_pcap_to_hc22000
        return convert_pcap_to_hc22000(input_file, output_file)

    if not check_tool("hcxpcapngtool"):
        return False, "hcxpcapngtool not found — install hcxtools."
    try:
        result = subprocess.run(
            ["hcxpcapngtool", "-o", output_file, input_file],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result.returncode == 0, (result.stdout + result.stderr).strip()
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# Cracking
# ---------------------------------------------------------------------------

def crack_wpa2(hash_file: str, wordlist: str,
               rules: Optional[List[str]] = None,
               extra_args: Optional[List[str]] = None) -> int:
    """Run hashcat in WPA2-EAPOL-PBKDF2 mode (-m 22000) interactively.

    hashcat -m 22000 <hash_file> <wordlist> [--rules ...]
    Runs interactively so the user can see live progress.
    Returns the process exit code.
    """
    if not check_tool("hashcat"):
        raise RuntimeError("hashcat not found — install hashcat.")
    cmd = ["hashcat", "-m", "22000", hash_file, wordlist]
    if rules:
        for rule in rules:
            cmd += ["-r", rule]
    if extra_args:
        cmd += extra_args
    return run_command_live(cmd, cwd=get_hashcat_dir())


def crack_pmkid(hash_file: str, wordlist: str,
                rules: Optional[List[str]] = None,
                extra_args: Optional[List[str]] = None) -> int:
    """Run hashcat in WPA2-PMKID mode (-m 22801) interactively.

    hashcat -m 22801 <hash_file> <wordlist> [--rules ...]
    Returns the process exit code.
    """
    if not check_tool("hashcat"):
        raise RuntimeError("hashcat not found — install hashcat.")
    cmd = ["hashcat", "-m", "22801", hash_file, wordlist]
    if rules:
        for rule in rules:
            cmd += ["-r", rule]
    if extra_args:
        cmd += extra_args
    return run_command_live(cmd, cwd=get_hashcat_dir())


def crack_wpa_legacy(hash_file: str, wordlist: str,
                     extra_args: Optional[List[str]] = None) -> int:
    """Run hashcat in legacy WPA-PSK mode (-m 2500) interactively."""
    if not check_tool("hashcat"):
        raise RuntimeError("hashcat not found.")
    cmd = ["hashcat", "-m", "2500", hash_file, wordlist]
    if extra_args:
        cmd += extra_args
    return run_command_live(cmd, cwd=get_hashcat_dir())


def show_cracked(hash_file: str, mode: int = 22000) -> Tuple[bool, str]:
    """Show previously cracked passwords from the hashcat potfile.

    hashcat -m <mode> <hash_file> --show
    Returns (success, output).
    """
    if not check_tool("hashcat"):
        return False, "hashcat not found."
    try:
        result = subprocess.run(
            ["hashcat", "-m", str(mode), hash_file, "--show"],
            capture_output=True,
            text=True,
            timeout=15,
            cwd=get_hashcat_dir(),
        )
        return result.returncode == 0, (result.stdout + result.stderr).strip()
    except Exception as exc:
        return False, str(exc)


def launch_interactive(args: Optional[List[str]] = None) -> int:
    """Launch hashcat interactively with arbitrary *args*."""
    if not check_tool("hashcat"):
        raise RuntimeError("hashcat not found.")
    cmd = ["hashcat"] + (args or [])
    return run_command_live(cmd, cwd=get_hashcat_dir())
