"""Wifite2 wrapper.

GitHub: https://github.com/derv82/wifite2
Wifite2 is an automated Wi-Fi auditing tool that wraps aircrack-ng,
hashcat, hcxdumptool and others into a unified attack workflow.

**Windows note**: Wifite2 is a Python script that internally calls
``airmon-ng`` (a Linux bash script) for monitor-mode management and relies
on Linux-specific process signals.  It cannot run natively on Windows.
Use the individual workflow menus in WifiTool instead — they call the
Windows-native equivalents (WlanHelper, airodump-ng.exe, aireplay-ng.exe,
pcap_utils) directly.
"""

import shutil
from typing import List, Optional

from .system import IS_WINDOWS, run_command_live


def _find_wifite() -> Optional[str]:
    """Return the wifite executable name, trying common variants."""
    for name in ("wifite", "wifite2"):
        if shutil.which(name):
            return name
    return None


def is_available() -> bool:
    """Return True if wifite / wifite2 is installed and runnable.

    Always returns ``False`` on Windows because wifite requires
    ``airmon-ng`` which is not available natively on Windows.
    """
    if IS_WINDOWS:
        return False
    return _find_wifite() is not None


def launch(interface: Optional[str] = None,
           extra_args: Optional[List[str]] = None) -> int:
    """Launch wifite2 interactively.

    wifite [--interface <interface>] [extra_args]

    Takes over the terminal — wifite manages target selection, attack
    execution and result reporting automatically.
    Returns the process exit code.

    Raises ``RuntimeError`` on Windows (not supported natively).
    """
    if IS_WINDOWS:
        raise RuntimeError(
            "wifite cannot run on Windows natively because it requires\n"
            "airmon-ng, which is a Linux bash script.\n\n"
            "Use the individual WifiTool workflow menus instead:\n"
            "  • System Setup → Enable monitor mode (WlanHelper / Npcap)\n"
            "  • Network Discovery → airodump-ng scan\n"
            "  • WPA/WPA2 Handshake Attack → capture + crack\n"
            "  • PMKID Attack → scapy capture + hashcat"
        )
    cmd_name = _find_wifite()
    if not cmd_name:
        raise RuntimeError("wifite / wifite2 not found — install wifite.")
    cmd = [cmd_name]
    if interface:
        cmd += ["--interface", interface]
    if extra_args:
        cmd += extra_args
    return run_command_live(cmd)


def launch_wep(interface: Optional[str] = None) -> int:
    """Launch wifite targeting WEP networks only."""
    return launch(interface, extra_args=["--wep"])


def launch_wpa(interface: Optional[str] = None,
               wordlist: Optional[str] = None) -> int:
    """Launch wifite targeting WPA/WPA2 networks.

    Optionally pass a *wordlist* path.
    """
    extra: List[str] = ["--wpa"]
    if wordlist:
        extra += ["--dict", wordlist]
    return launch(interface, extra_args=extra)


def launch_pmkid(interface: Optional[str] = None) -> int:
    """Launch wifite using PMKID attack only."""
    return launch(interface, extra_args=["--pmkid"])
