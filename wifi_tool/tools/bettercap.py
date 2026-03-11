"""Bettercap wrapper.

GitHub: https://github.com/bettercap/bettercap
Bettercap is a comprehensive network attack and monitoring framework
with Wi-Fi, Bluetooth, and Ethernet modules plus a web UI.
"""

import subprocess
from typing import List, Optional

from .system import check_tool, run_command_live


def launch(interface: str,
           caplet: Optional[str] = None,
           extra_args: Optional[List[str]] = None) -> int:
    """Launch bettercap interactively on *interface*.

    bettercap -iface <interface> [-caplet <caplet>] [extra_args]

    Takes over the terminal — user interacts via bettercap REPL or web UI.
    Returns the process exit code.
    """
    if not check_tool("bettercap"):
        raise RuntimeError("bettercap not found — install bettercap.")
    cmd = ["bettercap", "-iface", interface]
    if caplet:
        cmd += ["-caplet", caplet]
    if extra_args:
        cmd += extra_args
    return run_command_live(cmd)


def wifi_recon(interface: str) -> int:
    """Start bettercap with Wi-Fi recon enabled.

    Equivalent to:  bettercap -iface <iface> -eval "wifi.recon on"
    """
    if not check_tool("bettercap"):
        raise RuntimeError("bettercap not found.")
    cmd = ["bettercap", "-iface", interface, "-eval", "wifi.recon on"]
    return run_command_live(cmd)


def wifi_deauth(interface: str, bssid: str) -> int:
    """Deauthenticate all clients from *bssid* using bettercap.

    bettercap -iface <iface> -eval "wifi.recon on; wifi.deauth <bssid>"
    """
    if not check_tool("bettercap"):
        raise RuntimeError("bettercap not found.")
    cmd = [
        "bettercap", "-iface", interface,
        "-eval", f"wifi.recon on; wifi.deauth {bssid}",
    ]
    return run_command_live(cmd)


def run_eval(interface: str, commands: str) -> int:
    """Run bettercap with an eval string (caplet commands).

    bettercap -iface <iface> -eval "<commands>"
    Runs interactively so the user sees the REPL output.
    """
    if not check_tool("bettercap"):
        raise RuntimeError("bettercap not found.")
    cmd = ["bettercap", "-iface", interface, "-eval", commands]
    return run_command_live(cmd)
