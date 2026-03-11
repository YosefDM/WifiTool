"""hcxdumptool + hcxtools wrappers.

hcxdumptool — https://github.com/ZerBea/hcxdumptool
hcxtools     — https://github.com/ZerBea/hcxtools

These tools capture WPA2/WPA3 handshakes and PMKIDs in pcapng format
optimised for hashcat.  hcxdumptool can request PMKID frames from APs
without any client being connected (clientless attack).
"""

import subprocess
from typing import Optional, Tuple

from .system import check_tool, run_command_live


def capture(interface: str, output_file: str,
            bssid_filter: Optional[str] = None,
            enable_status: int = 3) -> int:
    """Run hcxdumptool to capture PMKIDs and handshakes simultaneously.

    hcxdumptool -i <interface> -o <output_file> --enable_status=3
                [--filterlist_ap=<bssid> --filtermode=2]

    Runs interactively.  User presses Ctrl+C to stop.
    Returns the process exit code.
    """
    if not check_tool("hcxdumptool"):
        raise RuntimeError("hcxdumptool not found — install hcxdumptool.")
    cmd = [
        "hcxdumptool",
        "-i", interface,
        "-o", output_file,
        f"--enable_status={enable_status}",
    ]
    if bssid_filter:
        # Write a temporary filter file expected by newer hcxdumptool versions
        import os
        import tempfile
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        tmp.write(bssid_filter.replace(":", "").lower() + "\n")
        tmp.close()
        cmd += [f"--filterlist_ap={tmp.name}", "--filtermode=2"]
    return run_command_live(cmd)


def convert_to_hashcat(input_file: str, output_file: str) -> Tuple[bool, str]:
    """Convert a pcapng capture to hashcat hc22000 format.

    hcxpcapngtool -o <output_file> <input_file>
    Returns (success, output).
    """
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


def get_capture_summary(capture_file: str) -> Tuple[bool, str]:
    """Print a summary of what is inside a pcapng capture file.

    hcxpcapngtool <capture_file>   (no -o flag → prints summary only)
    Returns (success, output).
    """
    if not check_tool("hcxpcapngtool"):
        return False, "hcxpcapngtool not found."
    try:
        result = subprocess.run(
            ["hcxpcapngtool", capture_file],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return result.returncode == 0, (result.stdout + result.stderr).strip()
    except Exception as exc:
        return False, str(exc)


def launch_interactive(interface: str,
                       extra_args: Optional[list] = None) -> int:
    """Launch hcxdumptool interactively with arbitrary extra arguments."""
    if not check_tool("hcxdumptool"):
        raise RuntimeError("hcxdumptool not found.")
    cmd = ["hcxdumptool", "-i", interface] + (extra_args or [])
    return run_command_live(cmd)
