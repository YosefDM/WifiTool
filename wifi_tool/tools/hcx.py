"""hcxdumptool + hcxtools wrappers.

hcxdumptool — https://github.com/ZerBea/hcxdumptool
hcxtools     — https://github.com/ZerBea/hcxtools

These tools capture WPA2/WPA3 handshakes and PMKIDs in pcapng format
optimised for hashcat.  hcxdumptool can request PMKID frames from APs
without any client being connected (clientless attack).

**Windows**: native replacements are provided via
:mod:`wifi_tool.tools.pcap_utils` (scapy + Npcap).  The wrapper functions
below automatically select the correct implementation.
"""

import subprocess
from typing import Optional, Tuple

from .system import IS_WINDOWS, check_tool, run_command_live


def capture(interface: str, output_file: str,
            bssid_filter: Optional[str] = None,
            enable_status: int = 3) -> int:
    """Capture PMKIDs and WPA handshakes on *interface*.

    On Linux/macOS runs::

        hcxdumptool -i <interface> -o <output_file> --enable_status=3
                    [--filterlist_ap=<bssid> --filtermode=2]

    On Windows uses the pure-Python
    :func:`~wifi_tool.tools.pcap_utils.capture_pmkid_eapol`
    (scapy + Npcap).  The adapter must already be in monitor mode — call
    :func:`~wifi_tool.tools.system.enable_monitor_mode` first.

    Runs interactively.  User presses Ctrl+C to stop.
    Returns the process exit code.
    """
    if IS_WINDOWS:
        from .pcap_utils import capture_pmkid_eapol
        return capture_pmkid_eapol(
            interface, output_file,
            bssid_filter=bssid_filter,
        )

    if not check_tool("hcxdumptool"):
        raise RuntimeError("hcxdumptool not found — install hcxdumptool.")
    cmd = [
        "hcxdumptool",
        "-i", interface,
        "-o", output_file,
        f"--enable_status={enable_status}",
    ]
    if bssid_filter:
        import os
        import tempfile
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        tmp.write(bssid_filter.replace(":", "").lower() + "\n")
        tmp.close()
        cmd += [f"--filterlist_ap={tmp.name}", "--filtermode=2"]
    return run_command_live(cmd)


def convert_to_hashcat(input_file: str, output_file: str) -> Tuple[bool, str]:
    """Convert a pcapng capture to hashcat hc22000 format.

    On Linux/macOS runs::

        hcxpcapngtool -o <output_file> <input_file>

    On Windows (when ``hcxpcapngtool`` is not on PATH) uses the pure-Python
    :func:`~wifi_tool.tools.pcap_utils.convert_pcap_to_hc22000` (scapy).

    Returns ``(success, output)``.
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


def get_capture_summary(capture_file: str) -> Tuple[bool, str]:
    """Return a summary of the contents of a pcapng capture file.

    On Linux/macOS runs ``hcxpcapngtool <capture_file>`` (no ``-o`` →
    summary only).

    On Windows (when ``hcxpcapngtool`` is absent) performs a quick parse
    via :func:`~wifi_tool.tools.pcap_utils.convert_pcap_to_hc22000` and
    reports the record count without writing any output file.

    Returns ``(success, output)``.
    """
    if IS_WINDOWS and not check_tool("hcxpcapngtool"):
        import os
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".hc22000", delete=False)
        tmp.close()
        try:
            from .pcap_utils import convert_pcap_to_hc22000
            ok, msg = convert_pcap_to_hc22000(capture_file, tmp.name)
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
        return ok, msg

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
    """Launch hcxdumptool interactively with arbitrary extra arguments.

    On Windows delegates to :func:`capture` (scapy/Npcap path).
    """
    if IS_WINDOWS:
        import os
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False)
        tmp.close()
        return capture(interface, tmp.name, bssid_filter=None)

    if not check_tool("hcxdumptool"):
        raise RuntimeError("hcxdumptool not found.")
    cmd = ["hcxdumptool", "-i", interface] + (extra_args or [])
    return run_command_live(cmd)
