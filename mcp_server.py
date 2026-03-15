#!/usr/bin/env python3
"""WifiTool MCP Server — developer/AI iteration loop.

Provides Claude Code with autonomous access to WifiTool internals so it can:
  1. Run attacks and read full output
  2. Inspect capture files and source code
  3. Retry cracking steps independently
  4. Fix the adapter state between runs

Register with Claude Code:
  claude mcp add --transport stdio python mcp_server.py
(run from the repo root)
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

# Ensure wifi_tool package is importable from the repo root
_REPO_ROOT = Path(__file__).parent.resolve()
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Output directory for capture files
_OUTPUT_ROOT = Path.home() / "wifitool-output"

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print(
        "ERROR: 'mcp' package not installed. Run: pip install mcp",
        file=sys.stderr,
    )
    sys.exit(1)

mcp = FastMCP("WifiTool")


# ---------------------------------------------------------------------------
# 1. run_attack
# ---------------------------------------------------------------------------

@mcp.tool()
def run_attack(
    ssid: str,
    bssid: str,
    channel: int,
    encryption: str,
    interface: str,
    wordlist_path: Optional[str] = None,
) -> str:
    """Run a full WifiTool attack via the CLI and return all output.

    Calls ``python main.py --cli`` with the given target parameters.
    Returns the combined stdout+stderr so Claude can analyse what succeeded
    or failed without any human in the loop.

    Args:
        ssid: Target network name (e.g. "HomeWifi").
        bssid: Target BSSID in colon-separated hex (e.g. "AA:BB:CC:DD:EE:FF").
        channel: Wi-Fi channel number (1-14 for 2.4 GHz, 36+ for 5 GHz).
        encryption: Encryption type: "WPA2", "WPA", "WPA3", or "WEP".
        interface: Wireless interface name (e.g. "Wi-Fi 2").
        wordlist_path: Absolute path to a wordlist file. If omitted the tool
            uses its built-in default wordlist.
    """
    cmd = [
        sys.executable,
        str(_REPO_ROOT / "main.py"),
        "--cli",
        "--ssid", ssid,
        "--bssid", bssid,
        "--channel", str(channel),
        "--encryption", encryption,
        "--interface", interface,
    ]
    if wordlist_path:
        cmd += ["--wordlist", wordlist_path]

    try:
        result = subprocess.run(
            cmd,
            cwd=str(_REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=600,  # 10-minute hard cap per run
        )
        combined = result.stdout
        if result.stderr:
            combined += "\n--- STDERR ---\n" + result.stderr
        if result.returncode != 0:
            combined += f"\n--- EXIT CODE: {result.returncode} ---"
        return combined or "(no output)"
    except subprocess.TimeoutExpired:
        return "ERROR: attack timed out after 600 seconds"
    except Exception as exc:
        return f"ERROR: {exc}"


# ---------------------------------------------------------------------------
# 2. scan_networks
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_networks() -> str:
    """Scan for nearby Wi-Fi networks and return them as JSON.

    On Windows uses ``netsh wlan show networks mode=bssid``.
    On Linux uses ``iwlist scan`` or ``nmcli`` as a fallback.

    Returns a JSON array of objects with keys:
      SSID, BSSID, Signal, Channel, Auth, Cipher, Radio
    """
    try:
        from wifi_tool.tools.system import IS_WINDOWS, scan_networks_windows
        if IS_WINDOWS:
            networks = scan_networks_windows()
            return json.dumps(networks, indent=2)

        # Linux fallback — nmcli
        result = subprocess.run(
            [
                "nmcli", "-t", "-f",
                "SSID,BSSID,SIGNAL,CHAN,SECURITY",
                "dev", "wifi", "list",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            networks = []
            for line in result.stdout.splitlines():
                parts = line.split(":")
                if len(parts) >= 5:
                    networks.append({
                        "SSID": parts[0],
                        "BSSID": ":".join(parts[1:7]),
                        "Signal": parts[7] if len(parts) > 7 else "",
                        "Channel": parts[8] if len(parts) > 8 else "",
                        "Auth": parts[9] if len(parts) > 9 else "",
                    })
            return json.dumps(networks, indent=2)
        return f"ERROR: nmcli failed ({result.stderr.strip()})"
    except Exception as exc:
        return f"ERROR: {exc}"


# ---------------------------------------------------------------------------
# 3. get_capture_files
# ---------------------------------------------------------------------------

@mcp.tool()
def get_capture_files(ssid: str) -> str:
    """List all files in the capture output directory for a given SSID.

    Output directory: ~/wifitool-output/<ssid>/

    Returns a JSON array of objects with keys:
      path, size_bytes, modified (ISO-8601 timestamp)

    Args:
        ssid: The SSID whose capture directory should be listed.
    """
    import datetime

    target_dir = _OUTPUT_ROOT / ssid
    if not target_dir.exists():
        return json.dumps({"directory": str(target_dir), "files": [], "note": "directory does not exist"})

    files = []
    for p in sorted(target_dir.rglob("*")):
        if p.is_file():
            stat = p.stat()
            files.append({
                "path": str(p),
                "size_bytes": stat.st_size,
                "modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
    return json.dumps({"directory": str(target_dir), "files": files}, indent=2)


# ---------------------------------------------------------------------------
# 4. read_file
# ---------------------------------------------------------------------------

@mcp.tool()
def read_file(path: str) -> str:
    """Read any text file by absolute path and return its contents.

    Useful for reading log files, hc22000 hash files, capture summaries, etc.
    Binary files are decoded with UTF-8 and errors are replaced.

    Args:
        path: Absolute path to the file to read.
    """
    try:
        p = Path(path)
        if not p.exists():
            return f"ERROR: file not found: {path}"
        if not p.is_file():
            return f"ERROR: not a file: {path}"
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return f"ERROR: {exc}"


# ---------------------------------------------------------------------------
# 5. check_tools
# ---------------------------------------------------------------------------

@mcp.tool()
def check_tools() -> str:
    """Return the availability of all WifiTool-tracked external tools.

    Returns a JSON object mapping tool name to a status dict:
      found (bool), path (str or null)

    Examples of tracked tools: aircrack-ng, hashcat, airodump-ng,
    aireplay-ng, hcxdumptool, hcxpcapngtool, bettercap, wifite.
    """
    try:
        import shutil
        from wifi_tool.tools.system import get_all_tool_status
        statuses = get_all_tool_status()
        result = {}
        for tool, found in statuses.items():
            result[tool] = {
                "found": found,
                "path": shutil.which(tool),
            }
        return json.dumps(result, indent=2)
    except Exception as exc:
        return f"ERROR: {exc}"


# ---------------------------------------------------------------------------
# 6. get_interfaces
# ---------------------------------------------------------------------------

@mcp.tool()
def get_interfaces() -> str:
    """Return available wireless interfaces as a JSON array of strings.

    On Windows returns friendly names from ``netsh wlan show interfaces``.
    On Linux returns interface names from ``iw dev``.
    """
    try:
        from wifi_tool.tools.system import get_wireless_interfaces
        ifaces = get_wireless_interfaces()
        return json.dumps(ifaces, indent=2)
    except Exception as exc:
        return f"ERROR: {exc}"


# ---------------------------------------------------------------------------
# 7. convert_pcap
# ---------------------------------------------------------------------------

@mcp.tool()
def convert_pcap(input_path: str, output_path: str) -> str:
    """Convert a pcap/pcapng capture file to hashcat hc22000 format.

    Calls ``pcap_utils.convert_pcap_to_hc22000()`` directly without running
    a full attack — useful for retrying conversion after a code fix.

    Args:
        input_path: Absolute path to the .cap or .pcapng input file.
        output_path: Absolute path to write the .hc22000 output file.

    Returns a plain-text success or error message.
    """
    try:
        from wifi_tool.tools.pcap_utils import convert_pcap_to_hc22000
        ok, msg = convert_pcap_to_hc22000(input_path, output_path)
        status = "OK" if ok else "FAILED"
        return f"{status}: {msg}"
    except Exception as exc:
        return f"ERROR: {exc}"


# ---------------------------------------------------------------------------
# 8. run_hashcat
# ---------------------------------------------------------------------------

@mcp.tool()
def run_hashcat(
    hash_file: str,
    wordlist: str,
    mode: int = 22000,
    extra_args: Optional[str] = None,
) -> str:
    """Run hashcat against a hash file and return the full output.

    Lets Claude retry cracking independently without a full attack re-run.

    Args:
        hash_file: Absolute path to the hash file (e.g. a .hc22000 file).
        wordlist: Absolute path to the wordlist file.
        mode: Hashcat hash mode (default 22000 for WPA-PBKDF2-PMKID+EAPOL).
        extra_args: Optional additional hashcat arguments as a single string
            (e.g. "--force --status").

    Returns combined stdout+stderr from hashcat.
    """
    try:
        from wifi_tool.tools.system import get_hashcat_dir
        hashcat_dir = get_hashcat_dir()
        hashcat_bin = "hashcat"
        cwd = hashcat_dir or str(_REPO_ROOT)

        cmd = [
            hashcat_bin,
            "-m", str(mode),
            hash_file,
            wordlist,
            "--status",
            "--status-timer=5",
        ]
        if extra_args:
            cmd += extra_args.split()

        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        combined = result.stdout
        if result.stderr:
            combined += "\n--- STDERR ---\n" + result.stderr
        if result.returncode not in (0, 1):  # 1 = exhausted but not an error
            combined += f"\n--- EXIT CODE: {result.returncode} ---"
        return combined or "(no output)"
    except subprocess.TimeoutExpired:
        return "ERROR: hashcat timed out after 300 seconds"
    except Exception as exc:
        return f"ERROR: {exc}"


# ---------------------------------------------------------------------------
# 9. fix_wlan
# ---------------------------------------------------------------------------

@mcp.tool()
def fix_wlan() -> str:
    """Restart the WLAN AutoConfig service (wlansvc) to recover the adapter.

    Call this if a previous attack run left the adapter in monitor mode or
    if wlansvc was stopped and not restarted, causing the interface to be
    unavailable for the next iteration.

    Returns the output of ``net start wlansvc`` (Windows) or a no-op message
    on Linux.
    """
    try:
        from wifi_tool.tools.system import restart_wlansvc
        msg = restart_wlansvc()
        return msg or "wlansvc restart attempted (no output)"
    except Exception as exc:
        return f"ERROR: {exc}"


# ---------------------------------------------------------------------------
# 10. read_source_file
# ---------------------------------------------------------------------------

@mcp.tool()
def read_source_file(relative_path: str) -> str:
    """Read a Python source file from the WifiTool repo by relative path.

    Claude MUST call this before proposing or making any code change, to
    read the actual current source rather than relying on memory.

    Args:
        relative_path: Path relative to the repo root, e.g.
            "wifi_tool/tools/pcap_utils.py" or "wifi_tool/tools/system.py".

    Returns the full file contents as a string, or an error message.
    """
    try:
        p = _REPO_ROOT / relative_path
        if not p.exists():
            return f"ERROR: file not found: {relative_path} (resolved to {p})"
        if not p.is_file():
            return f"ERROR: not a file: {relative_path}"
        if p.suffix not in (".py", ".md", ".txt", ".bat", ".iss", ".yml", ".yaml", ".cfg", ".toml", ".ini", ".spec"):
            return f"ERROR: refusing to read binary or unknown file type: {p.suffix}"
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return f"ERROR: {exc}"


# ---------------------------------------------------------------------------
# 11. inspect_hc22000
# ---------------------------------------------------------------------------

@mcp.tool()
def inspect_hc22000(path: str) -> str:
    """Parse a hc22000 hash file and report what data it actually contains.

    Answers the most common post-conversion question: "was anything useful
    captured?" without Claude having to interpret raw base64 blobs.

    hc22000 line format:
      WPA*01*<pmkid>*<mac_ap>*<mac_sta>*<ssid_hex>***        (PMKID)
      WPA*02*<mic>*<mac_ap>*<mac_sta>*<ssid_hex>*<anonce>*<eapol>*<flags>
                                                              (EAPOL handshake)

    Returns a JSON object with:
      records         — total line count
      pmkid_records   — type-01 (PMKID) lines
      eapol_records   — type-02 (EAPOL handshake) lines
      complete_handshakes — eapol lines where MIC and EAPOL data are non-empty
      ssids           — decoded SSIDs seen (hex → UTF-8 best-effort)
      bssids          — AP MAC addresses seen
      error           — present only if the file could not be read

    Args:
        path: Absolute path to the .hc22000 file.
    """
    try:
        p = Path(path)
        if not p.exists():
            return json.dumps({"error": f"file not found: {path}"})
        if not p.is_file():
            return json.dumps({"error": f"not a file: {path}"})

        pmkid_count = 0
        eapol_count = 0
        complete_hs = 0
        ssids: list = []
        bssids: list = []

        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or not line.startswith("WPA*"):
                continue
            parts = line.split("*")
            if len(parts) < 6:
                continue

            rec_type  = parts[1]   # "01" or "02"
            mac_ap    = parts[3]
            ssid_hex  = parts[5]

            # decode SSID
            try:
                ssid = bytes.fromhex(ssid_hex).decode("utf-8", errors="replace")
            except ValueError:
                ssid = ssid_hex

            if mac_ap and mac_ap not in bssids:
                bssids.append(mac_ap)
            if ssid and ssid not in ssids:
                ssids.append(ssid)

            if rec_type == "01":
                pmkid_count += 1
            elif rec_type == "02":
                eapol_count += 1
                # parts[2]=MIC  parts[7]=EAPOL data  — non-empty means usable
                mic_present   = len(parts) > 2 and bool(parts[2])
                eapol_present = len(parts) > 7 and bool(parts[7])
                if mic_present and eapol_present:
                    complete_hs += 1

        return json.dumps(
            {
                "records": pmkid_count + eapol_count,
                "pmkid_records": pmkid_count,
                "eapol_records": eapol_count,
                "complete_handshakes": complete_hs,
                "ssids": ssids,
                "bssids": bssids,
            },
            indent=2,
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# 12. run_aircrack
# ---------------------------------------------------------------------------

@mcp.tool()
def run_aircrack(
    cap_file: str,
    wordlist: str,
    bssid: Optional[str] = None,
) -> str:
    """Run aircrack-ng against a capture file and return all output.

    Lets Claude retry the CPU cracking path independently, without re-running
    the full attack (which also runs hashcat, bettercap, wifite, etc.).

    Args:
        cap_file: Absolute path to the .cap or .pcapng file to crack.
        wordlist: Absolute path to the wordlist file.
        bssid: Optional target BSSID (colon-separated hex). When the capture
            file contains multiple networks, specifying the BSSID tells
            aircrack-ng which handshake to attack.

    Returns combined stdout+stderr from aircrack-ng.
    """
    cmd = ["aircrack-ng", "-w", wordlist]
    if bssid:
        cmd += ["-b", bssid]
    cmd.append(cap_file)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        combined = result.stdout
        if result.stderr:
            combined += "\n--- STDERR ---\n" + result.stderr
        if result.returncode not in (0, 1):
            combined += f"\n--- EXIT CODE: {result.returncode} ---"
        return combined or "(no output)"
    except FileNotFoundError:
        return "ERROR: aircrack-ng not found on PATH"
    except subprocess.TimeoutExpired:
        return "ERROR: aircrack-ng timed out after 300 seconds"
    except Exception as exc:
        return f"ERROR: {exc}"


# ---------------------------------------------------------------------------
# 13. list_wordlists
# ---------------------------------------------------------------------------

@mcp.tool()
def list_wordlists() -> str:
    """Scan known wordlist locations and return available files as JSON.

    Searches the following directories in order:
      - <repo_root>/wordlists/           (dev copies)
      - C:\\Program Files\\WifiTool\\wordlists\\  (Windows installer)
      - /usr/share/wordlists/            (Kali Linux / Parrot)
      - /usr/share/dict/                 (common Linux)
      - ~/wordlists/                     (user home)

    Returns a JSON array of objects with keys:
      path, size_bytes, size_human, lines (if file is small enough to count quickly)
    """
    import datetime

    search_dirs = [
        _REPO_ROOT / "wordlists",
        Path(r"C:\Program Files\WifiTool\wordlists"),
        Path("/usr/share/wordlists"),
        Path("/usr/share/dict"),
        Path.home() / "wordlists",
    ]
    text_exts = {".txt", ".lst", ".dic", ".dict", ""}

    found = []
    seen = set()

    for d in search_dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*")):
            if not p.is_file():
                continue
            if p.suffix.lower() not in text_exts:
                continue
            rp = str(p.resolve())
            if rp in seen:
                continue
            seen.add(rp)

            stat = p.stat()
            size = stat.st_size

            def _human(n: int) -> str:
                for unit in ("B", "KB", "MB", "GB"):
                    if n < 1024:
                        return f"{n:.1f} {unit}"
                    n /= 1024
                return f"{n:.1f} TB"

            entry: dict = {
                "path": rp,
                "size_bytes": size,
                "size_human": _human(size),
            }
            # Count lines only for files ≤ 50 MB to keep it fast
            if size <= 50 * 1024 * 1024:
                try:
                    with open(rp, "rb") as fh:
                        entry["lines"] = sum(1 for _ in fh)
                except Exception:
                    pass
            found.append(entry)

    return json.dumps(found, indent=2)


# ---------------------------------------------------------------------------
# 14. get_potfile
# ---------------------------------------------------------------------------

@mcp.tool()
def get_potfile(hash_file: Optional[str] = None) -> str:
    """Read the hashcat potfile and return cracked password entries.

    Hashcat records every cracked password in its potfile so it will not
    re-crack the same hash in subsequent runs (exit code 1 with no output).
    Call this when hashcat exits without printing a password — the answer
    may already be in the potfile.

    Searches for the potfile at:
      - <hashcat_dir>/hashcat.potfile     (Windows, next to hashcat.exe)
      - ~/.hashcat/hashcat.potfile        (default on all platforms)
      - <hash_file>.pot                  (per-session potfile, if hash_file given)

    Args:
        hash_file: Optional absolute path to the hash file used in the run.
            If supplied, also checks for a matching <hash_file>.pot file.

    Returns plain text of all matching potfile lines, or a message if empty/not found.
    """
    try:
        from wifi_tool.tools.system import get_hashcat_dir
        candidates = [Path.home() / ".hashcat" / "hashcat.potfile"]

        hc_dir = get_hashcat_dir()
        if hc_dir:
            candidates.insert(0, Path(hc_dir) / "hashcat.potfile")

        if hash_file:
            candidates.append(Path(hash_file).with_suffix(".pot"))
            # also ~/.hashcat/<stem>.potfile
            candidates.append(
                Path.home() / ".hashcat" / (Path(hash_file).stem + ".potfile")
            )

        results = {}
        for pot in candidates:
            if pot.is_file():
                content = pot.read_text(encoding="utf-8", errors="replace").strip()
                results[str(pot)] = content if content else "(empty)"

        if not results:
            return "No potfile found in any of the standard locations."

        lines = []
        for path_str, content in results.items():
            lines.append(f"=== {path_str} ===")
            lines.append(content)
        return "\n".join(lines)
    except Exception as exc:
        return f"ERROR: {exc}"


# ---------------------------------------------------------------------------
# 15. capture_handshake
# ---------------------------------------------------------------------------

@mcp.tool()
def capture_handshake(
    interface: str,
    bssid: str,
    channel: int,
    output_path: str,
    timeout: int = 60,
) -> str:
    """Run only the Scapy capture phase without the full attack sequence.

    Sets monitor mode and channel, captures for *timeout* seconds, then
    restores managed mode. Does NOT run hashcat or aircrack — use
    convert_pcap() + inspect_hc22000() + run_hashcat() to process the result.

    Faster than run_attack() for iterating on capture bugs; a single pass
    takes ~timeout seconds instead of 5+ minutes.

    Args:
        interface: Wireless interface friendly name (e.g. "Wi-Fi 2").
        bssid: Target AP BSSID in colon-separated hex (e.g. "AA:BB:CC:DD:EE:FF").
        channel: Wi-Fi channel to lock to before capture.
        output_path: Absolute path for the output .cap file.
        timeout: Capture duration in seconds (default 60).

    Returns a plain-text log of what happened (frame counts, errors).
    """
    log_lines: list = []

    def _log(msg: str, level: str = "info") -> None:
        log_lines.append(f"[{level.upper()}] {msg}")

    try:
        from wifi_tool.tools.system import (
            IS_WINDOWS,
            enable_monitor_mode,
            disable_monitor_mode,
            get_npcap_device_name,
            set_channel_windows,
            kill_interfering_processes,
            restart_wlansvc,
        )
        from wifi_tool.tools.pcap_utils import capture_pmkid_eapol

        # Step 1: resolve Npcap device name (needs wlansvc running)
        scapy_iface = interface
        if IS_WINDOWS:
            npf = get_npcap_device_name(interface)
            if npf:
                scapy_iface = npf
                _log(f"Npcap device: {npf}")
            else:
                _log("Could not resolve Npcap device name — will use interface name directly", "warning")

        # Step 2: enable monitor mode
        ok, msg = enable_monitor_mode(interface)
        _log(f"Monitor mode: {msg}", "info" if ok else "error")
        if not ok:
            return "\n".join(log_lines)

        # Step 3: set channel (Windows only, must happen before wlansvc stop)
        if IS_WINDOWS:
            ok_ch, ch_msg = set_channel_windows(interface, channel)
            _log(f"Set channel {channel}: {ch_msg}", "info" if ok_ch else "warning")

        # Step 4: stop wlansvc
        kill_out = kill_interfering_processes()
        if kill_out:
            _log(f"kill_interfering_processes: {kill_out}")

        try:
            # Step 5: capture
            _log(f"Starting capture on {scapy_iface} for {timeout}s (BSSID filter: {bssid})")
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            ret = capture_pmkid_eapol(
                interface=scapy_iface,
                output_file=output_path,
                bssid_filter=bssid,
                timeout=timeout,
                log_cb=_log,
            )
            _log(f"capture_pmkid_eapol returned {ret}", "info" if ret == 0 else "error")

            out_p = Path(output_path)
            if out_p.exists():
                _log(f"Output file: {output_path} ({out_p.stat().st_size} bytes)")
            else:
                _log("Output file was not created", "warning")

        finally:
            # Step 6: restore wlansvc before WlanHelper
            restart_out = restart_wlansvc()
            if restart_out:
                _log(f"restart_wlansvc: {restart_out}")

            # Step 7: disable monitor mode
            ok_d, msg_d = disable_monitor_mode(interface)
            _log(f"Monitor mode restored: {msg_d}", "info" if ok_d else "warning")

        return "\n".join(log_lines)

    except Exception as exc:
        log_lines.append(f"[ERROR] Unexpected exception: {exc}")
        return "\n".join(log_lines)


# ---------------------------------------------------------------------------
# 16. get_interface_mode
# ---------------------------------------------------------------------------

@mcp.tool()
def get_interface_mode(interface: str) -> str:
    """Return the current mode and channel of a wireless interface.

    On Windows queries WlanHelper.exe for the current mode (monitor/managed)
    and channel. Useful for confirming whether fix_wlan() or a previous
    run left the adapter in the correct state before the next iteration.

    On Linux uses ``iw dev <interface> info``.

    Args:
        interface: Interface friendly name on Windows (e.g. "Wi-Fi 2"),
            or interface name on Linux (e.g. "wlan0").

    Returns a JSON object with keys: interface, mode, channel, raw_output.
    """
    try:
        from wifi_tool.tools.system import IS_WINDOWS, find_npcap_wlanhelper

        if IS_WINDOWS:
            helper = find_npcap_wlanhelper()
            if not helper:
                return json.dumps({"error": "WlanHelper not found — is Npcap installed?"})

            mode_result = subprocess.run(
                [helper, interface, "mode"],
                capture_output=True, text=True, timeout=10,
            )
            mode_str = (mode_result.stdout + mode_result.stderr).strip()

            ch_result = subprocess.run(
                [helper, interface, "channel"],
                capture_output=True, text=True, timeout=10,
            )
            ch_str = (ch_result.stdout + ch_result.stderr).strip()

            return json.dumps(
                {
                    "interface": interface,
                    "mode": mode_str,
                    "channel": ch_str,
                    "raw_output": f"mode: {mode_str} | channel: {ch_str}",
                },
                indent=2,
            )

        # Linux: iw dev <iface> info
        result = subprocess.run(
            ["iw", "dev", interface, "info"],
            capture_output=True, text=True, timeout=10,
        )
        raw = (result.stdout + result.stderr).strip()
        mode, channel = None, None
        for line in raw.splitlines():
            ls = line.strip()
            if ls.startswith("type "):
                mode = ls.split(None, 1)[1] if " " in ls else ls
            elif ls.startswith("channel "):
                parts = ls.split()
                channel = parts[1] if len(parts) > 1 else ls
        return json.dumps(
            {"interface": interface, "mode": mode, "channel": channel, "raw_output": raw},
            indent=2,
        )

    except Exception as exc:
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# 17. validate_pcap
# ---------------------------------------------------------------------------

@mcp.tool()
def validate_pcap(path: str) -> str:
    """Read a pcap file with Scapy and report what 802.11 content it contains.

    Answers the question that file size alone cannot: "does this capture
    actually have anything useful?" A 10 KB file with 0 EAPOL frames means
    the channel was wrong; 4 EAPOL frames but inspect_hc22000 returns 0
    records points to a conversion bug.

    Returns a JSON object with:
      file              — absolute path
      size_bytes        — file size
      total_packets     — total frames in the file
      dot11_frames      — 802.11 frames
      beacon_frames     — 802.11 beacon frames (confirms the right AP was seen)
      eapol_frames      — EAPOL frames (the ones that matter for cracking)
      pmkid_candidates  — EAPOL msg-1 frames that may carry PMKID
      bssids_seen       — AP MAC addresses found in beacon/probe frames
      ssids_seen        — SSIDs found in beacon frames
      error             — present only on failure

    Args:
        path: Absolute path to the .cap or .pcapng file.
    """
    try:
        from wifi_tool.tools.pcap_utils import _require_scapy
        sc = _require_scapy()
    except ImportError as exc:
        return json.dumps({"error": f"Scapy not available: {exc}"})

    try:
        p = Path(path)
        if not p.exists():
            return json.dumps({"error": f"file not found: {path}"})

        try:
            packets = sc.rdpcap(str(p))
        except Exception as exc:
            return json.dumps({"error": f"failed to read pcap: {exc}"})

        total = len(packets)
        dot11 = 0
        beacons = 0
        eapol = 0
        pmkid_candidates = 0
        bssids: list = []
        ssids: list = []

        for pkt in packets:
            has_dot11 = pkt.haslayer("Dot11")
            if has_dot11:
                dot11 += 1

            if pkt.haslayer("Dot11Beacon"):
                beacons += 1
                try:
                    bssid_str = pkt["Dot11"].addr3
                    if bssid_str and bssid_str not in bssids:
                        bssids.append(bssid_str)
                    elt = pkt["Dot11Beacon"].payload
                    while elt and hasattr(elt, "ID"):
                        if elt.ID == 0:
                            ssid = bytes(elt.info).decode("utf-8", errors="replace").strip("\x00")
                            if ssid and ssid not in ssids:
                                ssids.append(ssid)
                            break
                        elt = elt.payload
                except Exception:
                    pass

            if pkt.haslayer("EAPOL"):
                eapol += 1
                # msg-1: KeyACK=1, KeyMIC=0 — may carry PMKID in key data
                try:
                    raw = bytes(pkt["EAPOL"])
                    if len(raw) >= 6:
                        key_info = int.from_bytes(raw[5:7], "big")
                        key_ack = bool(key_info & 0x0080)
                        key_mic = bool(key_info & 0x0100)
                        if key_ack and not key_mic:
                            pmkid_candidates += 1
                except Exception:
                    pass

        return json.dumps(
            {
                "file": str(p.resolve()),
                "size_bytes": p.stat().st_size,
                "total_packets": total,
                "dot11_frames": dot11,
                "beacon_frames": beacons,
                "eapol_frames": eapol,
                "pmkid_candidates": pmkid_candidates,
                "bssids_seen": bssids,
                "ssids_seen": ssids,
            },
            indent=2,
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")
