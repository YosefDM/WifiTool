"""Modern GUI for WifiTool -- customtkinter-based interface.

Layout
------
  Top:    Interface selector | Scan button | Wordlist picker
  Left:   Treeview of nearby networks
  Right:  Live attack log
  Bottom: Selected-network info | Attack / Stop buttons | Result label
"""

import queue
import subprocess
import threading
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Dict, List, Optional

import customtkinter as ctk

from ..tools.system import IS_WINDOWS, get_wireless_interfaces, scan_networks_windows
from ..tools.unified_attack import AttackTarget, UnifiedAttacker


# Appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

_LEVEL_PREFIX: Dict[str, str] = {
    "phase":   "\n| ",
    "success": "+ ",
    "error":   "x ",
    "warn":    "! ",
    "info":    "  ",
    "output":  "  | ",
}


class WifiToolApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("WiFi Tool")
        self.geometry("1200x720")
        self.minsize(900, 580)

        self._networks: List[Dict] = []
        self._attacker: Optional[UnifiedAttacker] = None
        self._attack_thread: Optional[threading.Thread] = None
        self._log_queue: queue.Queue = queue.Queue()
        self._selected_net: Optional[Dict] = None

        self._build_ui()
        self._refresh_interfaces()
        self._auto_fill_wordlist()
        self._poll_queue()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        # Toolbar
        toolbar = ctk.CTkFrame(self, height=52, corner_radius=0)
        toolbar.grid(row=0, column=0, sticky="ew")
        toolbar.columnconfigure(3, weight=1)

        ctk.CTkLabel(toolbar, text="Interface:").grid(
            row=0, column=0, padx=(12, 4), pady=10
        )
        self._iface_var = ctk.StringVar(value="")
        self._iface_cb = ctk.CTkComboBox(
            toolbar, variable=self._iface_var, width=170,
            values=[], state="readonly"
        )
        self._iface_cb.grid(row=0, column=1, padx=4, pady=10)

        self._scan_btn = ctk.CTkButton(
            toolbar, text="Scan Networks", width=130, command=self._on_scan
        )
        self._scan_btn.grid(row=0, column=2, padx=10, pady=10)

        ctk.CTkLabel(toolbar, text="Wordlist:").grid(
            row=0, column=4, padx=(20, 4), pady=10
        )
        self._wl_var = ctk.StringVar(value="")
        self._wl_entry = ctk.CTkEntry(
            toolbar, textvariable=self._wl_var, width=290,
            placeholder_text="Path to wordlist (rockyou.txt ...)"
        )
        self._wl_entry.grid(row=0, column=5, padx=4, pady=10)
        ctk.CTkButton(
            toolbar, text="Browse...", width=80, command=self._browse_wordlist
        ).grid(row=0, column=6, padx=(4, 12), pady=10)

        # Main content
        content = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)
        content.columnconfigure(0, weight=3)
        content.columnconfigure(1, weight=2)
        content.rowconfigure(0, weight=1)

        # Left: network list
        net_frame = ctk.CTkFrame(content)
        net_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        net_frame.columnconfigure(0, weight=1)
        net_frame.rowconfigure(1, weight=1)

        ctk.CTkLabel(
            net_frame, text="Nearby Networks",
            font=ctk.CTkFont(size=14, weight="bold")
        ).grid(row=0, column=0, sticky="w", padx=10, pady=(8, 4))

        self._tree = self._build_treeview(net_frame)
        self._tree.grid(row=1, column=0, sticky="nsew", padx=(8, 0), pady=(0, 8))

        vsb = ttk.Scrollbar(net_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.grid(row=1, column=1, sticky="ns", padx=(0, 4), pady=(0, 8))
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # Right: attack log
        log_frame = ctk.CTkFrame(content)
        log_frame.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(1, weight=1)

        ctk.CTkLabel(
            log_frame, text="Attack Log",
            font=ctk.CTkFont(size=14, weight="bold")
        ).grid(row=0, column=0, sticky="w", padx=10, pady=(8, 4))

        self._log_box = ctk.CTkTextbox(
            log_frame, state="disabled",
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color="#1a1a1a",
        )
        self._log_box.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))

        # Bottom bar
        bottom = ctk.CTkFrame(self, height=88, corner_radius=0)
        bottom.grid(row=2, column=0, sticky="ew")
        bottom.columnconfigure(3, weight=1)

        self._target_label = ctk.CTkLabel(
            bottom, text="No network selected", font=ctk.CTkFont(size=12)
        )
        self._target_label.grid(row=0, column=0, padx=12, pady=(10, 2), sticky="w")

        self._attack_btn = ctk.CTkButton(
            bottom, text="ATTACK", width=130,
            fg_color="#1b5e20", hover_color="#2e7d32",
            command=self._on_attack, state="disabled",
        )
        self._attack_btn.grid(row=0, column=1, padx=(0, 6), pady=(8, 2))

        self._stop_btn = ctk.CTkButton(
            bottom, text="STOP", width=100,
            fg_color="#7f0000", hover_color="#b71c1c",
            command=self._on_stop, state="disabled",
        )
        self._stop_btn.grid(row=0, column=2, padx=(0, 12), pady=(8, 2))

        self._progress = ctk.CTkProgressBar(bottom, mode="indeterminate", width=280)
        self._progress.grid(row=0, column=3, padx=16, pady=(8, 2), sticky="e")
        self._progress.set(0)

        self._result_label = ctk.CTkLabel(
            bottom, text="",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#4caf50",
        )
        self._result_label.grid(
            row=1, column=0, columnspan=5, padx=12, pady=(0, 8), sticky="w"
        )

    def _build_treeview(self, parent: ctk.CTkFrame) -> ttk.Treeview:
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Wifi.Treeview",
            background="#2b2b2b", foreground="#e0e0e0",
            font=("Segoe UI", 12),
            rowheight=32, fieldbackground="#2b2b2b", borderwidth=0,
        )
        style.configure(
            "Wifi.Treeview.Heading",
            background="#1a1a2e", foreground="#7eb0d4",
            font=("Segoe UI", 12, "bold"), relief="flat",
        )
        style.map(
            "Wifi.Treeview",
            background=[("selected", "#1f538d")],
            foreground=[("selected", "#ffffff")],
        )
        cols = ("SSID", "BSSID", "Ch", "Security", "Signal")
        tree = ttk.Treeview(
            parent, columns=cols, show="headings",
            style="Wifi.Treeview", selectmode="browse",
        )
        widths = {"SSID": 240, "BSSID": 170, "Ch": 50, "Security": 110, "Signal": 80}
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=widths[col], minwidth=40)
        return tree

    # ------------------------------------------------------------------
    # Interface management
    # ------------------------------------------------------------------

    def _auto_fill_wordlist(self) -> None:
        """Pre-fill the wordlist field with the bundled or default wordlist."""
        from ..tools.unified_attack import find_default_wordlist
        default = find_default_wordlist()
        if default:
            self._wl_var.set(default)

    def _refresh_interfaces(self) -> None:
        ifaces = get_wireless_interfaces()
        if not ifaces:
            ifaces = ["(no interfaces found)"]
        self._iface_cb.configure(values=ifaces)
        self._iface_var.set(ifaces[0])

    # ------------------------------------------------------------------
    # Network scanning
    # ------------------------------------------------------------------

    def _on_scan(self) -> None:
        self._scan_btn.configure(state="disabled", text="Scanning...")
        threading.Thread(target=self._do_scan, daemon=True).start()

    def _do_scan(self) -> None:
        nets: List[Dict] = []
        if IS_WINDOWS:
            raw = scan_networks_windows()
            for n in raw:
                auth = n.get("Auth", "").upper()
                if "WPA3" in auth:
                    sec = "WPA3"
                elif "WPA2" in auth:
                    sec = "WPA2"
                elif "WPA" in auth:
                    sec = "WPA"
                elif auth in ("OPEN", "NONE", ""):
                    sec = "Open"
                else:
                    sec = n.get("Auth", "?")
                nets.append({
                    "ssid":     n.get("SSID", ""),
                    "bssid":    n.get("BSSID", ""),
                    "channel":  n.get("Channel", "?"),
                    "security": sec,
                    "signal":   n.get("Signal", "?"),
                })
        else:
            iface = self._iface_var.get()
            try:
                r = subprocess.run(
                    ["iw", "dev", iface, "scan"],
                    capture_output=True, text=True, timeout=15,
                )
                nets = _parse_iw_scan(r.stdout)
            except Exception:
                pass

        self.after(0, self._populate_tree, nets)

    def _populate_tree(self, nets: List[Dict]) -> None:
        self._networks = nets
        for row in self._tree.get_children():
            self._tree.delete(row)
        for n in nets:
            self._tree.insert("", "end", values=(
                n.get("ssid", ""),
                n.get("bssid", ""),
                n.get("channel", "?"),
                n.get("security", "?"),
                n.get("signal", "?"),
            ))
        self._scan_btn.configure(state="normal", text="Scan Networks")
        self._append_log(f"Scan complete -- {len(nets)} network(s) found", "info")

    # ------------------------------------------------------------------
    # Network selection
    # ------------------------------------------------------------------

    def _on_select(self, _event=None) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        idx = self._tree.index(sel[0])
        if 0 <= idx < len(self._networks):
            self._selected_net = self._networks[idx]
            n = self._selected_net
            self._target_label.configure(
                text=(
                    f"Selected:  {n['ssid']}   "
                    f"({n['bssid']})   "
                    f"{n['security']}   "
                    f"Ch {n['channel']}"
                )
            )
            if self._attack_thread is None or not self._attack_thread.is_alive():
                self._attack_btn.configure(state="normal")

    # ------------------------------------------------------------------
    # Wordlist
    # ------------------------------------------------------------------

    def _browse_wordlist(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Wordlist",
            filetypes=[("Text / gz files", "*.txt *.gz"), ("All files", "*.*")],
        )
        if path:
            self._wl_var.set(path)

    # ------------------------------------------------------------------
    # Attack control
    # ------------------------------------------------------------------

    def _on_attack(self) -> None:
        if not self._selected_net:
            return

        n = self._selected_net
        try:
            channel = int(n.get("channel", 6))
        except (ValueError, TypeError):
            channel = 6

        target = AttackTarget(
            ssid=n.get("ssid", ""),
            bssid=n.get("bssid", ""),
            channel=channel,
            encryption=n.get("security", "WPA2"),
        )
        iface = self._iface_var.get()
        wordlist = self._wl_var.get().strip() or None
        out_dir = Path.home() / "wifitool-output" / (target.ssid or "unknown")

        self._clear_log()
        self._result_label.configure(text="")
        self._attack_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._progress.start()

        self._append_log(
            f"Starting unified attack on '{target.ssid}'  [{target.bssid}]", "phase"
        )
        if not wordlist:
            self._append_log(
                "No wordlist set -- cracking phases will be skipped", "warn"
            )

        self._attacker = UnifiedAttacker(
            target=target,
            interface=iface,
            wordlist=wordlist,
            output_dir=out_dir,
            log_cb=self._queue_log,
            result_cb=self._on_result,
        )
        self._attack_thread = threading.Thread(
            target=self._attacker.run, daemon=True
        )
        self._attack_thread.start()

    def _on_stop(self) -> None:
        if self._attacker:
            self._attacker.stop()
        self._append_log("Attack stopped by user", "warn")
        self._attack_ended()

    def _attack_ended(self) -> None:
        self._progress.stop()
        self._progress.set(0)
        self._stop_btn.configure(state="disabled")
        self._attack_btn.configure(
            state="normal" if self._selected_net else "disabled"
        )

    def _on_result(self, password: Optional[str]) -> None:
        self.after(0, self._show_result, password)

    def _show_result(self, password: Optional[str]) -> None:
        self._attack_ended()
        if password:
            self._result_label.configure(
                text=f"  PASSWORD FOUND:  {password}",
                text_color="#4caf50",
            )
            self._append_log(f"PASSWORD FOUND: {password}", "success")
        else:
            self._result_label.configure(
                text="  Password not found -- all methods exhausted",
                text_color="#ef5350",
            )
            self._append_log(
                "All attack phases exhausted -- password not found", "warn"
            )

    # ------------------------------------------------------------------
    # Log helpers (thread-safe via queue)
    # ------------------------------------------------------------------

    def _queue_log(self, message: str, level: str = "info") -> None:
        self._log_queue.put((message, level))

    def _poll_queue(self) -> None:
        try:
            while True:
                msg, level = self._log_queue.get_nowait()
                self._append_log(msg, level)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _append_log(self, message: str, level: str = "info") -> None:
        prefix = _LEVEL_PREFIX.get(level, "  ")
        self._log_box.configure(state="normal")
        self._log_box.insert("end", prefix + message + "\n")
        self._log_box.configure(state="disabled")
        self._log_box.see("end")

    def _clear_log(self) -> None:
        self._log_box.configure(state="normal")
        self._log_box.delete("1.0", "end")
        self._log_box.configure(state="disabled")


# ------------------------------------------------------------------
# Linux iw scan parser
# ------------------------------------------------------------------

def _parse_iw_scan(output: str) -> List[Dict]:
    """Basic parser for ``iw dev <iface> scan`` stdout."""
    networks: List[Dict] = []
    current: Dict = {}

    for line in output.splitlines():
        s = line.strip()
        if s.startswith("BSS ") and "(" in s:
            if current:
                networks.append(current)
            bssid = s.split()[1].split("(")[0].strip()
            current = {
                "bssid": bssid, "ssid": "",
                "channel": "?", "security": "Open", "signal": "?",
            }
        elif s.startswith("SSID:"):
            current["ssid"] = s[5:].strip()
        elif "DS Parameter set: channel" in s:
            current["channel"] = s.split("channel")[-1].strip()
        elif s.startswith("signal:"):
            current["signal"] = s.split(":", 1)[1].strip()
        elif "WPA3" in s:
            current["security"] = "WPA3"
        elif "RSN:" in s or ("WPA2" in s and current.get("security") != "WPA3"):
            current["security"] = "WPA2"
        elif "WPA:" in s and current.get("security") not in ("WPA2", "WPA3"):
            current["security"] = "WPA"
        elif "WEP" in s and current.get("security") == "Open":
            current["security"] = "WEP"

    if current:
        networks.append(current)
    return networks


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

def run() -> None:
    """Launch the WifiTool GUI."""
    app = WifiToolApp()
    app.mainloop()
