"""Main WifiTool application — rich menu-driven UI wiring all real tools."""

import glob as _glob
import os
import sys
import time
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from ..data.attacks import ALL_ATTACKS, ATTACK_BY_PROTOCOL
from ..data.protocols import ALL_PROTOCOLS
from ..tools import (
    aircrack,
    bettercap,
    hashcat_tool,
    hcx,
    krack,
    system,
    wifite,
)
from ..ui.panels import (
    render_attack_detail,
    render_banner,
    render_legal_panel,
    render_protocol_detail,
    render_protocol_table,
    render_tool_status,
)

console = Console()

OUTPUT_DIR_DEFAULT = Path.home() / "wifitool-output"


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def _pause(msg: str = "Press [Enter] to continue...") -> None:
    console.print(f"\n[dim]{msg}[/dim]")
    input()


def _heading(title: str, color: str = "cyan") -> None:
    console.print()
    console.print(Rule(f"[bold {color}]{title}[/bold {color}]", style=color))
    console.print()


def _require_root() -> bool:
    if not system.is_root():
        console.print(
            Panel(
                "[bold red]Root privileges required.[/bold red]\n\n"
                "Most Wi-Fi tools (airmon-ng, airodump-ng, hcxdumptool, etc.) "
                "require root to manipulate network interfaces.\n\n"
                "Re-run with: [bold]sudo wifitool[/bold]",
                border_style="red",
            )
        )
        return False
    return True


def _require_tool(name: str, package: Optional[str] = None) -> bool:
    """Check that *name* is installed; offer apt-get install if not."""
    if system.check_tool(name):
        return True
    pkg = package or system.TOOL_PACKAGES.get(name, name)
    console.print(
        f"[red]✘ {name} is not installed.[/red]\n"
        f"  Package: [bold]{pkg}[/bold]\n"
        f"  Install: [bold cyan]sudo apt-get install {pkg}[/bold cyan]"
    )
    if system.is_root():
        if Confirm.ask(f"Install [bold]{pkg}[/bold] now?", default=False):
            ok, out = system.install_tool(pkg)
            console.print(out)
            if ok:
                console.print(f"[green]✔ {pkg} installed.[/green]")
                return True
            else:
                console.print(f"[red]Installation failed.[/red]")
    return False


def _pick_interface(monitor_preferred: bool = True) -> Optional[str]:
    """Prompt the user to pick a wireless interface from detected ones."""
    interfaces = system.get_wireless_interfaces()
    if not interfaces:
        console.print("[yellow]No wireless interfaces detected.[/yellow]")
        iface = Prompt.ask("Enter interface name manually (or blank to cancel)")
        return iface.strip() or None

    table = Table(box=box.SIMPLE, show_header=False)
    table.add_column("#", style="bold cyan", justify="right", min_width=3)
    table.add_column("Interface")
    for i, iface in enumerate(interfaces, 1):
        table.add_row(str(i), iface)
    console.print(table)

    hint = " (use a monitor-mode interface, e.g. wlan0mon)" if monitor_preferred else ""
    choice = Prompt.ask(f"Select interface number or type name{hint}", default="1")
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(interfaces):
            return interfaces[idx]
    return choice.strip() or None


def _pick_output_dir() -> Path:
    """Ask for (or confirm) the output directory, creating it if needed."""
    default = str(OUTPUT_DIR_DEFAULT)
    path_str = Prompt.ask("Output directory", default=default)
    out = Path(path_str).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    return out


# ---------------------------------------------------------------------------
# Workflow: System Setup
# ---------------------------------------------------------------------------

def menu_system_setup() -> None:
    _clear()
    _heading("System Setup")
    render_tool_status(console)
    console.print()

    while True:
        console.print(
            "[1] List wireless interfaces\n"
            "[2] Enable monitor mode\n"
            "[3] Disable monitor mode\n"
            "[4] Kill interfering processes (airmon-ng check kill)\n"
            "[5] Install missing tools\n"
            "[0] Back\n"
        )
        choice = Prompt.ask("Select", choices=["0", "1", "2", "3", "4", "5"])

        if choice == "0":
            return

        if choice == "1":
            ifaces = system.get_wireless_interfaces()
            if ifaces:
                console.print("[green]Wireless interfaces:[/green]")
                for i in ifaces:
                    console.print(f"  • {i}")
            else:
                console.print("[yellow]No wireless interfaces found.[/yellow]")
            _pause()

        elif choice == "2":
            if not _require_root():
                _pause()
                continue
            if not _require_tool("airmon-ng"):
                _pause()
                continue
            iface = _pick_interface(monitor_preferred=False)
            if not iface:
                continue
            console.print(f"[cyan]Enabling monitor mode on {iface}...[/cyan]")
            ok, result = system.enable_monitor_mode(iface)
            if ok:
                console.print(f"[green]✔ Monitor mode enabled → {result}[/green]")
            else:
                console.print(f"[red]✘ Failed: {result}[/red]")
            _pause()

        elif choice == "3":
            if not _require_root():
                _pause()
                continue
            iface = _pick_interface()
            if not iface:
                continue
            ok, result = system.disable_monitor_mode(iface)
            status_color = "green" if ok else "red"
            status_mark = "✔" if ok else "✘"
            console.print(f"[{status_color}]{status_mark} {result}[/{status_color}]")
            _pause()

        elif choice == "4":
            if not _require_root():
                _pause()
                continue
            console.print("[cyan]Killing interfering processes...[/cyan]")
            out = system.kill_interfering_processes()
            console.print(out)
            _pause()

        elif choice == "5":
            status = system.get_all_tool_status()
            missing = [t for t, ok in status.items() if not ok]
            if not missing:
                console.print("[green]All tools are installed.[/green]")
            else:
                console.print(f"[yellow]Missing: {', '.join(missing)}[/yellow]")
                if _require_root():
                    for tool in missing:
                        pkg = system.TOOL_PACKAGES[tool]
                        if Confirm.ask(f"Install [bold]{pkg}[/bold]?", default=True):
                            ok, out = system.install_tool(pkg)
                            console.print(out[-500:] if len(out) > 500 else out)
                            console.print(
                                f"[green]✔ {pkg} installed[/green]"
                                if ok else
                                f"[red]✘ {pkg} installation failed[/red]"
                            )
            _pause()


# ---------------------------------------------------------------------------
# Workflow: Network Discovery
# ---------------------------------------------------------------------------

def menu_network_discovery() -> None:
    _clear()
    _heading("Network Discovery — airodump-ng")

    if not _require_root():
        _pause()
        return
    if not _require_tool("airodump-ng"):
        _pause()
        return

    console.print(
        "[dim]airodump-ng will scan all channels and list nearby APs and clients.\n"
        "Press [bold]Ctrl+C[/bold] inside airodump-ng to stop capturing.[/dim]\n"
    )

    iface = _pick_interface()
    if not iface:
        return

    channel_str = Prompt.ask(
        "Channel to scan (leave blank to scan all channels)", default=""
    )
    channel = int(channel_str) if channel_str.strip().isdigit() else None

    out_dir = _pick_output_dir()
    prefix = str(out_dir / "scan")

    console.print(
        f"\n[cyan]Starting airodump-ng on [bold]{iface}[/bold], "
        f"output prefix: [bold]{prefix}[/bold][/cyan]\n"
    )
    aircrack.scan_networks(iface, prefix, channel=channel)

    # After airodump-ng exits, show the CSV if it exists
    csvs = _glob.glob(f"{prefix}*.csv")
    if csvs:
        _parse_and_show_scan_csv(csvs[0])
    _pause()


def _parse_and_show_scan_csv(csv_path: str) -> None:
    """Parse an airodump-ng CSV and render a summary table."""
    try:
        with open(csv_path, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return

    ap_table = Table(
        title="Discovered Access Points",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
    )
    for col in ("BSSID", "CH", "ENC", "CIPHER", "AUTH", "PWR", "#Data", "ESSID"):
        ap_table.add_column(col, min_width=8)

    in_ap_section = True
    ap_count = 0
    for line in lines:
        stripped = line.strip()
        if stripped == "":
            in_ap_section = False
            continue
        if stripped.startswith("BSSID") or stripped.startswith("Station"):
            continue
        if in_ap_section:
            parts = [p.strip() for p in stripped.split(",")]
            if len(parts) >= 15:
                bssid, _, _, ch, speed, enc, cipher, auth, pwr, beacons, data = (
                    parts[0], parts[1], parts[2], parts[3], parts[4],
                    parts[5], parts[6], parts[7], parts[8], parts[9], parts[10],
                )
                essid = parts[13] if len(parts) > 13 else ""
                ap_table.add_row(bssid, ch, enc, cipher, auth, pwr, data, essid)
                ap_count += 1

    if ap_count:
        console.print(ap_table)
    else:
        console.print("[yellow]No APs parsed from CSV — check capture file.[/yellow]")


# ---------------------------------------------------------------------------
# Workflow: WEP Analysis
# ---------------------------------------------------------------------------

def menu_wep_analysis() -> None:
    _clear()
    _heading("WEP Analysis — Aircrack-ng (PTW/FMS Attack)", "red")

    if not _require_root():
        _pause()
        return
    for tool in ("airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"):
        if not _require_tool(tool):
            _pause()
            return

    console.print(
        "[dim]This workflow captures WEP IVs from a target AP using ARP replay "
        "injection, then cracks the key using the PTW statistical attack.[/dim]\n"
    )

    while True:
        console.print(
            "[1] Capture IVs from target AP (airodump-ng + ARP replay)\n"
            "[2] Crack a WEP capture file (aircrack-ng -z)\n"
            "[0] Back\n"
        )
        choice = Prompt.ask("Select", choices=["0", "1", "2"])
        if choice == "0":
            return

        if choice == "1":
            iface = _pick_interface()
            if not iface:
                continue
            bssid = Prompt.ask("Target AP BSSID (e.g. AA:BB:CC:DD:EE:FF)")
            ch_str = Prompt.ask("Channel")
            if not ch_str.isdigit():
                console.print("[red]Invalid channel.[/red]")
                continue
            channel = int(ch_str)
            out_dir = _pick_output_dir()
            prefix = str(out_dir / "wep_capture")

            console.print(
                f"\n[cyan]Step 1 — Targeting AP {bssid} on channel {channel}...[/cyan]\n"
                "[dim]airodump-ng will run in the foreground.  "
                "Open a second terminal and run 'aireplay-ng -3' to inject ARP frames, "
                "or leave it to collect IVs passively.  Press Ctrl+C to stop.[/dim]\n"
            )
            # Targeted capture (interactive — user stops with Ctrl+C)
            aircrack.capture_targeted(iface, bssid, channel, prefix)

            # Offer immediate crack
            caps = _glob.glob(f"{prefix}*.cap")
            if caps and Confirm.ask("Crack the capture now?", default=True):
                _crack_wep_file(caps[0])
            _pause()

        elif choice == "2":
            cap_file = Prompt.ask("Path to .cap file")
            if not os.path.isfile(cap_file):
                console.print("[red]File not found.[/red]")
                _pause()
                continue
            _crack_wep_file(cap_file)
            _pause()


def _crack_wep_file(cap_file: str) -> None:
    console.print(f"\n[cyan]Running aircrack-ng PTW attack on {cap_file}...[/cyan]\n")
    ok, output, key = aircrack.crack_wep(cap_file)
    console.print(output)
    if key:
        console.print(
            Panel(
                f"[bold green]KEY FOUND: {key}[/bold green]",
                border_style="green",
                padding=(1, 2),
            )
        )
    elif not ok:
        console.print("[yellow]Key not found — try collecting more IVs (aim for 80,000+).[/yellow]")


# ---------------------------------------------------------------------------
# Workflow: WPA/WPA2 Handshake Attack
# ---------------------------------------------------------------------------

def menu_wpa_attack() -> None:
    _clear()
    _heading("WPA/WPA2 Handshake Attack", "yellow")

    if not _require_root():
        _pause()
        return

    console.print(
        "[dim]This workflow captures a 4-way handshake by deauthenticating a "
        "connected client, then cracks it offline with hashcat or aircrack-ng.[/dim]\n"
    )

    while True:
        console.print(
            "[1] Capture handshake (airodump-ng + deauth)\n"
            "[2] Check capture for handshake\n"
            "[3] Crack handshake with hashcat (GPU-accelerated)\n"
            "[4] Crack handshake with aircrack-ng (CPU)\n"
            "[0] Back\n"
        )
        choice = Prompt.ask("Select", choices=["0", "1", "2", "3", "4"])
        if choice == "0":
            return

        if choice == "1":
            for tool in ("airodump-ng", "aireplay-ng"):
                if not _require_tool(tool):
                    _pause()
                    break
            else:
                iface = _pick_interface()
                if not iface:
                    continue
                bssid = Prompt.ask("Target AP BSSID")
                ch_str = Prompt.ask("Channel")
                if not ch_str.isdigit():
                    console.print("[red]Invalid channel.[/red]")
                    continue
                channel = int(ch_str)
                client = Prompt.ask("Client MAC to deauth (blank = broadcast)", default="")
                out_dir = _pick_output_dir()
                prefix = str(out_dir / "wpa_capture")

                console.print(
                    f"\n[cyan]Starting capture on {bssid} ch{channel}...[/cyan]\n"
                    "[dim]airodump-ng will run.  When you see 'WPA handshake' "
                    "in the top-right corner, press Ctrl+C.[/dim]\n"
                )
                # Run capture (blocking, user Ctrl+C's when done)
                aircrack.capture_targeted(iface, bssid, channel, prefix)

                # Send deauth after capture ends (or user can do it before)
                if Confirm.ask("Send deauth frames now to force handshake?", default=True):
                    console.print("[cyan]Sending deauth...[/cyan]")
                    ok, out = aircrack.deauth(iface, bssid, client or None)
                    console.print(out)

                caps = _glob.glob(f"{prefix}*.cap")
                if caps:
                    has_hs, out = aircrack.check_handshake(caps[0])
                    if has_hs:
                        console.print(f"[green]✔ Handshake detected in {caps[0]}[/green]")
                    else:
                        console.print("[yellow]No handshake detected yet — try again.[/yellow]")
            _pause()

        elif choice == "2":
            cap = Prompt.ask("Path to .cap file")
            if not os.path.isfile(cap):
                console.print("[red]File not found.[/red]")
                _pause()
                continue
            has_hs, out = aircrack.check_handshake(cap)
            console.print(out)
            console.print(
                f"[green]✔ Handshake present[/green]"
                if has_hs else
                "[red]✘ No handshake found[/red]"
            )
            _pause()

        elif choice == "3":
            if not _require_tool("hashcat"):
                _pause()
                continue
            if not _require_tool("hcxpcapngtool", "hcxtools"):
                _pause()
                continue
            cap = Prompt.ask("Path to .cap/.pcapng file")
            if not os.path.isfile(cap):
                console.print("[red]File not found.[/red]")
                _pause()
                continue
            out_dir = _pick_output_dir()
            hash_file = str(out_dir / "wpa.hc22000")
            console.print("[cyan]Converting capture to hashcat format...[/cyan]")
            ok, out = hashcat_tool.convert_pcap(cap, hash_file)
            console.print(out)
            if not ok or not os.path.isfile(hash_file):
                console.print("[red]Conversion failed.[/red]")
                _pause()
                continue
            wordlist = Prompt.ask("Wordlist path (e.g. /usr/share/wordlists/rockyou.txt)")
            if not os.path.isfile(wordlist):
                console.print("[red]Wordlist file not found.[/red]")
                _pause()
                continue
            rules_str = Prompt.ask("Rules file (leave blank for none)", default="")
            rules = [rules_str] if rules_str.strip() else None
            console.print(
                "\n[cyan]Running hashcat -m 22000 "
                "(press [bold]q[/bold] inside hashcat to quit)...[/cyan]\n"
            )
            hashcat_tool.crack_wpa2(hash_file, wordlist, rules=rules)
            # Show cracked results
            ok2, cracked = hashcat_tool.show_cracked(hash_file, 22000)
            if cracked.strip():
                console.print(
                    Panel(
                        f"[bold green]{cracked}[/bold green]",
                        title="Cracked Password",
                        border_style="green",
                    )
                )
            _pause()

        elif choice == "4":
            if not _require_tool("aircrack-ng"):
                _pause()
                continue
            cap = Prompt.ask("Path to .cap file")
            wordlist = Prompt.ask("Wordlist path")
            bssid = Prompt.ask("AP BSSID (optional)", default="")
            if not os.path.isfile(cap):
                console.print("[red]Capture file not found.[/red]")
                _pause()
                continue
            if not os.path.isfile(wordlist):
                console.print("[red]Wordlist not found.[/red]")
                _pause()
                continue
            console.print("\n[cyan]Running aircrack-ng dictionary attack...[/cyan]\n")
            ok, output, key = aircrack.crack_wpa(cap, wordlist, bssid=bssid or None)
            console.print(output[-3000:] if len(output) > 3000 else output)
            if key:
                console.print(
                    Panel(
                        f"[bold green]PASSPHRASE FOUND: {key}[/bold green]",
                        border_style="green",
                        padding=(1, 2),
                    )
                )
            _pause()


# ---------------------------------------------------------------------------
# Workflow: PMKID Attack
# ---------------------------------------------------------------------------

def menu_pmkid_attack() -> None:
    _clear()
    _heading("PMKID Attack — Clientless WPA2 Cracking", "yellow")

    if not _require_root():
        _pause()
        return

    console.print(
        "[dim]The PMKID attack (discovered by Jens Steube / hashcat, 2018) captures "
        "the PMKID from the AP's first EAPOL frame — no client needed.  The PMKID "
        "is a deterministic function of the network password and can be cracked "
        "offline with hashcat.[/dim]\n"
    )

    while True:
        console.print(
            "[1] Capture PMKID (hcxdumptool)\n"
            "[2] Convert capture to hashcat format (hcxpcapngtool)\n"
            "[3] Crack PMKID with hashcat (-m 22801)\n"
            "[0] Back\n"
        )
        choice = Prompt.ask("Select", choices=["0", "1", "2", "3"])
        if choice == "0":
            return

        if choice == "1":
            if not _require_tool("hcxdumptool"):
                _pause()
                continue
            iface = _pick_interface()
            if not iface:
                continue
            bssid = Prompt.ask("Filter to BSSID (leave blank for all APs)", default="")
            out_dir = _pick_output_dir()
            out_file = str(out_dir / "pmkid_capture.pcapng")
            console.print(
                f"\n[cyan]Running hcxdumptool on {iface}...[/cyan]\n"
                "[dim]Press Ctrl+C to stop capturing.[/dim]\n"
            )
            hcx.capture(iface, out_file, bssid_filter=bssid or None)
            console.print(f"[green]Capture saved to: {out_file}[/green]")
            # Show summary
            ok, summary = hcx.get_capture_summary(out_file)
            if summary:
                console.print(summary)
            _pause()

        elif choice == "2":
            if not _require_tool("hcxpcapngtool", "hcxtools"):
                _pause()
                continue
            in_file = Prompt.ask("Input pcapng file")
            if not os.path.isfile(in_file):
                console.print("[red]File not found.[/red]")
                _pause()
                continue
            out_dir = _pick_output_dir()
            out_file = str(out_dir / "pmkid.hc22000")
            ok, output = hcx.convert_to_hashcat(in_file, out_file)
            console.print(output)
            if ok:
                console.print(f"[green]✔ Converted: {out_file}[/green]")
            else:
                console.print("[red]Conversion failed.[/red]")
            _pause()

        elif choice == "3":
            if not _require_tool("hashcat"):
                _pause()
                continue
            hash_file = Prompt.ask("Hash file (.hc22000 or PMKID text)")
            if not os.path.isfile(hash_file):
                console.print("[red]Hash file not found.[/red]")
                _pause()
                continue
            wordlist = Prompt.ask("Wordlist path")
            if not os.path.isfile(wordlist):
                console.print("[red]Wordlist not found.[/red]")
                _pause()
                continue
            rules_str = Prompt.ask("Rules file (blank for none)", default="")
            rules = [rules_str] if rules_str.strip() else None

            # Determine mode: 22801 (PMKID only) or 22000 (PMKID + EAPOL)
            mode_str = Prompt.ask("Hash mode (22000 = PMKID+EAPOL, 22801 = PMKID only)", default="22000")
            mode = int(mode_str) if mode_str.isdigit() else 22000

            console.print(
                f"\n[cyan]Running hashcat -m {mode}...[/cyan]\n"
                "[dim]Press q inside hashcat to quit.[/dim]\n"
            )
            if mode == 22801:
                hashcat_tool.crack_pmkid(hash_file, wordlist, rules=rules)
            else:
                hashcat_tool.crack_wpa2(hash_file, wordlist, rules=rules)

            ok2, cracked = hashcat_tool.show_cracked(hash_file, mode)
            if cracked.strip():
                console.print(
                    Panel(
                        f"[bold green]{cracked}[/bold green]",
                        title="Cracked Password",
                        border_style="green",
                    )
                )
            _pause()


# ---------------------------------------------------------------------------
# Workflow: KRACK Vulnerability Test
# ---------------------------------------------------------------------------

def menu_krack_test() -> None:
    _clear()
    _heading("KRACK — Key Reinstallation Attack Test", "red")

    console.print(
        Panel(
            "This runs the official PoC scripts from [bold]vanhoef/krackattacks-scripts[/bold] "
            "(https://github.com/vanhoef/krackattacks-scripts) to test whether a "
            "specific device is vulnerable to CVE-2017-13077+.\n\n"
            "[dim]The script sets up a rogue AP clone and replays handshake message 3 "
            "to check if the target device reinstalls its key and resets the nonce counter.[/dim]",
            border_style="red",
            padding=(1, 2),
        )
    )

    # Check if repo is present
    repo = krack.find_repo()
    deps = krack.check_dependencies()

    dep_table = Table(box=box.SIMPLE, show_header=False)
    dep_table.add_column("Dep", style="bold", min_width=16)
    dep_table.add_column("Status")
    for dep, ok in deps.items():
        dep_table.add_row(
            dep,
            Text("✔ found", style="green") if ok else Text("✘ missing", style="red"),
        )
    dep_table.add_row(
        "krackattacks-scripts",
        Text(f"✔ {repo}", style="green") if repo else Text("✘ not cloned", style="red"),
    )
    console.print(dep_table)
    console.print()

    while True:
        console.print(
            "[1] Clone krackattacks-scripts from GitHub\n"
            "[2] Install Python requirements\n"
            "[3] Run KRACK client test\n"
            "[0] Back\n"
        )
        choice = Prompt.ask("Select", choices=["0", "1", "2", "3"])
        if choice == "0":
            return

        if choice == "1":
            dest = Prompt.ask("Clone to directory", default="/opt/krackattacks-scripts")
            console.print(f"[cyan]Cloning from GitHub to {dest}...[/cyan]")
            ok, out = krack.clone_repo(dest)
            console.print(out)
            console.print(
                "[green]✔ Cloned.[/green]" if ok else "[red]✘ Clone failed.[/red]"
            )
            _pause()

        elif choice == "2":
            repo_dir = krack.find_repo()
            if not repo_dir:
                console.print("[red]Repo not found. Clone it first (option 1).[/red]")
                _pause()
                continue
            ok, out = krack.install_requirements(repo_dir)
            console.print(out)
            console.print(
                "[green]✔ Requirements installed.[/green]"
                if ok else "[red]✘ pip install failed.[/red]"
            )
            _pause()

        elif choice == "3":
            if not _require_root():
                _pause()
                continue
            if not krack.find_script():
                console.print(
                    "[red]krack-test-client.py not found.  "
                    "Clone the repo first (option 1).[/red]"
                )
                _pause()
                continue
            iface = _pick_interface()
            if not iface:
                continue
            target_mac = Prompt.ask("Target device MAC address (blank to skip)", default="")
            console.print("\n[cyan]Running KRACK test script...[/cyan]\n")
            krack.run_test(iface, target_mac=target_mac or None)
            _pause()


# ---------------------------------------------------------------------------
# Workflow: Bettercap
# ---------------------------------------------------------------------------

def menu_bettercap() -> None:
    _clear()
    _heading("Bettercap — Network Attack & Monitoring Framework", "magenta")

    if not _require_tool("bettercap"):
        _pause()
        return

    console.print(
        Panel(
            "Bettercap (https://github.com/bettercap/bettercap) is a comprehensive "
            "network attack and monitoring framework covering Wi-Fi, Bluetooth, "
            "Ethernet, and more.  It features an interactive REPL and optional web UI.\n\n"
            "[dim]Wi-Fi modules: wifi.recon, wifi.deauth, wifi.assoc, wifi.show[/dim]",
            border_style="magenta",
            padding=(1, 2),
        )
    )

    while True:
        console.print(
            "[1] Launch bettercap interactive REPL\n"
            "[2] Launch with Wi-Fi recon enabled\n"
            "[3] Launch with a caplet file\n"
            "[4] Wi-Fi deauth (specific BSSID)\n"
            "[0] Back\n"
        )
        choice = Prompt.ask("Select", choices=["0", "1", "2", "3", "4"])
        if choice == "0":
            return

        if not _require_root():
            _pause()
            continue

        if choice == "1":
            iface = _pick_interface()
            if not iface:
                continue
            console.print(f"\n[magenta]Launching bettercap on {iface}...[/magenta]\n")
            bettercap.launch(iface)
            _pause()

        elif choice == "2":
            iface = _pick_interface()
            if not iface:
                continue
            console.print(
                f"\n[magenta]Launching bettercap with wifi.recon on {iface}...[/magenta]\n"
                "[dim]Type 'wifi.show' to list APs, 'help' for all commands.[/dim]\n"
            )
            bettercap.wifi_recon(iface)
            _pause()

        elif choice == "3":
            iface = _pick_interface()
            if not iface:
                continue
            caplet = Prompt.ask("Caplet file path")
            if not os.path.isfile(caplet):
                console.print("[red]Caplet file not found.[/red]")
                _pause()
                continue
            bettercap.launch(iface, caplet=caplet)
            _pause()

        elif choice == "4":
            iface = _pick_interface()
            if not iface:
                continue
            bssid = Prompt.ask("Target BSSID (or 'all' to deauth all clients)")
            console.print(f"\n[magenta]Running bettercap deauth against {bssid}...[/magenta]\n")
            bettercap.wifi_deauth(iface, bssid)
            _pause()


# ---------------------------------------------------------------------------
# Workflow: Wifite2
# ---------------------------------------------------------------------------

def menu_wifite() -> None:
    _clear()
    _heading("Wifite2 — Automated Wi-Fi Auditing", "blue")

    if not wifite.is_available():
        console.print("[red]✘ wifite / wifite2 not found.[/red]")
        console.print("  Install: [bold cyan]sudo apt-get install wifite[/bold cyan]")
        console.print(
            "  Source:  [dim]https://github.com/derv82/wifite2[/dim]"
        )
        _pause()
        return

    console.print(
        Panel(
            "Wifite2 (https://github.com/derv82/wifite2) wraps aircrack-ng, hashcat, "
            "and hcxdumptool into an automated workflow: it scans for targets, "
            "selects an attack strategy, executes it, and reports results.\n\n"
            "[dim]It handles WEP, WPA handshake capture, PMKID, and WPS attacks "
            "automatically.[/dim]",
            border_style="blue",
            padding=(1, 2),
        )
    )

    if not _require_root():
        _pause()
        return

    while True:
        console.print(
            "[1] Launch wifite2 (attack all found networks)\n"
            "[2] Launch wifite2 — WEP targets only\n"
            "[3] Launch wifite2 — WPA/WPA2 targets only\n"
            "[4] Launch wifite2 — PMKID attack only\n"
            "[0] Back\n"
        )
        choice = Prompt.ask("Select", choices=["0", "1", "2", "3", "4"])
        if choice == "0":
            return

        iface = _pick_interface()
        if not iface:
            continue

        if choice == "1":
            console.print("\n[blue]Launching wifite2...[/blue]\n")
            wifite.launch(iface)
        elif choice == "2":
            console.print("\n[blue]Launching wifite2 (WEP only)...[/blue]\n")
            wifite.launch_wep(iface)
        elif choice == "3":
            wl = Prompt.ask("Wordlist (leave blank to use wifite default)", default="")
            console.print("\n[blue]Launching wifite2 (WPA/WPA2)...[/blue]\n")
            wifite.launch_wpa(iface, wordlist=wl or None)
        elif choice == "4":
            console.print("\n[blue]Launching wifite2 (PMKID only)...[/blue]\n")
            wifite.launch_pmkid(iface)
        _pause()


# ---------------------------------------------------------------------------
# Reference: Protocols
# ---------------------------------------------------------------------------

def menu_protocol_reference() -> None:
    _clear()
    _heading("Wi-Fi Protocol Reference")
    render_protocol_table(console)

    while True:
        console.print(
            "\n[1] WEP detail\n"
            "[2] WPA detail\n"
            "[3] WPA2 detail\n"
            "[4] WPA3 detail\n"
            "[0] Back\n"
        )
        choice = Prompt.ask("Select", choices=["0", "1", "2", "3", "4"])
        if choice == "0":
            return
        idx = int(choice) - 1
        _clear()
        render_protocol_detail(console, ALL_PROTOCOLS[idx])
        _pause()
        _clear()
        render_protocol_table(console)


# ---------------------------------------------------------------------------
# Reference: Attacks
# ---------------------------------------------------------------------------

def menu_attack_reference() -> None:
    _clear()
    _heading("Attack Vector Reference")

    attack_table = Table(
        box=box.ROUNDED,
        border_style="red",
        header_style="bold cyan",
        show_lines=True,
    )
    attack_table.add_column("#", style="bold", justify="right", min_width=3)
    attack_table.add_column("Attack", min_width=30)
    attack_table.add_column("Protocol", min_width=10)
    attack_table.add_column("Year", min_width=6)
    attack_table.add_column("Severity", min_width=10)
    attack_table.add_column("CVE", min_width=18)

    for i, atk in enumerate(ALL_ATTACKS, 1):
        attack_table.add_row(
            str(i),
            atk.name,
            atk.protocol,
            atk.year,
            f"[{atk.severity_color}]{atk.severity}[/{atk.severity_color}]",
            atk.cve,
        )
    console.print(attack_table)

    while True:
        num_str = Prompt.ask(
            f"Enter attack number for details [1-{len(ALL_ATTACKS)}] or 0 to go back",
            default="0",
        )
        if num_str == "0":
            return
        if num_str.isdigit() and 1 <= int(num_str) <= len(ALL_ATTACKS):
            _clear()
            render_attack_detail(console, ALL_ATTACKS[int(num_str) - 1])
            _pause()
            _clear()
            console.print(attack_table)
        else:
            console.print("[red]Invalid selection.[/red]")


# ---------------------------------------------------------------------------
# Main menu & entry point
# ---------------------------------------------------------------------------

MENU_ITEMS = [
    ("1",  "System Setup",              "Interface management, monitor mode, tool install"),
    ("2",  "Network Discovery",         "Scan nearby Wi-Fi networks with airodump-ng"),
    ("3",  "WEP Analysis",              "IV capture + PTW/FMS crack (aircrack-ng)"),
    ("4",  "WPA/WPA2 Handshake Attack", "Capture handshake, crack with hashcat / aircrack-ng"),
    ("5",  "PMKID Attack",              "Clientless WPA2 capture + crack (hcxdumptool + hashcat)"),
    ("6",  "KRACK Vulnerability Test",  "CVE-2017-13077+ nonce reinstallation test"),
    ("7",  "Bettercap Framework",       "Interactive network monitoring & attack REPL"),
    ("8",  "Wifite2",                   "Automated Wi-Fi auditing (WEP/WPA/PMKID/WPS)"),
    ("9",  "Protocol Reference",        "WEP / WPA / WPA2 / WPA3 technical details"),
    ("10", "Attack Reference",          "FMS / KRACK / PMKID / Dragonblood deep-dives"),
    ("11", "Legal & Ethics",            "Responsible use guidelines and legal framework"),
    ("0",  "Exit",                      ""),
]

MENU_DISPATCH = {
    "1":  menu_system_setup,
    "2":  menu_network_discovery,
    "3":  menu_wep_analysis,
    "4":  menu_wpa_attack,
    "5":  menu_pmkid_attack,
    "6":  menu_krack_test,
    "7":  menu_bettercap,
    "8":  menu_wifite,
    "9":  menu_protocol_reference,
    "10": menu_attack_reference,
    "11": lambda: (render_legal_panel(console), _pause()),
}


def _render_main_menu() -> None:
    status = system.get_all_tool_status()
    installed = sum(1 for v in status.values() if v)
    total = len(status)
    ifaces = system.get_wireless_interfaces()
    root_str = "[green]✔ root[/green]" if system.is_root() else "[red]✘ not root[/red]"
    tools_str = (
        f"[green]{installed}/{total} tools installed[/green]"
        if installed == total
        else f"[yellow]{installed}/{total} tools installed[/yellow]"
    )
    iface_str = ", ".join(ifaces) if ifaces else "[yellow]none detected[/yellow]"

    status_line = f" {root_str}  |  {tools_str}  |  Interfaces: {iface_str}"

    table = Table(box=box.ROUNDED, border_style="cyan", show_header=False,
                  padding=(0, 2))
    table.add_column("#", style="bold cyan", min_width=4, justify="right")
    table.add_column("Option", style="bold white", min_width=28)
    table.add_column("Description", style="dim")
    for num, name, desc in MENU_ITEMS:
        table.add_row(num, name, desc)

    console.print(
        Panel(
            table,
            title="[bold cyan]Main Menu[/bold cyan]",
            subtitle=status_line,
            border_style="cyan",
            padding=(0, 1),
        )
    )


def run() -> None:
    """Entry point — show banner, then loop through main menu."""
    _clear()
    render_banner(console)

    if not system.is_root():
        console.print(
            "[yellow]⚠ Not running as root.  Most capture operations require "
            "root privileges (sudo).[/yellow]\n"
        )

    valid_choices = [item[0] for item in MENU_ITEMS]

    while True:
        _render_main_menu()
        choice = Prompt.ask("Select option", choices=valid_choices)
        if choice == "0":
            console.print("\n[cyan]Goodbye.[/cyan]\n")
            break
        handler = MENU_DISPATCH.get(choice)
        if handler:
            try:
                handler()
            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted.[/yellow]")
            except RuntimeError as exc:
                console.print(f"\n[red]Error: {exc}[/red]")
                _pause()
        _clear()
        render_banner(console)
