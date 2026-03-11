"""Reusable rich UI components for WifiTool."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich import box

from ..data.protocols import ALL_PROTOCOLS, PROTOCOL_COMPARISON
from ..data.attacks import ALL_ATTACKS
from ..tools.system import (
    IS_WINDOWS,
    NPCAP_DOWNLOAD_URL,
    TOOL_PACKAGES,
    TOOL_PACKAGES_WINDOWS,
    TOOL_REPOS,
    WINDOWS_NOT_AVAILABLE,
    find_npcap_wlanhelper,
    get_all_tool_status,
)


def _npcap_available() -> bool:
    """Return True if Npcap's WlanHelper.exe is found on this Windows system."""
    return find_npcap_wlanhelper() is not None

BANNER = r"""
 __        ___  __ _  _____           _
 \ \      / (_)/ _(_)|_   _|__   ___ | |
  \ \ /\ / /| | |_| |  | |/ _ \ / _ \| |
   \ V  V / | |  _| |  | | (_) | (_) | |
    \_/\_/  |_|_| |_|  |_|\___/ \___/|_|

  Educational Wi-Fi Security Analysis Suite
"""


def render_banner(console: Console) -> None:
    """Print the WifiTool ASCII banner."""
    console.print(
        Panel(
            Text(BANNER, style="bold cyan", justify="center"),
            subtitle="[dim]For use in authorized, sandboxed environments only[/dim]",
            border_style="cyan",
            padding=(0, 2),
        )
    )


def render_tool_status(console: Console) -> None:
    """Print a table showing which real tools are installed."""
    status = get_all_tool_status()
    active_packages = TOOL_PACKAGES_WINDOWS if IS_WINDOWS else TOOL_PACKAGES
    pkg_label = "winget / Chocolatey package" if IS_WINDOWS else "apt package"

    # Tools replaced by the Python pcap_utils module on Windows
    _PYTHON_NATIVE_WINDOWS = {"hcxdumptool", "hcxpcapngtool"}
    # Tool replaced by WlanHelper on Windows
    _WLANHELPER_TOOLS = {"airmon-ng"}

    table = Table(
        title="Installed Tools",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Tool", style="bold white", min_width=16)
    table.add_column("Status", min_width=18)
    table.add_column(pkg_label, style="dim", min_width=14)
    table.add_column("GitHub Source", style="dim")

    pkg_to_repo = {
        "aircrack-ng": TOOL_REPOS["aircrack-ng"],
        "hashcat": TOOL_REPOS["hashcat"],
        "hcxdumptool": TOOL_REPOS["hcxdumptool"],
        "hcxtools": TOOL_REPOS["hcxtools"],
        "bettercap": TOOL_REPOS["bettercap"],
        "wifite": TOOL_REPOS["wifite"],
    }

    for tool, apt_pkg in TOOL_PACKAGES.items():
        installed = status.get(tool, False)
        win_pkg = active_packages.get(tool, apt_pkg)
        display_pkg = win_pkg if IS_WINDOWS else apt_pkg

        if IS_WINDOWS and tool in _PYTHON_NATIVE_WINDOWS:
            status_text = Text("✔ Python/scapy", style="green bold")
            display_pkg = "scapy (pip install scapy)"
        elif IS_WINDOWS and tool in _WLANHELPER_TOOLS:
            helper_ok = _npcap_available()
            if helper_ok:
                status_text = Text("✔ via WlanHelper", style="green bold")
            else:
                status_text = Text("✘ Npcap needed", style="yellow bold")
            display_pkg = f"Npcap — {NPCAP_DOWNLOAD_URL}"
        elif IS_WINDOWS and win_pkg == WINDOWS_NOT_AVAILABLE:
            status_text = Text("— Linux only", style="dim")
        elif installed:
            status_text = Text("✔ installed", style="green bold")
        else:
            status_text = Text("✘ missing", style="red bold")

        repo = pkg_to_repo.get(apt_pkg, "")
        table.add_row(tool, status_text, display_pkg, repo)

    console.print(table)


def render_protocol_table(console: Console) -> None:
    """Print a comparison table of all Wi-Fi security protocols."""
    cmp = PROTOCOL_COMPARISON
    table = Table(
        title="Wi-Fi Protocol Comparison",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
    )
    for header in cmp["headers"]:
        table.add_column(header, min_width=12)
    for row in cmp["rows"]:
        table.add_row(*row)
    console.print(table)


def render_protocol_detail(console: Console, protocol) -> None:
    """Render a detailed panel for a single Protocol dataclass."""
    color = protocol.color

    # Overview
    console.print(
        Panel(
            protocol.overview,
            title=f"[bold {color}]{protocol.name} — {protocol.full_name}[/bold {color}]",
            subtitle=f"[dim]{protocol.standard} | {protocol.year}[/dim]",
            border_style=color,
            padding=(1, 2),
        )
    )

    # Spec table
    spec = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    spec.add_column("Field", style="bold", min_width=18)
    spec.add_column("Value")
    for field_name, value in [
        ("Encryption", protocol.encryption),
        ("Integrity", protocol.integrity),
        ("Key Management", protocol.key_management),
        ("Key Length", protocol.key_length),
        ("Security Status", f"[{color}]{protocol.security_level}[/{color}]"),
    ]:
        spec.add_row(field_name, value)
    console.print(spec)

    # How it works
    if protocol.how_it_works:
        table = Table(
            title="How It Works",
            box=box.ROUNDED,
            border_style=color,
            show_header=False,
            padding=(0, 1),
        )
        table.add_column("Step", style="bold cyan", min_width=4, justify="right")
        table.add_column("Description")
        for i, step in enumerate(protocol.how_it_works, 1):
            table.add_row(str(i), step)
        console.print(table)

    # Vulnerabilities
    if protocol.vulnerabilities:
        vuln_table = Table(
            title="Known Vulnerabilities",
            box=box.ROUNDED,
            border_style="red",
            show_header=False,
            padding=(0, 1),
        )
        vuln_table.add_column("", style="red", min_width=2)
        vuln_table.add_column("Vulnerability")
        for vuln in protocol.vulnerabilities:
            vuln_table.add_row("⚠", vuln)
        console.print(vuln_table)

    # Improvements
    if protocol.improvements:
        imp_table = Table(
            title="Improvements Over Predecessor",
            box=box.ROUNDED,
            border_style="green",
            show_header=False,
            padding=(0, 1),
        )
        imp_table.add_column("", style="green", min_width=2)
        imp_table.add_column("Improvement")
        for imp in protocol.improvements:
            imp_table.add_row("✓", imp)
        console.print(imp_table)


def render_attack_detail(console: Console, attack) -> None:
    """Render a detailed panel for a single Attack dataclass."""
    color = attack.severity_color

    # Header panel
    console.print(
        Panel(
            attack.summary,
            title=f"[bold {color}]{attack.name}[/bold {color}]",
            subtitle=(
                f"[dim]Protocol: {attack.protocol} | "
                f"Year: {attack.year} | "
                f"Severity: [{color}]{attack.severity}[/{color}][/dim]"
            ),
            border_style=color,
            padding=(1, 2),
        )
    )

    # Meta table
    meta = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    meta.add_column("Field", style="bold", min_width=16)
    meta.add_column("Value")
    meta.add_row("CVE", attack.cve)
    meta.add_row("Researchers", attack.researchers)
    console.print(meta)

    # Technical detail
    console.print(
        Panel(
            attack.technical_detail,
            title="Technical Detail",
            border_style="dim",
            padding=(1, 2),
        )
    )

    # Step-by-step
    steps_table = Table(
        title="Step-by-Step Attack Walkthrough",
        box=box.ROUNDED,
        border_style=color,
        show_header=False,
        padding=(0, 1),
    )
    steps_table.add_column("Step", style="bold cyan", min_width=4, justify="right")
    steps_table.add_column("Action")
    for i, step in enumerate(attack.steps, 1):
        steps_table.add_row(str(i), step)
    console.print(steps_table)

    # Impact + Mitigation side by side (two panels)
    console.print(
        Panel(attack.impact, title="[red]Impact[/red]",
              border_style="red", padding=(1, 2))
    )
    console.print(
        Panel(attack.mitigation, title="[green]Mitigation[/green]",
              border_style="green", padding=(1, 2))
    )

    # References
    if attack.references:
        ref_table = Table(
            title="References",
            box=box.SIMPLE,
            show_header=False,
            padding=(0, 1),
        )
        ref_table.add_column("", style="dim", min_width=2)
        ref_table.add_column("Reference", style="dim")
        for ref in attack.references:
            ref_table.add_row("→", ref)
        console.print(ref_table)


def render_legal_panel(console: Console) -> None:
    """Render the legal and ethical use panel."""
    legal_text = (
        "[bold red]⚠ IMPORTANT LEGAL NOTICE[/bold red]\n\n"
        "This tool is for [bold]educational and authorized penetration testing[/bold] "
        "use only, in sandboxed lab environments.\n\n"
        "[bold]Using these tools against any network you do not own or do not have "
        "explicit written permission to test is illegal.[/bold]\n\n"
        "• [bold]USA[/bold]: Computer Fraud and Abuse Act (CFAA) — federal crime\n"
        "• [bold]UK[/bold]: Computer Misuse Act — criminal offense\n"
        "• [bold]EU[/bold]: Directive on Attacks Against Information Systems\n\n"
        "Penetration testers operate under signed Rules of Engagement (RoE) documents "
        "that define scope and authorization. All testing conducted with this tool "
        "must have appropriate prior written authorization."
    )
    console.print(
        Panel(
            legal_text,
            title="[bold red]Legal & Ethical Framework[/bold red]",
            border_style="red",
            padding=(1, 2),
        )
    )

    responsible_text = (
        "[bold]Why open-source attack tools are published:[/bold]\n\n"
        "1. Forcing vendors to patch — public PoC code creates urgency\n"
        "2. Academic validation — reproducible research requires published methodology\n"
        "3. Defensive use — defenders use the same tools to assess their own networks\n"
        "4. Education — OSCP, CEH, SANS GWAPT certifications rely on real tools\n\n"
        "[dim]References:\n"
        "  Vanhoef (2017) — Key Reinstallation Attacks — CCS 2017 — https://krackattacks.com\n"
        "  Vanhoef & Ronen (2019) — Dragonblood — IEEE S&P 2020\n"
        "  Steube (2018) — PMKID Attack — https://hashcat.net/forum/thread-7717.html[/dim]"
    )
    console.print(
        Panel(
            responsible_text,
            title="[bold yellow]Responsible Disclosure[/bold yellow]",
            border_style="yellow",
            padding=(1, 2),
        )
    )
