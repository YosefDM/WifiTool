"""KRACK vulnerability test wrapper.

Wraps: vanhoef/krackattacks-scripts
GitHub: https://github.com/vanhoef/krackattacks-scripts
Paper:  "Key Reinstallation Attacks: Forcing Nonce Reuse in WPA2" — CCS 2017
        https://krackattacks.com

The scripts use a modified hostapd/wpa_supplicant to intercept and
replay 4-way handshake messages, detecting whether a device resets its
nonce counter upon receiving a retransmitted message 3.
"""

import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from .system import check_tool, run_command_live


REPO_URL = "https://github.com/vanhoef/krackattacks-scripts"

# Candidate installation directories (searched in order)
SEARCH_DIRS: List[str] = [
    "/opt/krackattacks-scripts",
    os.path.expanduser("~/krackattacks-scripts"),
    "/usr/local/share/krackattacks-scripts",
    "/usr/share/krackattacks-scripts",
    # Windows paths
    os.path.expanduser("~/Documents/krackattacks-scripts"),
    r"C:\Tools\krackattacks-scripts",
]

# Relative paths of the main test script inside the repo
SCRIPT_CANDIDATES = [
    "krack-test-client.py",
    "krackattack/krack-test-client.py",
]


def find_repo() -> Optional[str]:
    """Return the base directory of the cloned krackattacks-scripts repo, or None."""
    for base in SEARCH_DIRS:
        if os.path.isdir(base):
            # Verify it looks like the right repo
            for script in SCRIPT_CANDIDATES:
                if os.path.isfile(os.path.join(base, script)):
                    return base
    return None


def find_script() -> Optional[str]:
    """Return the full path to krack-test-client.py, or None."""
    base = find_repo()
    if base is None:
        return None
    for candidate in SCRIPT_CANDIDATES:
        full = os.path.join(base, candidate)
        if os.path.isfile(full):
            return full
    return None


def check_dependencies() -> dict:
    """Check that the KRACK test script dependencies are present."""
    return {
        "python3": check_tool("python3") or check_tool("python"),
        "hostapd": check_tool("hostapd"),
        "wpa_supplicant": check_tool("wpa_supplicant"),
        "git": check_tool("git"),
    }


def clone_repo(target_dir: Optional[str] = None) -> Tuple[bool, str]:
    """Clone the krackattacks-scripts repository.

    git clone https://github.com/vanhoef/krackattacks-scripts <target_dir>
    Returns (success, output).
    """
    if not check_tool("git"):
        return False, "git not found — install git first."
    dest = target_dir or SEARCH_DIRS[0]
    if os.path.isdir(dest):
        return False, f"Directory already exists: {dest}"
    try:
        result = subprocess.run(
            ["git", "clone", REPO_URL, dest],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.returncode == 0, (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return False, "git clone timed out."
    except Exception as exc:
        return False, str(exc)


def install_requirements(repo_dir: Optional[str] = None) -> Tuple[bool, str]:
    """Install Python requirements for krackattacks-scripts.

    Uses the current Python interpreter's pip to ensure compatibility.
    """
    base = repo_dir or find_repo()
    if base is None:
        return False, "krackattacks-scripts repo not found. Clone it first."
    req_file = os.path.join(base, "requirements.txt")
    if not os.path.isfile(req_file):
        return False, f"requirements.txt not found in {base}."
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", req_file],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.returncode == 0, (result.stdout + result.stderr).strip()
    except Exception as exc:
        return False, str(exc)


def run_test(interface: str,
             target_mac: Optional[str] = None,
             extra_args: Optional[List[str]] = None) -> int:
    """Run the KRACK client test script against a target device.

    python krack-test-client.py <interface> [target_mac] [extra_args]

    The script sets up a rogue AP clone, positions itself as MITM, and
    detects nonce reinstallation by observing whether the target resets
    its packet counter after receiving a replayed message 3.

    Runs interactively (verbose output).  Returns the process exit code.
    """
    script = find_script()
    if script is None:
        raise RuntimeError(
            "KRACK test scripts not found.\n"
            f"Clone with: git clone {REPO_URL}"
        )
    cmd = [sys.executable, script, interface]
    if target_mac:
        cmd.append(target_mac)
    if extra_args:
        cmd += extra_args
    return run_command_live(cmd)
