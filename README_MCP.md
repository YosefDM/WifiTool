# WifiTool MCP Server

`mcp_server.py` provides Claude Code with autonomous control over WifiTool
so it can iterate through attacks, read failures, fix source code, and re-run
— all without a human in the loop between iterations.

---

## Installation

Install the `mcp` package (once, in the same environment used to run WifiTool):

```
pip install mcp
```

---

## Registration

From the **repo root**, register the server with Claude Code:

```
claude mcp add --transport stdio python mcp_server.py
```

The server runs as a subprocess — no persistent daemon needed.

---

## Available tools

### Core iteration loop

| Tool | Purpose |
|---|---|
| `run_attack(ssid, bssid, channel, encryption, interface, wordlist_path?)` | Run a full attack via `python main.py --cli` and return all output |
| `scan_networks()` | List nearby Wi-Fi networks as JSON |
| `get_capture_files(ssid)` | List files in `~/wifitool-output/<ssid>/` with sizes and timestamps |
| `read_file(path)` | Read any text file by absolute path |
| `check_tools()` | Show which external tools (hashcat, aircrack-ng, …) are found on PATH |
| `get_interfaces()` | List available wireless interfaces |
| `fix_wlan()` | Restart wlansvc to recover the adapter after a failed run |
| `read_source_file(relative_path)` | Read a repo source file before making any code change |

### Isolated retry — skip the full attack when retrying one step

| Tool | Purpose |
|---|---|
| `capture_handshake(interface, bssid, channel, output_path, timeout?)` | Run only the Scapy capture phase (~timeout seconds vs 5+ min for full attack) |
| `convert_pcap(input_path, output_path)` | Convert a pcap to hc22000 format without a full re-run |
| `run_hashcat(hash_file, wordlist, mode?, extra_args?)` | Run hashcat and return full output |
| `run_aircrack(cap_file, wordlist, bssid?)` | Run aircrack-ng (CPU path) and return full output |

### Diagnosis — understand what was captured and what failed

| Tool | Purpose |
|---|---|
| `validate_pcap(path)` | Count 802.11/EAPOL/beacon frames — confirms whether anything was captured |
| `inspect_hc22000(path)` | Parse hc22000 and report PMKID/EAPOL record counts, SSIDs, BSSIDs |
| `get_potfile(hash_file?)` | Read the hashcat potfile — check if a password was already cracked |
| `list_wordlists()` | Scan known wordlist locations so Claude knows what's available |
| `get_interface_mode(interface)` | Query current monitor/managed mode and channel via WlanHelper |

---

## Intended usage pattern

Claude Code uses these tools to drive an autonomous fix-and-retry loop:

1. **`scan_networks()`** — identify the authorised target network
2. **`run_attack(...)`** — execute a full attack and capture all output
3. Analyse output — identify what failed (no EAPOL frames, conversion error, hashcat issue, wrong channel, etc.)
4. **`read_source_file(...)`** — read the relevant source file *before* making any edit
5. Edit the source file directly on disk using the filesystem tools
6. **`fix_wlan()`** — restart wlansvc if the adapter was left in a bad state
7. **`run_attack(...)`** again — verify the fix
8. Repeat steps 2–7 until a password is returned
9. Only after a successful crack (or a deliberate decision to stop): commit, push, and open a PR

Claude must **not** open a PR mid-iteration. All code changes in a session are
batched into a single PR opened only after a password is cracked or after the
session is explicitly ended.

---

## Security note

`mcp_server.py` is gitignored — it is a local developer tool, not distributed
to end users. It must only be used against networks you own or have explicit
written authorisation to test.
