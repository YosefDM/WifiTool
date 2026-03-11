"""Wi-Fi protocol data: WEP, WPA, WPA2, WPA3."""

from dataclasses import dataclass, field
from typing import List


@dataclass
class Protocol:
    name: str
    full_name: str
    year: str
    standard: str
    encryption: str
    integrity: str
    key_management: str
    key_length: str
    security_level: str
    color: str
    overview: str
    how_it_works: List[str]
    vulnerabilities: List[str]
    improvements: List[str]


WEP = Protocol(
    name="WEP",
    full_name="Wired Equivalent Privacy",
    year="1997",
    standard="IEEE 802.11 (original)",
    encryption="RC4 stream cipher",
    integrity="CRC-32 (ICV)",
    key_management="Static pre-shared key",
    key_length="40-bit or 104-bit + 24-bit IV",
    security_level="Broken",
    color="red",
    overview=(
        "WEP was introduced as part of the original IEEE 802.11 standard in 1997. "
        "Its goal was to provide wireless networks with security equivalent to a wired "
        "network. It was widely deployed throughout the late 1990s and early 2000s before "
        "its critical flaws became publicly understood."
    ),
    how_it_works=[
        "A shared secret key (40 or 104 bits) is configured on the AP and all clients",
        "For each packet, a random 24-bit IV is generated and prepended to the key",
        "RC4 uses this combined key to generate a keystream",
        "The plaintext XORed with the keystream produces the ciphertext",
        "A CRC-32 integrity check (ICV) is appended to detect tampering",
    ],
    vulnerabilities=[
        "IV Reuse — 24-bit IV space allows only ~16.7M unique IVs; repeats in under an hour on busy networks",
        "FMS Attack (2001) — 'Weak IVs' leak key bytes via RC4 key scheduling flaw",
        "CRC-32 is not cryptographic — bit-flipping attacks possible without detection",
        "No per-session keys — all clients share one static key indefinitely",
        "No forward secrecy — one key compromise exposes all past and future traffic",
        "PTW Attack — improved statistical attack requiring far fewer IVs (~40,000)",
    ],
    improvements=[],
)

WPA = Protocol(
    name="WPA",
    full_name="Wi-Fi Protected Access",
    year="2003",
    standard="IEEE 802.11i (draft)",
    encryption="TKIP (RC4 with per-packet key mixing)",
    integrity="Michael MIC",
    key_management="4-Way Handshake (PMK via PBKDF2-SHA1 x4096)",
    key_length="128-bit temporal keys + 48-bit IV",
    security_level="Deprecated",
    color="yellow",
    overview=(
        "WPA was released in 2003 as an emergency stopgap after WEP's weaknesses became "
        "publicly known. It was designed to run on existing WEP hardware with a firmware "
        "update, which constrained its design choices. WPA introduced TKIP and the "
        "4-way handshake, dramatically improving security over WEP while remaining "
        "backward compatible with existing hardware."
    ),
    how_it_works=[
        "TKIP: per-packet key mixing — each packet uses a freshly derived key, not just IV+static key",
        "Extended 48-bit sequence counter (TSC) eliminates IV reuse",
        "Michael MIC provides cryptographic integrity instead of CRC-32",
        "Automatic temporal key rekeying refreshes keys periodically",
        "4-Way Handshake: AP sends ANonce → Client derives PTK → Client sends SNonce+MIC → AP sends GTK",
        "PMK derived from pre-shared password via PBKDF2-SHA1 with 4,096 iterations",
    ],
    vulnerabilities=[
        "Dictionary/brute-force attack on the 4-way handshake via offline PMK derivation",
        "Beck-Tews Attack (2008) — partial decryption of short TKIP-encrypted packets",
        "Ohigashi-Morii Attack (2009) — TKIP MITM extension of Beck-Tews",
        "TKIP still uses RC4 internally — inherits stream cipher weaknesses",
        "Weak passwords recoverable with GPU-accelerated offline cracking (hashcat)",
        "Chop-Chop attack — can decrypt packets one byte at a time under certain conditions",
    ],
    improvements=[
        "Per-packet key mixing eliminates IV reuse vulnerability",
        "Michael MIC replaces insecure CRC-32",
        "48-bit sequence counter replaces 24-bit IV",
        "Temporal keys replace single static key",
    ],
)

WPA2 = Protocol(
    name="WPA2",
    full_name="Wi-Fi Protected Access 2",
    year="2004 (mandatory 2006)",
    standard="IEEE 802.11i (full)",
    encryption="AES-CCMP (AES-CTR + CBC-MAC)",
    integrity="CBC-MAC (part of CCMP)",
    key_management="4-Way Handshake + RSNA (PMK via PBKDF2-SHA1 x4096)",
    key_length="128-bit AES keys",
    security_level="Vulnerable (patched)",
    color="yellow",
    overview=(
        "WPA2, ratified in 2004 and mandated for Wi-Fi certified devices from 2006, "
        "replaced TKIP/RC4 with the much stronger AES-CCMP. CCMP provides both "
        "confidentiality (AES-CTR) and integrity (CBC-MAC) in a single construction. "
        "This addressed all known cryptographic weaknesses of WEP and WPA. It remained "
        "the dominant Wi-Fi security standard for over a decade before WPA3."
    ),
    how_it_works=[
        "AES-CCMP replaces TKIP/RC4 — uses 128-bit AES in Counter Mode (CTR) for encryption",
        "CBC-MAC provides authenticated encryption in a single pass",
        "4-Way Handshake retained from WPA with identical structure",
        "RSN (Robust Security Network) negotiation during association",
        "CCMP nonce includes packet number to prevent replay attacks",
        "GTK (Group Temporal Key) used for broadcast/multicast traffic",
    ],
    vulnerabilities=[
        "KRACK (2017) — Key Reinstallation Attack exploits 4-way handshake state machine",
        "PMKID Attack (2018) — Clientless offline cracking via HMAC-SHA1 PMKID",
        "Dictionary/brute-force on 4-way handshake — same as WPA",
        "DEAUTH attacks — unauthenticated management frames enable forced reconnections",
        "Evil Twin / Rogue AP — no mutual AP authentication in basic mode",
        "Hole196 — authenticated insider can forge GTK-encrypted broadcast frames",
    ],
    improvements=[
        "AES-CCMP replaces insecure RC4/TKIP",
        "Authenticated encryption (confidentiality + integrity combined)",
        "Mandatory support for CCMP — TKIP only as fallback",
        "RSNA provides stronger security negotiation framework",
    ],
)

WPA3 = Protocol(
    name="WPA3",
    full_name="Wi-Fi Protected Access 3",
    year="2018",
    standard="Wi-Fi Alliance WPA3 Specification",
    encryption="AES-CCMP-128 (Personal) / AES-GCMP-256 (Enterprise)",
    integrity="BIP-CMAC-128 (PMF mandatory)",
    key_management="SAE (Simultaneous Authentication of Equals / Dragonfly)",
    key_length="128-bit (Personal) / 192-bit (Enterprise)",
    security_level="Current standard (known implementation flaws)",
    color="green",
    overview=(
        "WPA3, introduced in 2018 by the Wi-Fi Alliance, replaced PSK (Pre-Shared Key) "
        "with SAE (Simultaneous Authentication of Equals), also known as the Dragonfly "
        "handshake. SAE provides forward secrecy and resistance to offline dictionary "
        "attacks. Protected Management Frames (PMF) are mandatory, preventing "
        "deauthentication attacks. However, shortly after release, the Dragonblood "
        "paper revealed implementation-level vulnerabilities."
    ),
    how_it_works=[
        "SAE (Dragonfly) replaces PSK — interactive handshake resistant to offline attacks",
        "Each SAE exchange produces fresh session keys — forward secrecy guaranteed",
        "Password-based key derivation uses Diffie-Hellman variant — no offline guessing",
        "PMF (Protected Management Frames) mandatory — prevents DEAUTH attacks",
        "Enhanced Open (OWE) for open networks — opportunistic encryption without authentication",
        "192-bit security suite available for enterprise environments",
    ],
    vulnerabilities=[
        "Dragonblood Side-Channel (2019) — timing/cache attacks on SAE encoding leak password info",
        "Downgrade Attack — WPA2/WPA3 transition mode allows forced WPA2 connection",
        "SAE Denial of Service — commit phase is CPU-intensive; flood attacks exhaust AP resources",
        "Implementation bugs in specific devices — many vendor-specific SAE issues found",
        "EAP-pwd vulnerabilities (related Dragonblood) affect enterprise EAP implementations",
    ],
    improvements=[
        "SAE eliminates offline dictionary attacks on the handshake",
        "Forward secrecy — past sessions safe even if password later compromised",
        "PMF mandatory — deauthentication attacks no longer effective",
        "Enhanced Open (OWE) encrypts open network traffic",
        "192-bit enterprise security mode added",
    ],
)

ALL_PROTOCOLS = [WEP, WPA, WPA2, WPA3]

PROTOCOL_COMPARISON = {
    "headers": ["Feature", "WEP", "WPA", "WPA2", "WPA3"],
    "rows": [
        ["Year", "1997", "2003", "2004", "2018"],
        ["Cipher", "RC4", "RC4 (TKIP)", "AES-CCMP", "AES-CCMP/GCMP"],
        ["Integrity", "CRC-32", "Michael MIC", "CBC-MAC", "BIP-CMAC"],
        ["Key Exchange", "Static PSK", "4-Way HS", "4-Way HS", "SAE (Dragonfly)"],
        ["IV Length", "24-bit", "48-bit (TSC)", "CCMP nonce", "CCMP nonce"],
        ["Forward Secrecy", "No", "No", "No", "Yes (SAE)"],
        ["DEAUTH Protection", "No", "No", "Optional", "Yes (mandatory)"],
        ["Offline Dict. Attack", "Yes", "Yes", "Yes", "No (SAE)"],
        ["Status", "[red]Broken[/red]", "[yellow]Deprecated[/yellow]", "[yellow]Vulnerable[/yellow]", "[green]Current[/green]"],
    ],
}
