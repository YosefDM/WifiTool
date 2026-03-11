"""Attack vector data for Wi-Fi security protocols."""

from dataclasses import dataclass, field
from typing import List


@dataclass
class Attack:
    name: str
    protocol: str
    year: str
    severity: str
    severity_color: str
    cve: str
    researchers: str
    summary: str
    technical_detail: str
    steps: List[str]
    impact: str
    mitigation: str
    references: List[str]


FMS_ATTACK = Attack(
    name="FMS Attack (Fluhrer-Mantin-Shamir)",
    protocol="WEP",
    year="2001",
    severity="Critical",
    severity_color="red",
    cve="N/A (pre-CVE era)",
    researchers="Scott Fluhrer, Itsik Mantin, Adi Shamir",
    summary=(
        "The FMS attack exploits the RC4 key scheduling algorithm (KSA) weakness. "
        "Certain IV values (called 'weak IVs') cause the KSA to produce a keystream "
        "that leaks information about early bytes of the secret key. By collecting "
        "enough packets using weak IVs, the entire WEP key can be statistically derived."
    ),
    technical_detail=(
        "The RC4 KSA initializes a permutation S using the key. For certain IV patterns "
        "(where the first byte is (A+3), second is 255, third is any value), the "
        "second byte of the keystream output correlates with key[A+3]. An attacker "
        "collects packets using these weak IVs, notes the second keystream byte "
        "(= first_encrypted_byte XOR known_SNAP_header_byte), and builds a frequency "
        "table. The most frequent value in each table reveals key bytes."
    ),
    steps=[
        "Enable monitor mode on wireless adapter",
        "Begin passive capture on target channel with airodump-ng",
        "Optionally inject ARP replay packets to accelerate IV collection (aireplay-ng -3)",
        "Collect minimum 40,000–80,000 unique IVs (more = higher success rate)",
        "Identify weak IV packets in the capture",
        "Run PTW or FMS statistical analysis: aircrack-ng capture.cap",
        "Key recovered — typically 40-bit key in seconds, 104-bit in minutes",
    ],
    impact=(
        "Complete WEP key recovery. All traffic on the network can be decrypted. "
        "An attacker can join the network and intercept all communications. "
        "On a busy network, the attack completes in under 10 minutes."
    ),
    mitigation="Migrate to WPA2 or WPA3. WEP cannot be patched.",
    references=[
        "Fluhrer, Mantin, Shamir — 'Weaknesses in the Key Scheduling Algorithm of RC4' (SAC 2001)",
        "Tews, Weinmann, Pyshkin — 'Breaking 104 bit WEP in less than 60 seconds' (2007)",
        "Aircrack-ng documentation: https://www.aircrack-ng.org",
    ],
)

PTW_ATTACK = Attack(
    name="PTW Attack (Pyshkin-Tews-Weinmann)",
    protocol="WEP",
    year="2007",
    severity="Critical",
    severity_color="red",
    cve="N/A",
    researchers="Andrei Pyshkin, Erik Tews, Ralf-Philipp Weinmann",
    summary=(
        "PTW is an improvement over the FMS attack that uses all captured packets "
        "(not just those with weak IVs) and requires far fewer packets. It can crack "
        "a 104-bit WEP key with only ~40,000 packets at 50% success probability, "
        "or ~85,000 for 95% success. PTW is the default algorithm in aircrack-ng."
    ),
    technical_detail=(
        "PTW uses a correlation attack rather than the FMS direct key byte correlation. "
        "It derives correlations between all IV bytes and all key bytes simultaneously, "
        "dramatically reducing the required sample size. The attack uses the Klein "
        "extension and achieves O(n) complexity improvements over FMS."
    ),
    steps=[
        "Enable monitor mode: airmon-ng start wlan0",
        "Capture traffic: airodump-ng -c [channel] -w capture wlan0mon",
        "Accelerate with ARP replay injection: aireplay-ng -3 -b [AP_MAC] wlan0mon",
        "Collect ~40,000+ IVs",
        "Run PTW attack (default in aircrack-ng): aircrack-ng -z capture-01.cap",
        "Key recovered",
    ],
    impact="Same as FMS — complete WEP key recovery. Faster and more reliable.",
    mitigation="Migrate to WPA2 or WPA3.",
    references=[
        "Tews, Weinmann, Pyshkin — 'Breaking 104 bit WEP in less than 60 seconds' (2007)",
        "Aircrack-ng source: https://github.com/aircrack-ng/aircrack-ng",
    ],
)

WPA_HANDSHAKE_ATTACK = Attack(
    name="WPA/WPA2 4-Way Handshake Dictionary Attack",
    protocol="WPA / WPA2",
    year="2003+",
    severity="High",
    severity_color="orange3",
    cve="N/A",
    researchers="Robert Moskowitz et al. (original analysis)",
    summary=(
        "The PMK (Pairwise Master Key) is derived from the pre-shared password via "
        "PBKDF2-SHA1 with 4,096 iterations. An attacker who captures the 4-way "
        "handshake can attempt offline dictionary or brute-force attacks: for each "
        "candidate password, compute the PMK, derive the PTK, and check whether it "
        "matches the captured MIC. Weak or common passwords are vulnerable."
    ),
    technical_detail=(
        "The PTK is derived as: PTK = PRF-512(PMK, 'Pairwise key expansion', "
        "min(AP_MAC,STA_MAC) || max(AP_MAC,STA_MAC) || min(ANonce,SNonce) || max(ANonce,SNonce)). "
        "The MIC in handshake message 2 or 3 is computed over the EAPOL frame using "
        "the first 16 bytes of the PTK. An attacker computes MIC for each candidate "
        "password and checks against the captured MIC. GPU acceleration (hashcat) "
        "enables hundreds of thousands of password trials per second."
    ),
    steps=[
        "Enable monitor mode: airmon-ng start wlan0",
        "Capture traffic on target channel: airodump-ng -c [ch] -w capture --bssid [AP_MAC] wlan0mon",
        "Force client reconnection: aireplay-ng -0 1 -a [AP_MAC] -c [CLIENT_MAC] wlan0mon",
        "Wait for 4-way handshake in capture (shown in airodump-ng top-right)",
        "Convert capture to hashcat format: hcxpcapngtool -o hash.hc22000 capture.pcapng",
        "Run dictionary attack: hashcat -m 22000 hash.hc22000 wordlist.txt",
        "Apply rules for mangled passwords: hashcat -m 22000 hash.hc22000 wordlist.txt -r rules/best64.rule",
    ],
    impact=(
        "Password recovery if the pre-shared key is weak, dictionary-based, or "
        "follows predictable patterns. Common default router passwords are trivially "
        "cracked. A strong random passphrase (>14 chars, mixed case/symbols) is "
        "computationally infeasible to crack."
    ),
    mitigation=(
        "Use a strong random passphrase (16+ characters, no dictionary words). "
        "Upgrade to WPA3 (SAE prevents offline attacks entirely)."
    ),
    references=[
        "IEEE 802.11i-2004 standard",
        "Hashcat WPA2 module: https://hashcat.net/wiki/doku.php?id=hashcat",
        "Vanhoef — Wi-Fi security analysis resources: https://papers.mathyvanhoef.com",
    ],
)

BECK_TEWS_ATTACK = Attack(
    name="Beck-Tews Attack (TKIP Partial Decryption)",
    protocol="WPA (TKIP)",
    year="2008",
    severity="Medium",
    severity_color="yellow",
    cve="CVE-2008-3686",
    researchers="Martin Beck, Erik Tews",
    summary=(
        "The Beck-Tews attack demonstrated the first practical decryption of "
        "WPA-TKIP encrypted packets. It exploits the Michael MIC algorithm weakness "
        "to partially decrypt short packets (specifically ARP packets) and forge "
        "new packets. It does not recover the WPA password."
    ),
    technical_detail=(
        "TKIP's Michael MIC uses a weak algorithm that allows recovery of the MIC key "
        "from a small number of frames. Once the MIC key is known, the attacker can "
        "inject arbitrary 7-byte payloads. The attack requires a Quality of Service "
        "(QoS) enabled AP and takes approximately 12-15 minutes."
    ),
    steps=[
        "Identify a WPA-TKIP protected QoS-enabled access point",
        "Capture encrypted ARP packet from the network",
        "Use chopchop-style decryption to recover the plaintext byte by byte",
        "Recover the Michael MIC key for the network-to-client direction",
        "Inject forged packets (limited to 7 bytes per minute)",
    ],
    impact=(
        "Limited practical impact — cannot decrypt arbitrary traffic or recover "
        "the network password. Primarily demonstrates TKIP is not secure. "
        "Extended by Ohigashi-Morii to a full MITM scenario in 2009."
    ),
    mitigation="Disable TKIP, use WPA2 with AES-CCMP only.",
    references=[
        "Beck, Tews — 'Practical attacks against WEP and WPA' (2008)",
        "CVE-2008-3686",
    ],
)

KRACK_ATTACK = Attack(
    name="KRACK — Key Reinstallation Attack",
    protocol="WPA2",
    year="2017",
    severity="Critical",
    severity_color="red",
    cve="CVE-2017-13077, CVE-2017-13078, CVE-2017-13079, CVE-2017-13080, CVE-2017-13081",
    researchers="Mathy Vanhoef, Frank Piessens (KU Leuven)",
    summary=(
        "KRACK exploits a flaw not in AES-CCMP itself, but in the WPA2 handshake "
        "state machine. When the ACK for handshake message 4 is blocked by an "
        "attacker-in-the-middle, the AP retransmits message 3. Upon receiving a "
        "retransmitted message 3, the spec requires the client to reinstall the "
        "already-in-use key — and reset the nonce counter to zero. Nonce reuse "
        "under AES-CTR mode enables XOR-based plaintext recovery."
    ),
    technical_detail=(
        "AES-CCMP in CTR mode is a stream cipher construction. Security depends "
        "entirely on each (key, nonce) pair being used exactly once. When the nonce "
        "resets to zero, subsequent packets reuse nonce values already used with "
        "the same key. An attacker who captured earlier packets can XOR them: "
        "C1 XOR C2 = P1 XOR P2, enabling traffic decryption. Linux/Android "
        "implementations were especially vulnerable — some installed an all-zero key."
    ),
    steps=[
        "Position attacker as man-in-the-middle between client and AP (rogue AP clone on different channel)",
        "Client initiates connection — attacker forwards messages 1 and 2 normally to AP",
        "AP sends message 3 (key installation) — attacker forwards to client",
        "Client installs key, sends message 4 — attacker BLOCKS message 4 from reaching AP",
        "AP retransmits message 3 (ACK timeout) — attacker forwards it to client",
        "Client reinstalls key and RESETS nonce counter to 0",
        "Attacker now has two ciphertexts encrypted under identical (key, nonce) pairs",
        "XOR the ciphertexts: C1 XOR C2 = P1 XOR P2 — traffic decrypted",
        "With known P1 (e.g., HTTP GET), recover P2 entirely",
    ],
    impact=(
        "Affected Android, Linux, iOS, macOS, Windows, and all embedded/IoT devices. "
        "Android 6.0 and Linux wpa_supplicant 2.4/2.5 installed an all-zero key — "
        "all traffic fully decryptable and injectable. Patches released within weeks "
        "for major platforms, but millions of IoT devices remain unpatched."
    ),
    mitigation=(
        "Apply OS/firmware patches (released Oct–Nov 2017). "
        "Use HTTPS/TLS as additional encryption layer. "
        "Upgrade to WPA3 (SAE eliminates nonce reinstallation by design)."
    ),
    references=[
        "Vanhoef, Piessens — 'Key Reinstallation Attacks: Forcing Nonce Reuse in WPA2' (CCS 2017)",
        "https://krackattacks.com",
        "CVE-2017-13077 through CVE-2017-13088",
        "PoC: https://github.com/vanhoef/krackattacks-scripts",
    ],
)

PMKID_ATTACK = Attack(
    name="PMKID Attack (Clientless WPA2 Capture)",
    protocol="WPA2",
    year="2018",
    severity="High",
    severity_color="orange3",
    cve="N/A",
    researchers="Jens Steube (atom / hashcat author)",
    summary=(
        "The PMKID attack eliminated the need to capture a live 4-way handshake "
        "with a client present. The PMKID is broadcast by APs in the first EAPOL "
        "frame and can be requested at any time. It is derived from the PMK "
        "(and hence the password) via HMAC-SHA1. Offline brute-force on the "
        "PMKID directly yields the network password."
    ),
    technical_detail=(
        "PMKID = HMAC-SHA1(PMK, 'PMK Name' || AP_MAC || Client_MAC)[0:16]. "
        "Because PMK = PBKDF2-HMAC-SHA1(password, SSID, 4096, 32), the PMKID "
        "is a deterministic function of (password, SSID, AP_MAC, Client_MAC). "
        "An attacker can request EAPOL RSN IE from any AP using hcxdumptool, "
        "extract the PMKID, and run offline brute-force with hashcat (-m 22801)."
    ),
    steps=[
        "Start monitor mode: airmon-ng start wlan0",
        "Capture PMKID frames (no client needed): hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=3",
        "Wait for PMKID in capture (usually a few seconds per AP)",
        "Convert to hashcat format: hcxpcapngtool -o pmkid.hc22801 capture.pcapng",
        "Run offline dictionary attack: hashcat -m 22801 pmkid.hc22801 wordlist.txt",
        "Apply rules: hashcat -m 22801 pmkid.hc22801 wordlist.txt -r rules/best64.rule",
    ],
    impact=(
        "Any WPA2 network is vulnerable to offline password guessing without "
        "requiring any clients to be connected. Dramatically lowers the bar for "
        "WPA2 cracking — previously required waiting for (or forcing) a client "
        "connection. Same password strength requirements apply."
    ),
    mitigation=(
        "Use a strong, random passphrase (16+ characters). "
        "Upgrade to WPA3 (SAE prevents offline attacks)."
    ),
    references=[
        "Steube — 'New attack on WPA/WPA2 using PMKID' (hashcat forum, 2018)",
        "https://hashcat.net/forum/thread-7717.html",
        "hcxdumptool: https://github.com/ZerBea/hcxdumptool",
    ],
)

DRAGONBLOOD_ATTACK = Attack(
    name="Dragonblood — WPA3 SAE Vulnerabilities",
    protocol="WPA3",
    year="2019",
    severity="High",
    severity_color="orange3",
    cve="CVE-2019-9494, CVE-2019-9496, CVE-2019-13377, CVE-2019-13456",
    researchers="Mathy Vanhoef, Eyal Ronen",
    summary=(
        "Dragonblood revealed multiple vulnerabilities in WPA3-Personal's SAE "
        "(Dragonfly) handshake shortly after WPA3's release. Attacks include "
        "timing-based and cache-based side-channels that leak password information, "
        "a downgrade attack forcing WPA2 connections, and a denial-of-service "
        "via SAE commit frame flooding."
    ),
    technical_detail=(
        "The SAE Hunting-and-Pecking algorithm (password encoding step) uses "
        "timing and cache access patterns that vary based on the password. "
        "An attacker observing timing of many SAE handshakes can build a model "
        "correlating timing to candidate passwords. Wi-Fi Alliance responded "
        "by specifying the hash-to-curve method (constant-time encoding). "
        "The downgrade attack exploits APs in WPA2/WPA3 transition mode — "
        "a fake WPA2-only AP causes clients to connect via WPA2."
    ),
    steps=[
        "[Side-Channel] Position near target AP with monitoring equipment",
        "[Side-Channel] Record timing of SAE commit frame responses across many handshakes",
        "[Side-Channel] Build timing oracle to distinguish correct vs. incorrect password prefixes",
        "[Side-Channel] Conduct accelerated dictionary search using timing correlations",
        "[Downgrade] Set up rogue AP advertising only WPA2 with same SSID",
        "[Downgrade] Client connects via WPA2 — capture and crack 4-way handshake normally",
        "[DoS] Flood AP with SAE commit frames to exhaust CPU resources",
    ],
    impact=(
        "Side-channel attacks require significant technical capability and many "
        "handshake observations but can reduce offline cracking search space. "
        "Downgrade attacks are practical against WPA2/WPA3 transition mode. "
        "DoS is low-cost and can prevent legitimate clients from connecting. "
        "Wi-Fi Alliance issued patches requiring constant-time SAE implementation."
    ),
    mitigation=(
        "Apply firmware updates implementing constant-time SAE encoding (hash-to-curve). "
        "Configure APs in WPA3-only mode (disable WPA2 transition mode). "
        "Enable SAE anti-clogging tokens to mitigate commit flooding DoS."
    ),
    references=[
        "Vanhoef, Ronen — 'Dragonblood: Analyzing the Dragonfly Handshake of WPA3 and EAP-pwd' (IEEE S&P 2020)",
        "https://dragonbloodattack.com",
        "CVE-2019-9494, CVE-2019-9496",
        "PoC: https://github.com/vanhoef/dragonblood",
    ],
)

ALL_ATTACKS = [
    FMS_ATTACK,
    PTW_ATTACK,
    WPA_HANDSHAKE_ATTACK,
    BECK_TEWS_ATTACK,
    KRACK_ATTACK,
    PMKID_ATTACK,
    DRAGONBLOOD_ATTACK,
]

ATTACK_BY_PROTOCOL = {
    "WEP": [FMS_ATTACK, PTW_ATTACK],
    "WPA": [WPA_HANDSHAKE_ATTACK, BECK_TEWS_ATTACK],
    "WPA2": [WPA_HANDSHAKE_ATTACK, KRACK_ATTACK, PMKID_ATTACK],
    "WPA3": [DRAGONBLOOD_ATTACK],
}
