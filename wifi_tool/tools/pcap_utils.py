"""Pure-Python Wi-Fi capture and pcap → hc22000 conversion utilities.

These modules are the Windows-native replacements for two Linux-only tools:

* **hcxdumptool** — live capture of PMKID frames and WPA handshakes.
  Replaced by :func:`capture_pmkid_eapol` which uses ``scapy`` + Npcap.

* **hcxpcapngtool** — offline conversion of a pcap/pcapng capture to
  hashcat's hc22000 format.
  Replaced by :func:`convert_pcap_to_hc22000` which uses ``scapy``.

Both functions work on all platforms; they are only *invoked* on Windows
when the native Linux tools are unavailable.

**Requirements (Windows)**:
  * ``pip install scapy``
  * Npcap installed with "Support raw 802.11 traffic (monitor mode)" checked
    — https://npcap.com/#download
"""

import struct
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# EAPOL Key frame field offsets (offsets within the full raw EAPOL bytes,
# i.e. starting from the EAPOL version byte).
# EAPOL header: version(1) type(1) length(2)  → body starts at byte 4
# Body layout:  descriptor(1) key_info(2) key_len(2) replay(8) nonce(32)
#               key_IV(16) key_RSC(8) reserved(8) MIC(16) data_len(2) data(n)
# ---------------------------------------------------------------------------
_EAPOL_HEADER = 4          # bytes before Key body
_OFF_KEY_INFO  = 5         # key_info word in raw frame (4 + 1)
_OFF_NONCE     = 17        # nonce in raw frame (4 + 1+2+2+8)
_OFF_MIC       = 81        # MIC in raw frame (4 + 1+2+2+8+32+16+8+8)
_OFF_MIC_END   = 97        # first byte after MIC (4 + 77 + 16)
_OFF_DATALEN   = 97        # key data length (same as _OFF_MIC_END)
_OFF_DATA      = 99        # start of key data

# Key-info bitmasks (big-endian 16-bit word)
_KI_KEY_TYPE = 0x0008   # 1 = pairwise
_KI_INSTALL  = 0x0040
_KI_KEY_ACK  = 0x0080
_KI_KEY_MIC  = 0x0100
_KI_SECURE   = 0x0200


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _require_scapy():
    """Return the ``scapy.all`` module or raise ``ImportError``."""
    try:
        import scapy.all as sc
        return sc
    except ImportError:
        raise ImportError(
            "scapy is required for Wi-Fi capture / pcap conversion on Windows.\n"
            "Install it:  pip install scapy\n"
            "Npcap (https://npcap.com) must also be installed for live capture."
        )


def _msg_number(key_info: int) -> int:
    """Identify the 4-way handshake message number from ``key_info``."""
    ack    = bool(key_info & _KI_KEY_ACK)
    mic    = bool(key_info & _KI_KEY_MIC)
    inst   = bool(key_info & _KI_INSTALL)
    secure = bool(key_info & _KI_SECURE)
    if ack and not mic:
        return 1
    if not ack and mic and not secure:
        return 2
    if ack and mic and inst:
        return 3
    if not ack and mic and secure:
        return 4
    return 0


def _zero_mic(raw: bytes) -> bytes:
    """Return *raw* with the 16-byte MIC field zeroed (required by hc22000)."""
    return raw[:_OFF_MIC] + b"\x00" * 16 + raw[_OFF_MIC_END:]


def _parse_eapol_key(raw: bytes) -> Optional[dict]:
    """Parse a raw EAPOL Key frame; return a field dict or ``None``."""
    if len(raw) < _OFF_MIC_END + 2:
        return None
    if raw[1] != 3:                        # EAPOL type 3 = Key
        return None
    body_len = struct.unpack_from("!H", raw, 2)[0]
    if _EAPOL_HEADER + body_len > len(raw):
        return None
    key_info = struct.unpack_from("!H", raw, _OFF_KEY_INFO)[0]
    if not (key_info & _KI_KEY_TYPE):      # pairwise only
        return None

    nonce    = raw[_OFF_NONCE : _OFF_NONCE + 32]
    mic      = raw[_OFF_MIC : _OFF_MIC_END]
    dlen     = struct.unpack_from("!H", raw, _OFF_DATALEN)[0]
    key_data = raw[_OFF_DATA : _OFF_DATA + dlen]
    end      = _EAPOL_HEADER + body_len

    return {
        "msg":          _msg_number(key_info),
        "key_info":     key_info,
        "nonce":        nonce,
        "mic":          mic,
        "key_data":     key_data,
        "raw":          raw[:end],
        "raw_zeroed":   _zero_mic(raw[:end]),
    }


def _pmkids_from_key_data(key_data: bytes) -> List[bytes]:
    """Extract PMKID values from an EAPOL Key frame's RSN Information Element."""
    pmkids: List[bytes] = []
    i = 0
    while i + 2 <= len(key_data):
        eid  = key_data[i]
        elen = key_data[i + 1]
        body = key_data[i + 2 : i + 2 + elen]
        if eid == 0x30 and len(body) >= 2:   # RSN IE
            try:
                off  = 2                                # skip version
                off += 4                                # group cipher suite
                pc   = struct.unpack_from("<H", body, off)[0]; off += 2
                off += pc * 4                           # pairwise cipher suites
                ac   = struct.unpack_from("<H", body, off)[0]; off += 2
                off += ac * 4                           # AKM suites
                off += 2                                # RSN capabilities
                if off + 2 <= len(body):
                    pmkid_count = struct.unpack_from("<H", body, off)[0]; off += 2
                    for _ in range(pmkid_count):
                        if off + 16 <= len(body):
                            pmkids.append(body[off : off + 16])
                            off += 16
            except (struct.error, IndexError):
                pass
        i += 2 + elen
    return pmkids


def _mac_bytes(mac_str: str) -> bytes:
    """Convert a colon-separated MAC string to raw bytes."""
    return bytes.fromhex(mac_str.replace(":", ""))


# ---------------------------------------------------------------------------
# Public API: offline pcap → hc22000 conversion
# ---------------------------------------------------------------------------

def convert_pcap_to_hc22000(input_file: str, output_file: str) -> Tuple[bool, str]:
    """Convert a pcap/pcapng capture to hashcat hc22000 format.

    This is a pure-Python, cross-platform replacement for::

        hcxpcapngtool -o <output_file> <input_file>

    Extracts:

    * **WPA/WPA2 4-way handshake** MIC records (type ``02``)
    * **PMKID** records captured in EAPOL msg-1 key data (type ``01``)

    Requires ``scapy`` (``pip install scapy``).
    Returns ``(success, message)``.
    """
    try:
        sc = _require_scapy()
    except ImportError as exc:
        return False, str(exc)

    try:
        packets = sc.rdpcap(input_file)
    except Exception as exc:
        return False, f"Failed to read capture file: {exc}"

    # BSSID (bytes) → SSID (bytes)
    ssid_by_bssid: Dict[bytes, bytes] = {}

    # (ap_mac_bytes, sta_mac_bytes) → session dict
    sessions: Dict[Tuple[bytes, bytes], dict] = {}

    seen: Set[str] = set()
    records: List[str] = []

    for pkt in packets:
        # ---- collect SSID from 802.11 beacon frames ----
        try:
            if pkt.haslayer("Dot11Beacon"):
                bssid_str = pkt["Dot11"].addr3
                if bssid_str:
                    elt = pkt["Dot11Beacon"].payload
                    while elt and hasattr(elt, "ID"):
                        if elt.ID == 0:   # SSID element
                            ssid_by_bssid[_mac_bytes(bssid_str)] = bytes(elt.info)
                            break
                        elt = elt.payload
        except Exception:
            pass

        # ---- process EAPOL frames ----
        if not pkt.haslayer("EAPOL"):
            continue
        try:
            dot11      = pkt["Dot11"]
            eapol_raw  = bytes(pkt["EAPOL"])
        except Exception:
            continue

        parsed = _parse_eapol_key(eapol_raw)
        if parsed is None:
            continue

        try:
            src_b = _mac_bytes(dot11.addr2)
            dst_b = _mac_bytes(dot11.addr1)
        except Exception:
            continue

        # KeyAck=1 → frame from AP; KeyAck=0 → frame from STA
        if parsed["key_info"] & _KI_KEY_ACK:
            ap_mac, sta_mac = src_b, dst_b
        else:
            ap_mac, sta_mac = dst_b, src_b

        pair = (ap_mac, sta_mac)
        sess = sessions.setdefault(pair, {})
        msg  = parsed["msg"]

        if msg == 1:
            sess["anonce"] = parsed["nonce"]
            # Extract PMKID from RSN IE in message-1 key data
            for pmkid in _pmkids_from_key_data(parsed["key_data"]):
                ssid = ssid_by_bssid.get(ap_mac, b"")
                line = (
                    f"WPA*01*{pmkid.hex()}"
                    f"*{ap_mac.hex()}*{sta_mac.hex()}"
                    f"*{ssid.hex()}***00"
                )
                if line not in seen:
                    seen.add(line)
                    records.append(line)

        elif msg == 2:
            sess["mic2"]        = parsed["mic"]
            sess["eapol2_zero"] = parsed["raw_zeroed"]

        elif msg == 3:
            # Message 3 carries ANonce too; prefer msg-1 value if available
            if "anonce" not in sess:
                sess["anonce"] = parsed["nonce"]

        elif msg == 4:
            sess["mic4"]        = parsed["mic"]
            sess["eapol4_zero"] = parsed["raw_zeroed"]

        # Emit a handshake record as soon as we have ANonce + msg-2 MIC
        if "anonce" in sess and "mic2" in sess:
            ssid    = ssid_by_bssid.get(ap_mac, b"")
            line = (
                f"WPA*02*{sess['mic2'].hex()}"
                f"*{ap_mac.hex()}*{sta_mac.hex()}"
                f"*{ssid.hex()}*{sess['anonce'].hex()}"
                f"*{sess['eapol2_zero'].hex()}*02"
            )
            if line not in seen:
                seen.add(line)
                records.append(line)

    if not records:
        return False, (
            "No WPA handshakes or PMKIDs found in the capture file.\n"
            "Ensure the capture contains an EAPOL 4-way handshake or "
            "PMKID frames."
        )

    try:
        Path(output_file).write_text("\n".join(records) + "\n", encoding="ascii")
    except OSError as exc:
        return False, f"Failed to write output file: {exc}"

    return True, f"Extracted {len(records)} hash record(s) → {output_file}"


# ---------------------------------------------------------------------------
# Public API: live PMKID / handshake capture
# ---------------------------------------------------------------------------

def capture_pmkid_eapol(
    interface: str,
    output_file: str,
    bssid_filter: Optional[str] = None,
    timeout: Optional[int] = None,
    log_cb=None,
) -> int:
    """Capture PMKID frames and WPA handshakes using scapy + Npcap.

    This is the Windows-native replacement for ``hcxdumptool``::

        hcxdumptool -i <interface> -o <output_file> --enable_status=3
                    [--filterlist_ap=<bssid> --filtermode=2]

    The adapter must already be in monitor mode — use
    :func:`~wifi_tool.tools.system.enable_monitor_mode` (WlanHelper.exe) first.

    Captured packets are saved to *output_file* in pcap format so they can
    be converted with :func:`convert_pcap_to_hc22000` afterwards.

    Requires ``scapy`` (``pip install scapy``) and Npcap
    (https://npcap.com) with raw 802.11 support enabled.

    *log_cb* is an optional callable ``(message: str, level: str) -> None``
    used to route output to the GUI log.  Falls back to ``print`` if omitted.

    Press Ctrl+C to stop.  Returns 0 on success, 1 on error.
    """
    def _log(msg: str, level: str = "info") -> None:
        if log_cb:
            log_cb(msg, level)
        else:
            print(msg)

    try:
        sc = _require_scapy()
    except ImportError as exc:
        _log(str(exc), "error")
        return 1

    bssid_filter_b: Optional[bytes] = None
    if bssid_filter:
        try:
            bssid_filter_b = bytes.fromhex(bssid_filter.replace(":", "").lower())
        except ValueError:
            _log(f"Invalid BSSID filter: {bssid_filter!r}", "error")
            return 1

    # Resolve NetworkInterface object — sc.sniff() on Windows needs this,
    # not the raw \Device\NPF_{GUID} string.
    iface_obj = interface
    iface_resolved = False
    try:
        for _obj in sc.conf.ifaces.values():
            _pcap = (
                getattr(_obj, "pcap_name", "")
                or getattr(_obj, "network_name", "")
            )
            if _pcap and _pcap.lower() == interface.lower():
                iface_obj = _obj
                iface_resolved = True
                break
    except Exception:
        pass

    iface_name = getattr(iface_obj, "name", interface)
    try:
        iface_count = len(list(sc.conf.ifaces.values()))
    except Exception:
        iface_count = "?"
    _log(
        f"Capture interface: {iface_name!r} "
        f"(matched={iface_resolved}, {iface_count} adapters visible to Scapy)",
        "info",
    )

    captured: list = []
    total_seen = 0
    target_seen = 0
    beacon_count = 0        # target beacons seen
    data_enc = 0            # target type=2 frames with Protected bit set (encrypted)
    data_open = 0           # target type=2 frames without Protected (may contain EAPOL)
    eapol_count = 0         # EAPOL frames confirmed
    beacons_saved: set = set()   # BSSIDs for which we already saved a beacon
    _t0 = time.monotonic()
    _last_status = _t0

    # LLC/SNAP header preceding EAPOL in 802.11 data frames
    _EAPOL_LLC_SNAP = b'\xaa\xaa\x03\x00\x00\x00\x88\x8e'

    def _handler(pkt) -> None:
        nonlocal total_seen, target_seen, beacon_count, data_enc, data_open, eapol_count, _last_status
        total_seen += 1
        try:
            dot11 = pkt.getlayer("Dot11")
            if dot11 is None:
                return

            # BSSID filter — AP MAC can appear in addr1, addr2, or addr3
            if bssid_filter_b:
                matched = False
                for _addr in (dot11.addr1, dot11.addr2, dot11.addr3):
                    if _addr:
                        try:
                            if _mac_bytes(_addr) == bssid_filter_b:
                                matched = True
                                break
                        except ValueError:
                            pass
                if not matched:
                    return

            target_seen += 1
            now = time.monotonic()
            elapsed = int(now - _t0)

            is_eapol = pkt.haslayer("EAPOL")
            is_beacon = pkt.haslayer("Dot11Beacon")

            if dot11.type == 2:
                # Check the Protected Frame bit (FCfield bit 6 = 0x40).
                # Set   → WPA2-encrypted data; EAPOL never appears here.
                # Clear → unencrypted data; EAPOL 4-way handshake lives here.
                try:
                    protected = bool(dot11.FCfield & 0x40)
                except Exception:
                    protected = False

                if protected:
                    data_enc += 1
                else:
                    data_open += 1
                    # Fallback EAPOL detection via raw LLC/SNAP bytes.
                    # Scapy sometimes stores the Dot11 payload as Raw without
                    # dissecting the LLC/SNAP layer.
                    if not is_eapol and _EAPOL_LLC_SNAP in bytes(pkt):
                        is_eapol = True
                    # Save ALL unprotected data frames — they are small (null
                    # data, EAPOL) and aircrack-ng may find a handshake that
                    # our Python converter misses.
                    if not is_eapol:
                        captured.append(pkt)

            if is_eapol:
                eapol_count += 1
                captured.append(pkt)
                _log(f"[{elapsed}s] EAPOL frame #{eapol_count} captured!", "success")
            elif is_beacon:
                beacon_count += 1
                # Save only the first beacon per BSSID — enough for SSID lookup.
                bssid_key = getattr(dot11, "addr3", None)
                if bssid_key not in beacons_saved:
                    beacons_saved.add(bssid_key)
                    captured.append(pkt)

            # Periodic status line — one per 10 s keeps the log readable
            if now - _last_status >= 10:
                _log(
                    f"[{elapsed}s] ● {beacon_count} beacons "
                    f"| {data_open} open / {data_enc} enc data "
                    f"| {eapol_count} EAPOL  (total: {total_seen})",
                    "info",
                )
                _last_status = now
        except Exception:
            pass

    _log(f"Sniffing on {iface_name!r} for up to {timeout}s…", "info")
    try:
        # monitor=True tells Npcap to open the interface with RFMON (raw 802.11)
        # mode requested at the pcap layer.  Without this flag Npcap may open
        # the device in normal mode even though WlanHelper already set it to
        # monitor mode, resulting in zero 802.11 frames received.
        sc.sniff(
            iface=iface_obj,
            prn=_handler,
            store=False,
            timeout=timeout,
            monitor=True,
        )
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        _log(f"Capture error: {exc}", "error")
        return 1

    _log(
        f"Capture done — {beacon_count} beacons | {data_count} data | "
        f"{eapol_count} EAPOL | {total_seen} total frames seen",
        "info",
    )

    if not captured:
        if total_seen == 0:
            _log(
                "No 802.11 frames received. "
                "Verify the adapter is in monitor mode and Npcap is installed "
                "with 'Support raw 802.11 traffic' enabled.",
                "warn",
            )
        elif target_seen == 0:
            _log(
                f"Saw {total_seen} frame(s) but none matched the target BSSID. "
                "Adapter may be on the wrong channel.",
                "warn",
            )
        else:
            _log(
                "No EAPOL handshake captured — no client reconnected during the window.",
                "warn",
            )
        return 1

    try:
        sc.wrpcap(output_file, captured)
        _log(f"Saved capture to {output_file}", "info")
    except Exception as exc:
        _log(f"Failed to save capture: {exc}", "error")
        return 1

    return 0
