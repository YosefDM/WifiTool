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

    _log(
        f"Scapy interface resolved: {getattr(iface_obj, 'name', interface)!r}"
        f" (matched={iface_resolved})",
        "info",
    )

    # Dump all Scapy-visible interfaces for diagnostics
    try:
        iface_names = [
            f"{getattr(o, 'name', '?')} / {getattr(o, 'pcap_name', '') or getattr(o, 'network_name', '?')}"
            for o in sc.conf.ifaces.values()
        ]
        _log(f"All Scapy interfaces: {'; '.join(iface_names)}", "info")
    except Exception:
        pass

    captured: list = []
    total_seen = 0          # every packet sniff() delivers
    target_seen = 0         # packets from the target BSSID (any type)
    frame_types: Dict[str, int] = {}

    def _handler(pkt) -> None:
        nonlocal total_seen, target_seen
        total_seen += 1
        try:
            dot11 = pkt.getlayer("Dot11")
            if dot11 is None:
                return

            # Track frame type breakdown for diagnostics
            try:
                ftype = f"type={dot11.type}/subtype={dot11.subtype}"
                frame_types[ftype] = frame_types.get(ftype, 0) + 1
            except Exception:
                pass

            # Check if this packet is from/to the target BSSID
            # Check addr1, addr2, addr3 — AP MAC appears in different fields
            # depending on frame direction (data vs management vs control)
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

            if pkt.haslayer("EAPOL") or pkt.haslayer("Dot11Beacon"):
                captured.append(pkt)
                _log(
                    f"Captured {len(captured)} frame(s) from target "
                    f"({'EAPOL' if pkt.haslayer('EAPOL') else 'Beacon'})"
                    f" | total seen: {total_seen} | from target: {target_seen}",
                    "info",
                )
        except Exception:
            pass

    _log(f"Sniffing on {interface!r} for up to {timeout}s — waiting for 802.11 frames…", "info")
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
        f"Capture done — total pkts seen: {total_seen} | "
        f"from target BSSID: {target_seen} | saved (EAPOL+Beacon): {len(captured)}",
        "info",
    )
    if frame_types:
        summary = ", ".join(f"{k}:{v}" for k, v in sorted(frame_types.items()))
        _log(f"Frame type breakdown: {summary}", "info")

    if not captured:
        if total_seen == 0:
            _log(
                "No 802.11 frames received at all. "
                "Verify the adapter is in monitor mode and Npcap is installed "
                "with 'Support raw 802.11 traffic' enabled.",
                "warn",
            )
        elif target_seen == 0:
            _log(
                f"Captured {total_seen} frame(s) but none from the target BSSID. "
                "The adapter may be on the wrong channel — check that the AP channel "
                "from the scan matches the channel the adapter is locked to.",
                "warn",
            )
        else:
            _log(
                f"Captured {target_seen} frame(s) from target but no EAPOL handshake. "
                "No client reconnected during the capture window.",
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
