#!/usr/bin/env python3
"""
ppp_5we_demo.py - PPPoE vs 5WE (RFC 2516 vs RFC 8822) frame demo

Companion code for the NSS paper "Still Connected: PPP Enhancements and WAN
Connectivity". It backs up three claims from the paper with something you can run:

  1. 5WE reuses the PPPoE data frame (same Ethertype 0x8864, same field offsets),
     only VER (1 -> 2) and the meaning of CODE / SESSION_ID change   (Table I)
  2. Because of that, a legacy access node that only looks at Ethertype and
     SESSION_ID forwards 5WE frames untouched                        (Sec II.A.1)
  3. PPPoE costs 8 bytes of Ethernet payload, which is where the 1492 MTU comes
     from, and the RFC 4638 "baby jumbo" approach in pppd 2.5.3 removes it  (Sec II.A.5)

No dependencies (pure struct). If scapy is installed, --scapy cross-checks the
hand-built frames against scapy's PPPoE dissector.

Usage:
    python3 ppp_5we_demo.py
    python3 ppp_5we_demo.py --qfi 9 --rqi 0 --pdu-session 42 --pcap out.pcap --scapy
"""
import argparse
import struct

ETH_PPPOE_DISC = 0x8863
ETH_PPPOE_SESS = 0x8864
PPP_IPV4, PPP_IPV6, PPP_ETH = 0x0021, 0x0057, 0x0031  # PPP Protocol IDs (Table I)
DISC_CODES = {0x09: "PADI", 0x07: "PADO", 0x19: "PADR", 0x65: "PADS", 0xA7: "PADT"}
PPP_NAMES = {PPP_IPV4: "IPv4", PPP_IPV6: "IPv6", PPP_ETH: "Ethernet"}
PPPOE_HDR = 6   # VER/TYPE(1) CODE(1) SESSION_ID(2) LENGTH(2)
PPP_PROTO = 2   # PPP Protocol ID inside the PPPoE payload


# --------------------------------------------------------------------------
# 5WE CODE field.
# Table I in the paper says CODE = QFI (6 bits) + RQI (1 bit) + reserved (1 bit).
# The bit ORDER below (QFI in the top 6 bits) follows that table's ordering.
# TODO before submitting: confirm the exact bit positions in RFC 8822 Section 5
# and flip these two functions if needed. Nothing else in the script depends on it.
# --------------------------------------------------------------------------
def encode_5we_code(qfi: int, rqi: bool) -> int:
    if not 0 <= qfi <= 63:
        raise ValueError("QFI is 6 bits (0-63)")
    return (qfi << 2) | (int(bool(rqi)) << 1)  # lowest bit reserved = 0


def decode_5we_code(code: int):
    return code >> 2, bool((code >> 1) & 1)


# --------------------------------------------------------------------------
# Frame builders
# --------------------------------------------------------------------------
def mac(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def eth(dst: bytes, src: bytes, etype: int) -> bytes:
    return struct.pack("!6s6sH", dst, src, etype)


def ipv4_packet(payload_len: int, proto: int = 17) -> bytes:
    """Minimal valid IPv4 header (10.0.0.1 -> 203.0.113.9) plus dummy payload."""
    total = 20 + payload_len
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, proto, 0,
                      bytes([10, 0, 0, 1]), bytes([203, 0, 113, 9]))
    s = sum(struct.unpack("!10H", hdr))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    hdr = hdr[:10] + struct.pack("!H", ~s & 0xFFFF) + hdr[12:]
    return hdr + bytes(payload_len)


def pppoe_discovery(dst, src, code, session_id=0, tags=b"") -> bytes:
    return eth(dst, src, ETH_PPPOE_DISC) + struct.pack("!BBHH", 0x11, code, session_id, len(tags)) + tags


SERVICE_NAME_TAG = struct.pack("!HH", 0x0101, 0)  # empty Service-Name = any service


def session_frame(dst, src, ver, code, session_id, ppp_proto, payload) -> bytes:
    """Shared by PPPoE (ver=1) and 5WE (ver=2): that is the whole point of RFC 8822."""
    body = struct.pack("!H", ppp_proto) + payload
    hdr = struct.pack("!BBHH", (ver << 4) | 1, code, session_id, len(body))
    return eth(dst, src, ETH_PPPOE_SESS) + hdr + body


def pppoe_data(dst, src, session_id, ppp_proto, payload):
    return session_frame(dst, src, 1, 0x00, session_id, ppp_proto, payload)


def we5_data(dst, src, pdu_session_id, qfi, rqi, ppp_proto, payload):
    return session_frame(dst, src, 2, encode_5we_code(qfi, rqi), pdu_session_id, ppp_proto, payload)


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------
def parse_frame(frame: bytes) -> dict:
    if len(frame) < 14 + PPPOE_HDR:
        return {"kind": "too short"}
    dst, src, etype = struct.unpack("!6s6sH", frame[:14])
    vt, code, sid, length = struct.unpack("!BBHH", frame[14:14 + PPPOE_HDR])
    ver, typ = vt >> 4, vt & 0xF
    info = {"etype": etype, "ver": ver, "type": typ, "code": code, "session_id": sid, "length": length}
    body = frame[14 + PPPOE_HDR:14 + PPPOE_HDR + length]
    if len(body) != length:
        info["kind"] = "malformed (LENGTH exceeds frame)"
    elif etype == ETH_PPPOE_DISC:
        info["kind"] = DISC_CODES.get(code, f"discovery 0x{code:02x}")
    elif etype == ETH_PPPOE_SESS:
        info["ppp_proto"] = struct.unpack("!H", body[:2])[0]
        info["payload_len"] = length - PPP_PROTO
        if ver == 1:
            info["kind"] = "PPPoE data"
        elif ver == 2:
            info["kind"] = "5WE data"
            info["qfi"], info["rqi"] = decode_5we_code(code)
        else:
            info["kind"] = f"unknown VER {ver}"
    else:
        info["kind"] = "not PPPoE"
    return info


# --------------------------------------------------------------------------
# Toy legacy access node (stands in for a DSLAM / OLT)
# --------------------------------------------------------------------------
class LegacyAccessNode:
    """
    Models the paper's premise: deployed access nodes recognise PPPoE traffic by
    Ethertype and SESSION_ID and never look at VER or CODE. This is a model of that
    premise, not a model of any real vendor's hardware.
    """
    def __init__(self):
        self.table = {}  # (src_mac, session_id) -> port, learned from upstream frames

    def forward(self, frame: bytes, in_port: str):
        _, src, etype = struct.unpack("!6s6sH", frame[:14])
        if etype not in (ETH_PPPOE_DISC, ETH_PPPOE_SESS):
            return "DROP (unknown Ethertype)", None
        sid = struct.unpack("!H", frame[16:18])[0]  # offset 14+2
        out = "uplink" if in_port == "subscriber" else "subscriber"
        self.table[(src, sid)] = in_port
        return f"FORWARD to {out} (session 0x{sid:04x})", frame  # frame is never rewritten


# --------------------------------------------------------------------------
# MTU math
# --------------------------------------------------------------------------
def fragments(ip_len: int, mtu: int) -> int:
    if ip_len <= mtu:
        return 1
    per_frag = (mtu - 20) // 8 * 8
    return -(-(ip_len - 20) // per_frag)


def mtu_report(eth_payload_mtu=1500, baby_jumbo=1508):
    overhead = PPPOE_HDR + PPP_PROTO
    ppp_mtu = eth_payload_mtu - overhead
    print(f"PPPoE/5WE overhead: {PPPOE_HDR} (header) + {PPP_PROTO} (PPP proto) = {overhead} bytes")
    print(f"Standard Ethernet payload {eth_payload_mtu} -> max IP packet {ppp_mtu}, TCP MSS {ppp_mtu - 40}")
    print(f"Baby-jumbo Ethernet payload {baby_jumbo} -> max IP packet {baby_jumbo - overhead} (RFC 4638 style)")
    print(f"{'IP packet':>10} | {'frags @1492':>11} | {'frags @1500 (baby jumbo)':>24}")
    for ip_len in (1400, 1492, 1500):
        print(f"{ip_len:>10} | {fragments(ip_len, ppp_mtu):>11} | {fragments(ip_len, baby_jumbo - overhead):>24}")


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------
def hexdump(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)


def write_pcap(path: str, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # linktype 1 = Ethernet
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", 1_700_000_000, i * 1000, len(fr), len(fr)) + fr)


def field_table(a: dict, b: dict):
    rows = [("Ethertype", f"0x{a['etype']:04x}", f"0x{b['etype']:04x}"),
            ("VER / TYPE", f"{a['ver']} / {a['type']}", f"{b['ver']} / {b['type']}"),
            ("CODE", f"0x{a['code']:02x}", f"0x{b['code']:02x}  (QFI={b['qfi']}, RQI={int(b['rqi'])})"),
            ("SESSION_ID", f"0x{a['session_id']:04x}", f"0x{b['session_id']:04x}"),
            ("LENGTH", str(a["length"]), str(b["length"])),
            ("PPP Protocol ID", f"0x{a['ppp_proto']:04x}", f"0x{b['ppp_proto']:04x}")]
    print(f"{'Field':<16} | {'PPPoE (RFC 2516)':<18} | {'5WE (RFC 8822)':<28} | same?")
    print("-" * 78)
    for name, x, y in rows:
        print(f"{name:<16} | {x:<18} | {y:<28} | {'yes' if x == y else 'NO'}")


def scapy_crosscheck(frames):
    try:
        from scapy.all import Ether, PPPoE
    except ImportError:
        print("scapy not installed, skipping (pip install scapy)")
        return
    for label, fr in frames:
        p = Ether(fr)
        if PPPoE in p:
            q = p[PPPoE]
            print(f"scapy sees {label}: version={q.version} type={q.type} code=0x{q.code:02x} "
                  f"sessionid=0x{q.sessionid:04x} len={q.len}")
        else:
            print(f"scapy did not decode {label} as PPPoE")


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--qfi", type=int, default=5)
    ap.add_argument("--rqi", type=int, default=1)
    ap.add_argument("--pdu-session", type=int, default=7)
    ap.add_argument("--payload", type=int, default=64, help="dummy IPv4 payload bytes")
    ap.add_argument("--pcap", default="ppp_5we_demo.pcap")
    ap.add_argument("--scapy", action="store_true", help="cross-check with scapy if installed")
    a = ap.parse_args()

    rg, bng = mac("02:00:00:00:00:01"), mac("02:00:00:00:00:99")
    bcast = bytes([0xFF] * 6)
    pcap_frames = []

    print("=== 1. PPPoE discovery (what 5WE replaces with 5G NAS) ===")
    sid = 0x1234  # the BNG hands this out in PADS
    steps = [("PADI", pppoe_discovery(bcast, rg, 0x09, 0, SERVICE_NAME_TAG)),
             ("PADO", pppoe_discovery(rg, bng, 0x07, 0, SERVICE_NAME_TAG)),
             ("PADR", pppoe_discovery(bng, rg, 0x19, 0, SERVICE_NAME_TAG)),
             ("PADS", pppoe_discovery(rg, bng, 0x65, sid, SERVICE_NAME_TAG))]
    for name, fr in steps:
        p = parse_frame(fr)
        assert p["kind"] == name
        print(f"{name}: session_id=0x{p['session_id']:04x}  {hexdump(fr[:22])}")
        pcap_frames.append(fr)
    print("(then LCP + PAP/CHAP + IPCP would run inside the session; skipped here)\n")

    print("=== 2. Data frames: same IPv4 packet, PPPoE vs 5WE ===")
    pkt = ipv4_packet(a.payload)
    f_pppoe = pppoe_data(bng, rg, sid, PPP_IPV4, pkt)
    f_5we = we5_data(bng, rg, a.pdu_session, a.qfi, a.rqi, PPP_IPV4, pkt)
    pa, pb = parse_frame(f_pppoe), parse_frame(f_5we)
    assert pa["kind"] == "PPPoE data" and pb["kind"] == "5WE data"
    assert (pb["qfi"], int(pb["rqi"])) == (a.qfi, a.rqi)
    assert len(f_pppoe) == len(f_5we)
    print(f"PPPoE: {hexdump(f_pppoe[:24])} ...")
    print(f"5WE  : {hexdump(f_5we[:24])} ...\n")
    field_table(pa, pb)
    print(f"\nSame frame length ({len(f_pppoe)} bytes), same offsets: only VER, CODE and SESSION_ID "
          f"meaning differ.\n")
    pcap_frames += [f_pppoe, f_5we]

    print("=== 3. Legacy access node (DSLAM/OLT model) ===")
    node = LegacyAccessNode()
    odd = eth(bng, rg, 0x88B5) + b"hypothetical brand-new 5G ethertype"  # 0x88B5 = IEEE local experimental
    for label, fr in [("PPPoE data", f_pppoe), ("5WE data", f_5we), ("new Ethertype", odd)]:
        verdict, out = node.forward(fr, "subscriber")
        unchanged = "frame unchanged" if out == fr else ""
        print(f"{label:<14} -> {verdict} {unchanged}")
    print("Reusing 0x8864 is what lets 5WE ride through gear that already knows PPPoE.\n")

    print("=== 4. MTU cost of PPPoE / 5WE ===")
    mtu_report()

    write_pcap(a.pcap, pcap_frames)
    print(f"\nWrote {len(pcap_frames)} frames to {a.pcap} (open in Wireshark to inspect the header bytes).")

    if a.scapy:
        print("\n=== Scapy cross-check ===")
        scapy_crosscheck([("PPPoE data", f_pppoe), ("5WE data", f_5we)])


if __name__ == "__main__":
    main()
