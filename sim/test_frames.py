"""Byte-level validation: the simulator's frame builder == ppp_5we_demo.py, plus RFC 8822 header facts.
Run: python -m sim.test_frames   (also collected by pytest)."""
import os
import struct

import ppp_5we_demo as demo
from sim.model import (BNG, OVERHEAD, RG, LegacyAccessNode, VerPolicingNode, build_frames,
                       fragment_sizes, parse_frame)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_byte_identical_to_demo():
    n = 0
    for ip_len in (20, 40, 84, 576, 1400, 1492):
        pkt = demo.ipv4_packet(ip_len - 20)
        for sid in (0x0001, 0x1234, 0xFFFF):
            assert build_frames(ip_len, 1492, "pppoe", sid=sid)[0] == demo.pppoe_data(BNG, RG, sid, demo.PPP_IPV4, pkt)
            for qfi in (0, 5, 9, 63):
                for rqi in (0, 1):
                    got = build_frames(ip_len, 1492, "5we", sid=sid, qfi=qfi, rqi=rqi)[0]
                    assert got == demo.we5_data(BNG, RG, sid, qfi, rqi, demo.PPP_IPV4, pkt)
                    n += 1
    return n


def test_matches_demo_pcap():
    """The demo's default PPPoE (sid 0x1234) and 5WE (PDU 7, QFI 5, RQI 1) frames, 64-B payload, are in its pcap."""
    with open(os.path.join(ROOT, "ppp_5we_demo.pcap"), "rb") as f:
        data = f.read()[24:]
    frames = []
    while data:
        incl = struct.unpack("<IIII", data[:16])[2]
        frames.append(data[16:16 + incl])
        data = data[16 + incl:]
    assert build_frames(84, 1492, "pppoe", sid=0x1234)[0] in frames
    assert build_frames(84, 1492, "5we", sid=7, qfi=5, rqi=1)[0] in frames


def test_rfc8822_header_facts():
    f = build_frames(84, 1492, "5we", sid=42, qfi=9, rqi=1)[0]
    assert struct.unpack("!H", f[12:14])[0] == 0x8864
    assert f[14] == 0x21                      # VER=2, TYPE=1
    assert f[15] == (9 << 2) | (1 << 1)       # QFI in 6 MSB, RQI bit 1, reserved bit 0 = 0
    p = parse_frame(f)
    assert (p["ver"], p["type"], p["qfi"], p["rqi"], p["session_id"]) == (2, 1, 9, True, 42)
    assert p["length"] == 84 + 2 and p["ppp_proto"] in (0x0021, 0x0031, 0x0057)  # LENGTH includes Protocol ID
    assert OVERHEAD == 8 and 1500 - OVERHEAD == 1492 and 1508 - OVERHEAD == 1500
    assert len(build_frames(1492, 1492, "pppoe")[0]) == 14 + 8 + 1492


def test_fragments_match_demo():
    for ip_len in (1400, 1492, 1500):
        for mtu in (1492, 1500):
            sizes = fragment_sizes(ip_len, mtu)
            assert len(sizes) == demo.fragments(ip_len, mtu) == len(build_frames(ip_len, mtu, "pppoe"))
            assert sum(s - 20 for s in sizes) == ip_len - 20 and all(s <= mtu for s in sizes)
            assert all((s - 20) % 8 == 0 for s in sizes[:-1])


def test_access_nodes():
    pppoe, we5 = build_frames(84, 1492, "pppoe")[0], build_frames(84, 1492, "5we")[0]
    legacy, police = LegacyAccessNode(), VerPolicingNode()
    assert legacy.forward(pppoe, "subscriber")[1] == pppoe and legacy.forward(we5, "subscriber")[1] == we5
    assert police.forward(pppoe, "subscriber")[1] == pppoe and police.forward(we5, "subscriber")[1] is None


if __name__ == "__main__":
    n = test_byte_identical_to_demo()
    test_matches_demo_pcap()
    test_rfc8822_header_facts()
    test_fragments_match_demo()
    test_access_nodes()
    print(f"frames ok: {n} 5WE + 18 PPPoE frames byte-identical to ppp_5we_demo.py; pcap, RFC 8822, fragments, access nodes ok")
