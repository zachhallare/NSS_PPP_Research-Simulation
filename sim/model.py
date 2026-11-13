"""Frame-level model. Every byte comes from ppp_5we_demo's own encoder (reused, not re-implemented)."""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ppp_5we_demo import (  # noqa: E402  (reuse the demo's codec verbatim)
    ETH_PPPOE_SESS, PPP_IPV4, PPPOE_HDR, PPP_PROTO, LegacyAccessNode,
    decode_5we_code, encode_5we_code, eth, fragments, ipv4_packet, mac,
    parse_frame, pppoe_data, session_frame, we5_data,
)

RG, BNG = mac("02:00:00:00:00:01"), mac("02:00:00:00:00:99")
OVERHEAD = PPPOE_HDR + PPP_PROTO  # 8 bytes: what turns 1500 into 1492
ETH_IPV4 = 0x0800


def fragment_sizes(ip_len, mtu):
    """IPv4 fragment lengths using the same 8-byte rule as demo.fragments()."""
    if ip_len <= mtu:
        return [ip_len]
    per, data, out = (mtu - 20) // 8 * 8, ip_len - 20, []
    while data > 0:
        take = min(per, data)
        out.append(20 + take)
        data -= take
    return out


def build_frames(ip_len, mtu, encap, sid=0x1234, qfi=5, rqi=1):
    """Frames on the wire for one IP packet of ip_len bytes. Lengths are exact; fragment flags are not set."""
    out = []
    for frag_len in fragment_sizes(ip_len, mtu):
        pkt = ipv4_packet(frag_len - 20)
        if encap == "pppoe":
            out.append(pppoe_data(BNG, RG, sid, PPP_IPV4, pkt))
        elif encap == "5we":
            out.append(we5_data(BNG, RG, sid, qfi, rqi, PPP_IPV4, pkt))
        elif encap == "ipoe":
            out.append(eth(BNG, RG, ETH_IPV4) + pkt)
        else:
            raise ValueError(encap)
    return out


def mix_stats(mix, mtu, encap):
    """Per-IP-packet averages over a weighted size mix [(ip_len, weight), ...]."""
    W = sum(w for _, w in mix)
    frames = wire = ip = fragd = 0.0
    for ip_len, w in mix:
        fr = build_frames(ip_len, mtu, encap)
        frames += w * len(fr)
        wire += w * sum(len(f) for f in fr)
        ip += w * ip_len
        fragd += w * (len(fr) > 1)
    return {"frames_per_pkt": frames / W, "wire_per_pkt": wire / W, "ip_per_pkt": ip / W,
            "frag_ratio": fragd / W, "overhead_pct": 100 * (wire - ip) / wire}


class VerPolicingNode(LegacyAccessNode):
    """Negative control: an access node that also polices VER == 1 on 0x8864 and so drops 5WE."""

    def forward(self, frame, in_port):
        etype = struct.unpack("!H", frame[12:14])[0]
        if etype == ETH_PPPOE_SESS and frame[14] >> 4 != 1:
            return "DROP (VER != 1)", None
        return super().forward(frame, in_port)


__all__ = ["encode_5we_code", "decode_5we_code", "session_frame", "pppoe_data", "we5_data",
           "parse_frame", "fragments", "fragment_sizes", "build_frames", "mix_stats",
           "LegacyAccessNode", "VerPolicingNode", "OVERHEAD", "RG", "BNG"]
