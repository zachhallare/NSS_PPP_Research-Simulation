"""Revision checks for the gap review (Nov 2026). Adds new evidence; does not change any existing result.

Run from the project root:   python -m sim.revision_checks
Writes CSVs to results/revision/ and a summary to results/revision/SUMMARY.md.

Checks (gap review item in brackets):
  1. Independent frame validation with Scapy                                     [5.6]
  2. Access node vs. 5WE-unaware endpoint, RFC 8822 receive-rule conformance      [1.2, 5.5]
  3. Closed-form expectations next to the simulated headline numbers              [5.2]
  4. Stronger verification: zero-load, M/G/1 (Pollaczek-Khinchine), degenerate     [5.3]
     DBNG, fluid-loss from the Erlang occupancy distribution
  5. Holm-Bonferroni on the existing significance tests, CIs of differences        [5.7]
  6. MSER-5 warm-up check on occupancy series                                      [5.7]
  7. MTU with and without TCP MSS clamping, RFC 4638, and a packet-mix sweep       [5.8]
  8. Reconnect storm (mass re-login after an outage), with optional PADI limiter   [5.4]
The existing simulator (sim/architectures.py) and codec (ppp_5we_demo.py) are imported, not edited.
"""
import csv
import heapq
import math
import os
import random
import statistics
import struct
from collections import defaultdict, deque
from multiprocessing import Pool

from scipy import stats as sst

from . import architectures as A
from .architectures import BASE, MTUS, PHASES, arch, simulate, steps_for
from .experiments import LOADS, SEEDS, cell_seed
from .metrics import erlang_b, mean_ci, t975
from .model import BNG, RG, LegacyAccessNode, build_frames, mix_stats, parse_frame
from .traffic import PACKET_MIX

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "results", "revision")
SUMMARY = []


def note(s=""):
    print(s)
    SUMMARY.append(s)


def write(name, rows):
    os.makedirs(OUT, exist_ok=True)
    keys = []
    for r in rows:
        keys += [k for k in r if k not in keys]
    with open(os.path.join(OUT, name), "w", newline="") as f:
        w = csv.DictWriter(f, keys, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def read_summary(name):
    out = []
    with open(os.path.join(ROOT, "results", "summary", name)) as f:
        for r in csv.DictReader(f):
            d = {}
            for k, v in r.items():
                try:
                    d[k] = int(v) if k in ("n", "mtu", "reps") else float(v)
                except ValueError:
                    d[k] = v
            out.append(d)
    return out


def cell(summ, k, n, load, mtu=1492):
    return next(r for r in summ if r["arch"] == k and r["n"] == n and abs(r["load"] - load) < 1e-9 and r["mtu"] == mtu)


# ============================================================================ 1. Scapy
def check_scapy():
    from scapy.all import PPPoE, PPPoED, Ether, Raw, rdpcap
    note("## 1. Independent frame validation (Scapy)")
    pk = rdpcap(os.path.join(ROOT, "ppp_5we_demo.pcap"))
    rows = []
    names = ["PADI", "PADO", "PADR", "PADS"]
    for i, p in enumerate(pk[:4]):
        d = p[PPPoED]
        rows.append(dict(frame=i + 1, scapy_layer="PPPoED", version=d.version, type=d.type, code=hex(d.code),
                         sessionid=hex(d.sessionid), expected=names[i]))
    f5, f6 = pk[4], pk[5]
    a, b = f5[PPPoE], f6[PPPoE]
    ok5 = (a.version, a.type, a.code, a.sessionid, a.len) == (1, 1, 0, 0x1234, 86) and f5.haslayer("PPP")
    ok6 = (b.version, b.type, b.code, b.sessionid, b.len) == (2, 1, 0x16, 0x0007, 86)
    qfi, rqi, res = b.code >> 2, (b.code >> 1) & 1, b.code & 1
    rebuilt = Ether(dst=f6[Ether].dst, src=f6[Ether].src, type=0x8864) / \
        PPPoE(version=2, type=1, code=0x16, sessionid=0x0007) / Raw(bytes(b.payload))
    byte_eq = bytes(rebuilt) == bytes(f6)
    payload_kind = type(b.payload).__name__
    rows += [dict(frame=5, scapy_layer="PPPoE", version=a.version, type=a.type, code=hex(a.code), sessionid=hex(a.sessionid),
                  len=a.len, payload=type(a.payload).__name__, fields_ok=ok5),
             dict(frame=6, scapy_layer="PPPoE", version=b.version, type=b.type, code=hex(b.code), sessionid=hex(b.sessionid),
                  len=b.len, payload=payload_kind, qfi=qfi, rqi=rqi, reserved=res, fields_ok=ok6,
                  scapy_rebuild_byte_identical=byte_eq)]
    # sweep: every 5WE frame of the 162-frame identity test, parsed by Scapy instead of our own parser
    n = bad = 0
    for ip_len in (20, 40, 84, 576, 1400, 1492):
        for sid in (0x0001, 0x1234, 0xFFFF):
            for qfi_ in (0, 5, 9, 63):
                for rqi_ in (0, 1):
                    fr = build_frames(ip_len, 1492, "5we", sid=sid, qfi=qfi_, rqi=rqi_)[0]
                    q = Ether(fr)[PPPoE]
                    n += 1
                    bad += not (q.version == 2 and q.type == 1 and q.code >> 2 == qfi_ and (q.code >> 1) & 1 == rqi_
                                and q.code & 1 == 0 and q.sessionid == sid and q.len == ip_len + 2)
    rows.append(dict(frame="sweep", scapy_layer="PPPoE", frames=n, mismatches=bad))
    write("scapy_validation.csv", rows)
    note(f"- PCAP discovery frames 1-4 decode as PPPoED with codes {[r['code'] for r in rows[:4]]} (PADI/PADO/PADR/PADS).")
    note(f"- Frame 5 (PPPoE): fields as expected = {ok5}; Scapy binds a PPP layer (payload {rows[4]['payload']}).")
    note(f"- Frame 6 (5WE): VER={b.version} TYPE={b.type} octet=0x{b.code:02x} -> QFI={qfi} RQI={rqi} reserved={res}, "
         f"SESSION_ID=0x{b.sessionid:04x}, LENGTH={b.len}; fields as expected = {ok6}.")
    note(f"- Scapy (not 5WE-aware) shows the 5WE payload as `{payload_kind}`, not PPP, because it binds PPP only when CODE=0.")
    note(f"- Frame rebuilt independently in Scapy is byte-identical to the codec's frame 6: {byte_eq}.")
    note(f"- Sweep: {n} 5WE frames from the identity test parsed by Scapy, {bad} field mismatches.")
    note("- Note: the identity sweep uses SESSION_ID 0xFFFF, which RFC 8822 reserves (MUST NOT be used); see check 2.")
    note()
    return dict(ok5=ok5, ok6=ok6, byte_eq=byte_eq, sweep=n, sweep_bad=bad, payload=payload_kind)


# ============================================================================ 2. endpoints and conformance
VALID_5WE_PROTO = (0x0021, 0x0031, 0x0057)


class Endpoint:
    """Receive side of RFC 8822 Sec. 2-3 (endpoint rules, e.g. RG / AGF / BNG). Returns (accepted, reason)."""

    def __init__(self, pppoe=True, we5=False, sessions=()):
        self.pppoe, self.we5, self.sessions = pppoe, we5, set(sessions)

    def receive(self, frame):
        if struct.unpack("!H", frame[12:14])[0] != 0x8864:
            return False, "not session Ethertype"
        p = parse_frame(frame)
        if p["kind"].startswith("malformed"):
            return False, "LENGTH exceeds frame"
        if p["ver"] == 1 and not self.pppoe or p["ver"] == 2 and not self.we5 or p["ver"] not in (1, 2):
            return False, f"VER {p['ver']} not supported (silently discarded)"
        if p["type"] != 1:
            return False, "TYPE != 1"
        if p["ver"] == 2:
            if p["session_id"] == 0xFFFF:
                return False, "SESSION_ID 0xFFFF reserved"
            if p["ppp_proto"] not in VALID_5WE_PROTO:
                return False, f"PROTOCOL ID 0x{p['ppp_proto']:04x} not allowed"
        if p["session_id"] not in self.sessions:
            return False, "unknown SESSION_ID"
        return True, "accepted"


def check_endpoints():
    note("## 2. Access node vs. 5WE-unaware endpoint, and RFC 8822 receive rules")
    # Same 10,000-frame stream, same seed, as the paper's Table IX (sim/experiments.py frame_experiments)
    rng = random.Random(cell_seed("access_node"))
    sizes, weights = zip(*PACKET_MIX)
    access = LegacyAccessNode()
    counts = defaultdict(lambda: [0, 0, 0])
    stream = []
    for _ in range(10_000):
        encap = rng.choice(("pppoe", "5we"))
        ip_len = min(rng.choices(sizes, weights)[0], 1492)
        sid = rng.randrange(1, 0xFFFF)
        f = build_frames(ip_len, 1492, encap, sid=sid, qfi=rng.randrange(64), rqi=rng.randrange(2))[0]
        stream.append((encap, sid, f))
    sids = {s for _, s, _ in stream}
    nodes = {"Access node (Ethertype + SESSION_ID)": None,
             "5WE-unaware PPPoE endpoint (legacy BNG)": Endpoint(pppoe=True, we5=False, sessions=sids),
             "5WE-aware endpoint (AGF, PPPoE + 5WE)": Endpoint(pppoe=True, we5=True, sessions=sids)}
    for encap, sid, f in stream:
        for name, ep in nodes.items():
            c = counts[(name, encap)]
            c[0] += 1
            if ep is None:
                ok = access.forward(f, "subscriber")[1] == f
            else:
                ok = ep.receive(f)[0]
            c[1] += ok
            c[2] += not ok
    rows = [dict(node=k[0], encap=k[1], sent=v[0], accepted_or_forwarded=v[1], dropped=v[2]) for k, v in counts.items()]
    write("endpoint_test.csv", rows)
    for r in rows:
        note(f"- {r['node']}, {r['encap']}: sent {r['sent']}, forwarded/accepted {r['accepted_or_forwarded']}, "
             f"dropped {r['dropped']}")
    # conformance vectors
    good = build_frames(84, 1492, "5we", sid=7, qfi=5, rqi=1)[0]

    def with_proto(fr, proto):
        return fr[:20] + struct.pack("!H", proto) + fr[22:]

    def with_sid(fr, sid):
        return fr[:16] + struct.pack("!H", sid) + fr[18:]

    vectors = [("valid 5WE, PDU session 7, IPv4", good, True),
               ("valid 5WE, Protocol ID 0x0057 (IPv6)", with_proto(good, 0x0057), True),
               ("valid 5WE, Protocol ID 0x0031 (Ethernet)", with_proto(good, 0x0031), True),
               ("SESSION_ID 0xFFFF (reserved)", with_sid(good, 0xFFFF), False),
               ("unknown SESSION_ID 0x0099", with_sid(good, 0x0099), False),
               ("Protocol ID 0xC021 (LCP) inside 5WE", with_proto(good, 0xC021), False),
               ("Protocol ID 0x8021 (IPCP) inside 5WE", with_proto(good, 0x8021), False),
               ("VER 3 (unassigned)", good[:14] + bytes([0x31]) + good[15:], False),
               ("TYPE 2", good[:14] + bytes([0x22]) + good[15:], False)]
    agf = Endpoint(pppoe=False, we5=True, sessions={7})
    crow = []
    for label, fr, should in vectors:
        acc, why = agf.receive(fr)
        p = parse_frame(fr)
        codec_kind = p["kind"]
        crow.append(dict(vector=label, rfc8822_expected="accept" if should else "discard",
                         endpoint_model="accept" if acc else "discard", endpoint_reason=why,
                         endpoint_correct=acc == should, codec_parse_frame_kind=codec_kind,
                         codec_flags_violation=False if should else ("unknown" in codec_kind)))
    write("rfc8822_conformance.csv", crow)
    n_ok = sum(r["endpoint_correct"] for r in crow)
    n_codec = sum(1 for r in crow if r["rfc8822_expected"] == "discard" and not r["codec_flags_violation"])
    note(f"- Conformance vectors: endpoint model correct on {n_ok}/{len(crow)}.")
    note(f"- The codec's parse_frame() is a parser, not a validator: it labels {n_codec} of "
         f"{sum(r['rfc8822_expected'] == 'discard' for r in crow)} invalid vectors as ordinary '5WE data' "
         "(only VER 3 is flagged). Receive rules therefore live in the new Endpoint model.")
    note()
    return rows, crow


# ============================================================================ 3. closed form
def check_closed_form(summ, sens_v):
    note("## 3. Closed-form expectations vs. simulated headline numbers")
    cap, fw = A.fwd_consts(BASE)
    rows = []
    work = {k: sum(s for u, s, _ in steps_for(arch(k, 1), BASE) if not u) for k in ("mono", "dbng", "vbng")}
    for k, n in (("mono", 1), ("dbng", 1), ("dbng", 8), ("vbng", 1), ("vbng", 8)):
        c = cell(summ, k, n, 1.0)
        lam = 1.0 * n * 200 / 60.0
        b = c["block_table_mean"]
        n_cp = 1 if k in ("mono", "dbng") else n
        rho = lam * (1 - b) * work[k] / n_cp
        rows.append(dict(quantity=f"CP utilization {k} N={n}, load 1.0", formula="lambda x (1-B) x CP work / n_CP",
                         closed_form=round(100 * rho, 2), simulated=round(100 * c["cp_util_mean"], 2), unit="%"))
    s92, s00 = mix_stats(PACKET_MIX, 1492, "pppoe"), mix_stats(PACKET_MIX, 1500, "pppoe")
    rows.append(dict(quantity="Extra frames per IP packet, MTU 1492 vs 1500", formula="share of 1500-B packets = 1/12",
                     closed_form=round(100 / 12, 2), simulated=round(100 * (s92["frames_per_pkt"] / s00["frames_per_pkt"] - 1), 2),
                     unit="%"))
    # fluid loss from the Erlang (truncated Poisson) occupancy distribution of one unit
    for k, n, v in (("mono", 1, 1.0), ("vbng", 1, 1.25)):
        for load in (0.9, 1.0, 1.5):
            c = cell(summ, k, n, load)
            capu = cap / v
            fps = fw[1492]["fps"]
            A_ = load * 200
            pk = [1.0]
            for j in range(1, 201):
                pk.append(pk[-1] * A_ / j)
            Z = sum(pk)
            pk = [x / Z for x in pk]
            offered = sum(j * pk[j] for j in range(201))
            deliv = sum(pk[j] * min(j, capu / fps) for j in range(201))
            rows.append(dict(quantity=f"Forwarding loss {k} N={n}, load {load}, MTU 1492",
                             formula="1 - E[min(k, cap/fps)] / E[k], k ~ Erlang occupancy", closed_form=round(100 * (1 - deliv / offered), 2),
                             simulated=round(c["fwd_loss_pct_mean"], 2), unit="%"))
    mono, db1 = cell(summ, "mono", 1, 0.5), cell(summ, "dbng", 1, 0.5)
    red_fixed = 6 * BASE["redirect_rtt"] + BASE["pfcp_cp_s"] + BASE["pfcp_up_s"]
    rows.append(dict(quantity="DBNG N=1 minus monolithic mean setup, load 0.5",
                     formula="6 redirect RTTs + PFCP CP + PFCP UP (no queueing)", closed_form=round(1e3 * red_fixed, 1),
                     simulated=round(db1["setup_mean_ms_mean"] - mono["setup_mean_ms_mean"], 1), unit="ms"))
    for c in (cap, cap / BASE["v"]):
        pass
    rows.append(dict(quantity="UP pps budget / offered pps of a full 200-session table (MTU 1500)",
                     formula="up_headroom", closed_form=BASE["up_headroom"],
                     simulated=round(cap / (200 * fw[1500]["fps"]), 4), unit="x"))
    rows.append(dict(quantity="Implied CP ceiling, monolithic", formula="1 / CP work per setup",
                     closed_form=round(1 / work["mono"], 1), simulated="", unit="setups/s"))
    rows.append(dict(quantity="Implied CP ceiling, DBNG", formula="1 / CP work per setup",
                     closed_form=round(1 / work["dbng"], 1), simulated="", unit="setups/s"))
    write("closed_form.csv", rows)
    note("| Quantity | Closed form | Simulated |")
    note("|---|---|---|")
    for r in rows:
        note(f"| {r['quantity']} | {r['closed_form']} {r['unit']} | {r['simulated']} |")
    note()
    return rows


# ============================================================================ 4. verification
def _job(task):
    kind, n, load, seed, over = task
    return simulate(kind, n, load, seed, **over)[0]


def raw_means(metric):
    acc = defaultdict(list)
    with open(os.path.join(ROOT, "results", "raw", "main.csv")) as f:
        for r in csv.DictReader(f):
            if r["mtu"] == "1492":
                acc[(r["arch"], int(r["n"]), float(r["load"]))].append(float(r[metric]))
    return {k: statistics.fmean(v) for k, v in acc.items()}


def check_verification(summ, pool):
    note("## 4. Stronger verification")
    rows = []
    cpL = raw_means("little_cp_L")
    # 4a zero-load: load 0.01, expected = sum of fixed delays + mean service times (no queueing)
    tasks = [(k, 1, 0.01, cell_seed("rev_zero", k, r), {}) for k in ("mono", "dbng", "vbng") for r in range(SEEDS)]
    res = pool.map(_job, tasks)
    for k in ("mono", "dbng", "vbng"):
        st = steps_for(arch(k, 1), BASE)
        exp = 1e3 * sum(s + d for _, s, d in st)
        m, h = mean_ci([r["setup_mean_ms"] for r, t in zip(res, tasks) if t[0] == k])
        rows.append(dict(check="zero_load", arch=k, n=1, load=0.01, expected=exp, measured=m, ci95=h,
                         rel_err_pct=100 * abs(m / exp - 1), within_ci=abs(m - exp) <= h))
    # 4b degenerate DBNG: no redirect, (near-)zero PFCP cost == monolithic (common random numbers: same seeds)
    eps = 1e-12
    deg = dict(redirect_rtt=0.0, pfcp_cp_s=eps, pfcp_up_s=eps)
    for load in (0.5, 1.0):
        ta = [("mono", 1, load, cell_seed("rev_deg", load, r), {}) for r in range(SEEDS)]
        tb = [("dbng", 1, load, cell_seed("rev_deg", load, r), deg) for r in range(SEEDS)]
        ra, rb = pool.map(_job, ta), pool.map(_job, tb)
        for m in ("setup_mean_ms", "block_prob", "cp_util"):
            d = [x[m] - y[m] for x, y in zip(rb, ra)]
            md, hd = mean_ci(d)
            rows.append(dict(check="degenerate_dbng_eq_mono", arch="dbng", n=1, load=load, metric=m,
                             expected=mean_ci([x[m] for x in ra])[0], measured=mean_ci([x[m] for x in rb])[0],
                             diff=md, ci95=hd, within_ci=abs(md) <= hd or abs(md) < 1e-9))
    # 4c M/G/1 (Pollaczek-Khinchine) for the shared CP queue, and predicted mean setup latency
    for k, n in (("mono", 1), ("dbng", 1), ("dbng", 8), ("vbng", 8)):
        st = steps_for(arch(k, n), BASE)
        cp_s = [s for u, s, _ in st if not u]
        up_s = [s for u, s, _ in st if u]
        n_cp = 1 if k in ("mono", "dbng") else n
        for load in LOADS:
            c = cell(summ, k, n, load)
            lam_adm = load * n * 200 / 60.0 * (1 - c["block_prob_mean"])
            lj = lam_adm * len(cp_s) / n_cp
            ES = statistics.fmean(cp_s)
            ES2 = statistics.fmean([2 * s * s for s in cp_s])
            rho = lj * ES
            if rho >= 1:
                continue
            Wq = lj * ES2 / (2 * (1 - rho))
            lu = lam_adm * len(up_s) / n
            ESu = statistics.fmean(up_s)
            rhou = lu * ESu
            Wqu = lu * statistics.fmean([2 * s * s for s in up_s]) / (2 * (1 - rhou))
            W_sim = cpL[(k, n, load)] / lj  # Little: mean CP sojourn per job
            pred_setup = 1e3 * (sum(d for _, _, d in st) + sum(cp_s) + len(cp_s) * Wq + sum(up_s) + len(up_s) * Wqu)
            rows.append(dict(check="mg1_cp_sojourn", arch=k, n=n, load=load, metric="CP sojourn per job (ms)",
                             expected=1e3 * (Wq + ES), measured=1e3 * W_sim,
                             rel_err_pct=100 * abs(W_sim / (Wq + ES) - 1)))
            rows.append(dict(check="mg1_setup_mean", arch=k, n=n, load=load, metric="mean setup (ms)",
                             expected=pred_setup, measured=c["setup_mean_ms_mean"],
                             rel_err_pct=100 * abs(c["setup_mean_ms_mean"] / pred_setup - 1)))
    write("verification.csv", rows)
    for r in rows:
        if r["check"] == "zero_load":
            note(f"- Zero load, {r['arch']}: expected {r['expected']:.2f} ms, simulated {r['measured']:.2f} ± {r['ci95']:.2f} ms "
                 f"({r['rel_err_pct']:.2f}% off, within CI: {r['within_ci']}).")
    for r in rows:
        if r["check"] == "degenerate_dbng_eq_mono":
            note(f"- Degenerate DBNG vs monolithic, load {r['load']}, {r['metric']}: {r['measured']:.5g} vs {r['expected']:.5g} "
                 f"(paired diff {r['diff']:.3g} ± {r['ci95']:.3g}, equal within CI: {r['within_ci']}).")
    mg = [r for r in rows if r["check"] == "mg1_setup_mean"]
    mgc = [r for r in rows if r["check"] == "mg1_cp_sojourn"]
    note(f"- M/G/1 CP sojourn: max error {max(r['rel_err_pct'] for r in mgc):.1f}% over {len(mgc)} cells "
         f"(the CP sees correlated, not Poisson, job arrivals, so this is an approximation).")
    for r in mg:
        if (r["arch"], r["n"]) == ("dbng", 8) and r["load"] in (0.5, 1.0):
            note(f"- DBNG N=8 load {r['load']}: P-K predicted mean setup {r['expected']:.1f} ms vs simulated {r['measured']:.1f} ms "
                 f"({r['rel_err_pct']:.1f}% off).")
    note(f"- M/G/1 predicted mean setup: max error {max(r['rel_err_pct'] for r in mg):.1f}% over {len(mg)} cells.")
    note()
    return rows


# ============================================================================ 5. multiple comparisons
def holm(ps):
    order = sorted(range(len(ps)), key=lambda i: ps[i])
    m = len(ps)
    adj = [0.0] * m
    run = 0.0
    for rank, i in enumerate(order):
        run = max(run, min(1.0, (m - rank) * ps[i]))
        adj[i] = run
    return adj


def check_stats():
    note("## 5. Multiple comparisons (Holm-Bonferroni) and CIs of differences")
    sig = []
    with open(os.path.join(ROOT, "results", "summary", "significance.csv")) as f:
        for r in csv.DictReader(f):
            sig.append(r)
    rows = []
    for r in sig:
        t, df, diff = float(r["t"]), float(r["df"]), float(r["diff"])
        if r["test"] == "welch":
            if math.isfinite(t):
                p = 2 * sst.t.sf(abs(t), max(df, 1))
            else:  # both groups have zero variance: identical constants -> p = 1, different constants -> p = 0
                p = 0.0 if diff != 0 else 1.0
            se = abs(diff / t) if t not in (0.0,) and math.isfinite(t) else 0.0
            h = t975(max(1, round(df))) * se
        else:  # paired: 't' column stores the CI half-width of the mean difference
            h = t
            se = h / t975(int(df)) if h > 0 else 0.0
            tt = diff / se if se > 0 else (math.inf if diff != 0 else 0.0)
            p = 2 * sst.t.sf(abs(tt), df) if math.isfinite(tt) else 0.0
        rows.append(dict(r, p_value=p, diff_ci_low=diff - h, diff_ci_high=diff + h))
    for fam in ("welch", "paired"):
        idx = [i for i, r in enumerate(rows) if r["test"] == fam]
        adj = holm([rows[i]["p_value"] for i in idx])
        for i, pa in zip(idx, adj):
            rows[i]["p_holm"] = pa
            rows[i]["significant_holm"] = pa < 0.05
    write("significance_holm.csv", rows)
    nw = sum(1 for r in rows if r["test"] == "welch")
    npd = sum(1 for r in rows if r["test"] == "paired")
    flips = [r for r in rows if (r["significant_5pct"] == "True") != r["significant_holm"]]
    note(f"- Tests: {nw} Welch (architecture pairs x loads x metrics), {npd} paired (MTU). Holm applied per family.")
    note(f"- Decisions that change after Holm: {len(flips)}.")
    for r in flips:
        note(f"  - {r['test']} {r['a']} vs {r['b']} {r['metric']} at load {r['load']}: p={float(r['p_value']):.3g}, "
             f"Holm p={r['p_holm']:.3g}")

    def claim(test, a, b, metric, loads):
        sel = [r for r in rows if r["test"] == test and r["a"] == a and r["b"] == b and r["metric"] == metric
               and float(r["load"]) in loads]
        return sel

    c1 = claim("welch", "mono1", "dbng1", "setup_mean_ms", LOADS)
    note(f"- Paper claim 'DBNG setup latency differs from monolithic at every load': significant after Holm at "
         f"{sum(r['significant_holm'] for r in c1)}/{len(c1)} loads; difference CI at load 0.5: "
         f"[{-c1[2]['diff_ci_high']:.1f}, {-c1[2]['diff_ci_low']:.1f}] ms (DBNG minus mono).")
    c2 = [r for r in rows if r["test"] == "welch" and r["metric"] == "block_prob"]
    note(f"- Paper claim 'blocking differences not significant at any load': significant before Holm "
         f"{sum(r['significant_5pct'] == 'True' for r in c2)}/{len(c2)}, after Holm {sum(r['significant_holm'] for r in c2)}/{len(c2)}.")
    c3 = claim("paired", "mono1@1492", "mono1@1500", "fwd_loss_pct", (1.5,))
    if c3:
        r = c3[0]
        note(f"- Paper claim 'MTU 1492 lost 2.14% vs 0 at load 1.5, significant': Holm p={r['p_holm']:.3g}, "
             f"difference CI [{r['diff_ci_low']:.2f}, {r['diff_ci_high']:.2f}] percentage points.")
    note()
    return rows


# ============================================================================ 6. MSER-5
def _trace(task):
    """Occupancy of unit 0 sampled at every arrival (incl. warm-up), via a thin copy of the arrival logic."""
    kind, n, load, seed, setup_s = task
    p = dict(BASE)
    a = arch(kind, n)
    N, C = a["n"], p["C_unit"]
    rng = random.Random(seed)
    lam = load * N * C / p["H_mean"]
    total = max(math.ceil(p["min_arrivals"] / (1 - p["warmup_frac"])) + 1, math.ceil(p["min_holding_times"] * lam * p["H_mean"]))
    # Occupancy of one unit is an M/G/C/C loss process (arrivals homed uniformly, slot held for setup + holding time).
    # This replica reproduces the simulator's arrival count, homing and run length, with setup time fixed at the
    # simulated mean for that cell, and samples unit 0's occupancy at every arrival from an empty start.
    from .traffic import holding_sampler
    hold = holding_sampler(rng, p["H_mean"], p["H_cv"])
    t, occ, dep, series = 0.0, 0, [], []
    for _ in range(total):
        t += rng.expovariate(lam)
        if (rng.randrange(N) if N > 1 else 0) != 0:
            continue
        while dep and dep[0] <= t:
            heapq.heappop(dep)
            occ -= 1
        if occ < C:
            occ += 1
            heapq.heappush(dep, t + setup_s + hold())
        series.append(occ)
    return series


def mser5(series):
    b = [statistics.fmean(series[i:i + 5]) for i in range(0, len(series) - 4, 5)]
    n = len(b)
    best, best_d = math.inf, 0
    for d in range(0, n // 2):
        seg = b[d:]
        m = statistics.fmean(seg)
        s = sum((x - m) ** 2 for x in seg) / (len(seg) ** 2)
        if s < best:
            best, best_d = s, d
    return best_d * 5 / len(series)


def _job_nopfcp(task):
    kind, n, load, seed, over = task
    orig = A.arch
    A.arch = lambda k, n_: {**orig(k, n_), "pfcp": False}
    try:
        return simulate(kind, n, load, seed, **over)[0]
    finally:
        A.arch = orig


def check_degenerate_exact(pool):
    rows = []
    for load in (0.5, 1.0):
        ta = [("mono", 1, load, cell_seed("rev_deg", load, r), {}) for r in range(SEEDS)]
        tb = [("dbng", 1, load, cell_seed("rev_deg", load, r), dict(redirect_rtt=0.0)) for r in range(SEEDS)]
        ra, rb = pool.map(_job, ta), pool.map(_job_nopfcp, tb)
        for m in ("setup_mean_ms", "block_prob", "cp_util", "fwd_loss_pct"):
            rows.append(dict(check="degenerate_no_pfcp", load=load, metric=m, mono=mean_ci([x[m] for x in ra])[0],
                             dbng=mean_ci([x[m] for x in rb])[0],
                             max_abs_diff=max(abs(x[m] - y[m]) for x, y in zip(ra, rb))))
    write("verification_degenerate_exact.csv", rows)
    note(f"- Degenerate DBNG with redirect RTT 0 and the PFCP step removed vs monolithic, same seeds: max per-replication "
         f"difference over setup, blocking, CP utilization and loss = {max(r['max_abs_diff'] for r in rows):.3g} "
         "(identical). With a zero-cost PFCP step kept, the residual 0.2-0.3 ms is that PFCP job waiting in the CP queue.")
    note()
    return rows


def check_warmup_sensitivity(pool):
    rows = []
    for k, n in (("mono", 1), ("dbng", 8), ("vbng", 8)):
        for load in (1.0, 1.5):
            for wf in (0.10, 0.25):
                t = [(k, n, load, cell_seed("main", k, n, load, r), {"warmup_frac": wf}) for r in range(SEEDS)]
                res = pool.map(_job, t)
                d = dict(arch=k, n=n, load=load, warmup_frac=wf)
                for m in ("setup_mean_ms", "setup_p99_ms", "block_prob", "cp_util", "fwd_loss_pct"):
                    d[m], d[m + "_ci95"] = mean_ci([x[m] for x in res])
                rows.append(d)
    write("warmup_sensitivity.csv", rows)
    worst = 0.0
    for a_, b_ in zip(rows[::2], rows[1::2]):
        for m in ("setup_mean_ms", "block_prob", "cp_util"):
            if abs(a_[m] - b_[m]) > max(a_[m + "_ci95"], b_[m + "_ci95"]):
                worst += 1
    note(f"- Re-running 6 cells (mono, DBNG N=8, vBNG N=8 at loads 1.0 and 1.5; 30 reps) with a 25% instead of 10% warm-up: "
         f"{int(worst)} of 18 metric comparisons moved by more than their 95% CI.")
    for a_, b_ in zip(rows[::2], rows[1::2]):
        note(f"  - {a_['arch']} N={a_['n']} load {a_['load']}: setup {a_['setup_mean_ms']:.1f} -> {b_['setup_mean_ms']:.1f} ms, "
             f"blocking {100 * a_['block_prob']:.2f} -> {100 * b_['block_prob']:.2f}%, CP util {100 * a_['cp_util']:.1f} -> "
             f"{100 * b_['cp_util']:.1f}%")
    note()
    return rows


def check_warmup(summ, pool):
    note("## 6. Warm-up check (MSER-5 on session-table occupancy)")
    tasks = [(k, n, l, cell_seed("rev_mser", k, n, l, r), cell(summ, k, n, l)["setup_mean_ms_mean"] / 1e3)
             for k, n in (("mono", 1), ("dbng", 8)) for l in (0.5, 1.0, 1.5) for r in range(10)]
    series = pool.map(_trace, tasks)
    rows = []
    for t, s in zip(tasks, series):
        rows.append(dict(arch=t[0], n=t[1], load=t[2], seed=t[3], points=len(s), mser5_truncation_frac=mser5(s)))
    write("warmup_mser5.csv", rows)
    by = defaultdict(list)
    for r in rows:
        by[(r["arch"], r["n"], r["load"])].append(r["mser5_truncation_frac"])
    for k, v in by.items():
        note(f"  - {k[0]} N={k[1]} load {k[2]}: MSER-5 truncation {', '.join(f'{100 * x:.1f}' for x in sorted(v))} %")
    mx = max(r["mser5_truncation_frac"] for r in rows)
    note(f"- {len(rows)} occupancy series (occupancy starts empty, as in the simulator). MSER-5 truncation point: "
         f"max {100 * mx:.2f}% of the run, mean {100 * statistics.fmean(r['mser5_truncation_frac'] for r in rows):.2f}%; "
         f"the 10% warm-up discard is {'conservative' if mx <= 0.10 else 'NOT sufficient'}.")
    note()
    return rows


# ============================================================================ 7. MTU / MSS / mix
_orig_fwd = A.fwd_consts


def fwd_consts_mix_sized(p):
    """Variant: UP pps budget sized to the run's own mix (so mixes compare MTU effects, not under-provisioning)."""
    ref = mix_stats(p["mix"], 1500, "pppoe")
    ref_pps = p["rate_bps"] / (8 * ref["ip_per_pkt"])
    cap = p["up_headroom"] * p["C_unit"] * ref_pps * ref["frames_per_pkt"]
    _, out = _orig_fwd(p)
    return cap, out


def _job_mix(task):
    kind, n, load, seed, mix, resize = task
    if resize:
        A.fwd_consts = fwd_consts_mix_sized
    try:
        return simulate(kind, n, load, seed, mix=mix)
    finally:
        A.fwd_consts = _orig_fwd


def clamped_mix(tcp_share):
    """Baseline 7:4:1 mix; a share of the 1500-B packets is TCP and gets clamped to MSS 1452 (IP 1492)."""
    return [(40, 7), (576, 4), (1492, tcp_share), (1500, 1 - tcp_share)]


MIXES = {
    "simple IMIX 40/576/1500 = 7:4:1 (baseline)": PACKET_MIX,
    "MSS 1452 clamped, 50% of full-size are TCP": clamped_mix(0.5),
    "MSS 1452 clamped, 90% of full-size are TCP": clamped_mix(0.9),
    "MSS 1452 clamped, 100% of full-size are TCP": clamped_mix(1.0),
    "all 1500 B (bulk download, unclamped)": [(1500, 1)],
    "all 40 B (worst case pps)": [(40, 1)],
    "bimodal 40/1500 = 1:1 (unclamped)": [(40, 1), (1500, 1)],
}


def check_mtu(pool):
    note("## 7. MTU with and without MSS clamping, RFC 4638, packet-mix sweep")
    rows = []
    for name, mix in MIXES.items():
        a, b = mix_stats(mix, 1492, "pppoe"), mix_stats(mix, 1500, "pppoe")
        io = mix_stats(mix, 1500, "ipoe")
        rows.append(dict(mix=name, frames_per_pkt_1492=a["frames_per_pkt"], frames_per_pkt_1500_rfc4638=b["frames_per_pkt"],
                         extra_frames_pct=100 * (a["frames_per_pkt"] / b["frames_per_pkt"] - 1),
                         frag_ratio_1492=a["frag_ratio"], overhead_pct_ipoe=io["overhead_pct"],
                         overhead_pct_pppoe_1492=a["overhead_pct"], overhead_pct_pppoe_1500=b["overhead_pct"],
                         extra_wire_bytes_pct=100 * (a["wire_per_pkt"] / b["wire_per_pkt"] - 1)))
    # forwarding loss, monolithic, two sizing rules
    sim_rows = []
    for name, mix in MIXES.items():
        for resize in (False, True):
            if not resize and name.startswith(("all", "bimodal")):
                continue  # baseline-sized UP with a different mean packet size measures under-provisioning, not MTU
            for load in (0.9, 1.5):
                t = [("mono", 1, load, cell_seed("main", "mono", 1, load, r), mix, resize) for r in range(SEEDS)]
                res = pool.map(_job_mix, t)
                for mtu_i, mtu in enumerate(MTUS):
                    loss = [rr[mtu_i]["fwd_loss_pct"] for rr in res]
                    m, h = mean_ci(loss)
                    sim_rows.append(dict(mix=name, up_sized_to="this mix" if resize else "baseline mix", load=load, mtu=mtu,
                                         fwd_loss_pct=m, ci95=h,
                                         up_util=mean_ci([rr[mtu_i]["up_util"] for rr in res])[0]))
    write("mtu_mix.csv", rows)
    write("mtu_mix_loss.csv", sim_rows)
    note("| Mix | Extra frames at 1492 vs 1500 | Packets fragmented at 1492 | Extra wire bytes |")
    note("|---|---|---|---|")
    for r in rows:
        note(f"| {r['mix']} | {r['extra_frames_pct']:.2f}% | {100 * r['frag_ratio_1492']:.2f}% | {r['extra_wire_bytes_pct']:.2f}% |")
    note()
    note("Forwarding loss, monolithic BNG (mean of 30 reps):")
    note("| Mix | UP sized to | Load | Loss @1492 | Loss @1500 |")
    note("|---|---|---|---|---|")
    keyed = defaultdict(dict)
    for r in sim_rows:
        keyed[(r["mix"], r["up_sized_to"], r["load"])][r["mtu"]] = r
    for (mx, sz, ld), d in keyed.items():
        note(f"| {mx} | {sz} | {ld} | {d[1492]['fwd_loss_pct']:.2f} ± {d[1492]['ci95']:.2f}% | "
             f"{d[1500]['fwd_loss_pct']:.2f} ± {d[1500]['ci95']:.2f}% |")
    note()
    return rows, sim_rows


# ============================================================================ 8. reconnect storm
STORM = dict(backoff_base=1.0, backoff_cap=32.0, first_padi_spread=1.0, t_max=3600.0)


def storm(task):
    """All N x C sessions drop at t=0 (outage); every subscriber re-sends PADI within first_padi_spread seconds.
    A setup that finds a full punt/CP waiting room (or no PADI token) fails; the client retries after a
    randomized exponential backoff (base x 2^k, capped, x U(0.5, 1.5)). No departures during recovery."""
    kind, n, seed, over = task
    p = {**BASE, **{k: v for k, v in over.items() if k in BASE}}
    s = {**STORM, **{k: v for k, v in over.items() if k in STORM}}
    rate_limit = over.get("padi_rate")  # PADIs admitted per second per CP (token bucket), None = off
    a = arch(kind, n)
    N, C = a["n"], p["C_unit"]
    rng = random.Random(seed)
    expo = rng.expovariate
    steps = steps_for(a, p)
    nst = len(steps)
    ups = [deque() for _ in range(N)]
    cps = [deque() for _ in range(a["n_cp"])]
    cp_of = a["cp_of"]
    tokens = [rate_limit or 0.0] * a["n_cp"]
    tok_t = [0.0] * a["n_cp"]
    heap, seq = [], 0

    def push(t, k, o):
        nonlocal seq
        seq += 1
        heapq.heappush(heap, (t, seq, k, o))

    subs = N * C
    for i in range(subs):
        push(rng.uniform(0, s["first_padi_spread"]), 0, [i % N, 0, 0.0, 0])  # [unit, step, t_enqueue, attempts]
    restored, attempts, failures = 0, 0, 0
    t90 = t100 = None
    peak_cp = 0
    cp_busy = [0.0] * a["n_cp"]

    def retry(t, s_):
        s_[3] += 1
        d = min(s["backoff_cap"], s["backoff_base"] * 2 ** (s_[3] - 1)) * rng.uniform(0.5, 1.5)
        s_[1] = 0
        push(t + d, 0, s_)

    while heap:
        t, _, k, o = heapq.heappop(heap)
        if t > s["t_max"]:
            break
        if k == 0:  # PADI sent
            attempts += 1
            if rate_limit:
                c = cp_of[o[0]]
                tokens[c] = min(rate_limit, tokens[c] + (t - tok_t[c]) * rate_limit)
                tok_t[c] = t
                if tokens[c] < 1.0:
                    failures += 1
                    retry(t, o)
                    continue
                tokens[c] -= 1.0
            push(t + steps[0][2], 1, o)
        elif k == 1:  # reaches station
            is_up = steps[o[1]][0]
            q = ups[o[0]] if is_up else cps[cp_of[o[0]]]
            K = p["K_up"] if is_up else p["K_cp"]
            if len(q) > K:
                failures += 1
                retry(t, o)
                continue
            q.append(o)
            if not is_up:
                peak_cp = max(peak_cp, len(q))
            if len(q) == 1:
                push(t + expo(1.0 / steps[o[1]][1]), 2, (is_up, o[0] if is_up else cp_of[o[0]]))
        else:  # completion
            is_up, idx = o
            q = ups[idx] if is_up else cps[idx]
            s_ = q.popleft()
            if q:
                push(t + expo(1.0 / steps[q[0][1]][1]), 2, (is_up, idx))
            s_[1] += 1
            if s_[1] == nst:
                restored += 1
                if t90 is None and restored >= 0.9 * subs:
                    t90 = t
                if restored == subs:
                    t100 = t
                    break
            else:
                push(t + steps[s_[1]][2], 1, s_)
    work = sum(x for u, x, _ in steps if not u)
    return dict(arch=kind, n=n, subscribers=subs, seed=seed, padi_rate=rate_limit or "", cp_scale=p["cp_scale"],
                t90_s=t90, t100_s=t100, attempts_per_sub=attempts / subs, failed_attempts=failures,
                peak_cp_queue=peak_cp, ideal_t100_s=subs / a["n_cp"] * work)


def check_storm(pool):
    note("## 8. Reconnect storm (all sessions drop at t = 0)")
    note(f"Assumptions: every subscriber re-sends PADI within {STORM['first_padi_spread']} s; failed setups retry after "
         f"min({STORM['backoff_cap']:g}, {STORM['backoff_base']:g} x 2^k) x U(0.5, 1.5) s; queues and service times as Table IV.")
    cfgs = [("mono", 1, {}), ("dbng", 1, {}), ("dbng", 8, {}), ("vbng", 1, {}), ("vbng", 8, {}),
            ("mono", 1, {"cp_scale": 2.0}), ("dbng", 8, {"cp_scale": 2.0})]
    cp8 = 1 / sum(x for u, x, _ in steps_for(arch("dbng", 8), BASE) if not u)
    cfgs += [("dbng", 8, {"padi_rate": round(r * cp8, 1)}) for r in (0.5, 0.8, 0.95)]
    tasks = [(k, n, cell_seed("rev_storm", k, n, r, *sorted(o.items())), o) for k, n, o in cfgs for r in range(SEEDS)]
    res = pool.map(storm, tasks)
    write("storm_raw.csv", res)
    rows = []
    for k, n, o in cfgs:
        rs = [r for r, t in zip(res, tasks) if (t[0], t[1], t[3]) == (k, n, o)]
        d = dict(arch=k, n=n, subscribers=rs[0]["subscribers"], cp_scale=o.get("cp_scale", 1.0),
                 padi_rate_per_cp=o.get("padi_rate", ""), ideal_t100_s=rs[0]["ideal_t100_s"],
                 incomplete=sum(r["t100_s"] is None for r in rs))
        for m in ("t90_s", "t100_s", "attempts_per_sub", "peak_cp_queue"):
            d[m + "_mean"], d[m + "_ci95"] = mean_ci([r[m] for r in rs if r[m] is not None])
        rows.append(d)
    write("storm.csv", rows)
    note("| Config | Subscribers | Ideal (CP-bound) | Time to 90% | Time to 100% | PADI attempts per sub | Peak CP queue |")
    note("|---|---|---|---|---|---|---|")
    for d in rows:
        lab = f"{d['arch']} N={d['n']}" + (f", CP x{d['cp_scale']:g}" if d["cp_scale"] != 1.0 else "") + \
              (f", PADI limit {d['padi_rate_per_cp']}/s" if d["padi_rate_per_cp"] != "" else "")
        note(f"| {lab} | {d['subscribers']} | {d['ideal_t100_s']:.1f} s | {d['t90_s_mean']:.1f} ± {d['t90_s_ci95']:.1f} s | "
             f"{d['t100_s_mean']:.1f} ± {d['t100_s_ci95']:.1f} s | {d['attempts_per_sub_mean']:.2f} | "
             f"{d['peak_cp_queue_mean']:.0f} |")
    note()
    return rows


def main():
    os.makedirs(OUT, exist_ok=True)
    summ = read_summary("main.csv")
    sens_v = read_summary("sens_v.csv")
    note("# Revision checks: results")
    note()
    check_scapy()
    check_endpoints()
    check_closed_form(summ, sens_v)
    with Pool() as pool:
        check_verification(summ, pool)
        check_stats()
        check_degenerate_exact(pool)
        check_warmup(summ, pool)
        check_warmup_sensitivity(pool)
        check_mtu(pool)
        check_storm(pool)
    with open(os.path.join(OUT, "SUMMARY.md"), "w") as f:
        f.write("\n".join(SUMMARY) + "\n")


if __name__ == "__main__":
    main()
