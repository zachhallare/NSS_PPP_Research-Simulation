"""Termination architectures and the session-level discrete-event simulator (stdlib heapq).

Model (all values are stated assumptions, see BASE and PHASES; nothing here is measured hardware):
- Poisson session arrivals; each subscriber is attached to one unit (UP / instance) uniformly at random.
- Finite session table of C_unit per unit; a slot is reserved from PADI until departure.
- Each of 5 setup phases = propagation delay -> UP punt queue -> CP queue (FIFO, exponential service,
  finite buffers K_up / K_cp; a full buffer fails the setup, counted as blocking).
- DBNG: one CP for all UPs; each phase adds the UP<->CP redirect RTT; after IPCP a PFCP session
  establishment costs one more CP job, one redirect RTT and one UP programming job.
- vBNG: N independent software BNGs (own CP + UP each); all service times x v, forwarding capacity / v.
- Forwarding is a fluid model: established sessions offer rate_bps of IP traffic; per-packet frame
  counts and wire bytes come from byte-exact frames (model.mix_stats); delivered = min(offered, capacity).
"""
import heapq
import math
import random
from collections import deque

from .model import mix_stats
from .traffic import PACKET_MIX, holding_sampler

PHASES = (  # (name, mean CP service time s, extra propagation delay s)
    ("PADI/PADO", 0.001, 0.0),
    ("PADR/PADS", 0.001, 0.0),
    ("LCP", 0.002, 0.0),
    ("PAP/CHAP", 0.010, 0.010),  # + RADIUS round trip to the AAA server
    ("IPCP", 0.005, 0.0),
)

BASE = dict(
    C_unit=200,          # session-table slots per unit (scaled-down model)
    H_mean=60.0,         # mean holding time, s (compressed time scale, see paper Sec. IV)
    H_cv=1.5,            # holding-time coefficient of variation (lognormal)
    access_rtt=0.002,    # RG <-> BNG round trip per phase, s
    redirect_rtt=0.010,  # DBNG UP <-> CP round trip per phase, s (~1000 km of fibre)
    punt_s=0.0002,       # UP punt/redirect service per control packet, s
    pfcp_cp_s=0.005,     # DBNG PFCP session establishment, CP side, s
    pfcp_up_s=0.001,     # DBNG PFCP rule programming, UP side, s
    K_up=32, K_cp=64,    # waiting-room size of punt and CP queues
    v=1.25,              # vBNG virtualization overhead factor
    cp_scale=1.0,        # multiplier on all CP service times (sensitivity)
    rate_bps=2e6,        # offered IP rate per established session
    up_headroom=1.05,    # UP pps capacity = 1.05 x full table at MTU 1500 (baseline mix)
    up_bps_cap=1e9,      # UP line rate (wire bits/s); not binding in the baseline
    mix=PACKET_MIX,
    min_arrivals=10_000, warmup_frac=0.10, min_holding_times=60,  # 20 H was too short for N>=4 (biased blocking)
)
MTUS = (1492, 1500)
ARCHS = [("mono", 1)] + [(k, n) for k in ("dbng", "vbng") for n in (1, 2, 4, 8)]


def arch(kind, n):
    if kind == "mono":
        return dict(kind=kind, n=1, n_cp=1, cp_of=(0,), redirect=False, pfcp=False, virt=False)
    if kind == "dbng":
        return dict(kind=kind, n=n, n_cp=1, cp_of=(0,) * n, redirect=True, pfcp=True, virt=False)
    if kind == "vbng":
        return dict(kind=kind, n=n, n_cp=n, cp_of=tuple(range(n)), redirect=False, pfcp=False, virt=True)
    raise ValueError(kind)


def steps_for(a, p):
    """(is_up_station, mean service s, delay before s). A phase's propagation delays are lumped before it."""
    f = p["v"] if a["virt"] else 1.0
    red = p["redirect_rtt"] if a["redirect"] else 0.0
    st = []
    for _, cp_s, extra in PHASES:
        st.append((True, p["punt_s"] * f, p["access_rtt"] + extra + red))
        st.append((False, cp_s * p["cp_scale"] * f, 0.0))
    if a["pfcp"]:
        st.append((False, p["pfcp_cp_s"] * p["cp_scale"], 0.0))
        st.append((True, p["pfcp_up_s"], red))
    return tuple(st)


def fwd_consts(p):
    """UP pps capacity and per-session forwarding constants per MTU (PPPoE/5WE: identical bytes)."""
    ref = mix_stats(PACKET_MIX, 1500, "pppoe")
    ref_pps = p["rate_bps"] / (8 * ref["ip_per_pkt"])
    cap_pps = p["up_headroom"] * p["C_unit"] * ref_pps * ref["frames_per_pkt"]
    out = {}
    for mtu in MTUS:
        s = mix_stats(p["mix"], mtu, "pppoe")
        pps = p["rate_bps"] / (8 * s["ip_per_pkt"])
        out[mtu] = dict(fps=pps * s["frames_per_pkt"], wire_bps=pps * s["wire_per_pkt"] * 8,
                        frag_ratio=s["frag_ratio"], overhead_pct=s["overhead_pct"])
    return cap_pps, out


class Station:
    __slots__ = ("K", "q", "t", "n_area", "busy_area", "acc", "done", "soj")

    def __init__(self, K):
        self.K, self.q = K, deque()
        self.reset(0.0)

    def reset(self, now):
        self.t, self.n_area, self.busy_area, self.acc, self.done, self.soj = now, 0.0, 0.0, 0, 0, 0.0

    def tick(self, now):
        dt = now - self.t
        if dt > 0:
            n = len(self.q)
            self.n_area += n * dt
            if n:
                self.busy_area += dt
            self.t = now


def simulate(kind, n, load, seed, **over):
    p = {**BASE, **over}
    a = arch(kind, n)
    N, C = a["n"], p["C_unit"]
    rng = random.Random(seed)
    expo, hold = rng.expovariate, holding_sampler(rng, p["H_mean"], p["H_cv"])
    lam = load * N * C / p["H_mean"]
    total = max(math.ceil(p["min_arrivals"] / (1 - p["warmup_frac"])) + 1,
                math.ceil(p["min_holding_times"] * lam * p["H_mean"]))
    n_warm = int(total * p["warmup_frac"])
    steps = steps_for(a, p)
    nsteps = len(steps)
    cap_pps, fw = fwd_consts(p)
    if a["virt"]:
        cap_pps /= p["v"]
    cap_bps = p["up_bps_cap"]

    ups = [Station(p["K_up"]) for _ in range(N)]
    cps = [Station(p["K_cp"]) for _ in range(a["n_cp"])]
    cp_of = a["cp_of"]
    occ, est = [0] * N, [0] * N
    ut = [0.0] * N
    occ_area, est_area = [0.0] * N, [0.0] * N
    deliv = {m: [0.0] * N for m in MTUS}
    util = {m: [0.0] * N for m in MTUS}

    def touch(u, now):
        dt = now - ut[u]
        if dt > 0:
            e = est[u]
            occ_area[u] += occ[u] * dt
            est_area[u] += e * dt
            if e:
                for m in MTUS:
                    off, offb = e * fw[m]["fps"], e * fw[m]["wire_bps"]
                    r = max(off / cap_pps, offb / cap_bps)
                    deliv[m][u] += (e if r <= 1 else e / r) * dt
                    util[m][u] += (r if r < 1 else 1.0) * dt
            ut[u] = now

    heap, seq = [], 0
    lat, hold_sum = [], 0.0
    arrivals = b_table = b_up = b_cp = n_est = 0
    t0 = 0.0

    def push(t, k, o):
        nonlocal seq
        seq += 1
        heapq.heappush(heap, (t, seq, k, o))

    def start(st, now):
        s = st.q[0]
        push(now + expo(1.0 / steps[s[1]][1]), 2, st)

    push(expo(lam), 0, None)
    i_arr = 0
    t = 0.0
    while heap:
        t, _, k, o = heapq.heappop(heap)
        if k == 0:  # session arrival (PADI)
            i_arr += 1
            if i_arr == total:
                break
            if i_arr == n_warm + 1:  # end of warm-up: reset all accumulators
                t0 = t
                for st in ups + cps:
                    st.tick(t)
                    st.reset(t)
                for u in range(N):
                    touch(u, t)
                    occ_area[u] = est_area[u] = 0.0
                    for m in MTUS:
                        deliv[m][u] = util[m][u] = 0.0
            meas = i_arr > n_warm
            arrivals += meas
            u = rng.randrange(N) if N > 1 else 0
            if occ[u] >= C:
                b_table += meas
            else:
                touch(u, t)
                occ[u] += 1
                push(t + steps[0][2], 1, [u, 0, t, meas, 0.0])
            push(t + expo(lam), 0, None)
        elif k == 1:  # session reaches a station
            s = o
            is_up = steps[s[1]][0]
            st = ups[s[0]] if is_up else cps[cp_of[s[0]]]
            if len(st.q) > st.K:  # waiting room full -> setup fails
                touch(s[0], t)
                occ[s[0]] -= 1
                if s[3]:
                    if is_up:
                        b_up += 1
                    else:
                        b_cp += 1
                continue
            st.tick(t)
            st.acc += 1
            s[4] = t
            st.q.append(s)
            if len(st.q) == 1:
                start(st, t)
        elif k == 2:  # station service completion
            st = o
            st.tick(t)
            s = st.q.popleft()
            st.done += 1
            st.soj += t - s[4]
            if st.q:
                start(st, t)
            s[1] += 1
            if s[1] == nsteps:  # session established
                u = s[0]
                touch(u, t)
                est[u] += 1
                h = hold()
                if s[3]:
                    lat.append(t - s[2])
                    hold_sum += h
                    n_est += 1
                push(t + h, 3, s)
            else:
                push(t + steps[s[1]][2], 1, s)
        else:  # departure (PADT)
            u = o[0]
            touch(u, t)
            occ[u] -= 1
            est[u] -= 1

    T = t - t0
    for st in ups + cps:
        st.tick(t)
    for u in range(N):
        touch(u, t)

    lat.sort()
    nl = len(lat)

    def pct(q):
        return lat[max(0, math.ceil(q * nl) - 1)] * 1e3 if nl else float("nan")

    cp0 = cps[0]
    common = dict(
        arch=kind, n=N, load=load, seed=seed, arrivals=arrivals, sim_time_s=T, lam=lam,
        setup_mean_ms=sum(lat) / nl * 1e3 if nl else float("nan"),
        setup_p95_ms=pct(0.95), setup_p99_ms=pct(0.99),
        block_prob=(b_table + b_up + b_cp) / arrivals,
        block_table=b_table / arrivals, block_up=b_up / arrivals, block_cp=b_cp / arrivals,
        carried_erl=sum(occ_area) / T,
        cp_util=sum(c.busy_area for c in cps) / (len(cps) * T),
        cp_util_max=max(c.busy_area for c in cps) / T,
        punt_util=sum(x.busy_area for x in ups) / (N * T),
        little_cp_L=cp0.n_area / T,
        little_cp_lW=(cp0.acc / T) * (cp0.soj / cp0.done) if cp0.done else float("nan"),
        little_sess_L=sum(est_area) / T,
        little_sess_lW=(n_est / T) * (hold_sum / n_est) if n_est else float("nan"),
    )
    rows = []
    for m in MTUS:
        d = sum(deliv[m]) / T  # time-average number of sessions' worth of traffic delivered
        offered = sum(est_area) / T
        rows.append(dict(common, mtu=m,
                         thr_mbps=d * fw[m]["wire_bps"] / 1e6,
                         goodput_mbps=d * p["rate_bps"] / 1e6,
                         thr_kpps=d * fw[m]["fps"] / 1e3,
                         fwd_loss_pct=100 * (1 - d / offered) if offered else 0.0,
                         up_util=sum(util[m]) / (N * T),
                         frag_ratio=fw[m]["frag_ratio"], overhead_pct=fw[m]["overhead_pct"]))
    return rows
