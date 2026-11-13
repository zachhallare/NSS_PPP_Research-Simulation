"""Round-3 revision checks (Nov 2026 panel review). Adds evidence; changes no earlier result.

Run from the project root:   python -m sim.round3_checks
Writes CSVs and SUMMARY.md to results/round3/.

  A. Capacity-matched DBNG: one CP with 8x faster service (cp_scale = 1/8), so total CP capacity equals
     eight vBNG instances. Steady-state (loads 0.5, 1.0, 1.3) and reconnect storm.        [panel REV-14]
  B. Reconnect storm with a finite shared RADIUS/AAA stage (one FIFO server for all units). [panel REV-29]
  C. Blocking versus session-table size: Erlang B at 200, 2,000 and 64,000 slots, load at 1% blocking,
     and a simulation check at 2,000 slots.                                                 [panel REV-27/28]
"""
import csv
import heapq
import math
import os
import random
import statistics
from collections import deque
from multiprocessing import Pool

from .architectures import BASE, arch, simulate, steps_for
from .experiments import SEEDS, cell_seed
from .metrics import erlang_b, mean_ci
from .revision_checks import STORM, storm

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "results", "round3")
LOG = []
MATCHED = 1 / 8


def note(s=""):
    print(s)
    LOG.append(s)


def write(name, rows):
    os.makedirs(OUT, exist_ok=True)
    keys = []
    for r in rows:
        keys += [k for k in r if k not in keys]
    with open(os.path.join(OUT, name), "w", newline="") as f:
        w = csv.DictWriter(f, keys, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def summary_cell(k, n, load, mtu=1492):
    with open(os.path.join(ROOT, "results", "summary", "main.csv")) as f:
        for r in csv.DictReader(f):
            if r["arch"] == k and int(r["n"]) == n and abs(float(r["load"]) - load) < 1e-9 and int(r["mtu"]) == mtu:
                return r
    return None


# ------------------------------------------------------------------ A. capacity-matched DBNG
def _sim(task):
    k, n, load, seed, over = task
    return simulate(k, n, load, seed, **over)[0]


def check_matched(pool):
    note("## A. Capacity-matched DBNG (one CP, service times x 1/8)")
    rows = []
    for load in (0.5, 1.0, 1.3):
        tasks = [("dbng", 8, load, cell_seed("main", "dbng", 8, load, r), {"cp_scale": MATCHED}) for r in range(SEEDS)]
        res = pool.map(_sim, tasks)
        d = dict(config="DBNG N=8, CP x1/8 (matched)", load=load)
        for m in ("setup_mean_ms", "setup_p99_ms", "block_prob", "cp_util"):
            d[m], d[m + "_ci"] = mean_ci([x[m] for x in res])
        rows.append(d)
        for k in ("dbng", "vbng"):
            c = summary_cell(k, 8, load)
            if c:
                rows.append(dict(config=f"{k.upper()} N=8 (baseline, Table XII runs)", load=load,
                                 setup_mean_ms=float(c["setup_mean_ms_mean"]), setup_p99_ms=float(c["setup_p99_ms_mean"]),
                                 block_prob=float(c["block_prob_mean"]), cp_util=float(c["cp_util_mean"])))
    write("matched_steady.csv", rows)
    note("| Config | Load | Mean setup (ms) | p99 setup (ms) | Blocking | CP util |")
    note("|---|---|---|---|---|---|")
    for r in rows:
        note(f"| {r['config']} | {r['load']} | {r['setup_mean_ms']:.1f} | {r['setup_p99_ms']:.1f} | "
             f"{100 * r['block_prob']:.2f}% | {100 * r['cp_util']:.1f}% |")
    cfgs = [("dbng", 8, {}), ("dbng", 8, {"cp_scale": MATCHED}), ("vbng", 8, {}), ("mono", 1, {})]
    tasks = [(k, n, cell_seed("r3_storm", k, n, r, *sorted(o.items())), o) for k, n, o in cfgs for r in range(SEEDS)]
    res = pool.map(storm, tasks)
    srows = []
    for k, n, o in cfgs:
        rs = [x for x, t in zip(res, tasks) if (t[0], t[1], t[3]) == (k, n, o)]
        d = dict(config=f"{k} N={n}" + (" CP x1/8 (matched)" if o else ""), ideal_t100_s=rs[0]["ideal_t100_s"])
        for m in ("t90_s", "t100_s", "attempts_per_sub"):
            d[m], d[m + "_ci"] = mean_ci([x[m] for x in rs if x[m] is not None])
        srows.append(d)
    write("matched_storm.csv", srows)
    note()
    note("| Storm config | CP-bound min (s) | 90% (s) | 100% (s) | PADIs/sub |")
    note("|---|---|---|---|---|")
    for d in srows:
        note(f"| {d['config']} | {d['ideal_t100_s']:.1f} | {d['t90_s']:.1f} ± {d['t90_s_ci']:.1f} | "
             f"{d['t100_s']:.1f} ± {d['t100_s_ci']:.1f} | {d['attempts_per_sub']:.2f} |")
    note()
    return rows, srows


# ------------------------------------------------------------------ B. storm with finite shared AAA
AAA_AFTER = 7  # index of the PAP/CHAP CP step in steps_for(): the CP sends Access-Request after it


def storm_aaa(task):
    """Same storm as revision_checks.storm, plus one shared FIFO AAA server (service s_aaa, waiting room K_aaa)
    visited once per setup right after the PAP/CHAP CP step. A full AAA queue fails the attempt (client retries)."""
    kind, n, seed, over = task
    p = {**BASE, **{k: v for k, v in over.items() if k in BASE}}
    s = dict(STORM)
    s_aaa, K_aaa = over["s_aaa"], over.get("K_aaa", 256)
    a = arch(kind, n)
    N, C = a["n"], p["C_unit"]
    rng = random.Random(seed)
    expo = rng.expovariate
    base_steps = list(steps_for(a, p))
    steps = [("up" if u else "cp", sv, dl) for u, sv, dl in base_steps]
    steps.insert(AAA_AFTER + 1, ("aaa", s_aaa, 0.0))
    nst = len(steps)
    queues = {("up", i): deque() for i in range(N)}
    queues.update({("cp", i): deque() for i in range(a["n_cp"])})
    queues[("aaa", 0)] = deque()
    K = {"up": p["K_up"], "cp": p["K_cp"], "aaa": K_aaa}
    cp_of = a["cp_of"]
    heap, seq = [], 0

    def push(t, k, o):
        nonlocal seq
        seq += 1
        heapq.heappush(heap, (t, seq, k, o))

    def qkey(kind_, unit):
        return (kind_, unit if kind_ == "up" else cp_of[unit] if kind_ == "cp" else 0)

    subs = N * C
    for i in range(subs):
        push(rng.uniform(0, s["first_padi_spread"]), 0, [i % N, 0, 0])
    restored = attempts = 0
    t90 = t100 = None
    peak_aaa = 0

    def retry(t, o):
        o[2] += 1
        d = min(s["backoff_cap"], s["backoff_base"] * 2 ** (o[2] - 1)) * rng.uniform(0.5, 1.5)
        o[1] = 0
        push(t + d, 0, o)

    while heap:
        t, _, k, o = heapq.heappop(heap)
        if t > s["t_max"]:
            break
        if k == 0:
            attempts += 1
            push(t + steps[0][2], 1, o)
        elif k == 1:
            key = qkey(steps[o[1]][0], o[0])
            q = queues[key]
            if len(q) > K[key[0]]:
                retry(t, o)
                continue
            q.append(o)
            if key[0] == "aaa":
                peak_aaa = max(peak_aaa, len(q))
            if len(q) == 1:
                push(t + expo(1.0 / steps[o[1]][1]), 2, key)
        else:
            q = queues[o]
            s_ = q.popleft()
            if q:
                push(t + expo(1.0 / steps[q[0][1]][1]), 2, o)
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
    return dict(arch=kind, n=n, s_aaa=s_aaa, cp_scale=p["cp_scale"], subscribers=subs, t90_s=t90, t100_s=t100,
                attempts_per_sub=attempts / subs, peak_aaa_queue=peak_aaa, aaa_bound_s=subs * s_aaa)


def check_aaa(pool):
    note("## B. Reconnect storm with a finite shared RADIUS/AAA server")
    rows = []
    cfgs = [("mono", 1, {}), ("dbng", 8, {}), ("dbng", 8, {"cp_scale": MATCHED}), ("vbng", 8, {})]
    for s_aaa in (0.002, 0.010):
        tasks = [(k, n, cell_seed("r3_aaa", k, n, s_aaa, r, *sorted(o.items())), {**o, "s_aaa": s_aaa})
                 for k, n, o in cfgs for r in range(SEEDS)]
        res = pool.map(storm_aaa, tasks)
        for k, n, o in cfgs:
            rs = [x for x, t in zip(res, tasks) if (t[0], t[1]) == (k, n) and t[3].get("cp_scale") == o.get("cp_scale")]
            d = dict(config=f"{k} N={n}" + (" CP x1/8 (matched)" if o else ""), aaa_capacity_per_s=round(1 / s_aaa),
                     aaa_bound_s=rs[0]["aaa_bound_s"], incomplete=sum(x["t100_s"] is None for x in rs))
            for m in ("t90_s", "t100_s", "attempts_per_sub", "peak_aaa_queue"):
                vals = [x[m] for x in rs if x[m] is not None]
                d[m], d[m + "_ci"] = mean_ci(vals) if vals else (float("nan"), 0.0)
            rows.append(d)
    write("storm_aaa.csv", rows)
    note("| Config | AAA auth/s | AAA-bound min (s) | 90% (s) | 100% (s) | PADIs/sub | Peak AAA queue |")
    note("|---|---|---|---|---|---|---|")
    for d in rows:
        note(f"| {d['config']} | {d['aaa_capacity_per_s']} | {d['aaa_bound_s']:.1f} | {d['t90_s']:.1f} ± {d['t90_s_ci']:.1f} | "
             f"{d['t100_s']:.1f} ± {d['t100_s_ci']:.1f} | {d['attempts_per_sub']:.2f} | {d['peak_aaa_queue']:.0f} |")
    note()
    return rows


# ------------------------------------------------------------------ C. blocking vs table size
def erlang_b_large(A, C):
    inv = 1.0
    for k in range(1, C + 1):
        inv = 1.0 + inv * k / A
    return 1.0 / inv


def load_at_blocking(C, target=0.01):
    lo, hi = 0.01, 2.0
    for _ in range(60):
        mid = (lo + hi) / 2
        if erlang_b_large(mid * C, C) < target:
            lo = mid
        else:
            hi = mid
    return lo


def check_table_size(pool):
    note("## C. Blocking versus session-table size (Erlang B, mean holding time only)")
    rows = []
    for C in (200, 2000, 64000):
        d = dict(slots=C, load_at_1pct_blocking=load_at_blocking(C))
        for load in (0.8, 0.9, 1.0, 1.1):
            d[f"blocking_at_{load}"] = erlang_b_large(load * C, C)
        rows.append(d)
    write("table_size_erlang.csv", rows)
    note("| Slots | Load at 1% blocking | Blocking @0.8 | @0.9 | @1.0 | @1.1 |")
    note("|---|---|---|---|---|---|")
    for d in rows:
        note(f"| {d['slots']:,} | {d['load_at_1pct_blocking']:.3f} | {100 * d['blocking_at_0.8']:.3f}% | "
             f"{100 * d['blocking_at_0.9']:.3f}% | {100 * d['blocking_at_1.0']:.2f}% | {100 * d['blocking_at_1.1']:.2f}% |")
    sim = []
    for load in (0.9, 1.0):
        tasks = [("mono", 1, load, cell_seed("r3_tbl", load, r), {"C_unit": 2000}) for r in range(10)]
        res = pool.map(_sim, tasks)
        m, h = mean_ci([x["block_prob"] for x in res])
        sim.append(dict(slots=2000, load=load, sim_blocking=m, ci=h, erlang_b=erlang_b_large(load * 2000, 2000),
                        setup_mean_ms=statistics.fmean(x["setup_mean_ms"] for x in res),
                        cp_util=statistics.fmean(x["cp_util"] for x in res)))
    write("table_size_sim.csv", sim)
    note()
    for d in sim:
        note(f"- Simulation, monolithic BNG, 2,000 slots, load {d['load']}: blocking {100 * d['sim_blocking']:.2f} ± "
             f"{100 * d['ci']:.2f}% (10 reps) vs Erlang B {100 * d['erlang_b']:.2f}%; CP util {100 * d['cp_util']:.1f}%.")
    note()
    return rows, sim


def main():
    os.makedirs(OUT, exist_ok=True)
    note("# Round-3 checks: results")
    note()
    with Pool() as pool:
        check_table_size(pool)
        check_matched(pool)
        check_aaa(pool)
    with open(os.path.join(OUT, "SUMMARY.md"), "w") as f:
        f.write("\n".join(LOG) + "\n")


if __name__ == "__main__":
    main()
