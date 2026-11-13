"""Experiment matrix, validation, sensitivity, figures and manifest. Entry point: python experiments.py --all"""
import csv
import hashlib
import os
import platform
import random
import sys
import time
import zlib
from collections import defaultdict
from multiprocessing import Pool

from . import test_frames
from .architectures import ARCHS, BASE, MTUS, PHASES, arch, fwd_consts, simulate, steps_for
from .metrics import crossing, erlang_b, mean_ci, paired_significant, welch_significant
from .model import LegacyAccessNode, VerPolicingNode, build_frames, fragment_sizes, fragments, mix_stats
from .traffic import PACKET_MIX, mix_with_full_share

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW, SUM, FIG = (os.path.join(ROOT, *p) for p in (("results", "raw"), ("results", "summary"), ("figures",)))
LOADS = (0.1, 0.3, 0.5, 0.7, 0.8, 0.9, 1.0, 1.1, 1.3, 1.5)  # x nominal capacity (N x C_unit sessions)
SEEDS = 30
METRICS = ("setup_mean_ms", "setup_p95_ms", "setup_p99_ms", "block_prob", "block_table", "block_up",
           "block_cp", "carried_erl", "cp_util", "cp_util_max", "punt_util", "thr_mbps", "goodput_mbps",
           "thr_kpps", "fwd_loss_pct", "up_util", "frag_ratio", "overhead_pct", "arrivals", "sim_time_s")
SENS = {  # tag: (param, values, [(arch, n)], loads)
    "sens_cp": ("cp_scale", (0.5, 1.0, 2.0, 4.0), [("mono", 1), ("dbng", 8)], LOADS),
    "sens_v": ("v", (1.0, 1.1, 1.25, 1.5), [("vbng", 4)], (0.5, 0.9, 1.3)),
    "sens_rtt": ("redirect_rtt", (0.002, 0.010, 0.040), [("dbng", 4)], (0.5, 0.9, 1.3)),
    "sens_cv": ("H_cv", (0.0, 0.5, 1.5, 3.0), [("mono", 1)], (0.7, 0.9, 1.1)),
}


def cell_seed(*key):
    return zlib.crc32("|".join(map(str, key)).encode())


def _run(task):
    tag, kind, n, load, rep, over = task
    seed = cell_seed(tag, kind, n, load, rep, *sorted(over.items()))
    rows = simulate(kind, n, load, seed, **over)
    for r in rows:
        r.update(tag=tag, rep=rep, **{"param_" + k: v for k, v in over.items()})
    return rows


def run(tasks, pool):
    return [r for rows in pool.map(_run, tasks, chunksize=4) for r in rows]


def write_csv(name, rows, folder=SUM):
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, name)
    keys = list(rows[0].keys())
    for r in rows:
        keys += [k for k in r if k not in keys]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, keys, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    return path


def summarize(rows, keys, metrics=METRICS):
    groups = defaultdict(list)
    for r in rows:
        groups[tuple(r[k] for k in keys)].append(r)
    out = []
    for g, rs in groups.items():
        d = dict(zip(keys, g), reps=len(rs))
        for m in metrics:
            d[m + "_mean"], d[m + "_ci95"] = mean_ci([r[m] for r in rs])
        out.append(d)
    return out


# ----------------------------------------------------------------------------- frame-level experiments
def frame_experiments():
    val = []
    for ip_len in (1400, 1492, 1500):
        for mtu in (1492, 1500):
            fr = build_frames(ip_len, mtu, "pppoe")
            val.append(dict(ip_len=ip_len, mtu=mtu, demo_fragments=fragments(ip_len, mtu),
                            sim_fragments=len(fr), fragment_ip_lengths=" ".join(map(str, fragment_sizes(ip_len, mtu))),
                            frame_lengths=" ".join(str(len(f)) for f in fr), match=fragments(ip_len, mtu) == len(fr)))
    write_csv("frame_fragment_validation.csv", val)

    n_ident = test_frames.test_byte_identical_to_demo()
    for t in (test_frames.test_matches_demo_pcap, test_frames.test_rfc8822_header_facts,
              test_frames.test_fragments_match_demo, test_frames.test_access_nodes):
        t()
    write_csv("frame_byte_identity.csv", [dict(frames_compared=n_ident + 18, identical=n_ident + 18,
                                               pcap_match=True, rfc8822_fields=True)])

    over = []
    for encap, mtu in (("ipoe", 1500), ("pppoe", 1492), ("5we", 1492), ("pppoe", 1500), ("5we", 1500)):
        s = mix_stats(PACKET_MIX, mtu, encap)
        over.append(dict(encap=encap, ip_mtu=mtu, eth_payload=mtu + (8 if encap != "ipoe" else 0), **s,
                         wire_efficiency_pct=100 * s["ip_per_pkt"] / s["wire_per_pkt"]))
    write_csv("frame_overhead.csv", over)

    sens = []
    for share in (0.0, 1 / 12, 0.25, 0.5):
        a, b = mix_stats(mix_with_full_share(share), 1492, "pppoe"), mix_stats(mix_with_full_share(share), 1500, "pppoe")
        sens.append(dict(share_1500B=share, frames_per_pkt_1492=a["frames_per_pkt"], frames_per_pkt_1500=b["frames_per_pkt"],
                         extra_frames_pct=100 * (a["frames_per_pkt"] / b["frames_per_pkt"] - 1),
                         wire_per_pkt_1492=a["wire_per_pkt"], wire_per_pkt_1500=b["wire_per_pkt"],
                         extra_wire_bytes_pct=100 * (a["wire_per_pkt"] / b["wire_per_pkt"] - 1),
                         overhead_pct_1492=a["overhead_pct"], overhead_pct_1500=b["overhead_pct"]))
    write_csv("sens_mix.csv", sens)

    rng = random.Random(cell_seed("access_node"))
    sizes, weights = zip(*PACKET_MIX)
    counts = defaultdict(lambda: [0, 0, 0])  # sent, forwarded unchanged, dropped
    nodes = {"legacy (Ethertype+SESSION_ID)": LegacyAccessNode(), "negative control (polices VER)": VerPolicingNode()}
    for _ in range(10_000):
        encap = rng.choice(("pppoe", "5we"))
        ip_len = min(rng.choices(sizes, weights)[0], 1492)
        f = build_frames(ip_len, 1492, encap, sid=rng.randrange(1, 0xFFFF), qfi=rng.randrange(64), rqi=rng.randrange(2))[0]
        for name, node in nodes.items():
            _, out = node.forward(f, "subscriber")
            c = counts[(name, encap)]
            c[0] += 1
            c[1] += out == f
            c[2] += out is None
    write_csv("access_node.csv", [dict(node=k[0], encap=k[1], sent=v[0], forwarded_unchanged=v[1], dropped=v[2],
                                       forwarded_pct=100 * v[1] / v[0]) for k, v in sorted(counts.items())])
    return over


# ----------------------------------------------------------------------------- derived tables
def sustainable(rows):
    by = defaultdict(dict)
    for r in rows:
        if r["mtu"] == MTUS[0]:
            by[(r["arch"], r["n"], r["rep"])][r["load"]] = r["block_prob"]
    per = defaultdict(list)
    cens = defaultdict(int)
    for (k, n, rep), d in by.items():
        xs = sorted(d)
        x = crossing(xs, [d[l] for l in xs])
        if x is None:
            cens[(k, n)] += 1
        else:
            per[(k, n)].append(x * n * BASE["C_unit"])
    out = []
    for k, n in ARCHS:
        m, h = mean_ci(per[(k, n)])
        out.append(dict(arch=k, n=n, capacity_sessions=n * BASE["C_unit"], sustainable_erl_mean=m, sustainable_erl_ci95=h,
                        sustainable_load_mean=m / (n * BASE["C_unit"]), reps=len(per[(k, n)]), censored=cens[(k, n)]))
    return out


def significance(rows):
    cell = defaultdict(list)
    for r in rows:
        cell[(r["arch"], r["n"], r["load"], r["mtu"])].append(r)
    out = []
    pairs = [(("mono", 1), ("dbng", 1)), (("mono", 1), ("vbng", 1)), (("dbng", 8), ("vbng", 8)), (("dbng", 1), ("dbng", 8))]
    for load in LOADS:
        for a, b in pairs:
            ra, rb = cell[(*a, load, 1492)], cell[(*b, load, 1492)]
            for m in ("setup_mean_ms", "setup_p99_ms", "block_prob", "cp_util"):
                xa, xb = [r[m] for r in ra], [r[m] for r in rb]
                t, df, sig = welch_significant(xa, xb)
                out.append(dict(test="welch", load=load, a="%s%d" % a, b="%s%d" % b, metric=m,
                                mean_a=mean_ci(xa)[0], mean_b=mean_ci(xb)[0], diff=mean_ci(xa)[0] - mean_ci(xb)[0],
                                t=t, df=df, significant_5pct=sig))
        for k, n in ARCHS:
            r92 = sorted(cell[(k, n, load, 1492)], key=lambda r: r["rep"])
            r00 = sorted(cell[(k, n, load, 1500)], key=lambda r: r["rep"])
            for m in ("fwd_loss_pct", "goodput_mbps", "thr_kpps", "up_util"):
                d, h, sig = paired_significant([r[m] for r in r92], [r[m] for r in r00])
                out.append(dict(test="paired", load=load, a=f"{k}{n}@1492", b=f"{k}{n}@1500", metric=m,
                                mean_a=mean_ci([r[m] for r in r92])[0], mean_b=mean_ci([r[m] for r in r00])[0],
                                diff=d, t=h, df=len(r92) - 1, significant_5pct=sig))
    return out


def _agree(m, h, e):
    """Analytic value inside the 95% CI, or both below 1e-4 (no blocking event observed, CI degenerate)."""
    return abs(m - e) <= h or (m < 1e-4 and e < 1e-4)


def validation(rows, cv_rows):
    out = []
    for r_ in summarize([r for r in rows if r["mtu"] == MTUS[0]], ("arch", "n", "load"),
                        ("little_cp_L", "little_cp_lW", "little_sess_L", "little_sess_lW", "cp_util", "block_prob",
                         "block_table", "lam", "setup_mean_ms")):
        k, n, load = r_["arch"], r_["n"], r_["load"]
        a = arch(k, n)
        cp_work = sum(s for is_up, s, _ in steps_for(a, BASE) if not is_up)
        lam_adm = r_["lam_mean"] * (1 - r_["block_table_mean"])
        out.append(dict(check="little_cp", arch=k, n=n, load=load, measured=r_["little_cp_L_mean"],
                        expected=r_["little_cp_lW_mean"],
                        rel_err_pct=100 * abs(r_["little_cp_L_mean"] / r_["little_cp_lW_mean"] - 1)))
        out.append(dict(check="little_sessions", arch=k, n=n, load=load, measured=r_["little_sess_L_mean"],
                        expected=r_["little_sess_lW_mean"],
                        rel_err_pct=100 * abs(r_["little_sess_L_mean"] / r_["little_sess_lW_mean"] - 1)))
        rho = lam_adm * cp_work / a["n_cp"]
        out.append(dict(check="cp_utilization", arch=k, n=n, load=load, measured=r_["cp_util_mean"], expected=rho,
                        rel_err_pct=100 * abs(r_["cp_util_mean"] / rho - 1)))
        if k == "mono":
            A = r_["lam_mean"] * (BASE["H_mean"] + r_["setup_mean_ms_mean"] / 1e3)
            eb = erlang_b(A, BASE["C_unit"])
            out.append(dict(check="erlang_b", arch=k, n=n, load=load, measured=r_["block_prob_mean"],
                            measured_ci95=r_["block_prob_ci95"], expected=eb,
                            within_ci=_agree(r_["block_prob_mean"], r_["block_prob_ci95"], eb)))
    for r_ in summarize([r for r in cv_rows if r["mtu"] == MTUS[0]], ("param_H_cv", "load"), ("block_prob", "lam")):
        A = r_["lam_mean"] * BASE["H_mean"]
        eb = erlang_b(A, BASE["C_unit"])
        out.append(dict(check="erlang_b_insensitivity", arch="mono", n=1, load=r_["load"], param_H_cv=r_["param_H_cv"],
                        measured=r_["block_prob_mean"], measured_ci95=r_["block_prob_ci95"], expected=eb,
                        within_ci=_agree(r_["block_prob_mean"], r_["block_prob_ci95"], eb)))
    return out


# ----------------------------------------------------------------------------- figures
COL = {"mono": "#2a78d6", "dbng": "#eb6834", "vbng": "#1baf7a"}  # categorical slots 1-3, fixed order
LBL = {"mono": "Monolithic", "dbng": "DBNG (CUPS)", "vbng": "vBNG"}
INK, MUTED, GRID = "#0b0b0b", "#6b6a64", "#e1e0d9"


def _style(plt):
    plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "DejaVu Serif"], "font.size": 8,
                         "axes.edgecolor": "#c3c2b7", "axes.labelcolor": INK, "xtick.color": MUTED, "ytick.color": MUTED,
                         "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.5, "axes.spines.top": False,
                         "axes.spines.right": False, "legend.frameon": False, "lines.linewidth": 1.4,
                         "lines.markersize": 4, "savefig.dpi": 300})


def _series(summ, k, n, metric, mtu=1492):
    pts = sorted((r["load"], r[metric + "_mean"], r[metric + "_ci95"]) for r in summ
                 if r["arch"] == k and r["n"] == n and r["mtu"] == mtu)
    return [p[0] for p in pts], [p[1] for p in pts], [p[2] for p in pts]


def figures(summ, sust, over, sens_cp):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    _style(plt)
    os.makedirs(FIG, exist_ok=True)
    lines = [("mono", 1, "-", "o"), ("dbng", 1, "-", "s"), ("dbng", 8, "--", "s"), ("vbng", 1, "-", "^"), ("vbng", 8, "--", "^")]

    def by_arch(ax, metric, scale=1.0):
        for k, n, ls, mk in lines:
            x, y, h = _series(summ, k, n, metric)
            y, h = [v * scale for v in y], [v * scale for v in h]
            ax.errorbar(x, y, yerr=h, color=COL[k], ls=ls, marker=mk, capsize=1.5, elinewidth=0.6,
                        label=f"{LBL[k]}" + ("" if k == "mono" else f", N={n}"))
        ax.set_xlabel("Offered load (x nominal capacity)")

    fig, axes = plt.subplots(2, 1, figsize=(3.5, 4.6), sharex=True)
    by_arch(axes[0], "setup_mean_ms")
    axes[0].set_ylabel("Mean setup latency (ms)")
    axes[0].set_title("(a) Mean", fontsize=8)
    axes[0].set_xlabel("")
    by_arch(axes[1], "setup_p99_ms")
    axes[1].set_ylabel("p99 setup latency (ms)")
    axes[1].set_title("(b) 99th percentile", fontsize=8)
    axes[1].legend(fontsize=6.5, loc="upper left")
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "fig2_latency_vs_load.png"))
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(3.5, 2.6))
    by_arch(ax, "block_prob", 100)
    ax.plot(LOADS, [100 * erlang_b(l * BASE["C_unit"], BASE["C_unit"]) for l in LOADS], color=MUTED, lw=0.8, ls=":",
            label="Erlang B, C=200 (analytic)")
    ax.axhline(1.0, color=MUTED, lw=0.6)
    ax.text(1.18, 0.7, "1% target", color=MUTED, fontsize=6.5)
    ax.set_yscale("symlog", linthresh=0.1)
    ax.set_ylim(0, 60)
    ax.set_ylabel("Blocking probability (%)")
    ax.legend(fontsize=6, loc="upper left")
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "fig3_blocking_vs_load.png"))
    plt.close(fig)

    fig = plt.figure(figsize=(3.5, 4.6))
    gs = fig.add_gridspec(2, 2)
    axes = [fig.add_subplot(gs[0, 0]), fig.add_subplot(gs[0, 1]), fig.add_subplot(gs[1, :])]
    labels = ["IPoE\n1500", "PPPoE\n1492", "PPPoE\n1500"]
    sel = [o for o in over if o["encap"] in ("ipoe", "pppoe")]
    for ax, key, yl in ((axes[0], "overhead_pct", "Overhead (% of wire bytes)"), (axes[1], "frames_per_pkt", "Frames per IP packet")):
        vals = [o[key] for o in sel]
        ax.bar(labels, vals, color=COL["mono"], width=0.55)
        for i, v in enumerate(vals):
            ax.text(i, v, f"{v:.3f}" if key == "frames_per_pkt" else f"{v:.2f}", ha="center", va="bottom", fontsize=6.5, color=INK)
        ax.set_ylabel(yl, fontsize=7)
        ax.tick_params(axis="x", labelsize=5.5)
        ax.grid(axis="x", visible=False)
    axes[1].set_ylim(0.95, 1.1)
    for mtu, ls in ((1492, "-"), (1500, "--")):
        for k in ("mono", "vbng"):
            x, y, h = _series(summ, k, 1, "fwd_loss_pct", mtu)
            axes[2].errorbar(x, y, yerr=h, color=COL[k], ls=ls, marker="o" if k == "mono" else "^", capsize=1.5,
                             elinewidth=0.6, label=f"{LBL[k]}, MTU {mtu}")
    axes[2].set_xlabel("Offered load (x nominal capacity)")
    axes[2].set_ylabel("Forwarding loss (%)")
    axes[2].legend(fontsize=6)
    for ax, t in zip(axes, "abc"):
        ax.set_title(f"({t})", fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "fig5_mtu_overhead_loss.png"))
    plt.close(fig)

    fig, axes = plt.subplots(2, 1, figsize=(3.5, 4.8))
    Ns = (1, 2, 4, 8)
    for k, mk in (("dbng", "s"), ("vbng", "^")):
        ys = [next(s for s in sust if s["arch"] == k and s["n"] == n) for n in Ns]
        axes[0].errorbar(Ns, [s["sustainable_erl_mean"] for s in ys], yerr=[s["sustainable_erl_ci95"] for s in ys],
                         color=COL[k], marker=mk, capsize=1.5, label=LBL[k])
    m1 = next(s for s in sust if s["arch"] == "mono")
    axes[0].errorbar([1], [m1["sustainable_erl_mean"]], yerr=[m1["sustainable_erl_ci95"]], color=COL["mono"], marker="o",
                     ls="none", label=LBL["mono"])
    axes[0].set_xscale("log", base=2)
    axes[0].set_xticks(Ns, [str(n) for n in Ns])
    axes[0].set_xlabel("Units N (user planes / instances)")
    axes[0].set_ylabel("Sessions at 1% blocking (Erlang)")
    axes[0].set_title("(a) Scale-out", fontsize=8)
    axes[0].legend(fontsize=6.5)
    seq = ["#9ec5f4", "#5a9be6", "#2a78d6", "#0d4a94"]  # one-hue sequential ramp (blue) for cp_scale
    for c, s in zip((0.5, 1.0, 2.0, 4.0), seq):
        pts = sorted((r["load"], r["block_prob_mean"]) for r in sens_cp
                     if r["arch"] == "dbng" and r["param_cp_scale"] == c and r["mtu"] == 1492)
        axes[1].plot([p[0] for p in pts], [100 * p[1] for p in pts], color=s, marker="s", label=f"CP cost x{c:g}")
    axes[1].set_yscale("symlog", linthresh=0.1)
    axes[1].set_ylim(0, 150)
    axes[1].set_xlabel("Offered load (x nominal capacity)")
    axes[1].set_ylabel("Blocking probability (%)")
    axes[1].set_title("(b) DBNG N=8, CP cost sensitivity", fontsize=8)
    axes[1].legend(fontsize=6.5)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "fig4_scale_out.png"))
    plt.close(fig)


# ----------------------------------------------------------------------------- manifest
def manifest(t_start, counts, argv):
    import matplotlib
    import numpy
    lines = ["# Results manifest", "",
             f"- Command: `python {' '.join(argv)}` (from the project root, clean shell)",
             f"- Python {platform.python_version()} ({platform.python_implementation()}), "
             f"matplotlib {matplotlib.__version__}, numpy {numpy.__version__} (plot dependency only), {platform.platform()}",
             "- Simulator: stdlib `heapq` event loop + `random.Random` (Mersenne Twister); no SimPy.",
             f"- Seeds: seed = zlib.crc32('tag|arch|n|load|rep[|param-tuple]'), rep = 0..{SEEDS - 1}; "
             "one seed per replication, shared by MTU 1492 and 1500 (common random numbers).",
             f"- Replication length: >= {BASE['min_arrivals']} measured arrivals and >= {BASE['min_holding_times']} mean "
             f"holding times; first {int(BASE['warmup_frac'] * 100)}% of arrivals discarded as warm-up.",
             f"- Wall time: {time.time() - t_start:.0f} s", "", "## Row counts", ""]
    lines += [f"- `{k}`: {v} rows" for k, v in counts.items()]
    lines += ["", "## Parameters", "", "See `results/summary/parameters.csv`.", "", "## SHA-256 of summary files", ""]
    for f in sorted(os.listdir(SUM)):
        with open(os.path.join(SUM, f), "rb") as fh:
            lines.append(f"- `{f}`: `{hashlib.sha256(fh.read()).hexdigest()}`")
    with open(os.path.join(ROOT, "results", "MANIFEST.md"), "w") as f:
        f.write("\n".join(lines) + "\n")


def parameters():
    p = dict(BASE)
    p.pop("mix")
    rows = [dict(parameter=k, value=v) for k, v in p.items()]
    rows += [dict(parameter=f"cp_service_{name}", value=s) for name, s, _ in PHASES]
    rows += [dict(parameter=f"extra_delay_{name}", value=d) for name, _, d in PHASES]
    rows += [dict(parameter="packet_mix_ip_bytes:weight", value=" ".join(f"{a}:{b}" for a, b in PACKET_MIX))]
    cap, fw = fwd_consts(BASE)
    rows += [dict(parameter="up_pps_capacity_derived", value=cap),
             dict(parameter="vbng_up_pps_capacity_derived", value=cap / BASE["v"])]
    for m in MTUS:
        rows += [dict(parameter=f"per_session_fps_mtu{m}", value=fw[m]["fps"]),
                 dict(parameter=f"per_session_wire_bps_mtu{m}", value=fw[m]["wire_bps"])]
    rows += [dict(parameter="loads", value=" ".join(map(str, LOADS))), dict(parameter="seeds_per_cell", value=SEEDS)]
    for a in ("mono", "dbng", "vbng"):
        st = steps_for(arch(a, 1), BASE)
        rows.append(dict(parameter=f"{a}_cp_work_per_setup_s", value=sum(s for u, s, _ in st if not u)))
        rows.append(dict(parameter=f"{a}_propagation_per_setup_s", value=sum(d for _, _, d in st)))
    return rows


def main(argv=None):
    argv = argv or sys.argv
    if "--figures" in argv:  # redraw from results/summary only, no simulation
        def load(name):
            out = []
            for r in csv.DictReader(open(os.path.join(SUM, name))):
                d = {}
                for k, v in r.items():
                    try:
                        d[k] = int(v) if k in ("n", "mtu") else float(v)
                    except ValueError:
                        d[k] = v
                out.append(d)
            return out
        figures(load("main.csv"), load("sustainable.csv"), load("frame_overhead.csv"), load("sens_cp.csv"))
        return
    if "--all" not in argv:
        print(__doc__)
        return
    t0 = time.time()
    counts = {}
    write_csv("parameters.csv", parameters())
    over = frame_experiments()
    print("frame experiments done")
    with Pool() as pool:
        tasks = [("main", k, n, l, r, {}) for k, n in ARCHS for l in LOADS for r in range(SEEDS)]
        rows = run(tasks, pool)
        rows.sort(key=lambda r: (r["arch"], r["n"], r["load"], r["rep"], r["mtu"]))
        write_csv("main.csv", rows, RAW)
        counts["raw/main.csv"] = len(rows)
        print(f"main matrix: {len(rows)} rows, {time.time() - t0:.0f}s")
        sens = {}
        for tag, (param, vals, archs, loads) in SENS.items():
            t = [(tag, k, n, l, r, {param: v}) for v in vals for k, n in archs for l in loads for r in range(SEEDS)]
            s = run(t, pool)
            s.sort(key=lambda r: (r["arch"], r["n"], r["param_" + param], r["load"], r["rep"], r["mtu"]))
            write_csv(f"{tag}.csv", s, RAW)
            counts[f"raw/{tag}.csv"] = len(s)
            sens[tag] = summarize(s, ("arch", "n", "param_" + param, "load", "mtu"))
            write_csv(f"{tag}.csv", sens[tag])
            print(f"{tag}: {len(s)} rows")
    summ = summarize(rows, ("arch", "n", "load", "mtu"))
    write_csv("main.csv", summ)
    sust = sustainable(rows)
    write_csv("sustainable.csv", sust)
    write_csv("significance.csv", significance(rows))
    cv_raw = []
    with open(os.path.join(RAW, "sens_cv.csv")) as f:
        for r in csv.DictReader(f):
            cv_raw.append({k: (float(v) if k not in ("arch", "tag") else v) for k, v in r.items()})
    write_csv("validation.csv", validation(rows, cv_raw))
    figures(summ, sust, over, sens["sens_cp"])
    manifest(t0, counts, argv)
    print(f"done in {time.time() - t0:.0f}s")
