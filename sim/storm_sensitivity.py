"""One-at-a-time sensitivity of the reconnect-storm result (revision, Nov 2026).

Run from the project root:   python -m sim.storm_sensitivity
Varies the three storm assumptions around the baseline (1 s PADI spread, backoff base 1 s / cap 32 s,
CP queue K_cp = 64) and reports time to restore 100% of sessions for mono, DBNG N=8 and vBNG N=8,
plus the DBNG/vBNG ratio. Writes results/revision/storm_sensitivity.csv.
"""
import os
from multiprocessing import Pool

from .experiments import SEEDS, cell_seed
from .metrics import mean_ci
from .revision_checks import OUT, storm, write

CASES = [("baseline", {}),
         ("PADI spread 0.1 s", {"first_padi_spread": 0.1}),
         ("PADI spread 10 s", {"first_padi_spread": 10.0}),
         ("PADI spread 60 s", {"first_padi_spread": 60.0}),
         ("backoff 0.5 s / cap 8 s", {"backoff_base": 0.5, "backoff_cap": 8.0}),
         ("backoff 2 s / cap 64 s", {"backoff_base": 2.0, "backoff_cap": 64.0}),
         ("CP queue K = 16", {"K_cp": 16}),
         ("CP queue K = 256", {"K_cp": 256}),
         ("CP queue K = 1024", {"K_cp": 1024})]
ARCHS = [("mono", 1), ("dbng", 8), ("vbng", 8)]


def main():
    tasks = [(k, n, cell_seed("rev_storm_sens", k, n, r, *sorted(o.items())), o)
             for _, o in CASES for k, n in ARCHS for r in range(SEEDS)]
    with Pool() as p:
        res = p.map(storm, tasks)
    rows = []
    for label, o in CASES:
        d = {"case": label}
        for k, n in ARCHS:
            rs = [r for r, t in zip(res, tasks) if (t[0], t[1], t[3]) == (k, n, o)]
            done = [r["t100_s"] for r in rs if r["t100_s"] is not None]
            d[f"{k}{n}_t100"], d[f"{k}{n}_ci"] = mean_ci(done) if done else (float("nan"), 0.0)
            d[f"{k}{n}_t90"] = mean_ci([r["t90_s"] for r in rs if r["t90_s"] is not None])[0]
            d[f"{k}{n}_incomplete"] = len(rs) - len(done)
        d["ratio_dbng8_vbng8"] = d["dbng8_t100"] / d["vbng8_t100"]
        rows.append(d)
        print(f"{label:<26} mono {d['mono1_t100']:6.1f}  dbng8 {d['dbng8_t100']:6.1f} ± {d['dbng8_ci']:.1f}  "
              f"vbng8 {d['vbng8_t100']:6.1f} ± {d['vbng8_ci']:.1f}  ratio {d['ratio_dbng8_vbng8']:.1f}  "
              f"incomplete {d['dbng8_incomplete']}/{d['vbng8_incomplete']}")
    write("storm_sensitivity.csv", rows)


if __name__ == "__main__":
    main()
