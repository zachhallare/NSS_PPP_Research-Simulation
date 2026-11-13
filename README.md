# NSS PPP/PPPoE study: code and results

Code behind "Still Connected: An Analysis of Point-to-Point Protocol Enhancements and Their Impact on Modern WAN Connectivity".

Repository: https://github.com/zachhallare/NSS_PPP_Research-Simulation

## Contents

- `ppp_5we_demo.py`, `ppp_5we_demo.pcap`: the PPPoE / 5WE frame codec and the six-frame capture (Section III-E).
- `sim/`: the BNG discrete-event simulator (`model.py`, `architectures.py`, `metrics.py`, `experiments.py`).
- `results/summary/`, `results/raw/`: the main grid behind Figs. 2 to 5 and Tables XI and XII.
- `figures/`: generated figures.

## Revision checks

All scripts run from this folder with Python 3 (Scapy and SciPy are needed for round 1).

| Script | What it does | Output |
|---|---|---|
| `python3 -m sim.revision_checks` | Round 1: Scapy cross-check, RFC 8822 endpoint and conformance tests, closed forms, near-zero-load and degenerate checks, Holm-Bonferroni, MSER-5 warm-up, MTU/MSS mix, reconnect storm | `results/revision/` |
| `python3 -m sim.storm_sensitivity` | Round 2: one-at-a-time sensitivity of the storm result (PADI spread, backoff, CP queue) | `results/revision/storm_sensitivity.csv` |
| `python3 -m sim.round3_checks` | Round 3: capacity-matched DBNG (steady state and storm), storm with a finite shared RADIUS/AAA server, blocking against session-table size (Erlang B and a 2,000-slot simulation) | `results/round3/` |

Each output folder has a `SUMMARY.md` with the numbers quoted in the paper. Every run is seeded, so re-running reproduces the same values.
