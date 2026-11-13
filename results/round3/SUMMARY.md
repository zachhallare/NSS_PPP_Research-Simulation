# Round-3 checks: results

## C. Blocking versus session-table size (Erlang B, mean holding time only)
| Slots | Load at 1% blocking | Blocking @0.8 | @0.9 | @1.0 | @1.1 |
|---|---|---|---|---|---|
| 200 | 0.899 | 0.028% | 1.032% | 5.44% | 11.89% |
| 2,000 | 0.986 | 0.000% | 0.000% | 1.76% | 9.51% |
| 64,000 | 1.009 | 0.000% | 0.000% | 0.31% | 9.11% |

- Simulation, monolithic BNG, 2,000 slots, load 0.9: blocking 0.00 ± 0.00% (10 reps) vs Erlang B 0.00%; CP util 57.1%.
- Simulation, monolithic BNG, 2,000 slots, load 1.0: blocking 1.77 ± 0.11% (10 reps) vs Erlang B 1.76%; CP util 62.2%.

## A. Capacity-matched DBNG (one CP, service times x 1/8)
| Config | Load | Mean setup (ms) | p99 setup (ms) | Blocking | CP util |
|---|---|---|---|---|---|
| DBNG N=8, CP x1/8 (matched) | 0.5 | 85.2 | 91.5 | 0.00% | 4.0% |
| DBNG N=8 (baseline, Table XII runs) | 0.5 | 121.4 | 202.3 | 0.00% | 32.1% |
| VBNG N=8 (baseline, Table XII runs) | 0.5 | 46.2 | 98.4 | 0.00% | 4.0% |
| DBNG N=8, CP x1/8 (matched) | 1.0 | 85.4 | 92.2 | 5.33% | 7.6% |
| DBNG N=8 (baseline, Table XII runs) | 1.0 | 151.2 | 317.9 | 5.47% | 60.5% |
| VBNG N=8 (baseline, Table XII runs) | 1.0 | 47.3 | 103.3 | 5.34% | 7.5% |
| DBNG N=8, CP x1/8 (matched) | 1.3 | 85.5 | 92.2 | 24.09% | 7.9% |
| DBNG N=8 (baseline, Table XII runs) | 1.3 | 155.7 | 333.8 | 24.18% | 63.1% |
| VBNG N=8 (baseline, Table XII runs) | 1.3 | 47.5 | 103.9 | 24.10% | 7.8% |

| Storm config | CP-bound min (s) | 90% (s) | 100% (s) | PADIs/sub |
|---|---|---|---|---|
| dbng N=8 | 38.4 | 58.1 ± 0.8 | 84.7 ± 0.4 | 5.53 |
| dbng N=8 CP x1/8 (matched) | 4.8 | 6.9 ± 0.1 | 10.4 ± 0.2 | 2.63 |
| vbng N=8 | 4.8 | 4.8 ± 0.0 | 7.8 ± 0.3 | 1.91 |
| mono N=1 | 3.8 | 3.7 ± 0.1 | 5.1 ± 0.2 | 1.72 |

## B. Reconnect storm with a finite shared RADIUS/AAA server
| Config | AAA auth/s | AAA-bound min (s) | 90% (s) | 100% (s) | PADIs/sub | Peak AAA queue |
|---|---|---|---|---|---|---|
| mono N=1 | 500 | 0.4 | 3.8 ± 0.1 | 5.4 ± 0.3 | 1.75 | 3 |
| dbng N=8 | 500 | 3.2 | 60.4 ± 0.7 | 84.9 ± 0.4 | 5.58 | 3 |
| dbng N=8 CP x1/8 (matched) | 500 | 3.2 | 6.9 ± 0.1 | 10.5 ± 0.3 | 2.62 | 16 |
| vbng N=8 | 500 | 3.2 | 5.0 ± 0.0 | 8.5 ± 0.2 | 1.98 | 15 |
| mono N=1 | 100 | 2.0 | 4.1 ± 0.1 | 5.4 ± 0.3 | 1.85 | 8 |
| dbng N=8 | 100 | 16.0 | 61.1 ± 0.7 | 85.4 ± 0.4 | 5.60 | 8 |
| dbng N=8 CP x1/8 (matched) | 100 | 16.0 | 16.3 ± 0.1 | 23.4 ± 1.4 | 3.28 | 257 |
| vbng N=8 | 100 | 16.0 | 15.8 ± 0.2 | 25.2 ± 1.7 | 2.99 | 257 |

