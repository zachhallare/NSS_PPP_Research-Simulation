# Revision checks: results

## 1. Independent frame validation (Scapy)
- PCAP discovery frames 1-4 decode as PPPoED with codes ['0x9', '0x7', '0x19', '0x65'] (PADI/PADO/PADR/PADS).
- Frame 5 (PPPoE): fields as expected = True; Scapy binds a PPP layer (payload PPP).
- Frame 6 (5WE): VER=2 TYPE=1 octet=0x16 -> QFI=5 RQI=1 reserved=0, SESSION_ID=0x0007, LENGTH=86; fields as expected = True.
- Scapy (not 5WE-aware) shows the 5WE payload as `Raw`, not PPP, because it binds PPP only when CODE=0.
- Frame rebuilt independently in Scapy is byte-identical to the codec's frame 6: True.
- Sweep: 144 5WE frames from the identity test parsed by Scapy, 0 field mismatches.
- Note: the identity sweep uses SESSION_ID 0xFFFF, which RFC 8822 reserves (MUST NOT be used); see check 2.

## 2. Access node vs. 5WE-unaware endpoint, and RFC 8822 receive rules
- Access node (Ethertype + SESSION_ID), pppoe: sent 5024, forwarded/accepted 5024, dropped 0
- 5WE-unaware PPPoE endpoint (legacy BNG), pppoe: sent 5024, forwarded/accepted 5024, dropped 0
- 5WE-aware endpoint (AGF, PPPoE + 5WE), pppoe: sent 5024, forwarded/accepted 5024, dropped 0
- Access node (Ethertype + SESSION_ID), 5we: sent 4976, forwarded/accepted 4976, dropped 0
- 5WE-unaware PPPoE endpoint (legacy BNG), 5we: sent 4976, forwarded/accepted 0, dropped 4976
- 5WE-aware endpoint (AGF, PPPoE + 5WE), 5we: sent 4976, forwarded/accepted 4976, dropped 0
- Conformance vectors: endpoint model correct on 9/9.
- The codec's parse_frame() is a parser, not a validator: it labels 5 of 6 invalid vectors as ordinary '5WE data' (only VER 3 is flagged). Receive rules therefore live in the new Endpoint model.

## 3. Closed-form expectations vs. simulated headline numbers
| Quantity | Closed form | Simulated |
|---|---|---|
| CP utilization mono N=1, load 1.0 | 6.0 % | 5.98 |
| CP utilization dbng N=1, load 1.0 | 7.58 % | 7.58 |
| CP utilization dbng N=8, load 1.0 | 60.5 % | 60.5 |
| CP utilization vbng N=1, load 1.0 | 7.48 % | 7.5 |
| CP utilization vbng N=8, load 1.0 | 7.49 % | 7.5 |
| Extra frames per IP packet, MTU 1492 vs 1500 | 8.33 % | 8.33 |
| Forwarding loss mono N=1, load 0.9, MTU 1492 | 0.15 % | 0.14 |
| Forwarding loss mono N=1, load 1.0, MTU 1492 | 0.63 % | 0.6 |
| Forwarding loss mono N=1, load 1.5, MTU 1492 | 2.21 % | 2.14 |
| Forwarding loss vbng N=1, load 0.9, MTU 1492 | 13.03 % | 12.74 |
| Forwarding loss vbng N=1, load 1.0, MTU 1492 | 18.01 % | 17.89 |
| Forwarding loss vbng N=1, load 1.5, MTU 1492 | 21.72 % | 21.64 |
| DBNG N=1 minus monolithic mean setup, load 0.5 | 66.0 ms | 66.7 |
| UP pps budget / offered pps of a full 200-session table (MTU 1500) | 1.05 x | 1.05 |
| Implied CP ceiling, monolithic | 52.6 setups/s |  |
| Implied CP ceiling, DBNG | 41.7 setups/s |  |

## 4. Stronger verification
- Zero load, mono: expected 40.00 ms, simulated 39.98 ± 0.04 ms (0.05% off, within CI: True).
- Zero load, dbng: expected 106.00 ms, simulated 106.02 ± 0.04 ms (0.02% off, within CI: True).
- Zero load, vbng: expected 45.00 ms, simulated 45.04 ± 0.05 ms (0.10% off, within CI: True).
- Degenerate DBNG vs monolithic, load 0.5, setup_mean_ms: 40.939 vs 40.771 (paired diff 0.167 ± 0.0667, equal within CI: False).
- Degenerate DBNG vs monolithic, load 0.5, block_prob: 0 vs 0 (paired diff 0 ± 0, equal within CI: True).
- Degenerate DBNG vs monolithic, load 0.5, cp_util: 0.031731 vs 0.031461 (paired diff 0.000269 ± 0.000165, equal within CI: False).
- Degenerate DBNG vs monolithic, load 1.0, setup_mean_ms: 41.825 vs 41.573 (paired diff 0.253 ± 0.0604, equal within CI: False).
- Degenerate DBNG vs monolithic, load 1.0, block_prob: 0.053672 vs 0.052301 (paired diff 0.00137 ± 0.00667, equal within CI: True).
- Degenerate DBNG vs monolithic, load 1.0, cp_util: 0.059904 vs 0.06019 (paired diff -0.000286 ± 0.000341, equal within CI: True).
- M/G/1 CP sojourn: max error 19.1% over 40 cells (the CP sees correlated, not Poisson, job arrivals, so this is an approximation).
- DBNG N=8 load 0.5: P-K predicted mean setup 124.4 ms vs simulated 121.4 ms (2.4% off).
- DBNG N=8 load 1.0: P-K predicted mean setup 165.8 ms vs simulated 151.2 ms (8.8% off).
- M/G/1 predicted mean setup: max error 10.1% over 40 cells.

## 5. Multiple comparisons (Holm-Bonferroni) and CIs of differences
- Tests: 160 Welch (architecture pairs x loads x metrics), 360 paired (MTU). Holm applied per family.
- Decisions that change after Holm: 7.
  - paired mono1@1492 vs mono1@1500 fwd_loss_pct at load 0.8: p=0.00287, Holm p=0.238
  - paired mono1@1492 vs mono1@1500 goodput_mbps at load 0.8: p=0.00297, Holm p=0.244
  - paired dbng1@1492 vs dbng1@1500 fwd_loss_pct at load 0.8: p=0.00608, Holm p=0.493
  - paired dbng1@1492 vs dbng1@1500 goodput_mbps at load 0.8: p=0.00628, Holm p=0.502
  - welch dbng8 vs vbng8 block_prob at load 1.1: p=0.0221, Holm p=0.885
  - paired vbng2@1492 vs vbng2@1500 thr_kpps at load 1.1: p=0.00822, Holm p=0.649
  - paired vbng2@1492 vs vbng2@1500 up_util at load 1.1: p=0.00822, Holm p=0.649
- Paper claim 'DBNG setup latency differs from monolithic at every load': significant after Holm at 10/10 loads; difference CI at load 0.5: [66.6, 66.8] ms (DBNG minus mono).
- Paper claim 'blocking differences not significant at any load': significant before Holm 1/40, after Holm 0/40.
- Paper claim 'MTU 1492 lost 2.14% vs 0 at load 1.5, significant': Holm p=4.04e-47, difference CI [2.12, 2.16] percentage points.

- Degenerate DBNG with redirect RTT 0 and the PFCP step removed vs monolithic, same seeds: max per-replication difference over setup, blocking, CP utilization and loss = 0 (identical). With a zero-cost PFCP step kept, the residual 0.2-0.3 ms is that PFCP job waiting in the CP queue.

## 6. Warm-up check (MSER-5 on session-table occupancy)
  - mono N=1 load 0.5: MSER-5 truncation 2.3, 2.3, 2.5, 2.9, 3.2, 3.7, 3.7, 3.9, 7.0, 12.5 %
  - mono N=1 load 1.0: MSER-5 truncation 3.7, 4.8, 5.0, 5.0, 7.6, 8.3, 9.1, 9.8, 12.2, 25.2 %
  - mono N=1 load 1.5: MSER-5 truncation 2.1, 2.1, 2.2, 2.4, 3.1, 3.4, 3.8, 4.4, 4.9, 11.8 %
  - dbng N=8 load 0.5: MSER-5 truncation 3.5, 4.3, 6.2, 6.6, 8.0, 8.5, 9.3, 9.6, 10.4, 22.8 %
  - dbng N=8 load 1.0: MSER-5 truncation 4.5, 4.5, 4.8, 6.1, 6.5, 7.1, 8.6, 15.1, 20.3, 23.0 %
  - dbng N=8 load 1.5: MSER-5 truncation 1.9, 2.0, 2.4, 3.4, 4.7, 6.1, 8.3, 11.5, 13.3, 16.7 %
- 60 occupancy series (occupancy starts empty, as in the simulator). MSER-5 truncation point: max 25.21% of the run, mean 7.25%; the 10% warm-up discard is NOT sufficient.

- Re-running 6 cells (mono, DBNG N=8, vBNG N=8 at loads 1.0 and 1.5; 30 reps) with a 25% instead of 10% warm-up: 3 of 18 metric comparisons moved by more than their 95% CI.
  - mono N=1 load 1.0: setup 41.5 -> 41.5 ms, blocking 5.33 -> 5.49%, CP util 6.0 -> 6.0%
  - mono N=1 load 1.5: setup 41.6 -> 41.6 ms, blocking 33.70 -> 33.84%, CP util 6.3 -> 6.3%
  - dbng N=8 load 1.0: setup 151.2 -> 150.9 ms, blocking 5.47 -> 5.66%, CP util 60.5 -> 60.4%
  - dbng N=8 load 1.5: setup 156.2 -> 155.9 ms, blocking 33.94 -> 34.04%, CP util 63.4 -> 63.3%
  - vbng N=8 load 1.0: setup 47.3 -> 47.3 ms, blocking 5.34 -> 5.48%, CP util 7.5 -> 7.5%
  - vbng N=8 load 1.5: setup 47.4 -> 47.4 ms, blocking 33.87 -> 33.98%, CP util 7.8 -> 7.8%

## 7. MTU with and without MSS clamping, RFC 4638, packet-mix sweep
| Mix | Extra frames at 1492 vs 1500 | Packets fragmented at 1492 | Extra wire bytes |
|---|---|---|---|
| simple IMIX 40/576/1500 = 7:4:1 (baseline) | 8.33% | 8.33% | 0.97% |
| MSS 1452 clamped, 50% of full-size are TCP | 4.17% | 4.17% | 0.48% |
| MSS 1452 clamped, 90% of full-size are TCP | 0.83% | 0.83% | 0.10% |
| MSS 1452 clamped, 100% of full-size are TCP | 0.00% | 0.00% | 0.00% |
| all 1500 B (bulk download, unclamped) | 100.00% | 100.00% | 2.76% |
| all 40 B (worst case pps) | 0.00% | 0.00% | 0.00% |
| bimodal 40/1500 = 1:1 (unclamped) | 50.00% | 50.00% | 2.65% |

Forwarding loss, monolithic BNG (mean of 30 reps):
| Mix | UP sized to | Load | Loss @1492 | Loss @1500 |
|---|---|---|---|---|
| simple IMIX 40/576/1500 = 7:4:1 (baseline) | baseline mix | 0.9 | 0.14 ± 0.02% | 0.00 ± 0.00% |
| simple IMIX 40/576/1500 = 7:4:1 (baseline) | baseline mix | 1.5 | 2.14 ± 0.02% | 0.00 ± 0.00% |
| simple IMIX 40/576/1500 = 7:4:1 (baseline) | this mix | 0.9 | 0.14 ± 0.02% | 0.00 ± 0.00% |
| simple IMIX 40/576/1500 = 7:4:1 (baseline) | this mix | 1.5 | 2.14 ± 0.02% | 0.00 ± 0.00% |
| MSS 1452 clamped, 50% of full-size are TCP | baseline mix | 0.9 | 0.00 ± 0.00% | 0.00 ± 0.00% |
| MSS 1452 clamped, 50% of full-size are TCP | baseline mix | 1.5 | 0.00 ± 0.00% | 0.00 ± 0.00% |
| MSS 1452 clamped, 50% of full-size are TCP | this mix | 0.9 | 0.00 ± 0.00% | 0.00 ± 0.00% |
| MSS 1452 clamped, 50% of full-size are TCP | this mix | 1.5 | 0.00 ± 0.00% | 0.00 ± 0.00% |
| MSS 1452 clamped, 90% of full-size are TCP | baseline mix | 0.9 | 0.00 ± 0.00% | 0.00 ± 0.00% |
| MSS 1452 clamped, 90% of full-size are TCP | baseline mix | 1.5 | 0.00 ± 0.00% | 0.00 ± 0.00% |
| MSS 1452 clamped, 90% of full-size are TCP | this mix | 0.9 | 0.00 ± 0.00% | 0.00 ± 0.00% |
| MSS 1452 clamped, 90% of full-size are TCP | this mix | 1.5 | 0.00 ± 0.00% | 0.00 ± 0.00% |
| MSS 1452 clamped, 100% of full-size are TCP | baseline mix | 0.9 | 0.00 ± 0.00% | 0.00 ± 0.00% |
| MSS 1452 clamped, 100% of full-size are TCP | baseline mix | 1.5 | 0.00 ± 0.00% | 0.00 ± 0.00% |
| MSS 1452 clamped, 100% of full-size are TCP | this mix | 0.9 | 0.00 ± 0.00% | 0.00 ± 0.00% |
| MSS 1452 clamped, 100% of full-size are TCP | this mix | 1.5 | 0.00 ± 0.00% | 0.00 ± 0.00% |
| all 1500 B (bulk download, unclamped) | this mix | 0.9 | 40.87 ± 0.31% | 0.00 ± 0.00% |
| all 1500 B (bulk download, unclamped) | this mix | 1.5 | 46.95 ± 0.01% | 0.00 ± 0.00% |
| all 40 B (worst case pps) | this mix | 0.9 | 0.00 ± 0.00% | 0.00 ± 0.00% |
| all 40 B (worst case pps) | this mix | 1.5 | 0.00 ± 0.00% | 0.00 ± 0.00% |
| bimodal 40/1500 = 1:1 (unclamped) | this mix | 0.9 | 21.17 ± 0.42% | 0.00 ± 0.00% |
| bimodal 40/1500 = 1:1 (unclamped) | this mix | 1.5 | 29.27 ± 0.02% | 0.00 ± 0.00% |

## 8. Reconnect storm (all sessions drop at t = 0)
Assumptions: every subscriber re-sends PADI within 1.0 s; failed setups retry after min(32, 1 x 2^k) x U(0.5, 1.5) s; queues and service times as Table IV.
| Config | Subscribers | Ideal (CP-bound) | Time to 90% | Time to 100% | PADI attempts per sub | Peak CP queue |
|---|---|---|---|---|---|---|
| mono N=1 | 200 | 3.8 s | 3.8 ± 0.1 s | 5.1 ± 0.1 s | 1.73 | 65 |
| dbng N=1 | 200 | 4.8 s | 5.0 ± 0.1 s | 6.4 ± 0.5 s | 1.98 | 65 |
| dbng N=8 | 1600 | 38.4 s | 58.9 ± 1.0 s | 84.8 ± 0.4 s | 5.54 | 65 |
| vbng N=1 | 200 | 4.8 s | 4.8 ± 0.1 s | 6.3 ± 0.5 s | 1.92 | 65 |
| vbng N=8 | 1600 | 4.8 s | 4.8 ± 0.0 s | 8.1 ± 0.3 s | 1.91 | 65 |
| mono N=1, CP x2 | 200 | 7.6 s | 7.7 ± 0.1 s | 10.8 ± 0.6 s | 2.37 | 65 |
| dbng N=8, CP x2 | 1600 | 76.8 s | 88.3 ± 1.2 s | 123.5 ± 0.6 s | 6.48 | 65 |
| dbng N=8, PADI limit 20.8/s | 1600 | 38.4 s | 73.0 ± 0.2 s | 108.8 ± 3.6 s | 5.87 | 28 |
| dbng N=8, PADI limit 33.3/s | 1600 | 38.4 s | 56.1 ± 0.5 s | 84.5 ± 0.5 s | 5.21 | 53 |
| dbng N=8, PADI limit 39.6/s | 1600 | 38.4 s | 37.4 ± 0.2 s | 81.7 ± 0.6 s | 4.93 | 65 |

