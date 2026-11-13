# Results manifest

- Command: `python experiments.py --all` (from the project root, clean shell)
- Python 3.12.10 (CPython), matplotlib 3.11.2, numpy 2.5.3 (plot dependency only), Windows-11-10.0.26300-SP0
- Simulator: stdlib `heapq` event loop + `random.Random` (Mersenne Twister); no SimPy.
- Seeds: seed = zlib.crc32('tag|arch|n|load|rep[|param-tuple]'), rep = 0..29; one seed per replication, shared by MTU 1492 and 1500 (common random numbers).
- Replication length: >= 10000 measured arrivals and >= 60 mean holding times; first 10% of arrivals discarded as warm-up.
- Wall time: 1254 s

## Row counts

- `raw/main.csv`: 5400 rows
- `raw/sens_cp.csv`: 4800 rows
- `raw/sens_v.csv`: 720 rows
- `raw/sens_rtt.csv`: 540 rows
- `raw/sens_cv.csv`: 720 rows

## Parameters

See `results/summary/parameters.csv`.

## SHA-256 of summary files

- `access_node.csv`: `5af902d3b30737301267f37d1b441a7e3d813577e87c93c8591f01f22270e57b`
- `frame_byte_identity.csv`: `1c1016b9642eb46668eab24180ce77920e44a5360a297a3a4d2cf1f658c06400`
- `frame_fragment_validation.csv`: `8b6ecec8b757e8c2d48c857a732bf023c886fb03594ededc37916a7a403ea546`
- `frame_overhead.csv`: `d2471f13d7aa1dc8632ca2db549d9c9a70e1bc6e0293bc9c8a59b80c0f674e2e`
- `main.csv`: `76c60f340d1b5b5ac7e2205c237beb836f9734ab79a3ef7e4a6863dfa316727c`
- `parameters.csv`: `fa4084d294eb83d203a72862ff447e6f8fe321e6e6e37ea3b8fb03d8f6f106a6`
- `sens_cp.csv`: `2e4a1a7169375d9983cfe86a03084ce49ad00c2a297cc81357e19dd6503e1bdf`
- `sens_cv.csv`: `08c256b40e9c586b0a34ae78fa8456d7f8f7634ce3c1290d850bc61ebf465ad1`
- `sens_mix.csv`: `761e042e89c1bac148b53ed59d6583cd5557baba2ab103fae7265673f58ae67e`
- `sens_rtt.csv`: `fe525d36e93cc9a8ca0c35d2721e4d2890b58fc2af4f3b48722d3430c306ef5e`
- `sens_v.csv`: `452dee626183677e46591f84f143af3a258743587c0ef621522482f4e2634f08`
- `significance.csv`: `4b8746303902a95bffb0d1dae3f5fc91b472dc564d56e5270511c36793ae0f28`
- `sustainable.csv`: `312daf007884303cfa6689dfc9c111ecec3081816ecde5941e977408d2735250`
- `validation.csv`: `45168f549ee96da1c940e790269ec65cb63aacfb4214d384635803a04c963a83`
