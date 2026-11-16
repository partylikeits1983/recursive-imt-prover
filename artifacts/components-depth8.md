# Component measurement report

**NOT a recursive aggregation benchmark. Client authorization is missing from the transition proof.**

Depth 8; one discarded warmup, 5 measured samples. Median [min, max].

Machine: Apple M2 Pro, 16 GiB RAM; Rayon threads 4. Compiler: rustc 1.98.1 (48a229cea 2026-09-01). Native CPU tuning off. OS: Darwin MacBook-Pro-4.local 24.2.0 Darwin Kernel Version 24.2.0: Fri Dec  6 18:56:34 PST 2024; root:xnu-11215.61.5~2/RELEASE_ARM64_T6020 arm64

| Component | ms median [range] |
|---|---:|
| Client witness | 7.595 [7.435, 8.497] |
| Client full-ZK proving | 907.186 [431.726, 1310.531] |
| Native client verification | 30.944 [30.507, 41.936] |
| Transition trace | 1.789 [1.240, 2.466] |
| Transition-only FRI proving | 1682.033 [1650.022, 1850.755] |
| Transition verification | 8.723 [8.229, 9.034] |
| Sequential component sum | 3583.173 [2612.358, 3947.952] |
| Idealized parallel component sum (not measured parallel execution) | 2882.560 [2173.144, 3071.421] |

Cold costs (one measurement each, not folded into warm numbers):

- client_build_ms: 26.887 ms
- client_setup_ms: 90.155 ms
- transition_build_ms: 52.583 ms
- transition_prepare_ms: 942.702 ms

Two child proof bytes: median 2,784,376, range 2,780,664–2,789,368.
Transition-only proof bytes: median 591,215, range 585,871–597,551.
**These prove different relations. This is not proof compression or a two-to-one aggregation result.**

Peak process high-water RSS: 298.7 MiB. Cumulative process peak; phase-specific peaks were not isolated.

Circuit costs: `{"client_dimensions": {"constraints": 11626, "matrix_nonzeros": 85584, "poseidon_permutations": 14, "public_inputs": 32, "witness_variables": 11648}, "recursive_spartan_whir_cost": null, "transition_app_permutations": 32, "transition_operations": 92997, "transition_witnesses": 119961}`.

Statement sizes: `{"canonical_field_bytes": 448, "envelope_bytes": 445, "field_elements": 112}`.

No recursive SPARK/WHIR costs, aggregate-only latency, quantum bound, complete composed soundness, or Ethereum gas result exists. Depths 4/16/32 are not benchmarked as complete systems; larger-batch and outer-WHIR experiments are deferred until recursion is complete.

Raw measurements: [components-depth8.json](components-depth8.json), [components-depth8.csv](components-depth8.csv).
Profile/security settings and exact upstream SHAs are stored in JSON. Notes, masks and proof randomness are fresh OS-random samples. Fixture construction, I/O, encoding, process startup and compilation are excluded from warm sums. Setup is explicitly reported above.
