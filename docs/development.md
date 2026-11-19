# Development map

The active path is a masked Keccak IMT child over Poly64/Poly192, followed by
non-ZK aggregation of the ordered child statements. Child IMT depth is fixed at 32.
The current statement is `(root, input_tag, output_commitment)`. See [protocol](protocol.md).
The 64-child acceptance test verifies 32 first aggregates and five merge levels
with a shared merge key, then checks the root in an independent process.
Statistical child ZK and end-to-end 128-bit classical security remain unproved.
See [security limits](binary-security.md) and [measurements](binary-veil.md).

| Location | Purpose |
|---|---|
| `src/binary/tree.rs`, `relation.rs` | Keccak IMT and membership statement |
| `src/binary/aggregation_tree.rs`, `aggregation_tree/` | Ordered statement commitments and the reusable merge prover and verifier |
| `src/binary/veil/` | Masked child, recursive verifier and aggregation |
| `crates/flock-backend/` | Native product-bus prover and linked Keccak backends |
| `src/binary/engine.rs`, `security.rs` | Non-ZK baseline and conditional security budgets |
| `src/bin/`, `src/benchmark.rs`, `src/files.rs` | CLI, measurements and bounded file I/O |
| `scripts/`, `benchmarks/` | Benchmark drivers and retained measurements |
| `vendor/` | Pinned sources required by documented upstream patches |

## Next work

Retain the 64-child integration test as the correctness gate after changes to the
recursive format: 32 first aggregates, then 16, 8, 4, 2 and 1 merges. Build the
merge circuit once, assert key reuse at every higher level and verify the final
proof in a fresh process. Different merge keys per level do not meet this gate.

The performance target is under 180 seconds from 64 prepared child proofs to
one independently verified aggregate on the M2 Pro. One minute is a stretch
target. Report child generation, setup, aggregation and final verification
separately, as well as full elapsed time. Keep aggregate proofs below 1.5 MB and work toward 1 MB. The
64-child correctness run is a baseline, not completion of the performance goal.

The [aggregation performance plan](aggregation-performance.md) covers worker
scheduling, the Keccak sumcheck experiment and commitment-opening costs.
For single-machine work, track committed linear intermediates and padding
against the recorded 184,549,376 initial codeword cells. Measure the memory
cost of running sibling pairs concurrently.

The recursive packing table now stores one scale per geometric coefficient run.
Native gates handle the remaining coefficients. An extra table for those rows
increased the final eight-child proof from 1.446 MB to 1.514 MB.
[Measured layouts](../benchmarks/binary/tree-merge/geometric-packing.json).
`tree-demo --setup-only --out run/layout` records geometry without generating proofs.

[SP1's packing approach](https://blog.succinct.xyz/sp1-hypercube/),
[Flock's linear-wire elimination](https://arxiv.org/html/2607.27491v1), and
[ZisK's proving orchestration](https://github.com/0xPolygonHermez/zisk/blob/main/distributed/README.md)
inform this work. Their timings are not matched-security benchmarks of this path.
Keep binary fields, Keccak, Johnson bounds and the 128-bit classical target.
Formal ZK analysis is deferred; conditional algebraic budgets remain distinct
from an end-to-end security claim.

Avoid repeating two rejected experiments: indexed Logup* required large
transmitted pushforwards; a shared AIR expression DAG gave about 2% improvement
with overlapping timing ranges. Do not implement Ethereum verification yet.

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --release --workspace
```

Vendored prover patches have targeted checks in their `LOCAL_CHANGES.md` files.
GitHub CI runs formatting, default-feature Clippy and library tests in one job.
The full depth-32 child proof is release-only; debug CI skips it.
Benchmarks and release regressions run locally.

Keep generated proofs and private fixtures under ignored `run/`. Commit only
measurements supporting documented results; recover superseded reports from Git.
`build.rs` records source fingerprints without embedding source in executables.
Never rewrite retained timings or fingerprints after a refactor.
