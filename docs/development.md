# Development map

The active path is a masked Keccak IMT child over Poly64/Poly192, followed by
non-ZK aggregation of the ordered child statements. Child IMT depth is fixed at 32.
The current statement is `(root, nullifier_hash)`; see [protocol](protocol.md).
The 64-child acceptance test passes: 32 first aggregates and five merge levels
use one merge circuit/key, followed by independent final verification.
Statistical child ZK and end-to-end 128-bit classical security remain unproved.
See [security limits](binary-security.md) and [measurements](binary-veil.md).

| Location | Purpose |
|---|---|
| `src/binary/tree.rs`, `relation.rs` | Keccak IMT and membership statement |
| `src/binary/aggregation_tree.rs`, `aggregation_tree/` | Statement binding, cyclic and fixed-authority merges, artifact I/O |
| `src/binary/veil/` | Masked child, recursive verifier and aggregation |
| `crates/flock-backend/` | Native product-bus prover and linked Keccak backends |
| `src/binary/engine.rs`, `security.rs` | Non-ZK baseline and conditional security budgets |
| `src/bin/`, `src/benchmark.rs`, `src/files.rs` | CLI, measurements and bounded file I/O |
| `src/legacy/`, `tests/legacy/` | Archived prime-field PoC, enabled by `legacy-prime` |
| `scripts/`, `benchmarks/` | Benchmark drivers and retained measurements |
| `vendor/` | Pinned sources required by documented upstream patches |

## Next work

Retain the 64-child integration test as the correctness gate after changes to the
recursive format: 32 first aggregates, then 16, 8, 4, 2 and 1 merges. Build the
merge circuit once, assert key reuse at every higher level and verify the final
proof in a fresh process. Different merge keys per level do not meet this gate.

The performance targets are at most 10 seconds per merge and 60 seconds from
64 child proofs to one verified aggregate, ideally 30 seconds. Report child
generation, setup, aggregation and final verification separately, as well as full
elapsed time. Keep aggregate proofs below 1.5 MB and work toward 1 MB. The
64-child correctness run is a baseline, not completion of the performance goal.

Optimize in this order:

1. Reduce committed linear intermediates and fixed-layout padding. The current
   format uses 553,648,128 initial codeword cells. Preserve one merge key.
2. Improve the measured arithmetic, bus and coordinate-conversion hot loops;
   reduce large copies and keep working sets within memory.
3. Run independent pairs concurrently with an explicit memory budget and shared
   setup. Measure total work and elapsed time; do not report an ideal parallel
   schedule as a measured result.

The [layout census](../benchmarks/binary/tree-merge/layout-census.json) found
geometric coefficient sequences in 99.7% of merge packing rows and 84.0% of
first-aggregation packing rows. Replacing 16 stored coefficients with one scale
is the next layout experiment; no proving speedup has been measured yet.
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

Use `--all-features` for changes affecting the archived prime implementation.
Vendored prover patches have targeted checks in their `LOCAL_CHANGES.md` files.
GitHub CI runs formatting, default-feature Clippy and library tests in one job.
The full depth-32 child proof is release-only; debug CI skips it.
Benchmarks and release regressions run locally.

Keep generated proofs and private fixtures under ignored `run/`. Commit only
measurements supporting documented results; recover superseded reports from Git.
`build.rs` records source fingerprints without embedding source in executables.
Never rewrite retained timings or fingerprints after a refactor.
