# Development map

The active path is a masked Keccak IMT child over Poly64/Poly192, followed by
one non-ZK aggregate of the ordered child statements. Depths are 16 and 32.
Batches through eight have verified independently; 16–64 remain a scaling target.
Statistical child ZK and end-to-end 128-bit classical security remain unproved.
See [security limits](binary-security.md) and [measurements](binary-veil.md).

| Location | Purpose |
|---|---|
| `src/binary/tree.rs`, `relation.rs` | Keccak IMT and membership statement |
| `src/binary/veil/` | Masked child, recursive verifier and aggregation |
| `crates/flock-backend/` | Native product-bus prover and linked Keccak backends |
| `src/binary/engine.rs`, `security.rs` | Non-ZK baseline and conditional security budgets |
| `src/bin/`, `src/benchmark.rs`, `src/files.rs` | CLI, measurements and bounded file I/O |
| `src/legacy/`, `tests/legacy/` | Archived prime-field PoC, enabled by `legacy-prime` |
| `scripts/`, `benchmarks/` | Benchmark drivers and retained measurements |
| `vendor/` | Pinned sources required by documented upstream patches |

## Next work

1. Reduce aggregate proving time. Profile arithmetic, bus evaluation, PCS and
   Keccak separately. Keep parameters fixed and report cold/warm ranges, setup,
   proof size, memory and independent verification. Current results exceed
   the latency target.
2. Extend the measured eight-child template to 16–64 under the existing resource
   guards. Measure main trace, PCS and Keccak memory before adding another
   recursion layer.
3. Complete the joint privacy and security analysis: simulation, abort
   probabilities, adaptive Fiat–Shamir composition and lifetime error budgets.
   Keep binary fields, Keccak and Johnson bounds. Conditional algebraic budgets
   are not an end-to-end security proof.

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
Benchmarks and release regressions run locally.

Keep generated proofs and private fixtures under ignored `run/`. Commit only
measurements supporting documented results; recover superseded reports from Git.
`build.rs` records source fingerprints without embedding source in executables.
Never rewrite retained timings or fingerprints after a refactor.
