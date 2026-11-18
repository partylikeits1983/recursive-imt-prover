# Development map

The active path is a masked Keccak IMT child over Poly64/Poly192, followed by
non-ZK aggregation of the ordered child statements. Child IMT depth is fixed at 32.
The current statement is `(root, nullifier_hash)`; see [protocol](protocol.md).
Four current children now pass through two first aggregates and one merge.
Same-key higher-level merging and 16–64-child scaling remain unfinished.
Statistical child ZK and end-to-end 128-bit classical security remain unproved.
See [security limits](binary-security.md) and [measurements](binary-veil.md).

| Location | Purpose |
|---|---|
| `src/binary/tree.rs`, `relation.rs` | Keccak IMT and membership statement |
| `src/binary/aggregation_tree.rs`, `aggregation_tree/` | Statement binding, fixed-authority merge and artifact I/O |
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
2. Build the [binary aggregation tree](aggregation-tree.md), with specialized
   first aggregation and a reusable 2-to-1 merge. The fixed-authority merge is
   measured; common geometry and cyclic authority are next. Preserve the ordered
   public statements through their fixed-size commitment and constrain the trusted
   verifier identities.
3. Scale to 16–64 with bounded memory and parallelism. Keep binary fields, Keccak,
   Johnson bounds and the 128-bit classical target. Formal ZK analysis is deferred;
   conditional algebraic budgets remain distinct from an end-to-end security claim.

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
