# Development map

Keep one active direction: add a complete, analyzed binary ZK child format to
the existing proof-only aggregation flow. The direct VEIL experiment tests the
missing algebraic pieces; it is not another production backend to optimize.

| Location | Purpose |
|---|---|
| `src/binary/tree.rs`, `relation.rs` | Keccak IMT and the child statement |
| `src/binary/engine.rs` | Working native, non-ZK child/aggregate baseline |
| `src/binary/veil/` | Experimental binary VEIL components and direct Keccak fixture |
| `src/bin/` | Binary demo, benchmark and VEIL experiment entry points |
| `src/benchmark.rs`, `files.rs` | Shared measurements and bounded artifact I/O |
| `src/legacy/` | Archived prime-field PoC; opt-in `legacy-prime` feature |
| `tests/legacy/` | Prime-field regressions, compiled as one optional test target |
| `scripts/` | Reproducible benchmark drivers |
| `benchmarks/` | Recorded measurements; no proof or private witness files |
| `vendor/p3-recursion/` | Pinned upstream code and documented patches |

## Next milestones

1. Complete the binary VEIL joint simulation and soundness accounting. The
   current local coding diagnostics are not an end-to-end security bound.
2. Adapt the MultiStark transcript and hiding oracle interface to additive WHIR.
   Apply the inner argument to verifier algebra rather than the whole Keccak
   execution. Account for every opening and preserve packed-bit performance
   where the privacy construction permits it.
3. Constrain verification of that complete child format in the Poly64/Poly192
   outer circuit. Authenticate the trusted authority and ordered public vector.
   Start with two children; the outer proof may remain non-ZK.
4. Establish the composed 128-bit classical bound, then measure final parameters
   for depths 8/16/32 and batch sizes 2/4/8/16. Do not spend time on Ethereum or
   another backend before this works.

The exact obligations and existing measurements live in
[binary-veil.md](binary-veil.md). Avoid copying status and security explanations
into additional documents; keep the README as the entry point.

## Checks

```sh
# Normal binary development: excludes the old prime CLI and its slow tests.
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --release

# Before publishing changes that also affect shared or legacy code.
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --release --all-features
```

The existing binary `demo`, `bench` and `veil-demo --verify` interfaces are
unchanged. A plain `cargo run` now selects the binary demo. The prime CLI retains
its executable name but requires `--features legacy-prime --bin recursive-imt-prover`.
Library callers use the `legacy` namespace for that implementation.

Source fingerprints are computed once by `build.rs`; executables contain only
the digest, not copies of the source files. Keccak and legacy SHA3 fingerprints
retain their respective framing. Benchmark reports share environment and RSS
collection. Historical reports retain the metadata from their original run.

Generated runs, proofs and private fixtures belong under ignored `run/`.
Keep historical raw benchmark records when they explain a research decision.
Do not rewrite their timings or fingerprints after refactoring.
