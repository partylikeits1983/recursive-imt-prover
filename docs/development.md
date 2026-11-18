# Development map

Keep one active direction: add a complete, analyzed binary ZK child format to
the existing proof-only aggregation flow. The VEIL module contains the
experimental masked child and its component checks.

The acceptance target is **depths 16 and 32**, **up to 64 children in one aggregate**,
**binary fields**, **Keccak throughout**, **statistical child ZK**, and **at least
128-bit end-to-end classical security**. The aggregate itself may be non-ZK. Aggregation of aggregates is deferred.
These requirements do not change when inspecting other implementations.

| Location | Purpose |
|---|---|
| `src/binary/tree.rs`, `relation.rs` | Keccak IMT and the child statement |
| `src/binary/engine.rs` | Poly64/Poly192 native, non-ZK child/aggregate baseline |
| `src/binary/security.rs` | Conditional algebraic budgets and N-child composition |
| `crates/flock-backend/` | Isolated final prover and old/new Plonky3 AIR adapter |
| `src/binary/veil/` | Experimental binary VEIL components and direct Keccak fixture |
| `src/bin/` | Binary demo, benchmark and VEIL experiment entry points |
| `src/benchmark.rs`, `files.rs` | Shared measurements and bounded artifact I/O |
| `src/legacy/` | Archived prime-field PoC; opt-in `legacy-prime` feature |
| `tests/legacy/` | Prime-field regressions, compiled as one optional test target |
| `scripts/` | Reproducible benchmark drivers |
| `benchmarks/` | Recorded measurements; no proof or private witness files |
| `vendor/` | Pinned Plonky3 sources required by documented recursion and prover patches |

## Next milestones

1. **Online masked transcript — implemented.** Fresh masks are committed before
   algebraic messages and challenges. One verifier replay produces the affine
   and product constraints. Native AIR sumcheck uses upstream arithmetic.
2. **Private oracle — implemented experimentally.** Additive WHIR authenticates
   only a uniformly masked combination of private columns. The child now stacks
   128 trace columns per commitment column, uses random low-degree coefficient
   padding, and verifies a compact functional instead of a dense weight table.
   The original interpolation oracle remains a component comparison fixture.
3. **Complete membership relation — implemented experimentally.** A fixed AIR
   connects adjacent Keccak hashes directly, including the amount, domains,
   path direction, schedule and root. It needs no product bus. The upstream
   zerocheck, private current/successor openings, public preprocessing and masked
   endpoint algebra are linked in one serialized child proof. Depths 16/32
   have independent-process measurements. This establishes the implemented
   relation, not the full privacy or composed security theorem.
4. **One-proof masked-child aggregation — implemented experimentally.**
   `masked-demo` compiles the complete child verifier for the fixed ordered batch.
   `crates/flock-backend` proves its arithmetic on the native product bus and its
   Keccak calls with the pinned upstream Flock circuit-table prover. Two- and
   four-child aggregates have passed independent-process verification and negative
   public-statement checks. The component bundle remains an explicitly non-succinct
   diagnostic. See the measurements and resource limits in `binary-veil.md`.
5. **Privacy/security review follows integration.** The user accepts a plausible
   statistical-ZK candidate for this milestone. Keep unproved claims labelled:
   joint simulation, adaptive/ROM composition, abort probabilities, salted-leaf
   lifetime budgets, and end-to-end 128-bit security remain to be established.
   Retain binary fields, Keccak, Johnson bounds and conservative algebraic
   parameters. Do not turn the conditional budget into a security certificate.
6. **Measure and optimize.** Benchmark depths 16/32 and batches 1/2/4/8/16/32/64,
   separately reporting circuit construction, proof generation, decoding,
   trusted setup and final verification. Profile before changing the design;
   compare a recursion tree only if the fixed batch hits a measured limit.
   Depth-32 N=4 now completes end to end, with 6 GiB of initial codewords and
   about 40.5 GB peak physical footprint including compressed/swapped pages.
   The local prover patches regenerate product-bus leaves, factor equality
   weights, omit fixed-zero preprocessing columns and release unused folded
   capacity; large bus columns defer their first extension-field allocation.
   Larger batches still need lower simultaneous sumcheck storage;
   the current construction/codeword guards remain in place. Authenticated
   verifier snapshots now avoid rebuilding proving tables: a fresh N=4 verifier
   takes about 140 ms total and 34 MB RSS. Reduce AIR opening reductions and
   simultaneous prover allocations next. Checkpointed Keccak
   GKR is a research lead (`binary-veil.md`), retaining the existing fields,
   hash and security target.

Do not implement Ethereum verification yet. Optimize the measured fixed-batch
prover before adding another recursion layer.

The exact obligations and existing measurements live in
[binary-veil.md](binary-veil.md). Avoid copying status and security explanations
into additional documents; keep the README as the entry point.

## Checks

GitHub CI has one Linux job: formatting, default-feature Clippy across targets,
and library unit tests. It uses the pinned Rust toolchain and a dependency cache.
Proof benchmarks and the full release regression suite remain local checks.

```sh
# Normal binary development: excludes the old prime CLI and its slow tests.
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --release --workspace

# Before publishing changes that also affect shared or legacy code.
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --release --workspace --all-features
```

The binary `demo`, `bench` and `veil-demo --verify` command names are retained.
Their v2 proof/trust formats deliberately reject v1 artifacts. A plain `cargo run` now selects the binary demo. The prime CLI retains
its executable name but requires `--features legacy-prime --bin recursive-imt-prover`.
Library callers use the `legacy` namespace for that implementation.

Source fingerprints are computed once by `build.rs`; executables contain only
the digest, not copies of the source files. Keccak and legacy SHA3 fingerprints
retain their respective framing. Benchmark reports share environment and RSS
collection. Historical reports retain the metadata from their original run.

Generated runs, proofs and private fixtures belong under ignored `run/`.
Keep the current reports and diagnostics supporting documented results.
Retrieve superseded measurements from Git history; remove duplicate logs.
Do not rewrite retained timings or fingerprints after refactoring.
