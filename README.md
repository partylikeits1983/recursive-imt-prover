# recursive-imt-prover

Research PoC for binary-field Keccak IMT proofs and N-to-one aggregation.
Each child proves knowledge of a private note under a public root and amount.
The aggregate authenticates the ordered list of those statements.

**Status:** binary aggregation works with non-ZK children. The experimental
VEIL path produces membership proof candidates through depth 8, with fresh-process
verification. Its ZK analysis, WHIR integration and aggregation are unfinished.
**End-to-end 128-bit security is not established.** There is no on-chain verifier.

## Run

Requires Rust 1.98.1. Use fresh output directories; four Rayon threads are the default.

```sh
cargo test --locked --release
cargo run --locked --release -- --out run/demo
cargo run --locked --release --bin bench -- --batch-size 2 --out run/bench-two
cargo run --locked --release --bin veil-demo -- --depth 0 --out run/veil-preimage
```

`demo` and `bench` use a deliberately low-security, **non-ZK** WHIR baseline.
`veil-demo` is a separate experimental format; depth 0 proves one note preimage.
Reports include timings, sizes and actual parameters. More queries alone do not
establish 128-bit security. The final target requires ZK children; the aggregate
may remain non-ZK.

## Work on the PoC

- [Development map and remaining work](docs/development.md)
- [Binary benchmarks](docs/binary-report.md) and [security limits](docs/binary-security.md)
- [VEIL implementation and measurements](docs/binary-veil.md)
- [Archived prime-field PoC](docs/prime-poc.md), enabled with `--features legacy-prime`

Dependencies: Plonky3 `=0.9.0-rc.2` (source `fe5e46d755b8a7d9069778361e21b33e5978b377`),
Plonky3-recursion `3a69ba61f713c8400b14eb3d8f0e52caa13512c7`.
The [vendored patches](vendor/p3-recursion/LOCAL_CHANGES.md) are documented separately.
