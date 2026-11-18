# recursive-imt-prover

Research PoC: private Keccak IMT membership candidates over binary fields,
aggregated into one non-ZK proof authenticating the ordered roots and amounts.
No on-chain verifier.

The masked child path uses **Poly64/Poly192, Keccak-256, additive WHIR and
VEIL-style statistical masking**. The aggregate proves the complete child
verification relation with Plonky3's native product bus and Flock Keccak circuits.
The aggregator receives child proofs and public statements only.

**Experimental security:** Johnson bounds and conservative algebraic budgets
support a 128-bit classical target. Joint statistical ZK, Fiat–Shamir knowledge
soundness and end-to-end 128-bit security still need review. Do not use this PoC
for real funds. The child privacy claim is a candidate, not an established theorem.

Requires Rust 1.98.1. Use fresh output directories; default: four threads.

```sh
cargo test --locked --release --workspace
cargo run --locked --release --bin masked-demo -- --depth 16 --batch-size 2 --out run/masked16
cargo run --locked --release --bin masked-demo -- --depth 32 --batch-size 2 --out run/masked32
# Repeated benchmark, excluding compilation and separating cold/warm samples:
cargo run --locked --release --bin masked-demo -- --depth 16 --batch-size 2 --samples 3 --out run/bench
# Independent verification; needs aggregate, statement and trusted data only:
cargo run --locked --release --bin masked-demo -- --verify --out run/masked16
```

Depths: 16/32. Batch schema: powers of two through 64; construction and memory
limits apply. Large batches are a scaling target, not a measured capability.
Reports record per-child timings, aggregation, verification, proof sizes and RSS.
Cold verification currently rebuilds trusted preprocessing; its time is separate
from cryptographic verification. Aggregation remains well above the latency target.
Measured depth-32, N=2: **58.6 s warm aggregation, 113.5 ms verification, 1.29 MB
aggregate** on an M2 Pro with four threads. Cold verifier setup adds about 12 s.
N=4 passes the codeword guard but has exceeded working memory;
64 children remain a research target.

`demo` / `bench` retain the original **non-ZK child** baseline.
`masked-demo --components` is a diagnostic bundle, not a single aggregate.

[Implementation and remaining work](docs/development.md) ·
[Masking and aggregation report](docs/binary-veil.md) ·
[Security limitations](docs/binary-security.md)

Pins: Plonky3 `=0.9.0-rc.2` (`fe5e46d755b8a7d9069778361e21b33e5978b377`);
recursion `3a69ba61f713c8400b14eb3d8f0e52caa13512c7`;
experimental Flock backend [PR #2582](https://github.com/Plonky3/Plonky3/pull/2582)
`708900d7a730d6ce4d5421d43e2193f2301920fa`.
[Recursion patches](vendor/p3-recursion/LOCAL_CHANGES.md) and
[Flock adapter](crates/flock-backend/README.md), including its narrow upstream
prover patches, document local changes.
