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
# Eight-child comparison using the linked Keccak GKR backend:
cargo run --locked --release --bin masked-demo -- --depth 32 --batch-size 8 --keccak-backend checkpoint --out run/eight
# Independent verification; keep verifier.key with the trusted data:
cargo run --locked --release --bin masked-demo -- --verify --out run/masked16
```

Depths: 16/32. Batches through eight have verified end to end. Batches 16–64
remain a scaling target; current construction and memory limits restrict them.
Reports include per-child timings, aggregation, verification, proof sizes and RSS.
Depth-32 measurements on an M2 Pro with four threads:

| Backend / children | Aggregation | Proof | Fresh verification |
|---|---:|---:|---:|
| Flock / 2 | 36.9 s warm median | 1.40 MB | 160 ms |
| Checkpoint / 2 | 32.5 s warm median | 1.82 MB | 172 ms |
| Checkpoint / 8 | 219.7 s warm median | 1.98 MB | 202 ms |

Proving remains above the latency target. Peak physical footprint, including
compressed/swapped memory, ranges from 10.6 GB for checkpoint N=2 to about
41.5 GB for N=8. [Raw measurements and limits](docs/binary-veil.md#reusing-authenticated-boolean-evaluations).
Fresh verification includes authenticated key loading; filesystem caches were
not reset. Keep `verifier.key` and independently trusted `trusted.json` (v2).
A key/digest pair supplied by an untrusted prover is insufficient.

`demo` / `bench` retain the original **non-ZK child** baseline.
`masked-demo --components` is a diagnostic bundle, not a single aggregate.
Both aggregate backends remain experimental. Flock is the default; checkpoint
uses a linked Keccak GKR argument and is the measured eight-child path.

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
