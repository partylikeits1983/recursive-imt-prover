# recursive-imt-prover

This prototype aggregates depth-32 Keccak-256 incremental Merkle tree (IMT)
membership proofs over binary fields. One proof authenticates an ordered list
of public Merkle roots and nullifier hashes. Clients keep their witnesses and
send the aggregator only their proofs and public statements.

**Research status.** The child uses experimental statistical zero-knowledge
masking. Its privacy proof and the end-to-end 128-bit security analysis remain
open. Verification runs natively. This prototype is unsuitable for real funds.

## Three-circuit design

| Circuit | Statement |
|---|---|
| IMT child | I know a leaf preimage and a path to the public root. The nullifier in the leaf hashes to the public nullifier hash. |
| First aggregation | Two masked child proofs verify under the pinned child key. |
| Recursive merge | Two aggregate proofs verify under the first-aggregation key at the base level or the merge key at higher levels. |

```text
64 children → 32 first aggregates → 16 → 8 → 4 → 2 → 1
                                    one merge circuit and key
```

First aggregation and merge produce the same proof format. Each aggregate
binds a child count and a Keccak digest of its ordered statements. A fresh
verifier recomputes the digest from the public list and checks the final proof
against its trusted key. Aggregates are non-ZK. The integration test used
the same merge key across all five levels and rejected tampered proofs,
statements and verifier data. [Architecture and acceptance test](docs/aggregation-tree.md)

## Child relation

```text
leaf           = Keccak256("IMT-KECCAK-LEAF2" || secret_num[32] || nullifier[32])
nullifier_hash = Keccak256("IMT-KECCAK-NULL1" || nullifier[32])
parent         = Keccak256("IMT-KECCAK-NODE1" || left[32] || right[32])
root           = MerkleRoot(leaf, siblings, leaf_index)
```

The tags are ASCII bytes without a terminator. The secret number is a 32-byte
little-endian unsigned integer. The nullifier, siblings and leaf index are
private. Children can use different roots, and a batch may repeat a valid
statement. The protocol covers membership only. A ledger would track accepted
roots and spent nullifiers separately.

Children use Poly64/Poly192, additive WHIR and VEIL-inspired masking. The
first aggregation circuit checks the child transcript, polynomial openings,
sumcheck, AIR constraints and masking consistency proofs. The tree uses
Plonky3's product bus linked to a committed Keccak GKR argument.
[Protocol architecture](docs/protocol.md)

## Security parameters

| Component | Current setting |
|---|---|
| Values / challenges | Poly64 / Poly192 |
| Hashes and transcripts | Keccak-256 |
| Child query target / code rate | 160 bits / 1/16 |
| Outer PCS target / initial rate / fold | 152 bits / 1/4 / 4 |
| WHIR grinding ceiling | 16 bits |
| Conditional algebraic floor | 144 bits |
| WHIR proximity analysis | `SecurityAssumption::JohnsonBound` |

All active WHIR configurations use Johnson with the pinned library's safety
margin: at rate `rho`, agreement is `1.05 * sqrt(rho)`, so the decoding radius
stays below Johnson. VEIL binding additionally uses the stricter cap of half the
code's minimum distance. These are component budgets toward a **128-bit classical
target**, not an end-to-end security certification or a 128-bit post-quantum claim.

The pinned Plonky3 analysis already incorporates Dao–Kominers–Thaler's improved
Johnson-regime proximity bound. Their beyond-Johnson result requires large
characteristic and does not justify moving this binary-field implementation
past Johnson. [Paper](https://eprint.iacr.org/2026/2056).
See [parameter rationale and limitations](docs/binary-security.md#parameters-and-accounting).

## Benchmarks

Both runs used an Apple M2 Pro with 16 GiB of memory and 12 Rayon workers.
Each run proved 64 independent children and processed one aggregation node at
a time. Per-proof times are medians. Fresh verification includes process
startup and trusted-key loading.

| Prover | Child proving | First pair | Merge | All 63 aggregations | Final file | Fresh verification |
|---|---:|---:|---:|---:|---:|---:|
| Previous | 2.33 s | 11.38 s | 10.85 s | 11 min 47 s | 895,139 B | 110 ms |
| Current | 2.55 s | 10.06 s | 10.01 s | 10 min 37 s | 893,611 B | 102 ms |

15 of 31 merges finished within 10 seconds. Merge times ranged from
9.63 to 11.97 seconds. The longest chain of six dependent nodes summed to
63.70 seconds. The target for aggregating 64 existing child proofs is one minute.

Setup, child proving and verification, aggregation and fresh verification took
14 min 07 s, excluding negative tests. The final proof was 953,487 bytes
before compression. Peak process-tree physical footprint was 12.8 GB.
[Current measurements](benchmarks/binary/tree-merge/affine-bus-sixty-four.json) and
[previous measurements](benchmarks/binary/tree-merge/preprocessing-digits-sixty-four.json).

## Running locally

Requires Rust 1.98.1. The tree prover uses the available CPU count, up to 64
workers. Use `--threads 12` to reproduce the latest benchmark. Use fresh output directories.
The full tree test is expensive and is excluded from routine CI.

```sh
cargo test --locked --release --workspace

# Eight children, four first aggregates, then two levels of the same merge.
cargo run --locked --release --bin tree-demo -- --batch-size 8 --out run/tree8

# Full acceptance test: 64 children, five merge levels and isolated verification.
RAYON_NUM_THREADS=12 cargo test --locked --release --test cyclic_tree -- --ignored --nocapture

# Requires only the final proof, ordered statements and trusted final key files.
cargo run --locked --release --bin tree-demo -- --verify --out run/tree8
```

The demo writes `aggregate.proof`, `statement.json`, `verifier.key`, `trusted.json`
and a timing report. Keep the verifier key and `trusted.json` with independently
trusted verifier data. A key and matching digest supplied only by an untrusted
prover do not establish authority.

Aggregate encoding and verifier snapshots have changed; regenerate older artifacts.

`demo` and `bench` retain the original **non-ZK child** baseline.
`masked-demo --components` produces a diagnostic proof bundle, not one aggregate.
`masked-demo --tree-pair` and `merge-demo` retain the earlier fixed-source-key
diagnostic path. Omitting `--tree-pair` selects flat-batch aggregation.

## Implementation and dependencies

[Development map](docs/development.md) ·
[Protocol architecture](docs/protocol.md) ·
[Masking and aggregation report](docs/binary-veil.md) ·
[Security limitations](docs/binary-security.md)

Pinned revisions:

- Plonky3 `=0.9.0-rc.2`: `fe5e46d755b8a7d9069778361e21b33e5978b377`.
- Plonky3-recursion: `3a69ba61f713c8400b14eb3d8f0e52caa13512c7`.
- Experimental Flock [PR #2582](https://github.com/Plonky3/Plonky3/pull/2582):
  `708900d7a730d6ce4d5421d43e2193f2301920fa`.

[Recursion patches](vendor/p3-recursion/LOCAL_CHANGES.md) and the
[Flock adapter](crates/flock-backend/README.md) document local upstream changes.

## References

These papers inform the design; their guarantees do not automatically transfer
to this implementation.

- [VEIL: Lightweight Zero-Knowledge for Hash-Based Multilinear Proof Systems](https://eprint.iacr.org/2026/683)
  — Dalal, Hemo, Rabinovich and Rothblum. Basis for the masking approach.
- [WHIR: Reed–Solomon Proximity Testing with Super-Fast Verification](https://eprint.iacr.org/2024/1586)
  — Arnon, Chiesa, Fenzi and Yogev. Proximity testing and polynomial commitments.
- [Fractal: Post-Quantum and Transparent Recursive Proofs from Holography](https://eprint.iacr.org/2019/1076)
  — Chiesa, Ojha and Spooner. Transparent recursive proof composition.
- [DEEP-FRI: Sampling Outside the Box Improves Soundness](https://eprint.iacr.org/2019/336)
  — Ben-Sasson, Goldberg, Kopparty and Saraf. Reed–Solomon proximity and STARK soundness.
- [Reed-Solomon Codes Beyond Johnson: Efficient Decoding and Smaller Cryptographic Proofs](https://eprint.iacr.org/2026/2056)
  — Dao, Kominers and Thaler. Improved bounds and their field-characteristic requirements.
- [On Reed–Solomon Proximity Gaps Conjectures](https://eprint.iacr.org/2025/2046)
  — Crites and Stewart. Limits of capacity-based proximity assumptions.
- [Zerocash: Decentralized Anonymous Payments from Bitcoin](https://eprint.iacr.org/2014/349)
  — Ben-Sasson et al. Private membership and public serial numbers in anonymous payments.
