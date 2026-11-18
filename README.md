# recursive-imt-prover

**Binary-field Keccak IMT proofs, with experimental statistical ZK and planned tree aggregation.**

A research proof of concept for aggregating Keccak-256 incremental Merkle tree
(IMT) membership proofs into one proof authenticating an ordered list of public
roots and nullifier hashes. Each child proves a private note-preimage and membership
relation. The aggregator receives child proofs and public statements, never the
original private witnesses.

**Status:** Experimental. Child statistical zero knowledge and end-to-end
128-bit security have not been established. Not suitable for production or
real funds. No on-chain verifier.

## Planned design: three circuits

| Circuit | Role | Status |
|---|---|---|
| IMT child | Prove private membership in a depth-32 Keccak IMT | Implemented with experimental masking |
| First aggregation | Verify two child proofs and produce a standard aggregate | Working first level via `--tree-pair`; common recursive format pending |
| Recursive merge | Verify two aggregates and produce another aggregate of the same format | Two-proof component test passes; reusable merge pending |

```text
8 IMT children → 4 first aggregates → 2 merges → 1 final merge
                                       same merge circuit/key
```

The design reuses **one merge circuit and verifier key at every higher level**.
This requires a common proof shape, stable circuit size and authenticated cyclic
verifier data. Final native verification needs no fourth circuit.

Every aggregate authenticates a fixed-size Keccak digest and child count. Final
verification recomputes that digest from the complete ordered `(root, nullifier_hash)`
list and checks the proof using independently trusted verifier data. It needs
neither child proofs nor intermediate aggregates. Roots may differ; repeated
statements are valid. Spending, spent-nullifier tracking and accepted-root history are outside
scope.

The planned tree supports balanced batches of 2, 4, 8, 16, 32 or 64 children.
Only the first aggregation is available for IMT proofs. Completion requires an
eight-child run through two merge levels using the exact same merge key, followed by fresh
process verification and tamper tests. See the [implementation plan](docs/aggregation-tree.md).

Aggregates are intentionally non-ZK. Their inputs are child proofs and public
statements; they add no privacy guarantee beyond the child construction.

## Child relation

Given a public root and nullifier hash, the child proves knowledge of a secret
number, nullifier and authentication path satisfying:

```text
leaf = Keccak256(
    "IMT-KECCAK-LEAF2" || secret_num[32] || nullifier[32]
)

nullifier_hash = Keccak256("IMT-KECCAK-NULL1" || nullifier[32])

parent = Keccak256(
    "IMT-KECCAK-NODE1" || left[32] || right[32]
)

MerkleRoot(leaf, path, leaf_index) == root
```

Domain tags are fixed ASCII bytes, without a terminator. `secret_num` is a
32-byte little-endian unsigned integer; the nullifier is 32 private bytes.
The same nullifier is constrained in both hashes. The tree is binary and
append-only; child proofs support depth 32 only.

| Public inputs | Private witness |
|---|---|
| Merkle root (32 bytes) | Secret number (32 bytes) |
| Nullifier hash (32 bytes) | Nullifier (32 bytes) |
| | Merkle siblings |
| | Leaf index / path directions |

Children use Poly64/Poly192 binary fields, Keccak-256, additive WHIR and
VEIL-inspired masking. The first aggregation constrains the complete child
verifier, including transcripts, PCS openings, sumcheck, AIR and consistency
checks. A native verifier result is not a substitute for these constraints.
The [protocol architecture](docs/protocol.md) describes the relation, masking,
aggregation, serialization and research contributions.

Checkpoint is the initial backend for the tree implementation: a native product
bus linked to a committed Keccak GKR argument. Flock, the current CLI default,
uses upstream Flock Keccak circuits. Existing flat-batch aggregation remains
available as a baseline; it is not the planned recursive merge.

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

Last repeated depth-32 root/nullifier-hash measurements, before the checkpoint
transcript update, on an Apple M2 Pro with four threads.
One cold and two warm samples; aggregation is the warm median. Fresh verification
includes process startup and authenticated verifier-key loading.

| Backend / children | Aggregation | Aggregate size | Fresh verification |
|---|---:|---:|---:|
| Checkpoint tree pair / 2 | 21.0 s | 1.35 MB | 136 ms |

Children took 3.2–4.0 s each, producing approximately 1.13 MB proofs. Warm
aggregation ranged from 20.7–21.3 s; the complete batch critical path was 29.2 s
median, excluding setup. Peak physical footprint was 8.2 GB. The compact format
is about 24% smaller than the previous aggregate, with about 11% longer aggregation
and higher memory use. Compilation is excluded; filesystem caches were not reset.
This measures the first tree level; recursive merging remains unimplemented.
[Raw measurements and optimization history](docs/binary-veil.md#compact-aggregate-proofs).

## Running locally

Requires Rust 1.98.1. The default is four threads; use fresh output directories.

```sh
cargo test --locked --release --workspace

# First tree level: two masked children -> one aggregate, then fresh verification.
cargo run --locked --release --bin masked-demo -- --tree-pair --batch-size 2 --keccak-backend checkpoint --out run/pair32

# Benchmark the same circuit, separating cold and warm samples.
cargo run --locked --release --bin masked-demo -- --tree-pair --batch-size 2 --samples 3 --keccak-backend checkpoint --out run/bench-pair32

# Independent verification of saved artifacts.
cargo run --locked --release --bin masked-demo -- --verify --out run/pair32
```

The demo writes `aggregate.proof`, `statement.json`, `verifier.key`, `trusted.json`
and a timing report. Keep the verifier key and `trusted.json` with independently
trusted verifier data. A key and matching digest supplied only by an untrusted
prover do not establish authority.

Aggregate encoding and verifier snapshots have changed; regenerate older artifacts.

`demo` and `bench` retain the original **non-ZK child** baseline.
`masked-demo --components` produces a diagnostic proof bundle, not one aggregate.
Omitting `--tree-pair` selects the existing flat-batch format. There is no
aggregate-of-aggregate CLI yet.

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
