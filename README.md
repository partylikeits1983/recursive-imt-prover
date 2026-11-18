# recursive-imt-prover

**Binary-field Keccak IMT proofs, with experimental statistical ZK and tree aggregation.**

A research proof of concept for aggregating Keccak-256 incremental Merkle tree
(IMT) membership proofs into one proof authenticating an ordered list of public
roots and nullifier hashes. Each child proves a private note-preimage and membership
relation. The aggregator receives child proofs and public statements, never the
original private witnesses.

**Status:** Experimental. Child statistical zero knowledge and end-to-end
128-bit security have not been established. Not suitable for production or
real funds. No on-chain verifier.

## Three-circuit design

| Circuit | Role | Status |
|---|---|---|
| IMT child | Prove private membership in a depth-32 Keccak IMT | Implemented with experimental masking |
| First aggregation | Verify two child proofs and produce a standard aggregate | Implemented in the common recursive format |
| Recursive merge | Verify two aggregates and produce another aggregate | Same circuit/key verified at two levels with eight children; 64-child test pending |

```text
64 IMT children → 32 first aggregates → 16 → 8 → 4 → 2 → 1
                                       same merge circuit/key
```

The design requires **one merge circuit and verifier key at every higher level**.
First aggregation and merge now share a fixed proof shape and verifier layout.
The cyclic circuit carries the merge authority, selects the pinned first authority
at the base level, and authenticates its own authority during final verification.
Final native verification needs no fourth circuit.

Every aggregate authenticates a fixed-size Keccak digest and child count. Final
verification recomputes that digest from the complete ordered `(root, nullifier_hash)`
list and checks the proof using independently trusted verifier data. It needs
neither child proofs nor intermediate aggregates. Roots may differ; repeated
statements are valid. Spending, spent-nullifier tracking and accepted-root history are outside
scope.

The tree is designed for balanced batches of 2, 4, 8, 16, 32 or 64 children.
`tree-demo` has verified eight children end to end: four first aggregates, two
four-child merges and one eight-child merge, using one merge circuit/key.
Fresh-process verification and statement, proof and authority rejection checks
passed. Completion requires the 64-child integration test using the exact same
merge circuit/key at all five higher levels, followed by fresh-process verification
and tamper tests. A tree with different merge keys per level does not meet this test.
See the [implementation plan](docs/aggregation-tree.md).

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

Checkpoint is the backend for `tree-demo`: a native product bus linked to a
committed Keccak GKR argument. The older `masked-demo` also supports Flock and
flat batches as diagnostic baselines.

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

The eight-child cyclic correctness run produced a **1,485,890-byte** final proof.
Native verification took 121 ms; fresh-process verification took 134 ms including
startup and trusted-key loading. Its three merges took 42.7–50.4 s each. Peak
physical footprint was 25.5 GB, including compressed/swapped memory. Concurrent
compilation affected the first-aggregation phase, so this is not a controlled
performance comparison. [Raw run](benchmarks/binary/tree-merge/cyclic-eight.json).

Earlier fixed-source-key depth-32 measurements on an Apple M2 Pro.
These precede the normalized cyclic format and do not measure same-key recursion.
Each row uses one cold and two warm samples; aggregation is the warm median.
Fresh verification includes process startup and authenticated verifier-key loading.

| Backend / children | Threads | Aggregation | Aggregate size | Fresh verification |
|---|---:|---:|---:|---:|
| Checkpoint tree pair / 2 | 4 | 20.6 s | 1.42 MB | 150 ms |
| Checkpoint merge / 4 | 8 | 28.9 s | 1.37 MB | 124 ms |

Children took 3.1–3.3 s warm and 3.3–3.9 s cold, producing approximately 1.13 MB
proofs. Aggregation excludes setup: 6.4 s for the pair and 17.8 s for the merge.
The merge consumes two already-created first aggregates; its timing excludes
child and first-aggregate proving. Warm merges ranged from 28.8–28.9 s.

Packing linear constraints reduced the merge's initial codeword cells from
688 million to 419 million. Fused extension multiplication removes a redundant
addition. Peak physical footprint was 14.9 GB (6.87 GB maximum RSS), including
compressed/swapped memory. A separate comparison using identical source proofs
measured 34.8 s with four threads and 26.4 s with eight, producing identical proof
bytes. Timings vary on this shared machine.

Both aggregate sizes meet the 1.5 MB target. The 1 MB and sub-10-second targets
remain unmet; a tree speed advantage has not been demonstrated. Compilation is
excluded; filesystem caches were not reset.
[Raw measurements and optimization history](docs/binary-veil.md#four-child-tree-merge).

## Running locally

Requires Rust 1.98.1. The default is four threads. Use fresh output directories.
The full tree test is expensive and is excluded from routine CI.

```sh
cargo test --locked --release --workspace

# Eight children, four first aggregates, then two levels of the same merge.
cargo run --locked --release --bin tree-demo -- --batch-size 8 --out run/tree8

# Full acceptance test: 64 children, five merge levels and isolated verification.
cargo test --locked --release --test cyclic_tree -- --ignored --nocapture

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
