# recursive-imt-prover

![CLI proof tree showing active child and aggregate proofs, with CPU and RAM readings](docs/images/tree-demo.png)

A work-in-progress research prover for depth-32 Keccak-256 incremental Merkle
tree (IMT) membership. It combines up to 64 independent client proofs into one
proof of an ordered list of Merkle roots and nullifier hashes.

The child uses experimental statistical masking. A formal zero-knowledge
proof for the child and an end-to-end analysis of the 128-bit classical
security target remain open.

## Run the demo

Requires Rust 1.98.1. Run from the repository root.

```sh
cargo prove -n 16 -j 4                      # 16 leaves, up to four proofs across the tree
cargo prove --keep --out run/saved-tree    # Save the default 64-leaf run
cargo prove --verify --out run/saved-tree  # Verify the saved root in a fresh process
```

A parent can start once both input proofs are ready and a proof slot is free.
The terminal shows proof progress, peak RAM and peak CPU. The summary includes
average client and aggregate proof times. Pass `--json` for machine-readable
results. Use independently trusted verifier data when verifying a saved bundle.

## How the tree works

Clients prove membership locally and send the aggregator their proofs and
public statements. First aggregation verifies two client proofs at a time.
Recursive merges then verify two equal-sized subtrees and bind them in
left-to-right order. One merge circuit and key cover every recursive level.

| Circuit | Public inputs | Private circuit inputs |
| --- | --- | --- |
| **IMT child** | 32-byte Merkle root and 32-byte nullifier hash | 32-byte secret number, 32-byte nullifier, 32-bit leaf index, and 32 sibling hashes |
| **First aggregation** | Ordered pair digest, leaf count of two, and merge authority | Two masked child proofs and their public leaf statements |
| **Recursive merge** | Ordered subtree digest, combined leaf count, and merge authority | Two aggregate proofs and their subtree digests and counts |

The child hashes the secret number and nullifier into a leaf, then recomputes
the Merkle root from the leaf and its path. It checks the public nullifier hash
against the same private nullifier. Applications handle accepted roots and
spent nullifiers.

The aggregate circuits use the same public layout. Each of two verifier
instances receives the parent digest, count, merge authority, and a fixed
left or right role. The authority contains a transcript identity and a
preprocessing commitment. The first merge level verifies against the pinned
first-aggregation key. Higher levels verify against the merge key.

The final verifier rehashes the full ordered list of leaf statements and
checks one root proof under an independently trusted merge key. Aggregation
proofs are non-ZK. [Protocol details](docs/protocol.md) · [Recursive design](docs/aggregation-tree.md)

## Proof sizes

Representative serialized sizes from a retained 64-leaf run on an Apple M2 Pro
with 12 Rayon threads and one aggregate at a time. The median timings cover
leaf proving and per-node aggregation, respectively.

| Proof | Leaves covered | Size per proof | Median time |
| --- | ---: | ---: | ---: |
| IMT child | 1 | ~1.13 MB | 2.50 s |
| First aggregation | 2 | ~0.98 MB | 9.74 s |
| Recursive merge | 4–64 | ~0.98 MB | 9.61 s |

The saved 64-leaf root proof was **909,023 bytes** after zlib compression. The
public statements and verifier key are separate files. Fresh verification took
112 ms in this run.
[Raw measurements](benchmarks/binary/tree-merge/conditional-swaps-sixty-four.json) · [Performance notes](docs/aggregation-performance.md)

## Proof stack and security

- **Rust and Plonky3** implement the prover and recursive verifiers over
  Poly64 values with Poly192 challenges.
- **Keccak-256 and additive WHIR** provide hashing and polynomial commitments.
  The child proves its Keccak AIR with VEIL-inspired masking.
- **Flock's product bus and committed Keccak GKR** link the recursive
  verifier's arithmetic constraints to its Keccak computations.
  [Implementation map](docs/development.md)

WHIR uses the **Johnson bound** with a safety margin. The child uses a code
rate of 1/16. The recursive prover starts at rate 1/4 for the main and Keccak
commitments and 1/2 for preprocessing. The pinned analysis uses Dao, Kominers,
and Thaler's improved bound within the Johnson regime.
[Security accounting](docs/binary-security.md#parameters-and-accounting)

Dao, Kominers, and Thaler also show that going beyond Johnson can shrink
proofs over fields of sufficiently large characteristic. That makes a
large-characteristic variant worth exploring. The current prover uses binary
fields, where related counterexamples constrain beyond-Johnson proximity
gaps on additive domains. Changing these parameters would require a soundness
argument for the chosen field, domain, and protocol.
[Beyond-Johnson bounds](https://eprint.iacr.org/2026/2056) · [Binary-field counterexamples](https://eccc.weizmann.ac.il/report/2026/237/)

## References

These papers inform the design and its security assumptions.

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
