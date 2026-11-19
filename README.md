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

These runs used an Apple M2 Pro with 16 GiB of memory and 12 Rayon workers.
Each run proved 64 independent children and processed one aggregation node at
a time. Per-proof times are medians. Fresh verification includes process
startup and trusted-key loading.

| Prover | Child proving | First pair | Merge | All 63 aggregations | Final file | Fresh verification |
|---|---:|---:|---:|---:|---:|---:|
| Previous | 2.55 s | 10.06 s | 10.01 s | 10 min 37 s | 893,611 B | 102 ms |
| Conditional swaps | 2.50 s | 9.74 s | 9.61 s | 10 min 15 s | 909,023 B | 112 ms |
| Keccak running sum | 2.45 s | 9.55 s | 9.89 s | 10 min 25 s | 908,310 B | 115 ms |

The running-sum prover took **10 min 26 s from ready children to a freshly
verified root**. The six nodes on its longest dependency path summed to
62.56 s. Four fixed-input merge samples per prover gave a lower pooled
median with the change, but the 64-child run took 1.7% longer than the
conditional-swaps run. [Running-sum measurements](benchmarks/binary/tree-merge/keccak-running-sum.json)

In the conditional-swaps run, 29 of 32 first pairs and 28 of 31 higher merges finished within
10 seconds. Higher merges ranged from 9.19 to 11.03 seconds. The longest chain of
six dependent nodes summed to 60.03 seconds. The wall-time target for the whole
tree is one minute.

Setup, child proving and verification, aggregation and fresh verification took
13 min 42 s, excluding negative tests. The final proof was 978,474 bytes
before compression. Peak process-tree physical footprint was 12.4 GB.
[Conditional-swaps measurements](benchmarks/binary/tree-merge/conditional-swaps-sixty-four.json) and
[previous measurements](benchmarks/binary/tree-merge/affine-bus-sixty-four.json).

[Plan for one-minute aggregation](docs/aggregation-performance.md)

## Running locally

From the repository root, run `cargo prove -j 3` for the 64-child release demo
with up to three proofs running across the tree.
Each invocation writes completed proofs to a unique temporary directory under
the git-ignored `run/`, reads sibling proofs from disk when needed, and removes
the directory on completion, error or Ctrl-C. The final verifier runs in a
fresh process. Use `--keep` with `--out` to save the verified result. An
existing `--out` path is left alone during an ordinary demo. Requires Rust 1.98.1.

```sh
cargo prove -j 3                             # 64-child tree, up to three proofs at once
cargo prove --help
cargo prove -n 8 -j 3                        # Shorter eight-child demo
cargo prove --keep --out run/saved-tree      # Keep the verified files
cargo prove --verify --out run/saved-tree    # Verify them independently
```

The demo prints the machine's CPU model, logical CPU count, prover thread
count, and total RAM before building the circuits. In a terminal it updates
the proof tree and the prover's peak RAM and CPU in place. Each row counts
completed proofs. A hollow diamond marks a proof being generated and a filled circle
marks a completed proof. Cyan marks the IMT child circuit, yellow the first
aggregation circuit, and magenta the recursive merge circuit through the root.
Set `NO_COLOR=1` for a monochrome tree. The example shows two pairs and one
merge proving at the same time.
`-j N` (`--jobs N`) sets the shared concurrency across the tree and defaults
to two. A parent can start as soon as both input proofs are saved. Free slots
go first to ready aggregates closest to the root, then to remaining leaves.
Use `--parallel-children N` or `--parallel-nodes N` to limit leaves or aggregates
within that budget. All proofs share the `--threads` pool. Near the root,
there may be fewer than `N` proofs ready. The final statement preserves input
order even when siblings finish out of order.

```text
Leaves   8/8   ● ● ● ● ● ● ● ●
               └┬┘ └┬┘ └┬┘ └┬┘
Pairs    2/4    ●   ●   ◇   ◇
                └─┬─┘   └─┬─┘
Merge 1  0/2      ◇       ·
                  └───┬───┘
Root     0/1          ·
```

After a fresh process verifies the root, the demo prints overall tree time and
each level's span from its first proof start to its last proof finish. Level
spans can overlap. **All leaves ready to verified root** starts when the last
leaf finishes and includes encoding, file I/O and fresh verification. The demo
runs its rejection checks after proving the tree and times them separately.

The per-proof averages give each tree node equal weight within its group.
The client average covers witness generation and proving for one leaf. The
aggregation average covers one call to the pair or merge prover, including
witness import and its built-in proof check. Both averages exclude setup,
disk I/O, extra rejection checks and fresh verification.

On macOS and Linux the demo includes the prover's peak resident RAM and CPU in
the final summary. CPU is sampled every 250 ms across all its threads, so 400%
means four fully occupied cores over one sample. The fresh verifier reports its
own peaks. Redirect stdout or pass `--json` to get `average_proof_ms`,
`peak_rss_bytes` and `peak_cpu_percent` in the JSON summary. Progress and
human-readable timings go to stderr. With `--keep`, `report.json` also contains
the circuit geometry and individual proof measurements.

A kept run contains `aggregate.proof`, `statement.json`, `verifier.key`, `trusted.json`
and a timing report. Keep the verifier key and `trusted.json` with independently
trusted verifier data. A key and matching digest supplied only by an untrusted
prover do not establish authority.

The default binary is `tree-demo`. For comparisons, `--bin masked-demo` proves
a flat batch of masked children with either aggregation backend. Its
`--components` option writes a diagnostic proof bundle. The `demo` and `bench`
binaries measure the non-ZK child baseline.

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
