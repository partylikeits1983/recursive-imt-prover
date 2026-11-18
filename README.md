# recursive-imt-prover

**Recursive IMT membership proofs over binary fields, with experimental statistical ZK.**

A research proof of concept for aggregating Keccak-256 incremental Merkle tree
(IMT) membership proofs into one proof authenticating an ordered list of public
roots and amounts. Each child proves a private note-preimage and membership
relation. The aggregator receives child proofs and public statements, never the
original private witnesses.

**Status:** Experimental. Child statistical zero knowledge and end-to-end
128-bit security have not been established. Not suitable for production or
real funds. No on-chain verifier.

## How it works

### Child proofs

Given a public root and amount, the child relation asserts knowledge of a secret,
nonce and authentication path satisfying:

```text
leaf = Keccak256(
    "IMT-KECCAK-LEAF1" || secret[32] || amount_u64_le || nonce[32]
)

parent = Keccak256(
    "IMT-KECCAK-NODE1" || left[32] || right[32]
)

MerkleRoot(leaf, path, leaf_index) == root
```

Domain tags are fixed ASCII bytes, without a terminator. The amount is exactly
eight bytes in little-endian order. The tree is binary and append-only; the
masked proof path supports depths 16 and 32.

| Public inputs | Private witness |
|---|---|
| Merkle root | Secret (32 bytes) |
| Amount (u64) | Nonce (32 bytes) |
| | Merkle siblings |
| | Leaf index / path directions |

Children use **Poly64/Poly192**, Keccak-256, additive WHIR and VEIL-inspired
masking. The intended privacy property is statistical zero knowledge; its joint
security argument remains unfinished. Johnson bounds and conservative algebraic
budgets support a **128-bit classical target**, not an established end-to-end
security guarantee.

### Recursive aggregation

```text
Child proof 1 ──┐
Child proof 2 ──┤
Child proof 3 ──┼── Recursive verifier ── Aggregate proof
       ...     │
Child proof N ──┘
```

The recursive circuit constrains the complete child verification relation:
transcripts, polynomial commitments, sumcheck, AIR and consistency checks. The
aggregate authenticates the exact number and order of `(root, amount)` statements.
Independent final verification requires no child proofs or original witnesses.

There is one final aggregate verifier. The child-verifier circuit is compiled
once and reused across the batch, sharing its fixed tables. Every child still
has separate witness values, wiring checks and public inputs. The trusted key
fixes the tree depth and batch size; one key accepting arbitrary N is not yet
implemented.

Next is a [binary aggregation tree](docs/aggregation-tree.md) with specialized
first aggregation and a reusable 2-to-1 merge. Fixed-size Keccak statement binding
is implemented; aggregate-of-aggregate verification and cyclic recursion are not.

Two experimental backends implement the outer proof:

- **Flock (default):** Plonky3 native product bus with Flock Keccak circuits.
- **Checkpoint:** The same arithmetic verifier with a linked Keccak GKR argument
  and authenticated openings binding it to the arithmetic proof.

The aggregate is intentionally non-ZK. Child proofs can be sent directly to the
aggregator; publication is not required. The outer proof adds no privacy guarantee
beyond the child construction.

Children may use different roots. Accepted-root history, spending and nullifiers
are outside scope; this PoC proves membership relative to the supplied roots.

## Benchmarks

Depth-32 measurements on an Apple M2 Pro with four threads. Aggregation figures
are warm medians; fresh verification includes authenticated verifier-key loading.

| Backend / children | Aggregation | Proof size | Fresh verification |
|---|---:|---:|---:|
| Flock / 2 | 27.8 s | 1.42 MB | 133 ms |
| Checkpoint / 2 | 22.5 s | 1.82 MB | 144 ms |
| Checkpoint / 8 | 121.3 s | 2.55 MB | 175 ms |

Batches through eight have verified end to end. Scaling to 16–64 children remains
a research target.

Aggregation remains expensive. Peak physical footprint ranges from about 6.4 GB
to 16.3 GB, including compressed/swapped memory. Filesystem caches were not reset.
[Raw measurements, ranges and optimization history](docs/binary-veil.md#specialized-air-evaluation).

## Running locally

Requires Rust 1.98.1. The default is four threads; use fresh output directories.

```sh
cargo test --locked --release --workspace

# Two masked children and one aggregate; verify again in a fresh process.
cargo run --locked --release --bin masked-demo -- --depth 16 --batch-size 2 --out run/masked16
cargo run --locked --release --bin masked-demo -- --depth 32 --batch-size 2 --out run/masked32

# Repeated checkpoint benchmark, separating cold and warm samples.
cargo run --locked --release --bin masked-demo -- --depth 32 --batch-size 2 --samples 3 --keccak-backend checkpoint --out run/bench

# Eight-child checkpoint benchmark; substantial memory required.
cargo run --locked --release --bin masked-demo -- --depth 32 --batch-size 8 --keccak-backend checkpoint --out run/eight

# Independent verification of saved artifacts.
cargo run --locked --release --bin masked-demo -- --verify --out run/masked16
```

The demo writes `aggregate.proof`, `statement.json`, `verifier.key`, `trusted.json`
and a timing report. Keep the verifier key and `trusted.json` with independently
trusted verifier data. A key and matching digest supplied only by an untrusted
prover do not establish authority.

`demo` and `bench` retain the original **non-ZK child** baseline.
`masked-demo --components` produces a diagnostic proof bundle, not one aggregate.

## Implementation and dependencies

[Development map](docs/development.md) ·
[Masking and aggregation report](docs/binary-veil.md) ·
[Security limitations](docs/binary-security.md)

Pinned revisions:

- Plonky3 `=0.9.0-rc.2`: `fe5e46d755b8a7d9069778361e21b33e5978b377`.
- Plonky3-recursion: `3a69ba61f713c8400b14eb3d8f0e52caa13512c7`.
- Experimental Flock [PR #2582](https://github.com/Plonky3/Plonky3/pull/2582):
  `708900d7a730d6ce4d5421d43e2193f2301920fa`.

[Recursion patches](vendor/p3-recursion/LOCAL_CHANGES.md) and the
[Flock adapter](crates/flock-backend/README.md) document local upstream changes.
