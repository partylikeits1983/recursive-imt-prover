# recursive-imt-prover

![CLI proof tree showing active child and aggregate proofs, with CPU and RAM readings](docs/images/tree-demo.png)

This prover combines up to 64 independent depth-32 Keccak-256 incremental Merkle
tree (IMT) proofs into one proof of an ordered batch. A client can prove preimage
membership with only the root public, or open a record with a public input tag and
output commitment. The release goal is to verify a real 64-leaf batch in one Ethereum
transaction for under 11 million gas, with a direct Solidity verifier and a
verifier-independent Rust prover.
Rust verifies the default LeanVM aggregate. Solidity checks the polynomial
opening for an experimental LeanVM terminal encoding. The custom-circuit backend
has a complete Solidity verifier for its experimental 64-client root. It used
104.57 million gas on a high-limit local Prague chain.

The masked backend uses experimental statistical masking. A formal zero-knowledge
proof for the child and an end-to-end analysis of the 128-bit classical
security target remain open.

## Default recursion benchmark

```sh
cargo bench --locked --bench leanvm-recursion
```

The benchmark builds the pinned LeanVM experimental prover, proves 64 synthetic
depth-32 Keccak preimages and performs 63 binary merges. It uses five worker
threads, WHIR rate 1/4 for clients and 1/2 for every merge, including the root.
Each merge verifies both child proofs. A fresh verifier checks the saved root
against the ordered digest computed by this repository’s IMT implementation.

On an M2 Pro one run took **4.62 s** for the clients and **23.33 s** for the
sequential merges. The final merge took **472 ms**. Its **277,552-byte** proof
verified natively in **11.83 ms** including the deferred bytecode check.
These defaults apply to performance benchmarking with synthetic witnesses.
LeanVM’s client proof is non-hiding, its per-round soundness target is 125 bits,
and EVM verification of this proof format is still open.
[Benchmark and terminal-rate comparison](docs/ethereum-root-verification.md#leanvm-recursion-benchmark-defaults)

An experimental terminal encoding reduces the same root to **142,180 bytes**.
Solidity verifies its polynomial opening in **16,497,923 gas** on Osaka,
including calldata. Supplying the 64 public IMT roots in order costs **16,602,641 gas**
for the opening check. Both entry points take three reduction values from Rust.
Full onchain verification for this encoding and the 11M gas target remain open.
[Checks and gas receipts](docs/ethereum-root-verification.md#binary-leanvm-terminal-transcript-and-opening)

## Aggregate masked client proofs in LeanVM

```sh
cargo prove --backend leanvm-masked -n 2 -j 1 --threads 4 --keep --out run/masked-pair
cargo prove --verify --out run/masked-pair
```

Each client proves knowledge of a preimage on a depth-32 Keccak path. LeanVM
verifies the serialized masked proof against the client's public root. A binary
parent then verifies the two recursive proofs and commits to the ordered roots.
Use `--prepare-children DIR` with the same backend and batch size to save the
native masked proofs, and `--from-children DIR` to aggregate them separately.

On four M2 Pro threads it took **219 s and 279 s** to wrap two saved masked
clients. Their ordinary merge took **0.897 s** and produced **286,416 bytes**.
Selecting rate 1/32 with the low-level terminal prover gave **7.838 s** and
**143,044 bytes** on the same two children. A fresh process verified both saved
roots and rejected the reversed public list. These are two-client measurements.
The statistical ZK argument and the 128-bit end-to-end bound are still open.
[Security and timings](docs/binary-security.md#masked-client-verifier-in-leanvm) · [Solidity gas](docs/ethereum-root-verification.md#masked-client-recursion-in-leanvm)

## Inspect the masked client verifier in LeanVM

The guest reads a saved masked client proof and its public root. The preimage and
private IMT path stay at the client. It replays the AIR sumcheck and verifies all
176 Merkle paths for the stacked coefficient oracle. With `--blend`, it uses those
authenticated rows to check all 18 rounds of a second sumcheck and derive the
point and value that the polynomial commitment must authenticate.

The `--whir` stage also authenticates the stacked polynomial at that point and
checks the native WHIR transcript seal. The `--membership` stage checks the two product openings, the affine AIR
equations and the mask opening. It exposes only the 32-byte IMT root.

Run from the repository root with a fresh client directory.

```sh
cargo run --quiet --locked --release --example masked-child -- \
  --preimage --aligned-oracle --samples 1 --out run/masked-client
cargo masked-oracle --blend prove run/masked-client run/masked-client/blend.proof -j 4
cargo masked-oracle --blend verify run/masked-client run/masked-client/blend.proof
cargo masked-oracle --whir prove run/masked-client run/masked-client/whir.proof -j 4
cargo masked-oracle --whir verify run/masked-client run/masked-client/whir.proof
cargo masked-oracle --membership prove run/masked-client run/masked-client/membership.proof -j 4
cargo masked-oracle --membership verify run/masked-client run/masked-client/membership.proof
```

On four M2 Pro threads, the same saved masked client took 1.05 s for the blend checkpoint and 15.24 s for the stacked WHIR checkpoint. Full membership took 184.78 s and produced a 243,488-byte standalone LeanVM proof. A fresh verifier needed only the public root in `statement.json` and that proof. The default 16-leaf demo below uses the non-hiding client.
[Verifier measurements and scope](docs/binary-security.md#masked-client-verifier-in-leanvm)

## Run the demo

Requires Rust 1.98.1, Git and Python 3. Run from the repository root. The first run builds and caches the pinned LeanVM executable.

```sh
cargo prove -n 16 -j 4                      # 16 leaves, up to 4 concurrent proof generations
cargo prove --keep --out run/saved-tree    # Save the default 64-leaf run
cargo prove --verify --out run/saved-tree  # Verify the saved root in a fresh process
```

The default demo uses the benchmark’s non-hiding LeanVM client. It proves a synthetic
32-byte preimage and a depth-32 Keccak path for every leaf. By default one proof runs at a time
with up to five prover threads. `-j` sets the concurrent proof limit and `--threads` sets
the thread budget divided among the jobs. The interactive tree updates as each proof completes.
Kept runs write `root.imt`, `statement.json`, `trusted.json` and `report.json`.

Use `cargo prove --backend masked` for the earlier masked record demo, or
`cargo prove --preimage` for its masked root-only client. The statistical-ZK argument for
that client remains open. [Preimage membership](docs/protocol.md#preimage-membership-client)

A parent can start once both input proofs are ready and a proof slot is free.
The terminal shows proof progress, peak RAM and peak CPU. The summary includes
elapsed proving time, the final merge time, proof size and native verification time. Pass `--json` for machine-readable
results. When a consumer already has the ordered batch digest and count, it
can verify them directly. Supply the 32-byte digest followed by the one-byte
count (`40` in hex for 64 leaves), and verifier metadata from a trusted source.

```sh
cargo prove --verify --out run/saved-tree --trusted "$TRUSTED_JSON" --expected-statement "$STATEMENT_HEX"
```

On the same two 32-client subtrees, the opt-in `terminal-merge --midpoint`
profile produced a **316,380-byte** compressed root in **45.33 seconds** on five
M2 Pro threads. The earlier four-variable profile took 49.07 seconds and
produced 351,600 bytes. Both use the 152-bit local WHIR target. Solidity checks
the statement, arithmetic, all 24 Keccak rounds and the polynomial opening.
The lowest full Solidity receipt for the strong profile used **104,570,178 gas** on high-limit local
Prague. It checks a separate prime-field certificate for the queried row folds
and sends 443,108 calldata bytes. Verifying those folds directly uses
106,637,610 gas and 314,724 bytes. The opt-in comparison profile uses
99,956,986 gas with a 121.48-bit conditional terminal bound. All three exceed
the 11M settlement budget.
The recursive knowledge-soundness proof and client statistical-ZK proof remain open.
[EVM verifier](crates/evm-verifier/) · [Measurements](docs/ethereum-root-verification.md) · [Production plan](docs/ethereum-terminal-proof-plan.md)

## How the tree works

Clients prove membership locally and send the aggregator their proofs and
public statements. First aggregation verifies two client proofs at a time.
Recursive merges then verify two equal-sized subtrees and bind them in
left-to-right order. One merge circuit and key cover every recursive level.

| Circuit | Public inputs | Private inputs (witness) | Shareable output from the prover |
| --- | --- | --- | --- |
| **IMT child** | Merkle root, input tag and output commitment (32 bytes each) | Input and output labels and nonces (32 bytes each), one shared 64-bit quantity, leaf index and 32 sibling hashes | One masked record proof and its public statement |
| **First aggregation** | 32-byte ordered pair digest, leaf count fixed at two, left/right roles, and merge authority | Two masked child proofs, their public statements, and sibling statement digests | One pair proof and the two ordered public leaf statements |
| **Recursive merge** | 32-byte parent digest, total leaf count, left/right roles, and merge authority | Two aggregate proofs, their subtree digests and leaf counts, and sibling subtree digests | One merge proof and the combined ordered list of public leaf statements |

**IMT child.** The client opens an existing record under the public root and
commits to a replacement carrying the same private quantity. The private path
authenticates the input record. Its nonce determines the public input tag.
An application can use that tag to reject repeated use and can append the
output commitment as a new record.

Passing `--packed-lanes` to `cargo prove` selects a versioned masked leaf that checks 64-bit path lanes and enforces bitness at each Keccak input. The aggregate verifies that circuit under its own pinned identity. [Leaf measurements and LeanVM comparison](docs/ethereum-root-verification.md#same-depth-32-leaf-in-the-current-binary-leanvm)

**First aggregation.** The circuit verifies both masked child proofs with the
fixed child verifier. It hashes each child's three public fields into a
statement digest. The left and right verifier instances
must agree on the digest of the ordered pair and on a leaf count of two.

**Recursive merge.** The circuit verifies two aggregate proofs with equal
power-of-two leaf counts. It checks that the public parent count is double
either input count and that the parent digest binds the two subtree digests
and counts in left-to-right order. Inputs covering two leaves use the pinned
first-aggregation key. Larger inputs use the carried merge authority, which
contains the merge verifier's transcript identity and preprocessing commitment.

The aggregator receives proofs and statement data. The three public fields per child
are witness data inside the first aggregation circuit and are also
published in the ordered output list. Aggregation proofs are non-ZK. The final
verifier rehashes that list and checks one root proof under an independently
trusted merge key. [Protocol details](docs/protocol.md) · [Recursive design](docs/aggregation-tree.md)

## Proof sizes and proving time

On the 12-core, 16 GiB MacBook Pro with M2 Pro, aggregating **64 saved child
proofs through fresh root verification took 409.81 s** (6 min 49.8 s).
The previous packed prover took 469.21 s before this run and
398.91 s in a repeat afterward. All three used AC power, the same saved
children, 12 Rayon threads and up to two concurrent parents.
The optimized replay fell between the controls, leaving the full-tree speedup inconclusive.

| Proof | Leaves covered | Median proof size | Median wall time per proof |
| --- | ---: | ---: | ---: |
| Record child (separate preparation run) | 1 | 1.13 MB | 3.51 s |
| First aggregation | 2 | 1.01 MB | 12.19 s |
| Recursive merge | 4–64 | 1.01 MB | 12.44 s |

Parent times overlap. Including key preparation, the optimized tree took
426.12 s. The compressed root was 948,828 bytes and verified in 133 ms
including process launch. The ordered statements and verifier key are separate
files. The isolated 65,536-permutation Keccak proof fell
from 1.343 s to 1.041 s (medians of four trials per build).

The three-minute target requires 2.28× the throughput of this replay.
An earlier packed build completed in 373.38 s on battery and produced the same
root proof. Before the packed chi and joint WHIR changes, the separate-opening
prover took 579.67 s on the same inputs. [Raw AC-powered trials](benchmarks/binary/tree-merge/packed-first-fold-m2.json) · [Earlier replay](benchmarks/binary/tree-merge/joint-packed-parent-m2.json) · [Child preparation](benchmarks/binary/tree-merge/record-replacement.json) · [Performance notes](docs/aggregation-performance.md)

## Proof stack and security

- **Rust and Plonky3** implement the prover and recursive verifiers over
  Poly64 values with Poly192 challenges.
- **Keccak-256 and additive WHIR** provide hashing and polynomial commitments.
  The child proves its Keccak AIR with VEIL-inspired masking.
- **Flock's product bus and committed Keccak GKR** link the recursive
  verifier's arithmetic constraints to its Keccak computations.
  [Implementation map](docs/development.md)

WHIR uses the **Johnson bound** with a safety margin. The child uses a code
rate of 1/16. The recursive prover uses rate 1/2 for its joint arithmetic and Keccak
commitment and for preprocessing. The pinned analysis uses Dao, Kominers,
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
