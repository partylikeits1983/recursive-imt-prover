# Binary Keccak masking and aggregation

The active child proves membership in a **depth-32** Keccak IMT over
Poly64/Poly192. VEIL-inspired masking aims for statistical ZK; its joint privacy
argument and end-to-end 128-bit security remain unestablished. Formal ZK analysis
is deferred while the recursive aggregation tree is built.

## Complete masked child and compact trace openings

`child.rs`, `membership_air.rs` and `air_algebra.rs` define the fixed relation.
Each of the 33 hashes occupies 25 rows; the trace is padded to 1,024 rows.
Trusted preprocessing pins round flags, domains, padding and the final output.
Constraints link successive hashes, enforce Boolean path directions, and bind
all public root bytes and the exact little-endian amount.

The native AIR proof is private intermediate state and is never serialized.
The compiler masks witness-dependent round messages, current and repeat-last
successor evaluations, and endpoint multiplication values. Trusted public and
preprocessed openings are derived independently. The child relation has no buses.

The v5 trace oracle stacks 128 columns at a time into coefficient vectors of
length 262,144. It uses Plonky3's additive NTT and WHIR:

- The final aligned coefficient block holds the trace. Earlier coefficients are
  independently random. The first q novel-basis polynomials span degrees 0..q-1,
  so random coefficients hide any fixed set of at most q queried rows. This local
  fact does not establish adaptive transcript simulation.
- Masked trace and auxiliary claims precede their batching challenges. Only a
  blend containing an independent random auxiliary column enters ordinary WHIR.
- A quadratic sumcheck connects claimed evaluations and queried rows to a real
  PCS opening. Verifier-derived functionals handle stacking and successor views.
- Stratified query groups share upper Merkle paths. Every routing bit and sibling
  remains constrained; the query count still includes all opened rows.
- Challenge sampling aborts on zero or one. Under uniform Poly192 draws, this
  costs 2^-191 per draw; a joint privacy analysis must charge every abort.

Mask and product vectors use the same authenticated functional-opening approach.
A deduplicated endpoint program reuses private multiplication gates. Neither
omitting witness fields nor a hiding PCS alone is treated as full ZK.

## Privacy target

Children use fresh CSPRNG randomness, a 160-bit query-miss target, rate 1/16 and
at least 144 conditional algebraic bits. VEIL binding also caps the proximity
radius at half the code distance. These are soundness parameters, not proof of
statistical privacy.

The target joint statistical distance is at most 2^-128 for up to 64 children.
A hypothetical 2^-144 per-child bound would leave margin, but that bound has not
been established for the joint transcript. Hash/CSPRNG assumptions and
Fiat-Shamir composition are separate. See [security limitations](binary-security.md).

## End-to-end aggregate

`masked-demo` produces independent child proofs and drops their IMT witnesses.
The aggregator receives only child proofs and public roots/amounts. Flock or the
checkpoint backend constrains the complete child verifier inside one non-ZK
proof. Final verification needs that aggregate, its public statement and trusted
verifier data, without the child proofs.

The ordered-vector format supports measured batches through eight children.
The new `--tree-pair` format verifies two children and authenticates a fixed-size
Keccak commitment plus count. Both template instances bind the same parent and
have fixed left/right roles. The full ordered public list remains available.
Aggregate-of-aggregate verification is the next step; see the
[three-circuit design](aggregation-tree.md).

The backend imports actual symbolic constraints and product-bus declarations.
It never substitutes a native verifier Boolean. Its independently trusted key
pins constraints, preprocessing, public layout, backend and transcript seed.
See [the backend implementation](../crates/flock-backend/README.md).

## Current optimizations

- Compile one child-verifier template, with shared preprocessing and separate
  witness columns, bus namespaces and hash roles for every child.
- Bound Boolean and Keccak-port coordinates from trusted constraints. Unknown
  values retain all 64 coordinates.
- Remove auxiliary copies with one or two uses; group larger fanouts without
  losing copy constraints. Compact fixed preprocessing and public-copy tables.
- Regenerate product-bus leaves in bounded chunks and defer column folds.
- Reuse only PCS-authenticated evaluations with unchanged opening requests.
- Specialize affine bus rounds and skip discarded AIR bus payload construction,
  preserving every constraint and activation check.

## Specialized AIR evaluation

Retained depth-32 measurements use an M2 Pro, four threads, Rust 1.98.1, release
with thin LTO. Each run has one cold and two warm samples. Compilation/profiling
are excluded; filesystem caches were not reset. Fresh verification includes
trusted-key loading. Physical footprint includes compressed/swapped memory.

| Backend / children | Cold aggregate | Warm median (range) | Proof size | Fresh verify | Peak physical footprint |
|---|---:|---:|---:|---:|---:|
| Checkpoint / 2 | 22.355 s | 22.488 s (22.371-22.605) | 1.817-1.819 MB | 143.54 ms | 6.436 GB |
| Flock / 2 | 28.505 s | 27.768 s (27.508-28.028) | 1.418-1.419 MB | 133.38 ms | 13.995 GB |
| Checkpoint / 8 | 122.334 s | 121.289 s (120.741-121.837) | 2.546 MB | 175.19 ms | 16.344 GB |

The two-child setup costs 5.716/5.762 s for checkpoint/Flock; warm batch critical
paths are 30.148/34.683 s. The eight-child setup costs 5.520 s and warm critical
path is 148.493 s. Its key is 259,099 bytes and conditional algebraic ledger is
145.995 bits. None meets the sub-ten-second aggregate target.

Raw reports preserve exact parameters and source fingerprints:

- [Checkpoint / 2](../benchmarks/binary/masked-aggregate/checkpoint-specialized-air-d32-n2.json)
  and [tamper checks](../benchmarks/binary/masked-aggregate/checkpoint-specialized-air-negative.json).
- [Flock / 2](../benchmarks/binary/masked-aggregate/flock-specialized-air-d32-n2.json)
  and [tamper checks](../benchmarks/binary/masked-aggregate/flock-specialized-air-negative.json).
- [Checkpoint / 8](../benchmarks/binary/masked-aggregate/checkpoint-specialized-air-d32-n8.json)
  and [tamper checks](../benchmarks/binary/masked-aggregate/checkpoint-specialized-air-n8-negative.json).

First tree-pair runs at depth 32 use the same parameters. These are single cold
correctness runs, not warm speed comparisons:

| Backend | Aggregate | Proof bytes | Fresh verify |
|---|---:|---:|---:|
| [Checkpoint](../benchmarks/binary/masked-aggregate/tree-pair-checkpoint-d32-n2.json) | 22.270 s | 1,812,906 | 139.91 ms |
| [Flock](../benchmarks/binary/masked-aggregate/tree-pair-flock-d32-n2.json) | 27.937 s | 1,413,185 | 128.67 ms |

[Tamper checks](../benchmarks/binary/masked-aggregate/tree-pair-negative.json)
include statement-format and verifier-configuration substitution.

Superseded measurements and smaller-depth experiments are available in Git
history before the depth-32 cleanup. Retained timings are never rewritten after
source changes.

## Committed Keccak GKR component

`crates/flock-backend/src/checkpoint_keccak` is an isolated, non-hiding
permutation-batch proof. It follows the checkpoint idea investigated in LeanVM,
using Plonky3's cubic sumcheck, Poly64/Poly192 and the existing additive-WHIR PCS.
It does not port LeanVM's RMFE implementation or inherit its formal claims.
The standalone component has a separate benchmark interface. An optional
aggregate backend now uses its linked variant, described below, with the native
product bus retaining all arithmetic and copy constraints. Flock remains the
default pending a measured benefit from switching.

The prover commits two Boolean tables containing the ordered input and output
states, each padded from 1600 to 2048 bits per permutation. One commitment covers
both tables. The transcript binds the protocol, count, application context and
commitment before sampling the output claim. It then reduces that claim backward
through 24 rounds. Each round proves the weighted chi equation with a cubic
sumcheck, batches its three endpoint values under a fresh Poly192 challenge,
and applies the exact transpose of theta/rho/pi to the resulting bit weights.
Iota is handled as its public affine constant. The prover recomputes the round
checkpoints instead of committing nonlinear wires.

The PCS authenticates the initial output evaluation and the final input
functional. An 11-round degree-two sumcheck reduces the arbitrary input bit
weights to one ordinary multilinear opening. Its endpoint product must match
the verifier's known weight evaluation times the PCS-authenticated input value.
A verifier receives the commitment and proof, not the original states. The raw
`prove` and `verify` reduction functions alone do **not** constitute acceptance;
`CommittedBatch` closes both boundaries through WHIR. Application inputs require
the additional link below; a standalone permutation proof alone is insufficient.

For `l = log2(batch)`, the reduction's conditional error numerator is
`24 * (3 * (l + 11) + 2)` over `|Poly192|`. The standalone component adds
`l + 11` for the initial output evaluation and `2 * 11` for the input closing,
charges the PCS candidate-set bound, and combines this with the prescribed-opening
security ledger. It requires at least 144 conditional algebraic bits and keeps
Johnson/152 PCS bits, a 16-bit
PoW ceiling, rate 1/2 and fold 4. This is a conditional algebraic/PCS calculation,
not a Fiat–Shamir, knowledge or end-to-end security theorem. Keccak's generic
classical collision work factor is reported separately; no new privacy or
post-quantum claim is made.

Tests compare the linear transpose and full permutation with independent native
Keccak, compare every optimized sumcheck round with dense evaluation, and close
forged output claims. Committed-proof tests reject changed commitments, counts,
contexts, output claims, GKR endpoints, PCS values and input-closing messages.
An invalid permutation output passes through the prover without a native
validity gate and is rejected by the actual verifier. The example serializes a
proof and statement and launches a fresh verification process:

```sh
cargo build --locked --release -p imt-flock-backend --example checkpoint-keccak
RAYON_NUM_THREADS=4 target/release/examples/checkpoint-keccak 4096 3 run/checkpoint4096
RAYON_NUM_THREADS=4 target/release/examples/checkpoint-keccak --verify run/checkpoint4096
```

M2 Pro, 16 GiB RAM, four threads, Rust 1.98.1, release profile; compilation
excluded. Three samples per size: one cold proof and two warm proofs. Filesystem
caches were not reset. These are **permutation component** measurements, not
child or aggregate timings:

| Permutations | Cold prove | Warm median (range) | Proof bytes | Fresh verifier wall | Peak physical footprint |
|---|---:|---:|---:|---:|---:|
| 4,096 | 1.059 s | 1.043 s (1.042–1.045) | 249,691 | 8.7 ms | 379 MB |
| 65,536 | 16.779 s | 15.845 s (15.688–16.001) | 335,364 | 10.0 ms | 3.62 GB |

Physical footprint is reported by macOS `time -l` and includes compressed
pages; it is separate from maximum RSS. The corresponding conditional
algebraic/PCS bounds are 150.09 and 148.23 bits. Raw reports contain every
sample, compiler/hardware metadata, the implementation source fingerprint and
the benchmark executable source digest:
[4,096 permutations](../benchmarks/binary/checkpoint-keccak/committed-4096.json),
[65,536 permutations](../benchmarks/binary/checkpoint-keccak/committed-65536.json).

### Link to the aggregate's native ports

Optional aggregate protocol `experimental-binary-masked-checkpoint-aggregate-v7` replaces
the Flock Boolean wire table with an ordinary native port table and a committed
Keccak GKR subargument. The one aggregate encoding contains both subarguments;
neither is sufficient on its own. The complete child verifier and its public
root/amount wiring remain in the arithmetic relation. No child witness or child
proof is needed by final verification.

The boundary commitment and fixed authority identity seed the arithmetic
transcript before its trace commitment and row challenges. Only after complete
arithmetic verification does `verify_with_trace_openings` return the authenticated
port values at the table's row-point suffix. These values and the row point are
bound into the Keccak transcript. Eight fresh coordinates form a random
multilinear combination of all 232 ports: 100 input limbs, 100 output limbs and
16 byte-swapped limbs on each side. Each limb is expanded into its exact 16
binary coordinates. A 12-round degree-two sumcheck reduces that functional to
one input and one output opening at the same row point. Together with the
permutation's input/output openings, four ordinary openings close the WHIR proof.

Both commitments precede the row challenges, so a false port link is a
nonzero polynomial of degree at most `l + 8` in those row/port coordinates,
where `l` is the padded permutation batch's log height. The link closing adds
`2 * 12`. The ledger conservatively charges this total over the product of
the arithmetic and boundary PCS candidate sets, then unions it with the Keccak
and arithmetic error terms. The initial candidate bound depends on committed
geometry and the Johnson/rate configuration, not on how many openings are
requested; later OOD samples are not used to shrink it. The combined conditional
floor remains 144 bits. This reasoning is a proposed conditional argument,
not a proof of adaptive Fiat–Shamir or knowledge composition.

Tests prove a real two-permutation arithmetic circuit and reject changed public
ports, altered arithmetic openings, boundary counts, swapped subarguments,
authority bindings and key digests. Separate tests generate invalid port-link
proofs without a native rejection gate and require the cryptographic verifier
to reject them. The old Flock path also verifies through the new key format.

Verifier snapshot `imt-binary-trusted-verifier-v2` authenticates the selected
backend along with the constraints, preprocessing, coordinate layout and
authority. Version-1 snapshots and previous aggregate formats are deliberately
rejected. Trusted key/digest provisioning remains unchanged. Recursive merging through 64 children and joint child statistical-ZK analysis remain open.
