# Binary Keccak masking and aggregation

The active child proves membership in a **depth-32** Keccak IMT over
Poly64/Poly192. VEIL-inspired masking aims for statistical ZK; its joint privacy
argument and end-to-end 128-bit security remain unestablished. Formal ZK analysis
is deferred while the recursive aggregation tree is built.

## Complete masked child and compact trace openings

`child.rs`, `membership_air.rs` and `air_algebra.rs` define the fixed relation.
Each of the 34 hashes occupies 25 rows; the trace is padded to 1,024 rows.
Trusted preprocessing pins round flags, domains, padding and the final output.
Constraints link successive hashes, enforce Boolean path directions, and bind
all public root and nullifier-hash bytes. Four private Poly64 carry columns
connect the nullifier in the leaf preimage to its separate hash preimage.

The native AIR proof is private intermediate state and is never serialized.
The compiler masks witness-dependent round messages, current and repeat-last
successor evaluations, and endpoint multiplication values. Trusted public and
preprocessed openings are derived independently. The child relation has no buses.

The v6 child retains an oracle stacking 128 columns at a time into coefficient vectors of
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
The aggregator receives only child proofs and public roots/nullifier hashes. Flock or the
checkpoint backend constrains the complete child verifier inside one non-ZK
proof. Final verification needs that aggregate, its public statement and trusted
verifier data, without the child proofs.

The ordered-vector format supports measured batches through eight children.
The new `--tree-pair` format verifies two children and authenticates a fixed-size
Keccak commitment plus count. Both template instances bind the same parent and
have fixed left/right roles. The full ordered public list remains available.
Two first aggregates can now merge under a fixed source key. Reusing one merge
circuit/key at every higher level remains unfinished; see the
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
- Pack constant-weighted bit sums into linear AIR rows, retaining Boolean
  constraints and every live copy-bus endpoint. Only internal values used exactly
  twice are eliminated; their prefix sums reconstruct them exactly.
- Regenerate product-bus leaves in bounded chunks and defer column folds.
- Release original trace tables before opening their committed bit coordinates.
- Use the fused Poly192 multiply-add for products with a zero addend, saving one
  arithmetic operation per general multiplication.
- Reuse only PCS-authenticated evaluations with unchanged opening requests.
- Specialize affine bus rounds and skip discarded AIR bus payload construction,
  preserving every constraint and activation check.
- Keep Keccak states packed through the first two instance rounds; use upstream
  packed Poly192 arithmetic and accumulate products before field reduction.
- Encode aggregate field elements at fixed width and use outer rate 1/4 to reduce
  opening traffic. Johnson, the PCS target and the conditional floor are unchanged.

## Four-child tree merge

Two actual depth-32 first aggregates now merge into one checkpoint proof for four
ordered `(root, nullifier_hash)` statements. The merge circuit fixes the source
authority and verifies both complete proofs. The output uses a new verifier key;
reuse of one key at every higher level remains unfinished.

Apple M2 Pro, Rust 1.98.1, release with thin LTO. Each stage has one
cold and two warm samples. Aggregation times exclude setup and compilation;
merge times also exclude creating the children and first aggregates. Filesystem
caches were not reset, and memory pressure was not controlled on this shared host.

| Measurement | First aggregation / 2 children | Merge / 4 children |
|---|---:|---:|
| Threads | 4 | 8 |
| Setup | 6.402 s | 17.791 s |
| Cold aggregation | 20.517 s | 32.328 s |
| Warm median (range) | 20.568 s (20.425–20.711) | 28.860 s (28.820–28.900) |
| Proof bytes | 1,422,998–1,423,350 | 1,369,673 |
| Fresh verification / full process wall | 128.0 ms / 150.5 ms | 112.6 ms / 124.3 ms |
| Witnesses per verifier template | 7,290,188 | 16,437,934 |
| Initial codeword cells | 218,103,808 | 419,430,400 |
| Peak physical footprint / maximum RSS | 7.98 GB / 5.18 GB | 14.89 GB / 6.87 GB |

Warm child proving took 3.117–3.328 s; the first sample's children took
3.350–3.932 s. Child proofs were 1,128,694–1,129,864 bytes. The first stage's warm
critical-path median, including child proving and verification, was 28.027 s.
The merge consumes two newly generated first aggregates and authenticates four
distinct statements in their original order.

Fused multiplication reduces a general Poly192 product from ten arithmetic
operations to nine. Against the previous source authority, it removes 31,722
witness values per verifier and reduces the merge proof from 1,429,334 to
1,373,517 bytes. Four threads measured a 34.784 s warm median; eight measured
26.395 s. Those runs produced byte-identical proofs and verifier files. The table
above uses newly generated source aggregates: their first-stage proofs grew from
about 1.39 to 1.42 MB, while the final merge proof is 1.37 MB. Verifier keys change;
the relation and security parameters do not.

The backend packs up to 16 constant-weighted bit additions into one linear AIR
row. It retains Boolean constraints and all live copy-bus endpoints. An omitted
intermediate must have exactly two original uses and is reconstructed by its
prefix sum. In the current merge, this removes 10,068,514 auxiliary values from
committed tables across the two instances. The witness runner still computes
them. This is an exact algebraic substitution; security parameters are unchanged.

With the earlier source authority held fixed, packing reduced initial codeword
cells from 687,865,856 to 419,430,400 (39.0%). That run measured a 33.046 s warm
median (32.308–33.784), a 1,382,186-byte proof and 15.44 GB physical footprint,
versus the previous 59.445 s median and 23.40 GB footprint. Source authorities,
code fingerprints, thread counts and samples are retained; these runs are not a
controlled timing comparison. A tree speed advantage remains unproven.

The final verifier succeeds with only the final proof, ordered statements and
trusted verifier files. Sixteen mutations are rejected, including changed roots,
nullifier hashes, ordering, counts, proof encoding and authority. The source
aggregate also passes the complete verifier circuit directly; changed public
inputs fail. The new first aggregate passes 17 fresh-process mutation
checks. Conditional algebraic accounting reports 146.208 bits for the current
merge; end-to-end security and joint child statistical ZK remain unestablished.
[Current samples, resource measurements and checks](../benchmarks/binary/tree-merge/fused-multiplication.json).
[Trace-storage measurements](../benchmarks/binary/tree-merge/release-traces.json).
[Packing measurements](../benchmarks/binary/tree-merge/packed-linear.json).
[Earlier merge measurements](../benchmarks/binary/tree-merge/depth32-four.json).

## Compact aggregate proofs

Aggregate encoding uses fixed-width field elements. The outer initial rate is
1/4, with fold 4, Johnson, a 152-bit PCS target, 16-bit grinding ceiling and
144-bit conditional floor. Child encoding is unchanged.
[Earlier encoding measurements](../benchmarks/binary/masked-aggregate/compact-d32-n2.json)
retain the original parameters and source fingerprints.

## Nullifier statement

The depth-32 `(root, nullifier_hash)` relation uses 34 Keccak permutations and
four private carry columns in the same 1,024-row trace and 128-column stacking.
The [initial measurements](../benchmarks/binary/masked-aggregate/nullifier-d32-n2.json)
used outer rate 1/2; they are historical, not current timings.

## Packed Keccak rounds

The checkpoint prover keeps Boolean states packed until two instance challenges
are bound. Four-bit subset-sum tables compute the early rounds exactly. Later
rounds use Plonky3's packed multiplication and unreduced accumulators. Tests
compare every round against the dense reference, including zero and one
challenges; real component proofs were byte-identical.

[Component comparison](../benchmarks/binary/checkpoint-keccak/packed-rounds-65536.json)
and [aggregation comparison](../benchmarks/binary/masked-aggregate/tree-pair-packed-rounds-d32-n2.json)
record the original root/amount relation, which predates nullifier hashes.

## Specialized AIR evaluation

Affine bus rounds avoid higher-degree evaluation work, while every constraint
and activation remains enforced. Historical reports preserve source revisions,
parameters, repeated samples and tamper checks:

- [Checkpoint / 2](../benchmarks/binary/masked-aggregate/checkpoint-specialized-air-d32-n2.json).
- [Flock / 2](../benchmarks/binary/masked-aggregate/flock-specialized-air-d32-n2.json).
- [Checkpoint / 8](../benchmarks/binary/masked-aggregate/checkpoint-specialized-air-d32-n8.json).

Older formats and smaller-depth experiments remain in Git history. Measurements
are never rewritten to describe a different source revision.

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
PoW ceiling and fold 4. The measurements below used rate 1/2; the current
configuration uses rate 1/4. This is a conditional algebraic/PCS calculation,
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

Optional aggregate protocol `experimental-binary-masked-checkpoint-aggregate-v9` replaces
the Flock Boolean wire table with an ordinary native port table and a committed
Keccak GKR subargument. The one aggregate encoding contains both subarguments;
neither is sufficient on its own. The complete child verifier and its public
root/nullifier-hash wiring remain in the arithmetic relation. No child witness or child
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

Verifier snapshot `imt-binary-trusted-verifier-v4` authenticates the selected
backend along with the constraints, preprocessing, coordinate layout and
authority. Earlier snapshots and previous aggregate formats are deliberately
rejected. Trusted key/digest provisioning remains unchanged. Recursive merging through 64 children and joint child statistical-ZK analysis remain open.

### Fixed-width checkpoint transcript regression

Checkpoint backend v6 and trusted-key v4 use the fixed-width transcript accepted
by the recursive verifier. A fresh depth-32 two-child run passed independent
verification and 17 negative checks. Its single cold aggregation took 21.7 s;
fresh verification took 137 ms. This is a format regression check, not a new
warm benchmark. [Raw run and checks](../benchmarks/binary/masked-aggregate/fixed-transcript-d32-n2.json).

The complete aggregate verifier also produced an actual outer proof for two small
checkpoint fixtures: 14.0 s proving, 99 ms verification and 1.25 MB. This does not
measure merging IMT aggregates or establish same-key recursion.
[Component scope and raw sample](../benchmarks/binary/checkpoint-keccak/recursive-aggregate.json).
