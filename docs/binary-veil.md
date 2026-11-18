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
- Keep Keccak states packed through the first two instance rounds; use upstream
  packed Poly192 arithmetic and accumulate products before field reduction.
- Encode aggregate field elements at fixed width and use outer rate 1/4 to reduce
  opening traffic. Johnson, the PCS target and the conditional floor are unchanged.

## Four-child tree merge

Two actual depth-32 first aggregates now merge into one checkpoint proof for four
ordered `(root, nullifier_hash)` statements. The merge circuit fixes the source
authority and verifies both complete proofs. The output uses a new verifier key;
reuse of one key at every higher level remains unfinished.

Apple M2 Pro, four threads, Rust 1.98.1, release with thin LTO. One cold and two
warm samples; compilation and creation of the four children/two first aggregates
are excluded. Filesystem caches were not reset.

| Operation | Measurement |
|---|---:|
| Merge setup | 19.304 s |
| Cold merge | 62.096 s |
| Warm merge median (range) | 59.445 s (54.802–64.088) |
| Aggregate proof bytes | 1,386,223 |
| Fresh verification / full process wall | 127.5 ms / 141.9 ms |
| Witnesses per source verifier template | 15,326,145 |
| Initial codeword cells | 687,865,856 |
| Peak physical footprint / maximum RSS | 23.40 GB / 8.14 GB |

Factoring constant Boolean selectors out of the Frobenius closing-weight sum
and sharing trailing row-coordinate products cut template witnesses from 19.4
to 15.3 million, and initial codeword cells by 16.3%. Parameters and proof
relations are unchanged. An earlier single cold run took 116.8 s and produced
1,441,981 bytes, but briefly overlapped unrelated compilation; it is diagnostic,
not a controlled timing comparison. The optimized run still exceeds physical
RAM, and no tree speed advantage over flat aggregation has been established.

The final verifier succeeds with only the final proof, ordered statements and
trusted verifier files. Sixteen mutations are rejected, including changed roots,
nullifier hashes, ordering, counts, proof encoding and authority. The source
aggregate also passes the complete verifier circuit directly; changed public
inputs fail. Conditional algebraic accounting reports 146.119 bits; end-to-end
security and joint child statistical ZK remain unestablished.
[Raw samples, resource measurements and checks](../benchmarks/binary/tree-merge/depth32-four.json).

## Compact aggregate proofs

Aggregate encoding now uses fixed-width field elements instead of variable-length
integers. The outer initial rate is 1/4; fold 4, Johnson, the 152-bit PCS target,
16-bit grinding ceiling and 144-bit conditional floor are retained. These are
size optimizations, not a stronger security claim. Child encoding is unchanged.

Depth-32 checkpoint tree pair on the M2 Pro with four threads, Rust 1.98.1,
release with thin LTO; one cold and two warm samples, excluding compilation:

| Operation | Measurement |
|---|---:|
| Child proving, all six children | 3.152–4.022 s |
| Child proof bytes | 1,127,590–1,130,405 |
| Aggregate setup | 6.187 s |
| Cold aggregation | 20.304 s |
| Warm aggregation median (range) | 21.018 s (20.710–21.326) |
| Aggregate proof bytes | 1,346,752–1,347,072 |
| Warm verification median | 115.5 ms |
| Fresh verifier wall | 136.2 ms |
| Warm batch critical path median | 29.186 s |
| Peak physical footprint / maximum RSS | 8.20 GB / 4.79 GB |

The aggregate is about 24% smaller than the earlier nullifier-statement baseline,
with about 11% longer aggregation and higher physical footprint (6.52 → 8.20 GB).
The 1.5 MB aggregate target is met for this pair; the 1 MB target and sub-10-second
aggregation target remain unmet. The codeword budget includes all 218,103,808
initial cells, including the checkpoint PCS. Conditional algebraic accounting
reports 146.218 bits; end-to-end security remains unestablished.

Fresh verification succeeds with only the proof, ordered statement and trusted
key files. Seventeen mutations of statements, proof bytes, encoding and authority
are rejected. Recursive Keccak and coordinate-opening components also pass real
proof tests. These measurements predate the complete aggregate-verifier circuit
and fixed-authority merge above; cyclic same-key merging remains unfinished.
[Raw samples, resource measurements and checks](../benchmarks/binary/masked-aggregate/compact-d32-n2.json).

## Nullifier statement

The current depth-32 relation authenticates `(root, nullifier_hash)`. Its extra
Keccak permutation and four private carry columns fit the same 1,024-row trace
and 128-column stacking. Parameters remain unchanged.

Earlier rate-1/2 checkpoint first aggregation on the M2 Pro, four threads,
Rust 1.98.1, release with thin LTO; one cold and two warm samples, excluding
compilation:

| Operation | Measurement |
|---|---:|
| Child proving, all six children | 3.319–4.330 s |
| Child decoding and verification | 416–464 ms |
| Child proof size | 1.128–1.130 MB |
| Aggregate setup | 6.409 s |
| Cold first aggregation | 18.068 s |
| Warm aggregation median (range) | 18.926 s (17.958–19.894) |
| Warm complete batch critical path median (range) | 27.190 s (25.596–28.783) |
| Aggregate proof size | 1.775–1.777 MB |
| Fresh verification, including process and key loading | 138.2 ms |
| Peak RSS / physical footprint | 4.286 / 6.522 GB |

Aggregation includes child import, circuit-witness generation, proving and an
internal verification. Setup is measured separately. Filesystem caches and
thermal state were not reset. The aggregate uses 51,386 Keccak permutations and
has a 146.253-bit conditional algebraic ledger, not an end-to-end security proof.
Plonky3's associated packing type now selects SIMD or scalar arithmetic, so the
optimized prover also compiles on generic x86 targets.

Single cold validation runs also passed for the Flock first aggregate
(31.622 s) and flat checkpoint aggregate (18.058 s), including fresh verification.
These are not warm medians. Each first-aggregation backend rejected all tested
statement, proof, encoding and authority mutations in separate verifier processes.

Raw reports: [current relation](../benchmarks/binary/masked-aggregate/nullifier-d32-n2.json).

## Packed Keccak rounds

The measurements below predate the nullifier relation and authenticate public
root/amount statements. They remain historical baselines, with their original
protocol versions and source fingerprints.

The checkpoint prover delays expanding Boolean states into Poly192 tables until
two instance challenges are bound. Four-bit subset-sum tables evaluate the early
rounds exactly; the first field table has half as many elements. Later rounds use
Plonky3's packed multiplication and unreduced accumulators. Proof equations,
messages, verifier keys and security parameters are unchanged.

Same-session measurements on the M2 Pro with four threads, one cold and two warm
samples per version, excluding compilation:

| Operation | Before warm median (range) | After warm median (range) |
|---|---:|---:|
| 65,536 committed Keccak permutations | 10.437 s (10.199–10.675) | 5.726 s (5.461–5.992) |
| Depth-32 two-child tree aggregation | 26.181 s (25.566–26.796) | 19.244 s (18.473–20.015) |
| Complete two-child batch critical path | 35.452 s (34.894–36.010) | 27.933 s (26.991–28.875) |

Cold aggregation changed from 22.135 to 18.610 s. Filesystem caches and thermal
state were not reset; use the raw ranges rather than treating these as universal
speedups. The component's peak physical footprint fell from 1.662 to 1.032 GB;
the aggregate still peaks at about 6.4 GB. Child proving remains 3.78–4.25 s in
the new batch, with a 1.81 MB aggregate and 147.86 ms fresh verification.

The component produced byte-identical proofs at 4,096 and 65,536 permutations.
The dense-reference test compares every sumcheck round, including zero and one
challenges. The old aggregate verifier accepts the new proof with the same key;
fresh-process tamper tests still reject changed statements, proofs and authority.
This is a prover optimization, not a security or privacy change. Recursive merging
and the sub-ten-second aggregate target remain unfinished.

Raw reports: [component comparison](../benchmarks/binary/checkpoint-keccak/packed-rounds-65536.json)
and [complete aggregation comparison](../benchmarks/binary/masked-aggregate/tree-pair-packed-rounds-d32-n2.json).

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
