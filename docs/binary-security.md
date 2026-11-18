# Binary Keccak research status

The native baseline is **non-ZK**, including its child proofs. The separate
experimental masked path proves Keccak membership at depths 16/32 and aggregates
two or four such proofs into one. Its full privacy/security argument is unfinished. These are
correctness/performance milestones, not completion of the private-transaction
objective. The aggregate does not need to be ZK. No child witness, note, path,
index or proving randomness is an argument to the aggregation API.

The acceptance gate is 128-bit security for **all** child and aggregate proofs,
binary fields, Keccak IMT proving and the stated aggregation latency targets.
The intended security class is classical; Keccak-256 does not support a claim
of 128-bit generic quantum collision security. Sub-128-bit reports are research
measurements only. No default or nominal PCS target is evidence of acceptance.

The accepted privacy target is statistical ZK, with the joint statistical error
budgeted across at most 64 child proofs. Child benchmarking covers depths 16/32.
Aggregation of aggregates is deferred. See the explicit (not yet proved)
[privacy budget](binary-veil.md#privacy-target-and-historical-v2-measurements).

## Masked-child aggregation status

The experimental masked path now has one real Flock/native-product-bus aggregate
of two independent child candidates, including fresh-process verification at
IMT depths 16 and 32. Its prover receives no original IMT witnesses. Flock is
non-hiding here; all its witness data comes from the published child proofs.

This supplies the verification relation, not the missing joint child simulator
or a Fiat–Shamir/knowledge composition theorem. The outer Johnson ledger enforces
at least 144 conditional algebraic bits (146.43 in the measured depth-32 batch),
separately from Keccak-256's generic 128-bit classical collision work factor.
The child masks, oracle randomness, aborts, salted commitments and CSPRNG/ROM
assumptions still require a composed analysis. Reports therefore keep
`full_zk_established: false` and `end_to_end_security_bits: null`.

The pinned Flock upstream PR is experimental. The local adapter and its weighted
claim/successor-bus changes also need review; see
[the backend notes](../crates/flock-backend/README.md). Numerical budgets and tests
are not a security certificate, and there is no 128-bit post-quantum claim.

## Current implementation pass

The native child and aggregate prover now use **Poly64 with Poly192 challenges**,
including actual in-circuit child verification. The v2 authority/transcript domain
and public transport reject the old Tower128/v1 proof family; use commit `40ac660`
to reproduce or verify historical artifacts. The separate Flock backend adds
the upstream pin documented in the root README.

Defaults are PCS target 152, grinding ceiling 16, and Johnson analysis. Both
child and outer authorities must have at least 144 bits in the union of upstream
**non-hash, uniform-challenge** terms. The aggregate constructor reassesses the
retained child authority and checks the union of N children plus its outer proof.
It cannot accept a weaker child merely because its own output configuration is
stronger. Explicit low-security test settings remain available for regressions.

The upstream combined floor is 127, **not a rounded 128-bit pass**. Its estimate
includes the 128-bit hash cap as an error term. Reports keep that combined result,
the non-hash algebraic union, and Keccak's conventional collision work factor
separate. Adding those different quantities is not an end-to-end work-security
proof. `child_zk` and `end_to_end_128_established` remain false on this native path.
Fiat–Shamir knowledge extraction and recursive composition remain obligations.

The VEIL v2 experiment corrects a separate binding-radius error, separates all
commitment/transcript hash domains, and has its own conditional inner-IOP ledger.
See [binary-veil.md](binary-veil.md). Its format is still not accepted by the
native recursive verifier.

## Measured v2 native baseline

Depth 8, N=2, three samples (one cold, two warm), four threads on the same
Apple M2 Pro / 16 GiB / Rust 1.98.1 machine. No compilation ran concurrently.
The historical command is `cargo run --locked --release --bin bench -- --depth 8 --batch-size 2
--samples 3 --out run/bench-two` (one shell line).

| Measurement | Warm median | Warm range |
|---|---:|---:|
| Child proving, four samples | 80.47 ms | 60.84–118.45 ms |
| Child native verification | 25.26 ms | 24.44–26.65 ms |
| Outer proving | 39.094 s | 36.887–41.301 s |
| Aggregation wall time | 40.176 s | 38.080–42.273 s |
| Aggregate decode + verify | 36.72 ms | 36.00–37.44 ms |
| Batch critical path | 40.491 s | 38.405–42.578 s |

Setup took 4.707 s. The outer proof was 1.260–1.263 MB; peak process RSS was
7.23 GiB. The independent verifier took **4.795 s wall time**, including 4.547 s
reconstructing trusted verifier data and 33.68 ms decoding/verifying the proof.
Warm verification excludes reconstruction; this distinction matters for latency.
The default codeword budget is 2^29 cells and is not a peak-RAM guarantee.

The child's conditional non-hash model is 148.181 bits, the outer's is 145.893,
and the N=2 algebraic union is **145.398 bits**. These are explicitly separate
from Keccak's generic 128-bit collision work factor. **Both proof formats in
this benchmark are non-ZK; the end-to-end acceptance flag remains false.**
The aggregation latency target is not met.

Raw reports are in [`benchmarks/binary/v2`](../benchmarks/binary/v2), including
failed attempts at PCS target 160. The child required at least 6 grinding bits
at that target; the larger outer circuit required 18, beyond the configured
ceiling of 16. The final run explicitly used target 152 and retained the same
144-bit algebraic floor. No automatic security fallback was used. All successful
v2 records share the same compiled source fingerprint, and the exact settings
are serialized alongside each measurement.

## Implemented relation

`cm = Keccak256("IMT-KECCAK-LEAF1" || secret[32] || amount_u64_le || nonce[32])`

`node = Keccak256("IMT-KECCAK-NODE1" || left[32] || right[32])`

Both tags are exactly 16 ASCII bytes. This is Ethereum-style Keccak-256, **not
SHA3-256**. Empty leaf digests are 32 zero bytes. The tree is fixed-depth and
append-only. The circuit constrains the sponge's input bytes, padding,
permutations, path selection bits, and equality with all 32 public root bytes.
The eight public amount bytes are exactly the bytes in the note preimage.

Binary-field byte values use raw tower coordinates, not `from_u64`, which would
retain only parity in characteristic two. Public input order is root bytes then
eight amount bytes, repeated in child order. Rust `u64` JSON deserialization
rejects negative, overflowing and fractional amounts. The circuit independently
rejects coordinates outside the eight-bit byte range.

Each child uses an independently generated secret and nonce. Fixtures append all
users after eight existing commitments, then append another commitment before
each user's path is taken. This supplies different, later roots. Root-history
authorization, spending, replay prevention and nullifiers are out of scope.

## Actual proof and recursion path

The selected path uses Poly64/Poly192, native Keccak-f tables, product buses and
additive WHIR. The Keccak table is committed as packed bits; all other tables are
dense. Commitments and Fiat-Shamir use Keccak-256, four-way commitment Merkle
trees, and a cap of 16 roots. The application IMT remains binary.

`PreparedAggregate` constructs N copies of the upstream native mixed-WHIR
verifier in one binary circuit. It checks Fiat-Shamir, PCS openings, sumcheck,
AIR constraints, product buses and trusted preprocessing. A native validity
check precedes encoding/witness packing, but is **not** the recursive statement:
the full verifier is constrained again inside the outer proof. Tests bypass the
native precheck and tamper with the compiled verifier's private proof values.

The fixed graph, trusted authority and public vector bind N and child order.
Repeated statements are permitted. An aggregate does not produce a new IMT root.

The fresh verification process loads only `aggregate.proof`, `statement.json`
and `trusted.json`. Trust data must be independently provisioned; accepting a
prover's replacement trust file would defeat the trust boundary. This prototype
reconstructs native authorities and checks their Keccak identities, which costs
much more than warm proof verification. It does not yet have a compact portable
snapshot for this native verifier family. Reconstruction time and process wall
time are reported separately; neither is hidden inside the warm verifier number.

## Historical Tower128 assessment

Dependencies for the selected path are Plonky3 crates `=0.9.0-rc.2` (published
source revision `fe5e46d755b8a7d9069778361e21b33e5978b377`) and Plonky3-recursion
`3a69ba61f713c8400b14eb3d8f0e52caa13512c7`, with the existing local recursion
patches described in [LOCAL_CHANGES.md](../vendor/p3-recursion/LOCAL_CHANGES.md).
The binary implementation adds no cryptographic dependency patches.

The historical WHIR proximity parameters use the **Johnson bound**. Its default PCS
target is deliberately only 32 bits, no grinding; dense code rate is 1/2, packed
code rate 1/8, and log folding factor is 4. These are low-security research
measurements. They are not a 128-bit configuration. Every report includes the
actual per-authority security terms and union-bound estimate from upstream.
The configurable minimum security floor fails closed if upstream cannot meet it.

The aggregate authority's bound does not include the child proof error. A
conservative composition must account for all N child arguments plus the outer
argument, their knowledge/extraction assumptions, Fiat-Shamir/ROM analysis, hash
collisions and any composition losses. No end-to-end bit-security theorem is
claimed. Increasing queries does not remove field-size losses: the Tower128
product-bus and constraint terms already cap the current graphs below 128 bits.
The current native implementation uses that larger Poly64/Poly192 challenge
field; it does not solve child ZK by itself.

The separate 80-bit-PCS experiment uses a 16-bit WHIR grinding ceiling and
reports 77.08-bit child / 75.20-bit outer models. It is also non-ZK and not a
128-bit configuration. Grinding is explicit through `--pow-bits`; the default
remains zero. Reports retain the requested ceiling and the resulting assessed
terms, rather than treating the nominal PCS target as achieved security.

### Larger binary challenge-field assessment

`cargo run --locked --release --example binary-security` constructs the actual
Keccak IMT relation over Poly64 with Poly192 challenges at depths 8, 16 and 32.
This example remains a parameter/authority assessment. It
does not generate a proof or add ZK. The relation builder is shared with the
Tower128 baseline; positive and tampered-root witness checks cover both carriers.

For depth 32, PCS targets 128, 144 and 160 give total upstream estimates of
124.75287106265998, 127.99980096020298 and 127.99999998098134 bits respectively.
At PCS target 160, every non-hash term exceeds 156 bits; the 128-bit Keccak-256
collision cap dominates. The upstream estimator adds that cap to all algebraic
errors, so its strict `require_security(128)` test rejects all three. We retain
that result rather than rounding to a pass. This is a promising conventional
128-bit-class candidate, but it is not an established end-to-end 128-bit theorem.
Hash collision assumptions, Fiat-Shamir/ROM losses and N-proof composition need
to be stated separately and analyzed. Outer graphs also need their own budget.

The raw terms and strict-gate results are in
[security-parameter-probe.json](../benchmarks/binary/v2/security-parameter-probe.json).
The example deliberately uses a low setup gate to inspect all terms, then
reports the separate strict-128 check. It cannot emit an accepted low-security
proof disguised as a 128-bit proof.

Keccak-256 has a generic classical collision cost around 2^128, generic quantum
preimage cost around 2^128, and generic quantum collision query cost around
2^(256/3). These are generic hash bounds, not a proof-system QROM theorem. We
make no claim of 128-bit post-quantum security.

## ZK investigation, including newer upstream code

Inspected and executed the binary reference example at Plonky3
[`0d803737b681774186cd283b1fd2d8e493655c82`](https://github.com/Plonky3/Plonky3/tree/0d803737b681774186cd283b1fd2d8e493655c82).
This is a research source pin, **not** the dependency used by the binary baseline.

* [`binary-pcs/src/zk`](https://github.com/Plonky3/Plonky3/tree/0d803737b681774186cd283b1fd2d8e493655c82/binary-pcs/src/zk)
  implements a salted, masked reference PCS and private **current-row** AIR
  compiler over BinaryField128. Its security contract derives bounded-query
  classical-ROM claims under explicit RNG and lifetime salted-leaf assumptions.
  It is experimental, not an independently audited security result.
* Its supported relation excludes next-row access, preprocessing, row selectors,
  public boundaries, permutation arguments, lookups and buses. The existing
  Keccak AIR needs row transitions; NativeBusCircuit needs product buses and
  preprocessing. These cannot simply be passed to this compiler.
* The reference sends full polynomial coefficient blends instead of using
  additive WHIR. Its native example, with four rows, two private columns and one
  constraint, produced a **420,000-byte** serialized proof at its declared
  80-bit bounded-ROM target (460 queries). This is not a measurement of private
  IMT membership and not an equal-security comparison with our WHIR baseline.
* Plonky3-recursion at the pinned HEAD has no native recursive verifier for that
  reference ZK proof format. Its existing native verifier accepts non-hiding
  MultiStark/WHIR proof formats.
* Latest `whir/src/pcs/zk/adapter.rs` still requires TwoAdicField and
  PrimeField64; the ZK sumcheck implementation also uses two-adic assumptions
  and a division by two. Porting only the PCS does not hide the native
  MultiStark zerocheck, product-GKR messages or terminal evaluations.

Thus there is now a binary ZK primitive upstream, but no supported **full
binary Keccak membership + native recursive verification** combination.

## Remaining security work

The experimental [masked-child and Flock implementation](binary-veil.md) now
supplies the full membership relation and aggregation of its complete verifier.
The earlier missing integration is implemented; its security argument remains
unfinished. The required review covers:

1. Joint simulation of masked algebraic messages, current/successor openings,
   committed random blends, adaptive queries and salted hash commitments.
2. Abort probabilities, randomness lifecycle and lifetime query/commitment
   budgets, with statistical error charged across up to 64 children.
3. Fiat–Shamir knowledge soundness and recursive composition, separating the
   conditional algebraic budgets from the hash/CSPRNG assumptions.

The local padding/coupling tests support individual algebraic claims; they are
not a joint simulator or an end-to-end security proof. A successful aggregate
cannot establish child privacy. Once child ZK is established, aggregation may
remain non-ZK because it receives only child transcripts and public statements,
never the original notes, paths or private random tapes.

Sources: [native binary support](https://plonky3.github.io/Plonky3-recursion/advanced_topics/binary_fields.html),
[VEIL](https://blog.succinct.xyz/veil/),
[VEIL implementation](https://github.com/succinctlabs/sp1/tree/749b0c63f226063c471a6238a94101f930c14a13/slop/crates/veil).

Fresh-process negative checks are recorded in
[`verification-negative.json`](../benchmarks/binary/v2/verification-negative.json).
All 12 cases rejected altered statements, authority data or proof bytes.
