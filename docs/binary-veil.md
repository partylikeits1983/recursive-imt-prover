# Binary VEIL implementation experiment

The experimental masked child links the native AIR prover, private trace
openings and VEIL-style algebraic consistency into a binary Keccak IMT proof.
It supports depths 16/32, independent-process verification, and a one-proof
Flock aggregate of complete masked-child verifiers. The older native aggregator
remains a separate non-ZK-child baseline. Cryptographic acceptance remains
**false**: joint statistical ZK and end-to-end 128-bit security are not established.
See [the current aggregate](#end-to-end-aggregate) below; earlier sections retain
their explicitly versioned component measurements.

## Complete masked child and compact trace openings

`child.rs`, `membership_air.rs` and `air_algebra.rs` define one fixed relation.
Each hash occupies 25 adjacent rows. Trusted preprocessing pins round flags,
input domains/padding and the actual final hash output. Constraints link each
previous digest into the left or right input of the next node hash, enforce
Boolean direction bits, and bind the public root and little-endian amount.
The original secret, nonce, path and index are never passed to aggregation.
The native ordinary AIR proof is private intermediate data and is not serialized.

The compiler masks all witness-dependent native round messages, current and
repeat-last successor evaluations, and private endpoint multiplication values.
A deduplicated endpoint program reuses 5,314 private multiplication gates.
Trusted public/preprocessed openings are computed independently. The fixed
relation has no bus interactions, avoiding an unnecessary product-bus ZK layer.

The first complete format (`IMTVCA01`) produced roughly 10 MB per child: 176
queries each opened 1,627 extension-field values. Raw evidence for that design
is in [masked-child-v1](../benchmarks/binary/masked-child-v1). Those depth-16/32
runs used twelve threads. Current runs below use four, so the old and new proving
timings are not a fixed-thread performance comparison.

The earlier measured format (`IMTVCA02`, `experimental-binary-masked-imt-v2`) stacks 32
trace columns into each longer oracle column. A sampled row now contains 52
extension-field values, including the independent auxiliary mask. The last
stack's unused slots are zero. Trusted geometry, including stacking, is bound
into the verifier identity and transcript. Version 1 child artifacts are rejected.
This changes only the private trace adapter; the inner Hadamard proof retains
its interpolation code and the original component fixtures retain their formats.

The oracle uses Plonky3's existing additive NTT with novel-basis coefficients:

- The final aligned coefficient block holds the stacked trace. Every coefficient
  before it is independently random. The first `q` novel polynomials have degrees
  `0..q-1`; their evaluation matrix at `q` distinct domain points is an invertible
  Vandermonde matrix times an invertible basis change. Consequently those random
  coefficients hide any fixed set of at most `q` queried rows. Repeated queries
  give fewer independent observations. This is a local privacy fact, not a full
  adaptive transcript simulator.
- Masked original-column claims precede the slot-combination challenge. Masked
  auxiliary claims precede the column-combination challenge. The resulting full
  vector `B` includes an independent auxiliary column with nonzero coefficient.
  Only `B` enters ordinary, non-hiding WHIR.
- A public quadratic sumcheck links the claimed evaluations and sampled rows to
  an actual WHIR opening. Its weight function is verifier-derived and bound by a
  compact descriptor. For a codeword point `x`, novel-basis generator factors
  `t_j(x)` give terminal weight `product_j(1-s_j+s_j*t_j(x))`. Prefix selectors,
  slot powers and upstream `Point::eval_next` handle the trace views. The verifier
  evaluates these in `O(q log n)` field operations. The prover still builds a
  dense table; no new polynomial commitment scheme is introduced.

Queries, rate and conditional floor remain 160 target bits, rate 1/16 and 144
conditional algebraic bits. The oracle ledger charges slot/column batching,
Johnson proximity, row queries, functional batching, WHIR candidate lists and
sumcheck. It is not a complete Fiat–Shamir/ROM or aggregation bound.

```sh
RAYON_NUM_THREADS=4 cargo run --locked --release --example masked-child -- \
  --depth 32 --samples 3 --out run/masked-child
```

Tests compare the compact functional against independent dense MLE evaluation,
check coefficient encoding against the actual upstream NTT, and exercise random
padding retargeting. Actual cryptographic tests reject swapped columns, slots
and successor views, changed geometry, and a forged claim generated with the
prover's relation precheck bypassed. Child tests constrain all hashes and reject
altered statements, trace cells, authority and transport bytes. These tests do
not by themselves establish full zero knowledge.

## Privacy target and historical v2 measurements

Child benchmarks now cover **depths 16 and 32 only**. The aggregation target is
one proof for up to **64** children; aggregating aggregates is deferred.
Statistical ZK is acceptable. The intended statistical-distance budget is at
most `2^-128` for the joint view of a batch. A conservative per-child allocation
of `2^-144` would sum to at most `2^-138` for 64 independently randomized children,
leaving margin for other statistical terms. This is a target, not an established
bound for this implementation. Computational hash/CSPRNG assumptions and
Fiat–Shamir programming/extraction terms must be reported separately.

Aggregation receives only children and public statements. Once joint child ZK
is proved, applying the aggregate algorithm to that view cannot increase its
statistical distance. Fresh masks and oracle randomness are required for every
child proof; reusing a consumed private commitment is unsupported. A 160-bit
query-miss soundness target does not itself prove the privacy budget.

Historical v2 measurements: Apple M2 Pro, 16 GiB RAM, four threads, Rust 1.98.1,
release/thin LTO. Three samples per depth; warm median and two-sample range:

| Depth | Cold prove | Warm prove (range) | Warm decode + verify | Proof size | Peak RSS |
|---|---:|---:|---:|---:|---:|
| 16 | 1.002 s | 0.923 s (0.906–0.940) | 95.32 ms | 2.194–2.195 MB | 1.42 GiB |
| 32 | 1.907 s | 1.730 s (1.702–1.759) | 94.88 ms | 2.210–2.211 MB | 2.79 GiB |

The private-oracle component is about 0.53 MB at depth 32; the masked algebraic
consistency component is about 1.68 MB. That remaining linear-size component
is the next proof-size/verifier-cost bottleneck. Independent column encodings
run in parallel; transcript challenges and commitments preserve their order.
Fresh verifier wall times were 111.58 and 111.73 ms, including about 9–10 ms of
trusted setup. Lifetime RSS includes earlier samples. Two warm samples do not
establish a latency distribution.

[Raw reports](../benchmarks/binary/masked-child-v2) retain exact parameters,
source fingerprints and measurements. Fifty default release tests passed for the compact format; the 24 affected
library, binary and security tests also passed after the depth/default/batch-limit
update. Formatting and all-feature Clippy passed.
Eleven fresh-process negative cases rejected statement, authority, parameter
and transport changes. The negative report records its earlier source fingerprint;
only parallel encoding changed between it and the timing build.

```sh
cargo build --locked --release --example masked-child
python3 scripts/bench-veil.py --out run/masked-children --depths 16 32 \
  --threads 4 --samples 3
```

## Upstream inspection and implementation plan

The next implementation steps are tracked in
[development.md](development.md#next-milestones). The source inspection found:

| Source | What can be reused | Missing support for this project |
|---|---|---|
| Plonky3 `binary-pcs/src/zk` | Binary reference masking and explicit transcript/security accounting | Fixed Tower128, current-row AIR only; no next rows, preprocessing, product buses or optimized hiding WHIR |
| Plonky3 `whir/src/pcs/zk/adapter.rs` | Hiding-PCS interface and claim-binding pattern | Requires `TwoAdicField + PrimeField64`; cannot instantiate with Poly64/Poly192 |
| VEIL `compiler`, `zk/prover_ctx.rs` | Commit masks first; send masked values online; replay one verifier to collect constraints | Needs a binary context and connection to MultiStark's actual prover |
| VEIL `zk/stacked_pcs` | Padded oracles, committed mask columns and masked evaluation claims | Implementation wraps BaseFold; additive WHIR integration is still needed |

Inspected Plonky3 HEAD
[`0d803737b681774186cd283b1fd2d8e493655c82`](https://github.com/Plonky3/Plonky3/tree/0d803737b681774186cd283b1fd2d8e493655c82)
and VEIL
[`749b0c63f226063c471a6238a94101f930c14a13`](https://github.com/succinctlabs/sp1/tree/749b0c63f226063c471a6238a94101f930c14a13/slop/crates/veil).
These are research references, not dependency upgrades. The application retains
Plonky3 `=0.9.0-rc.2` and recursion
`3a69ba61f713c8400b14eb3d8f0e52caa13512c7`. The sumcheck fixture explicitly
depends on the same already-locked `p3-sumcheck` and `p3-multilinear-util` versions.

The original integration boundary needed to change: MultiStark uses
`PrescribedPointPcs::open_at` / `verify_at`, whose verifier returns concrete
`OpeningEvals`. Passing the original trace evaluations through that interface
would expose them. The implemented adapter instead links masked evaluation expressions
to the compiler's constraints while WHIR authenticates the permitted masked
combination. An `Mmcs` replacement or hiding commitment alone does not do this.

## Private-oracle WHIR bridge

`oracle.rs`, `whir.rs` and `private_sumcheck.rs` now implement an experimental
bridge using the pinned binary additive WHIR. It authenticates one or two MLE
openings of private polynomial tables in one consumed commitment. The private
sumcheck fixture publishes a commitment and dot-product claim, not its tables.
This is a component of the intended child compiler, **not an IMT child proof**.

The protocol is:

1. Pad each oracle column with independent random interpolation coordinates.
   Commit those columns and one independent full-field mask column together
   using salted Keccak Merkle leaves. The code's disjoint additive domains give
   the Cauchy-minor query-hiding property already used by the inner argument.
2. Send the data and mask MLE evaluations through the online masked compiler.
   Derive `alpha` only after those messages and their commitments are bound.
3. Form `B = W_0 + alpha W_1 + ... + alpha^c R`, including all padding. Commit
   **only B** through ordinary Poly64/Poly192 WHIR. Original private tables and
   their unmasked evaluations never enter that non-hiding WHIR prover.
4. Bind the WHIR root and the public evaluations of B, then draw one paired
   query schedule against the original salted commitment. Each queried B value
   must equal the same random combination of authenticated oracle rows.
5. Randomly batch the MLE evaluations and queried codeword evaluations into a
   dense linear functional of B. A public quadratic sumcheck reduces that
   functional to one MLE evaluation. The existing WHIR `open_at` / `verify_at`
   authenticates its three Poly64 coordinate polynomials at that point.
6. The inner algebraic argument constrains the hidden claims' random combination
   to the authenticated public B evaluations. The private sumcheck additionally
   constrains its terminal values to the oracle's hidden claims.

This uses upstream sumcheck arithmetic, additive WHIR and Keccak MMCS; it does
not introduce a new PCS or upgrade dependency revisions. A complete masked B
vector is no longer sent by this oracle bridge. The reference implementation
still builds dense functional weights in `O(q * padded_length)` time, and its
original oracle storage currently uses Poly192 cells. Those costs need profiling
before large Keccak traces. This does not yet preserve packed-bit storage.

The local conditional ledger includes query misses, Johnson proximity, hidden
claim batching, dense-functional batching, WHIR and the extra sumcheck. The
last two reductions charge the WHIR commitment's candidate-list size before
their challenges. Both prover and verifier enforce the 144-bit conditional
floor. **This is not a complete ROM or composed 128-bit bound.**

For fixed coins and paired queries, the privacy coupling extends as follows.
Change each W column's message and translate padding to preserve its opened
rows. Keep B fixed by setting `R' = (B - sum alpha^j W'_j) / alpha^c`.
Linearity preserves R's queried rows too. Translating the compiler's independent
message masks preserves all masked evaluation messages. Importantly, keeping
the entire B vector fixed preserves every WHIR opening, OOD value, fold and final
polynomial jointly. `tests/veil_privacy.rs` checks this for two points and a
repeated query. A full adaptive transcript/commitment simulator and ROM knowledge
composition proof remain required; this algebraic test does not establish them.

```sh
cargo test --locked --release --test veil_oracle --test veil_privacy
cargo run --locked --release --example veil-oracle -- \
  --variables 8 --points 2 --samples 3 --out run/veil-oracle-small
cargo run --locked --release --example veil-oracle -- \
  --variables 12 --points 2 --samples 3 --out run/veil-oracle-large
```

The example stores only the last serialized proof, public statement, trusted
parameters and JSON measurements; it then verifies in a fresh process. Proving
includes setup and all commitments on every sample. Reports explicitly mark
full-ZK and end-to-end security acceptance as unfinished. Its aggregation
limitation was subsequently addressed by the Flock path below.

Measured component results (two private tables, two evaluation points; three
samples with the first reported separately as cold):

| Entries per table | Cold prove | Warm prove, median [range] | Warm decode + verify, median [range] | Proof bytes, range | Peak RSS |
|---|---:|---:|---:|---:|---:|
| 256 | 76.84 ms | 40.63 [37.90–43.36] ms | 11.23 [11.05–11.42] ms | 383,441–384,185 | 14.1 MiB |
| 4,096 | 389.74 ms | 374.79 [359.49–390.09] ms | 145.75 [145.39–146.11] ms | 459,811–460,154 | 94.8 MiB |

Both final artifacts passed verification in a fresh process, taking 13.66 ms
and 148.64 ms wall time respectively. Setup is rebuilt in every sample. These
are **oracle-component measurements, not client or aggregation timings**.
Raw reports are in [`benchmarks/binary/oracle-v1`](../benchmarks/binary/oracle-v1),
with hardware, compiler, parameters and source fingerprint
`4ab754f21a6a3c082279787411cf3cecc6be66c51f95cb5e388f1c334071bea9`.
They precede the native AIR adapter and successor-view changes below.

## Native AIR transcript boundary

`native.rs` adapts the pinned `AirZerocheck::prove` without copying or modifying
its arithmetic kernels. The upstream transcript drivers generate a trusted
interaction schedule from AIR degrees and trace height. The adapter checks
public framing exactly, groups three Poly64 coefficients into each private
Poly192 message, and routes the complete message through the committed-mask
context before returning a challenge. Whole Poly192 challenges are split into
their base coefficients only after sampling. No independently masked 64-bit
limbs or 64-bit soundness challenges are substituted.

Verifier replay consumes the same schedule. The upstream
`RoundPolyInterpolator` supplies the characteristic-two-safe coefficients of
each affine claim reduction. Tests run the **actual upstream Keccak AIR** and
check that its native verifier and compiled reduction agree. A second test
generates an actual masked algebraic proof for a public Boolean trace, then
bypasses the prover precheck to confirm a forged round is rejected. This test's
trace is public; it does not establish a private Keccak proof.

The adapter currently rejects lookup/bus reductions, grinding and bit-sampling
steps. Schedule drift is an internal invariant failure. An upstream ordinary
proof remains private intermediate state and must never be serialized as the
ZK output. The fixed membership child now supplies the private AIR terminal evaluator and
preprocessed/public boundary checks without a product bus. Joint simulation and
the complete child verifier inside aggregation were unfinished at this milestone;
the current Flock path implements that verification relation.

The private oracle additionally supports current and **repeat-last successor**
views at one point, using Plonky3's `NextStatement` weights. Both views open the
same consumed commitment, and their ordered view schedule is transcript-bound.
Tests authenticate these claims, reject changed values and swapped/substituted
views, and cover the final-row boundary. Existing all-current proof transcripts
retain their encoding. This supplies the next-row opening needed by the native Keccak AIR. The fixed
membership child now connects these through its terminal-algebra program.

Validation for these adapters: 45 default release tests passed, formatting and
all-target/all-feature Clippy passed, and saved oracle-v1 and direct VEIL-v2
artifacts verified in fresh processes after the changes. Tests demonstrate
implementation checks, not a full-ZK or end-to-end security theorem.

## Miden comparison

Inspected Miden at
[`2c7458102640b2feb4c22d88846a554a0d98c771`](https://github.com/0xMiden/miden-vm/tree/2c7458102640b2feb4c22d88846a554a0d98c771).
Its current [recursive VM adapter](https://github.com/0xMiden/miden-vm/blob/2c7458102640b2feb4c22d88846a554a0d98c771/crates/stark/vm/src/recursive/mod.rs)
accepts Eidos STARKs. The
[advice adapter](https://github.com/0xMiden/miden-vm/blob/2c7458102640b2feb4c22d88846a554a0d98c771/crates/stark/core/src/recursive/advice.rs)
rejects nonempty hiding salts. The inspected
[recursion benchmark](https://github.com/0xMiden/miden-vm/blob/2c7458102640b2feb4c22d88846a554a0d98c771/benches/synthetic-bench/benches/recursive_verify/config.rs)
selects Eidos and exercises 3–7 VM proofs plus one precompile proof. These are
not measurements of binary Keccak ZK aggregation at our required parameters.
No Miden timing or speedup has been reproduced in this repository.

Useful implementation references are its generated arithmetic-verifier code,
content-addressed proof/claim inputs, cached fixtures and separate trace/proving
measurements. The project's field, Keccak and 128-bit requirements remain fixed;
Miden is a design reference, not a replacement backend.

## Online transcript milestone

`compiler.rs` now commits one vector of fresh masks **before** the first
algebraic protocol message. Each outgoing field element is masked immediately;
Fiat–Shamir challenges absorb those masked messages. The proof later opens the
same commitment in the existing inner argument. A replacement commitment is
not accepted. Private commitment state is consumed and is neither cloneable
nor serializable.

`sumcheck.rs` exercises that context with a quadratic product sumcheck, reusing
Plonky3's round-coefficient and variable-folding kernels over Poly192. One
verifier replay defines the prover's and verifier's affine/product constraints.
The fixed program, public tables, claimed sum, parameters and message count are
bound before the initial mask commitment. Replay checks exact framing, labels,
challenge calls and consumption; the derived constraints are bound before the
final inner argument. The new `IMTVSC01` transport is separate from the direct
Keccak `IMTVEIL2` proof format, whose transcript is unchanged.

This fixture's two polynomial tables are **public**. Its verifier evaluates
both polynomials independently at the derived point and constrains both masked
terminal values as well as their product. Checking only round consistency would
leave the claimed polynomial unauthenticated. Replacing those public tables
with private trace oracles requires the hiding PCS adapter in the next milestone.

```sh
cargo test --locked --release --lib --test veil_sumcheck -- --test-threads=1
```

Tests include valid serialized proofs, changed statements and parameters,
malformed shapes/transport, altered masks and commitments, and schedule drift.
Adversarial tests bypass the prover's native checks to generate actual algebraic
proof attempts with false rounds or terminal values; verification rejects them.
One attempt satisfies the terminal product but lies about both oracle values.
These are correctness tests, not a full adaptive-transcript simulator or a
Fiat–Shamir soundness proof. The default inner conditional floor remains 144
bits; no compiled-protocol or end-to-end 128-bit claim follows from it.

Validation for this milestone: 38 default release tests passed, including seven
new compiler/sumcheck tests; all-target, all-feature Clippy passed with warnings
denied. Existing native aggregation and its independent verification tests pass.

## v2 corrections and security scope

The serialized proof now starts with `IMTVEIL2`; trust metadata and the transcript
bind `experimental-binary-veil-inner-v2`. v1 proofs are rejected. Keccak leaf,
node and transcript inputs have distinct fixed domain prefixes. All original
Plonky3 and recursion dependencies remain pinned.

The previous query calculator used WHIR's Johnson radius directly. That is not
sufficient for the VEIL binding theorem, whose hypotheses additionally require
`delta <= Delta/2`. With code rate `rho`, v2 chooses

```text
delta = min(Johnson_radius(rho), (1-rho)/2)
q = ceil(query_bits / -log2(1-delta))
```

The proximity error still uses Plonky3's proven Johnson calculation. The extra
cap is required by this VEIL reduction, not a stronger RS conjecture. At base
rate 1/16 and product rate 1/8, a 160-bit query target requires **176 and 193**
queries. The old 83/112 schedule yields only about 75.7/93.0 query-miss bits
under this binding argument. Historical diagnostics must not be cited as a
160-bit VEIL bound. All queried rows count against independent padding.

The new conditional inner-IOP ledger includes both code-query terms, the mask
and product proximity generators, the square-code generator, Hadamard residual
batching, all three product-vector links, and affine/public batching. Challenges
exclude zero and one; the field terms conservatively charge one bit for this
conditioning. The default inner algebraic floor is 144 bits, checked by both
proving and verification. This is conditional interactive analysis, **not** a
Fiat–Shamir/ROM extraction theorem or recursive composition certificate.

`tests/veil_privacy.rs` checks the joint algebraic view via a bijective change
of private randomness. For two different valid witnesses, it adjusts the two
padding triples to preserve all product claims, solves Cauchy systems to preserve
all queried rows, and adjusts both auxiliary masks to preserve the full blends,
product residual and dot claims. It also preserves the masked witness and the
correlated mask commitment's queried rows. Duplicate queries are included.

For example, for fixed nonzero blend coefficients, preserve `phi` by setting
`M' = (phi + A'B' + C') / sigma`, and preserve the dot blend by setting
`R' = (blend + A' + rho B' + rho^2 C') / rho^3`. The product-code identity makes
all opened mask evaluations agree. This establishes an algebraic coupling test;
it does not construct a simulator for the full random-oracle transcript.

The reference for the binding hypotheses is the authors' formalization at
[`064fb9e16fc46448010266fb77e00076985a3a23`](https://github.com/succinctlabs/veil-formal-verification/tree/064fb9e16fc46448010266fb77e00076985a3a23):
`ZkDotProduct/Defs.lean` (`hδΔ`) and
`ZkHadamard/Defs.lean` (`hδStarΔStar`). These definitions assume proximity
properties; the repository is not a certification of our concrete implementation.

## Reproduce

```sh
cargo build --locked --release --bin veil-demo
RAYON_NUM_THREADS=4 target/release/veil-demo --depth 0 --samples 3 \
  --out run/veil-preimage
RAYON_NUM_THREADS=4 target/release/veil-demo --depth 1 --samples 3 \
  --out run/veil-membership
target/release/veil-demo --verify --out run/veil-membership
```

Use fresh output directories. Depth zero is one private note-preimage proof;
depth one and above prove actual IMT membership. The statement is the same
ordered `(root, amount)` encoding as the binary baseline. Only the latest sample's
proof and statement are retained. `trusted.json` must be provisioned independently
of the prover in a real deployment. It binds the fixed relation and parameters.

`report.json` records raw measurements, warm median/range, setup, fresh-process
verification, lifetime peak RSS and local coding diagnostics. Compilation is
excluded. Samples are sequential and reuse the relation. The default 2 GiB
retained-commitment budget excludes scratch, relation storage and allocator
overhead; it is not a peak-memory guarantee. `--max-retained-bytes` changes that
resource limit. `--inspect` does not generate a proof.

## Measured v2 direct proofs

Three samples per depth, four Rayon threads, the same M2 Pro / 16 GiB / Rust
1.98.1 machine, no concurrent compilation. Each median/range below uses the two
warm samples. Native aggregation and these direct VEIL proofs are different
formats; the aggregate above does not verify these child proofs.

| Relation | Warm prove (range) | Warm decode + verify | Proof size | Peak RSS |
|---|---:|---:|---:|---:|
| Note preimage | 1.142 s (1.133–1.151) | 273 ms | 17.48 MB | 1.14 GiB |
| IMT depth 1 | 2.361 s (2.316–2.406) | 596 ms | 34.66 MB | 2.48 GiB |
| IMT depth 8 | 12.072 s (11.677–12.467) | 3.031 s | 139.94 MB | 6.00 GiB |

The conditional inner-IOP ledgers report 152.228, 151.233 and 149.237 bits,
respectively. These are **not** complete ZK or Fiat–Shamir security certificates.
Fresh verifier wall times were 0.368, 0.777 and 3.446 seconds. The domain-tagged
hash wrapper preserves upstream batched Keccak; scalar and batched hashes are
checked against independent RustCrypto results at block boundaries.

Raw reports are in
[`benchmarks/binary/v2`](../benchmarks/binary/v2). Proofs remain under ignored
`run/`. That benchmark pass had 31 passing default release tests and all-feature
Clippy with warnings denied; the legacy prime code was not modified. The online
compiler milestone above adds separate tests and does not rewrite these timings.

## Implemented components

* `code.rs`: interpolation Reed–Solomon encoding on disjoint additive domains,
  using Plonky3 `BasisNtt`. Input and padding are evaluations on a Cantor
  subspace; output is evaluated on a disjoint coset. The product code has twice
  the input dimension. Every unused input position receives fresh randomness.
* `vector.rs`: VEIL-style committed dot-product and Hadamard arguments.
  Commitments reuse Plonky3's `MerkleTreeHidingMmcs`, Keccak-256 and two
  192-bit random salts per leaf. Private commitment data is neither serializable
  nor cloneable; producing its opening proof consumes it.
* `constraints.rs`: masked affine and multiplication constraints, public-input
  binding, multiplication-vector consistency, and the two random tautological
  padding triples needed to hide the three multiplication-vector dot products.
  Affine constants are explicit, not an unconstrained alleged constant wire.
* `transcript.rs`: Keccak Fiat–Shamir with framed labels, lengths, a protocol
  domain and a binding to the complete trusted relation, parameters and ordered
  public vector. The current format aborts on a zero or one challenge after one draw.
* `keccak.rs`: a direct translation of **upstream `KeccakBinaryAir::default()`**
  into the inner constraint language, including state Booleanity. Fixed round
  flags, selectors, sponge padding, domain tags, capacity bits and IMT linking
  are constrained. No new Keccak permutation implementation is used.

Arithmetic and masks use `Poly192 = GF(2^192)`. Additive-transform twiddles use
the embedded `Poly64 = GF(2^64)`. All hashing on this path is Keccak-256. The
application tree still hashes 16-byte tags, secret, amount in little endian and
nonce exactly as documented in `binary-security.md`.

The target is **160 bits for query-miss probabilities**, with the binding cap
described above and Plonky3's Johnson proximity diagnostics. The base code rate
is 1/16; the product code rate is 1/8. These require 176 and 193 queried rows
respectively. The combined product/dot opening uses one 193-row schedule,
and all those rows count against the padding budget. Proofs cannot supply their
own rates, query counts or message dimensions.

## Why this is not the fast final architecture

VEIL applies its inner argument to the relatively small *algebraic verifier
transcript*. The direct experiment instead feeds it an entire Keccak execution
to test the binary port against a real application relation. Consequently it
sends a masked vector and full random linear-combination messages proportional
to that execution. It has no WHIR oracle adapter and loses packed-bit trace
storage. Its time and size must not be represented as the overhead of a complete
VEIL compiler.

For one permutation, the direct relation has 78,400 variables and 78,400
multiplication constraints. At depth 8 it has 705,608 variables and 709,704
multiplication constraints. Just retaining its two committed encodings and
Merkle trees needs approximately 6.12 GiB, before temporary buffers or relation
storage. This is a concrete reason to finish the transcript/oracle adapter
before attempting a recursive verifier for the direct format.

There is no general rule that doubling a proof makes it zero knowledge. Some
specific systems obtain hiding with trace or polynomial padding of roughly
that size. Such bounds depend on the protocol, query schedule and compiler;
they are not an upper bound for arbitrary binary recursion.

## Privacy argument to complete

The local encoding property is algebraic: interpolation from a subspace to a
disjoint coset gives a diagonally scaled Cauchy generator. Every square minor
is nonzero. Any `q` distinct queried coordinates therefore have full rank on
any `q` random padding coordinates and are uniformly distributed independently
of the unpadded message. Tests compare this generator with the NTT and check
small minors. The argument also holds after extension to GF(2^192).

Each witness value is sent as `w + m` with an independently sampled committed
mask. Dot-product blends and the Hadamard residual have additional random
masks; their nonzero challenge coefficients are necessary for hiding. This
alone is not a simulator for the entire correlated view.

For the multiplication-vector claims, append `(r,s,rs)` and
`(r+1,t,(r+1)t)` for independent uniform `r,s,t`. With their powers-of-challenge
weights `a,b`, the three padding contributions are

```text
A = a*r + b*(r+1)
B = a*s + b*t
C = a*r*s + b*(r+1)*t
```

For challenge different from zero and one, `a`, `b`, and `a+b` are nonzero.
The inverse is `r=(A+b)/(a+b)`, `s=((r+1)*B+C)/a`, `t=(C+r*B)/b`.
Thus these three contributions are jointly uniform in characteristic two.
The code tests this inverse. The multiplication commitment is absorbed **before**
sampling the linking challenge, so its vectors cannot adapt to that challenge.

Still required: a complete joint simulator for both commitments, full blends,
product residual, opened rows and authentication paths; explicit conditioning
on aborting challenges; adaptive queries and commitment-view hiding;
the random-oracle and lifetime leaf/salt budgets; and composition with the
implemented masked oracle/WHIR adapter. These are security obligations, not claims
that statistical tests establish ZK.

## Soundness and remaining integration

The report's conditional inner-IOP ledger now includes the local algebraic
reductions. It still excludes full Fiat–Shamir knowledge extraction, the concrete
hash/CSPRNG assumptions and recursive aggregation composition.
`end_to_end_security_bits` is deliberately null. A 192-bit field and a 160-bit
query target do not discharge those obligations. Keccak-256's conventional
128-bit classical collision limit and its quantum limitations remain unchanged.

The native masked transcript, fixed membership AIR, stacked oracle and complete
recursive verifier are implemented. The remaining security work is specific:

1. Complete the joint simulator and concrete security ledger for their
   combined view, including ordinary and out-of-domain PCS openings.
2. Review the native Poly64/Poly192 recursive verifier for the **complete new
   format**, including the inner argument, oracle links, trusted authority,
   child public values, count and order.
3. Analyze the whole composition with up to 64 children, then benchmark
   the final parameters. Keep the outer argument non-ZK and give it only child
   proofs and public statements.

The existing non-ZK aggregate remains available as a separate correctness
baseline. No Boolean shortcut, witness-sharing API or relabeling of that
aggregate is used to claim completion here.

### Current v5 child verifier and Flock aggregate

`IMTVCA05` / `experimental-binary-masked-imt-v5` rejects all earlier child
artifacts. The inner format is `IMTVEIL4`; its companion sumcheck/oracle formats
are `IMTVSC03` and `IMTVPO03`. Historical measurements above retain their original
versions and are not timings for v5.

The complete circuit in `child/recursive.rs` now connects the trusted child
identity and public root/amount to native AIR replay, public preprocessing,
private current/next openings, every endpoint product, and the inner VEIL check.
The circuit importer accepts only the proof and public statement. It never takes
the original secret, nonce, path, index or masking randomness. Circuit execution
at depth 16 has accepted real child proofs and rejected altered inputs. The complete verifier is now enforced inside the one-proof Flock aggregate.
Its privacy claim remains experimental.

The version introduces these implementation changes:

- Transcript framing uses fixed-width little-endian lengths and dimensions,
  explicit padding to 16-bit Keccak words, and canonical Poly192 coefficients.
  Postcard is only a transport codec. Every packed word is constrained by the
  Keccak AIR, including the range checks.
- The enclosing transcript absorbs a domain-tagged continuation of the verified
  WHIR transcript. Every WHIR check remains enforced before this seal is used.
- Public uniform dot/Hadamard combinations use existing additive WHIR instead
  of broadcasting their entire vectors. A quadratic functional sumcheck checks
  the original prefix dot product and sampled codeword coordinates. A transpose
  of Plonky3's additive NTT supplies the prefix weights on novel coefficients.
  These additional PCS and batching terms are included in the conditional ledger.
- Trusted replay coefficients and inner dot weights are derived from the already
  authenticated statement/transcript and used directly in constraints. They are
  not prover-supplied hints. Rehashing their large redundant serializations was
  removed. The generic WHIR API still binds independently supplied weights.
- Challenge sampling draws once and aborts on zero or one. Under a uniform
  random-oracle output, each draw has abort probability `2^-191`; the final
  statistical privacy ledger must charge the number of draws. This avoids
  computing sixteen unused retry paths in the verifier circuit.
- Trace columns are stacked 128 at a time. The depth-16/32 oracle coefficient
  lengths are now 131,072/262,144. This trades more native commitment work for
  narrower opened rows and less recursive Keccak work.
- Query groups use the same deepest-first stratification as Plonky3 WHIR:
  each power-of-two group samples once per equal high-bit stratum. For a fixed
  bad-coordinate set, AM-GM bounds the group's miss probability by
  `(1-delta)^group_size`; multiplying the independent groups preserves the
  existing q-query bound. Random padding still covers all q opened rows.
  Upper Merkle paths are shared within each complete group; every redundant
  sibling and all routing bits remain constrained.

The v5 child additionally substitutes the trusted Keccak schedule directly into
its round constraints, while retaining equality checks against committed schedule
columns. Its path selection uses one combined gated equation. The full depth-16
verifier has 7,086,749 witnesses, down from 8,192,096 in the initial v4 circuit.

### End-to-end aggregate

`masked-demo` generates independent masked children, drops their IMT witnesses,
and passes only proof data and ordered root/amount statements to the aggregator.
One non-hiding Plonky3 multi-STARK enforces every child verifier. Its Flock table
checks all Keccak permutations; the ordinary arithmetic and public-input tables
are linked through the native product bus. Final verification consumes only that
proof, the statement, and trusted configuration. Count, order, roots, amounts,
transcript and verifier identity are bound.

The final backend is isolated in `crates/flock-backend`: the existing child and
recursion packages remain pinned, while the Flock circuit-table prover uses the
explicit open upstream PR revision listed in the README. It imports actual
symbolic AIR constraints, not native verifier results. The local mixed PCS adapter
only forwards weighted claims on unchanged Boolean columns. A product-bus check
replaces the fanout successor opening, with periodic row addresses and a checked
repeat-last endpoint. [Adapter details](../crates/flock-backend/README.md).

The original complete outer prover exceeded about 30 GiB of dirty/swapped memory
on this 16 GiB M2 Pro. A successful intermediate Flock run at depth 16, N=2,
produced one 1,077,291-byte proof in 105.6 seconds aggregation wall time. Cached
verification took 35.3 ms; fresh-process cryptographic verification took 29.0 ms,
plus 17.7 seconds to reconstruct trusted setup. This was a single cold sample,
not a repeated-run median. The initial successor-column variant at depth 32 was
killed with exit 137; subsequent changes remove its large address preprocessing.
The current successor-bus/periodic-address backend also completed depth 32, N=2:
108.94 s aggregation wall, 32.11 ms cached verification, 27.37 ms fresh-process
cryptographic verification, 15.76 s fresh trusted setup, and 1,076,869 proof bytes.
Child proving was 3.70–3.97 s with 1.128 MB proofs. This is one cold sample. Its
outer conditional algebraic budget is 146.43 bits; the hash work factor is
128 bits. [Raw report](../benchmarks/binary/masked-aggregate/flock-d32-n2.json).

Repeated depth-16, N=2 run with the same current backend: one cold and two warm
samples, four threads on the M2 Pro, compilation excluded. Warm aggregation was
**99.48 s median (98.71–100.25 s)**; decoded verification was **26.72 ms median
(26.03–27.41 ms)**. The cold aggregate took 114.02 s. Warm child proving ranged
from 1.68 to 1.92 s, with 293–305 ms native verification. Aggregate proofs were
1,075,969–1,076,583 bytes. Warm critical-path median was 103.70 s. The independent
verifier took 28.96 ms after 16.45 s trusted setup (17.47 s process wall).
Two warm samples establish an initial range, not a latency distribution.
[Raw repeated report](../benchmarks/binary/masked-aggregate/flock-d16-n2.json).

The three-component diagnostic at depths 16 and 32 also verifies in a fresh
process, but carries 3N proofs and is **not** a compressed aggregate. It is selected
explicitly by `--components`; it is not the default masked path.

```sh
cargo run --locked --release --bin masked-demo -- --depth 16 --batch-size 2 --out run/masked16
cargo run --locked --release --bin masked-demo -- --depth 32 --batch-size 2 --out run/masked32
cargo run --locked --release --bin masked-demo -- --depth 16 --batch-size 2 --samples 3 --out run/masked-bench
cargo run --locked --release --bin masked-demo -- --verify --out run/masked16
```

The fixed-batch format accepts powers of two through 64, subject to circuit and
memory budgets. This does not claim a successful 64-child run. Construction is
linear in N, and padding boundaries can double memory for a small circuit increase.
RSS is a process high-water measurement; macOS compression and swap mean it can
understate total live memory. Compilation is excluded; trusted setup and cold/warm
samples are recorded separately.

Neither a successful aggregate nor the conditional algebraic ledger establishes
the joint child simulation or an end-to-end 128-bit Fiat–Shamir/knowledge theorem.
Privacy review follows this implementation milestone, as requested. The aggregate
itself is deliberately non-hiding.

## Aggregate v2: bounded coordinate encoding

The Flock adapter now commits each trusted preprocessing column using only its
occupied low coordinates, and each Keccak bridge column using 16 coordinates.
General arithmetic and fanout values retain 64 coordinates. The verifier identity
binds these widths; out-of-range witnesses are rejected, and every original AIR
equation is retained. See the local encoding argument and negative opening tests
in [the adapter](../crates/flock-backend/README.md). This changes the aggregate
protocol to v2 and backend identity to v4; use the original revision to verify
historical aggregate artifacts. The child format is unchanged.

Depth 32, N=2, M2 Pro, four threads, compilation excluded:

| Measurement | Result |
|---|---:|
| Initial main + preprocessing codeword storage | 5 GiB, down from 8 GiB |
| Cold aggregation | 87.64 s |
| Warm aggregation, two samples | 82.61 s median; 82.49–82.73 s |
| Warm final verification including decoding | 29.40 ms median; 28.82–29.99 ms |
| Aggregate proof | 1.010–1.011 MB |
| Fresh verifier setup | 12.10 s |
| Fresh cryptographic verification | 28.95 ms |
| Conditional outer algebraic ledger | 146.54 bits |

The three proofs passed the public-statement/corruption checks; the retained
aggregate passed independent-process verification. The initial codeword storage
is **not** total working memory. Reported peak RSS was 7.96 GB, and macOS sampling
reported a peak physical footprint of `28.2G`, including compressed/swapped
memory. One two-second `sample` profile ran during the first warm child's
generation; aggregate timing intervals were not profiled. Critical-path timings
include that instrumentation, so do not use them as a clean throughput comparison.
The earlier depth-32 run was one cold sample (108.94 s); it is not a warm baseline.

Raw measurements:
[`flock-bounded-d32-n2.json`](../benchmarks/binary/masked-aggregate/flock-bounded-d32-n2.json).

The actual four-child attempt constructed 28,824,623 witnesses and 102,752 Keccak
calls, then rejected the required 1,342,177,280 initial codeword cells (10 GiB)
against the 2^30-cell guard. No aggregate proof was produced:
[`flock-bounded-d32-n4-failure.json`](../benchmarks/binary/masked-aggregate/flock-bounded-d32-n4-failure.json).
The 64-child target remains incomplete. Reducing native fanout/arithmetic tables
and Keccak committed states matters more than raising this allocation guard.

### LeanVM lead for the next optimization

Inspected [LeanVM revision `1e674918`](https://github.com/leanEthereum/leanVM/tree/1e674918a76c8bd86284ba9443556b646309b96e).
Its standalone Keccak GKR commits selected round states and reduces output claims
through the intervening rounds. This is a component to investigate without adding
a VM. That revision uses F128 challenges and states a 125-bit ROM target, so it
cannot replace this project's 128-bit path as-is. Any reuse must retain Poly192
challenges, bind both Keccak boundaries to the native bus, authenticate the
checkpoint openings, and include the GKR reduction in the security ledger.
Plonky3's inspected `p3-gkr` currently supplies product-tree GKR, not this Keccak
layer protocol; no such integration is implemented or claimed here.

## Aggregate v4: partitioned tables and bounded opening work

The adapter separates whole fanout ID groups by coordinate width and partitions
independent arithmetic rows by their fixed per-column bounds. Groups merge under
a 10% bit-cell budget to reduce opening work; groups just above a padding boundary
split when this saves at least 25% of padded cells. All original live rows and
witness-bus occurrences remain. Fixed-zero columns use no coordinates, and only
bus declarations with an identically zero fixed activation are removed.
Protocol v4 / backend v6 reject prior aggregate artifacts. The child format,
Johnson parameters and conditional security floors are unchanged.

The intermediate v3 layout demonstrated why fewer committed cells alone are not
a latency guarantee: depth-32 N=2 produced a valid 1,872,708-byte aggregate in
295.82 s, with 262.97 ms decode/verification. That diagnostic was interrupted after
its first cold sample; it is not a repeated benchmark. A one-second profile
identified deferred ring-switch suffix-bank sweeps as the hot path. See
[`flock-partitions-d32-n2-diagnostic.json`](../benchmarks/binary/masked-aggregate/flock-partitions-d32-n2-diagnostic.json).

N=4 initial codewords fell from 10 GiB to 6 GiB, passing the existing 8 GiB guard.
Both the fine partition and coalesced layout nevertheless exceeded the machine's
working-memory capacity before producing an aggregate. The coalesced attempt
reached an observed 46,182,924,032-byte physical footprint (including compressed
and swapped memory), then macOS killed it under low swap. The four child proofs
had generated and verified successfully. Raw incomplete reports:
[`fine partition`](../benchmarks/binary/masked-aggregate/flock-compact-d32-n4-failure.json),
[`coalesced`](../benchmarks/binary/masked-aggregate/flock-coalesced-d32-n4-failure.json).
These are failed aggregate attempts, not four-child performance results.

Two narrow patches then address measured or directly identified allocation costs:

- [Deferred openings](../vendor/p3-sumcheck/LOCAL_CHANGES.md) restrict equality
  sweeps to the fixed-prefix support. Dense differential tests cover the exact
  Poly64/Poly192 tensor formula, including prefixes extending into suffix banks.
- [Product-bus materialization](../vendor/p3-multi-stark/LOCAL_CHANGES.md) releases
  each temporary block after appending it to a preallocated prefix, instead of
  keeping all blocks and their concatenation alive together.

With these patches, depth-32 N=2 completed three samples and fresh-process
verification: cold aggregation 58.72 s, warm median 57.50 s (57.29–57.70 s), warm
decode/verification 114.75 ms (114.32–115.17 ms), and about 1.30 MB per aggregate.
Fresh verifier setup took 13.18 s and cryptographic verification 117.44 ms.
The observed peak physical footprint was 26,242,179,008 bytes. Only lightweight
process-memory reads ran during this benchmark; compilation and profiling were
excluded. The conditional outer algebraic ledger is 146.55 bits.
[`Raw three-sample report`](../benchmarks/binary/masked-aggregate/flock-support-d32-n2.json).
This improves proving over v2 but regresses verification and size; reducing
openings of redundant public copies is the next optimization.

Neither patch changes verifier equations, proof messages, challenges or security
parameters. Both vendored crates retain the pinned upstream sources, licenses and
standalone regression tests; only one source file in each differs from upstream.

## Aggregate v5: eliminate redundant public openings

The native public table repeats each public field element on every row and
constrains it equal to the supplied value. The adapter now verifies that exact
symbolic form at import and substitutes the public value into every original
bus field and constraint. The statement and witness-bus declarations remain;
only uniquely determined committed copies are removed. A single constrained-zero
placeholder satisfies the PCS table interface. This uses full field values and
does not depend on assuming that public inputs are small integers.

The transformation has a direct equivalence argument: any old satisfying trace
has those copies equal to the publics, and any new satisfying trace extends to
an old one by inserting those copies. The copy bus still binds each public value
to its corresponding witness ID. Tests reject both a changed public value and a
nonzero placeholder. Protocol v5 / backend v7 bind the transformed AIR; child
proofs and security parameters remain unchanged.

Depth-32 N=2, three samples on the same M2 Pro / four-thread configuration:

| Measurement | v5 result |
|---|---:|
| Cold aggregation | 58.27 s |
| Warm aggregation | 60.12 s median; 59.57–60.68 s |
| Warm verification including decoding | 118.22 ms median; 117.07–119.37 ms |
| Aggregate size | about 1.29 MB |
| Fresh verifier setup | 13.15 s |
| Fresh cryptographic verification | 116.44 ms |

All samples and the independent verifier passed. Public-copy elimination saves
about 18 KB here but does not materially improve verification latency; the extra
partitioned AIRs remain a verification tradeoff. The v2 layout's 29 ms result is
still faster for verification, while v5 reduces initial codewords from 5 GiB to
3 GiB and warm aggregation from 82.6 s to about 60 s. These are small repeated
samples on one laptop, not an exhaustive comparison. The 64-child target remains
unmeasured. [Raw v5 report](../benchmarks/binary/masked-aggregate/flock-public-d32-n2.json).

Depth 16 also passed a single cold end-to-end run and fresh-process verification:
aggregation 54.55 s, decode/verification 103.11 ms, and a 1,234,514-byte
aggregate. Child proving was 1.89 s and 1.76 s. This is one cold observation, not a warm comparison.
[Raw depth-16 report](../benchmarks/binary/masked-aggregate/flock-public-d16-n2.json).

A depth-32 N=4 diagnostic with the same v5 source generated and verified all
four children, but produced no aggregate. A controller interrupted it after its
current physical footprint crossed a 40 GiB diagnostic budget; the sampled
lifetime peak was 45,754,121,536 bytes. This was a controlled SIGINT, not a verifier
rejection or OS kill. A one-second profile during the attempt showed
`BusPlan::prove -> PreparedProductGkr::new_owned -> ProductLayers::from_leaves ->
IdentityPrefix::reduce`. Thus product-bus layer construction remains a concrete
memory bottleneck after the temporary-allocation patch. The codeword guard alone
is insufficient to predict working memory. See the
[incomplete diagnostic report](../benchmarks/binary/masked-aggregate/flock-public-d32-n4-failure.json).
No successful four- or 64-child aggregate is claimed.


## Regenerated product-bus leaves (same v5 proof format)

The pinned GKR `ProductLeaves` interface now also handles separate trees. The bus
prover regenerates 16,384-leaf chunks directly from committed tables, retains the
quarter-size product level, and regenerates the bottom sumcheck layer before
handing its half-size folded prefix to the upstream dense kernel. Boundary and
periodic selectors retain their original full-block coordinates. This changes
prover storage and work; no hash, field, security parameter, verifier equation,
proof encoding or transcript message changes.

Differential tests compare complete proofs and subsequent transcript challenges
against the dense prover, including Poly64/Poly192, odd/even heights, empty and
partial prefixes, identity tails and chunk boundaries. Bus tests preserve the
same rejection transcripts for unequal products and incorrect prefix lengths.
The implementation and exact upstream differences are documented in
[GKR](../vendor/p3-gkr/LOCAL_CHANGES.md),
[bus](../vendor/p3-bus/LOCAL_CHANGES.md) and
[multi-STARK](../vendor/p3-multi-stark/LOCAL_CHANGES.md).

Depth-32 N=2, three samples on the same M2 Pro with four threads:

| Measurement | Regenerated-leaf result |
|---|---:|
| Cold aggregation | 61.88 s |
| Warm aggregation | 61.62 s median; 61.46–61.78 s |
| Warm verification including decoding | 119.04 ms median; 117.51–120.58 ms |
| Aggregate size | 1,286,316–1,287,712 bytes |
| Fresh verifier setup / decode and verification | 13.43 s / 118.26 ms |
| Observed lifetime physical-footprint peak | 26,273,029,760 bytes |

All samples and independent verification passed. This does **not** improve the
whole-prover memory peak at N=2: the prior v5 run was about 26.29 GB. Warm proving
is slightly slower in this small comparison. The compact product representation
has a smaller retained leaf layer, but another live allocation can dominate the
process peak. Physical footprint includes compressed/swapped memory and differs
from the report's resident-memory metric. Compilation and profiling are excluded.
[Raw report](../benchmarks/binary/masked-aggregate/flock-streaming-d32-n2.json).

The N=4 diagnostic reached the AIR sumcheck after completing the regenerated GKR
reduction, then crossed the same 40 GiB stop budget. Its observed physical peak
was 45,801,471,424 bytes. The one-second profile now shows
`AirZerocheck::prove_with_lookup_and_bus -> RoundStateExt::round_poly_packed -> Chip::eval`,
in place of the prior product-layer construction. The controller sent SIGINT;
no aggregate was produced. This identifies the next memory bottleneck, rather
than establishing successful four-child aggregation.
[Incomplete diagnostic](../benchmarks/binary/masked-aggregate/flock-streaming-d32-n4-failure.json).

A separate retry with `MIMALLOC_PURGE_DELAY=0` and allocator statistics enabled
also stopped at the AIR sumcheck, with an observed 45,793,918,400-byte peak.
Immediate purging did not remove the bottleneck; allocator defaults are unchanged.

## Factored bus-composition equality weights

The shared AIR sumcheck now stores each bus equality polynomial as two short
factor tables, with its bound prefix absorbed into one factor. This preserves
all weights exactly, including a zero prefix, and uses O(sqrt(height)) storage
per AIR. It removes 2,362,442,112 bytes of dense equality arrays in depth-32 N=4.
Dense-polynomial differential tests and all 17 upstream bus tests pass; the
application's 70 enabled release tests pass as well.

The same N=4 diagnostic still exceeded its 40 GiB budget, now at an observed
43,499,089,152-byte physical peak, about 2.3 GB lower than the regenerated-leaf
run. No aggregate was completed. The remaining AIR-sumcheck storage is still a
scaling blocker. [Raw diagnostic](../benchmarks/binary/masked-aggregate/flock-factored-d32-n4-failure.json).

## Compact arithmetic preprocessing (aggregate v6)

Arithmetic partitions now omit every preprocessing column that is identically
zero. A trusted original-to-compact map replaces those references by zero in
all AIR constraints and bus fields. Every retained cell is unchanged. Tests
compare retained and omitted cells with the original native tables, then check
the actual constraints and complete bus multisets. This is a projection of fixed
public preprocessing, not a new witness assumption. Aggregate protocol v6 and
backend identity v8 bind the changed layout; child format v5 is unchanged.

At depth 32, N=4, the ten arithmetic partitions now have 5–10 preprocessing
columns each, instead of 14. Initial codeword storage is still 6 GiB: zero
columns already used zero bit coordinates in the PCS. The saving is in native
table and sumcheck allocations. This retry still crossed the 40 GiB diagnostic
budget during the AIR sumcheck and was interrupted without an aggregate; the
observed physical peak was 44,081,802,816 bytes. Stopped-run peaks occur at different
moments, so their ordering is not a comparison of completed prover peaks.
[Raw diagnostic](../benchmarks/binary/masked-aggregate/flock-compact-pp-d32-n4-failure.json).

Depth-32 N=2 completed three samples and independent verification with v6.
Cold aggregation took 57.80 s; the two warm samples took 58.24–59.05 s
(median 58.64 s). Warm decoding and verification took 113.21–113.85 ms
(median 113.53 ms). Fresh verifier setup took 12.05 s, followed by 114.12 ms
for decoding and verification. Observed lifetime physical footprint peaked at
24,105,094,528 bytes, compared with 26,273,029,760 bytes in the regenerated-leaf
checkpoint. Physical footprint includes compressed/swapped pages; it is not
resident RAM. These are small local samples, not a statistical performance claim.
[Raw report](../benchmarks/binary/masked-aggregate/flock-compact-pp-d32-n2.json).

The depth-16 N=2 cold run also passed independent verification: 56.15 s
aggregation, 101.38 ms decoding and verification, and 1,235,297 proof bytes.
Its observed lifetime physical-footprint peak was 23,752,411,776 bytes.
[Raw report](../benchmarks/binary/masked-aggregate/flock-compact-pp-d16-n2.json).

## Releasing folded polynomial capacity

Large folded AIR and bus polynomials now return unused vector capacity to the
allocator once their evaluation tables shrink. Upstream folds truncate in place;
retaining their original buffers across mixed-height stages unnecessarily keeps
earlier, larger allocations live. The low-level representation fold retains its
in-place contract; its caller releases unused capacity. Buffers below 64 KiB are
left alone. Values, proof format, transcripts and security parameters are unchanged.

The polynomial regression checks every evaluation against the dense fold and
checks the retained allocation. All 479 enabled upstream multi-STARK tests pass,
including transcript comparisons and packed/representation kernels. The full
application release suite passes 70 tests (11 expensive tests remain opt-in).

The first complete depth-32 N=4 run now passes both in-process negative checks
and independent verification in a fresh process. All four actual masked child
proofs are authenticated by one non-hiding aggregate; the final verifier receives
no child proofs or original witnesses.

| Measurement | Depth 32, N=4, one cold sample |
|---|---:|
| Trusted setup | 31.96 s |
| Per-child proving | 3.62–3.86 s |
| Per-child verification including decoding | 319.82–436.39 ms |
| Aggregate witness generation | 9.44 s |
| Outer proof generation | 124.92 s |
| Total aggregation | 135.69 s |
| Aggregate decoding and verification | 121.07 ms |
| Aggregate size | 1,332,780 bytes |
| Child-to-aggregate critical path, excluding setup | 152.12 s |
| Fresh verifier setup / decoding and verification | 29.74 s / 126.70 ms |
| Observed lifetime physical-footprint peak | 43,444,315,520 bytes |

The controller checks current physical footprint every two seconds and did not
interrupt this run. Its lifetime peak still exceeded 40 GiB between samples:
this is **not** a completed run within a strict 40 GiB peak bound. It used the
same stop policy as the earlier interrupted diagnostics. The result establishes
four-child correctness on this machine, not low-memory or low-latency aggregation.
It is one cold sample, so no warm median is claimed.
[Raw report](../benchmarks/binary/masked-aggregate/flock-compact-fold-d32-n4.json).
Larger batches, including 64 children, remain unvalidated and subject to the
construction/codeword limits.

The updated depth-32 N=2 three-sample run also passed independent verification.
Cold aggregation took 55.85 s; warm aggregation took 53.00–55.31 s (median
54.16 s), versus the preceding checkpoint's 58.64 s median. Warm decoding and
verification took 114.37–115.07 ms (median 114.72 ms). Proof sizes ranged from
1,286,399 to 1,288,190 bytes. Fresh verifier setup took 12.17 s, followed by
113.24 ms for decoding and verification. Observed lifetime physical footprint
peaked at 22,100,967,552 bytes, down from 24,105,094,528 in the preceding run.
These small local samples support the allocation change; they are not a broad
performance guarantee. [Raw report](../benchmarks/binary/masked-aggregate/flock-compact-fold-d32-n2.json).

## Reuse and source pins

Plonky3 and recursion pins are listed in the main README; the Flock outer prover
uses an additional isolated upstream revision. Existing Plonky3
crates supply transforms, MMCS and Keccak. The recursive adapter adds explicit
hash-domain support to the existing vendored verifier; see
[LOCAL_CHANGES.md](../vendor/p3-recursion/LOCAL_CHANGES.md).

VEIL source reference:
[`749b0c63f226063c471a6238a94101f930c14a13`](https://github.com/succinctlabs/sp1/tree/749b0c63f226063c471a6238a94101f930c14a13/slop/crates/veil).
The port follows its dot-product, Hadamard and inner-constraint structure, with
the documented binary code, transcript and parameter adaptations. Its original
two-adic encoding and internal 100-bit target are not used. The applicable
[MIT notice](licenses/VEIL-MIT.txt) is retained.

References: [VEIL paper](https://eprint.iacr.org/2026/683),
[authors' overview](https://blog.succinct.xyz/veil/), and
[formal development](https://github.com/succinctlabs/veil-formal-verification).
None of these sources certifies this new Rust adaptation or its parameters.

Fresh-process negative checks are recorded in
[`verification-negative.json`](../benchmarks/binary/v2/verification-negative.json).
All 12 cases rejected altered statements, authority data or proof bytes.
