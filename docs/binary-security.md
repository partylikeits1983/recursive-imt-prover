# Binary Keccak research status

The implemented binary path is **non-ZK**, including its child proofs. It is a
correctness/performance milestone, not completion of the private-transaction
objective. The aggregate does not need to be ZK. No child witness, note, path,
index or proving randomness is an argument to the aggregation API.

The acceptance gate is 128-bit security for **all** child and aggregate proofs,
binary fields, Keccak IMT proving and the stated aggregation latency targets.
The intended security class is classical; Keccak-256 does not support a claim
of 128-bit generic quantum collision security. Sub-128-bit reports are research
measurements only. No default or nominal PCS target is evidence of acceptance.

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

The selected path uses BinaryField128, native Keccak-f tables, product buses and
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

## Soundness

Dependencies for the selected path are Plonky3 crates `=0.9.0-rc.2` (published
source revision `fe5e46d755b8a7d9069778361e21b33e5978b377`) and Plonky3-recursion
`3a69ba61f713c8400b14eb3d8f0e52caa13512c7`, with the existing local recursion
patches described in [LOCAL_CHANGES.md](../vendor/p3-recursion/LOCAL_CHANGES.md).
The binary implementation adds no cryptographic dependency patches.

All selected WHIR proximity parameters use the **Johnson bound**. Default PCS
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
The native Poly64/Poly192 path is a possible larger-challenge-field direction;
it does not solve child ZK by itself.

The separate 80-bit-PCS experiment uses a 16-bit WHIR grinding ceiling and
reports 77.08-bit child / 75.20-bit outer models. It is also non-ZK and not a
128-bit configuration. Grinding is explicit through `--pow-bits`; the default
remains zero. Reports retain the requested ceiling and the resulting assessed
terms, rather than treating the nominal PCS target as achieved security.

### Larger binary challenge-field assessment

`cargo run --locked --release --example binary-security` constructs the actual
Keccak IMT relation over Poly64 with Poly192 challenges at depths 8, 16 and 32.
This is a parameter/authority assessment, not a new accepted proof path. It
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
[binary-poly-security.json](../benchmarks/binary/raw/binary-poly-security.json).
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

## Minimum remaining construction

There are two concrete routes. The new [VEIL experiment](binary-veil.md)
implements the binary encoding and inner algebraic argument for route 2, plus
direct Keccak-preimage and IMT relation experiments. The full compiler and
recursive integration remain unfinished; neither complete route is implemented.

1. Reuse the new current-row ZK compiler by flattening the entire fixed
   membership circuit into one wide current-row relation, including every
   Keccak round and wiring equality. This avoids extending its security theorem
   to buses. Then implement a native recursive verifier for its exact reference
   proof/transcript format. Full coefficient blends and one quotient per
   constraint make this an unattractive low-latency route; first measure a
   small single-permutation instance before attempting a complete depth-8 tree.
2. Keep the efficient native MultiStark relation and integrate a suitable
   binary-field ZK compiler, such as an adapted VEIL construction. This requires
   masking every witness-dependent algebraic message, not just the PCS:
   constraint batching/zerocheck, sumcheck rounds, product-bus GKR and terminal
   evaluations. It also needs a hiding additive-code/WHIR opening interface with
   a proven leakage budget, private CSPRNG lifecycle, and recursive verification
   of all added consistency checks. The existing Succinct VEIL Rust prototype
   uses two-adic fields/BaseFold, so it is not a drop-in binary WHIR adapter.

The proposed privacy argument for route 2 is a composition argument: masked
oracle answers must be jointly simulatable for the complete query schedule;
committed one-time pads hide all algebraic messages; a ZK consistency proof binds
these masked messages to the original verifier equations. Rank, mask reuse,
adaptive transcript queries, oracle openings, Fiat-Shamir and composition must
all be analyzed. This paragraph is a specification of missing obligations, not
a proof that a partial implementation would be ZK.

Once the child proof is fully ZK, the outer proof may remain non-ZK: it processes
only already-ZK proof transcripts and their public statements. It must never
receive the original notes, paths or the child's private random tape.

Sources: [native binary support](https://plonky3.github.io/Plonky3-recursion/advanced_topics/binary_fields.html),
[VEIL](https://blog.succinct.xyz/veil/),
[VEIL implementation](https://github.com/succinctlabs/sp1/tree/749b0c63f226063c471a6238a94101f930c14a13/slop/crates/veil).
