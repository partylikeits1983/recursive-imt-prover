# Security scope

The active relation is depth-32 binary-field Keccak IMT membership. Children use
experimental statistical masking; aggregates are intentionally non-ZK. The goal
is 128-bit classical security for every proof and efficient recursive merging.
Joint child ZK and end-to-end security remain open. Production use requires
reviewing the masking of jointly observed children and bounding soundness for
the complete accepted statement, including the terminal proof and its EVM
verification. See the [release milestones](ethereum-terminal-proof-plan.md#release-milestones).

## Production acceptance criteria

The leaf must prove knowledge of a private Keccak preimage and ordered depth-32 IMT path to an application-approved root. The aggregator receives only the client proof and public statement. The joint distribution of up to 64 client proofs needs a statistical simulator, including commitments, openings, verifier challenges and aborts. Fresh private coins are a separate assumption about the honest client. Non-hiding aggregation can then operate on those public inputs and proofs. A simulator for the whole batch also needs to handle the shared random oracle and the aggregation algorithm's interface. [VEIL](https://eprint.iacr.org/2026/683)

For fixed public statements, let δᵢ bound the distance between the real and simulated i-th client view, conditioned on the preceding proofs and public context in the same oracle experiment. Replacing the clients in order gives a joint distance of at most Σδᵢ by the triangle inequality. Running a non-hiding aggregator on that view and independent randomness is randomized post-processing and cannot increase statistical distance. A sufficient per-client allocation for 64 proofs is 2⁻¹³⁴. This argument requires a composable conditional client simulator. An isolated honest-verifier masking experiment does not supply one.

The cryptographic target is at least 128 bits of classical attack work using hashes alone. Merkle binding uses collision resistance. The non-interactive knowledge and statistical privacy arguments must specify the random-oracle model for Fiat–Shamir. Record the adversary's hash-query budget, the extractor loss, all recursive levels, and the statistical distance separately. No production profile has an end-to-end bound today. The shared-root diagnostic of 145.94 conditional algebraic bits is computed from the actual WHIR geometry, batching degrees and linked opening. A proof of round-by-round knowledge soundness for that composition is still required. [Shared-opening implementation](../crates/flock-backend/src/terminal_opening/side.rs) · [Fiat–Shamir security, Theorem 3.15](https://eprint.iacr.org/2023/1071)

The client draws private masks, padding, product masks and both Merkle salt fields directly from its byte source. There is a bijection from each consecutive 24 bytes to one Poly192 element. The default source is the operating system and `prove_trace_with_coins` also accepts externally supplied private randomness. With independent uniform input bytes the implemented sampler gives independent uniform field elements. An operating system generally implements a CSPRNG. Replacing randomness with a short deterministic seed would need a computational assumption. The full joint-transcript simulator remains open. The old and new Rust binaries cross-verified each other's packed-record proofs. In three samples each on an M2 Pro, the two warm samples averaged 2.44 s with the former internal seed expansion and 3.26 s with direct system reads. [Private coins](../src/binary/veil/coins.rs) · [Salted rows](../src/binary/veil/vector.rs)

A reference route for a theorem-backed leaf is Aurora's bounded-query, perfectly ZK R1CS IOP of knowledge, followed by a salted BCS transformation under its stated hypotheses. Theorem 3.15 of Block et al. upper-bounds classical compiled knowledge error by `Q ε_rbr-k + 3(Q²+1)/2^κ` and statistical distance by `z + 4ℓ/2^(κ/4)` in the explicitly programmable random-oracle model. Here ℓ is the IOP proof length and z is its statistical honest-verifier ZK error. With z = 0, an illustrative ℓ ≤ 2²⁶ and a valid 64-proof hybrid, κ ≥ 648 suffices for that privacy term to be at most 2⁻¹²⁸. A 256-bit digest does not establish the requested distance by this particular bound. The actual IOP length, shared-oracle composition, hash construction and round-by-round extractor need instantiation for the chosen protocol. Full-round Keccak-256 can continue to define the application tree independently of proof hashing. The reference implementation exposes proven and heuristic low-degree settings separately. [Aurora, Theorem 9.2](https://eprint.iacr.org/2018/828) · [BCS compiler and definitions](https://eprint.iacr.org/2023/1071) · [Pinned reference implementation](https://github.com/scipr-lab/libiop/tree/a2ed2ec2f3e85f29b6035951553b02cb737c817a)

I also ran libiop's parameter calculator on a reference case with 2²¹ R1CS constraints and 2²¹−1 variables over GF(2¹⁹²). With ZK on, zero grinding, a 150-bit target, localization 3 and both low-degree settings set to `proven`, four extra code dimensions gave a 2²⁷-symbol domain, 462 FRI query repetitions, a 925-position masking bound and 151.30 reported interactive bits. Two extra code dimensions gave a 2²⁵-symbol domain, a 3,251-position masking bound and 151.09 interactive bits. This sizes a reference R1CS case only. It establishes neither the cost of proving this IMT circuit with Aurora nor a Fiat–Shamir or aggregation bound. The calculation used the pinned source with portability fixes to uninstantiated comparison operators for Apple Clang. [Aurora parameter selection](https://github.com/scipr-lab/libiop/blob/a2ed2ec2f3e85f29b6035951553b02cb737c817a/libiop/protocols/aurora_iop.tcc)

## Masked client verifier in LeanVM

The guest takes a public IMT root, two proof commitments and serialized masked proof messages. It fixes the remaining 64 public statement bytes to zero, replays all 22 native AIR challenges, derives the 40 Poly192 affine sumcheck coefficients and derives the stacked oracle query positions from that transcript. It verifies all 176 salted row paths against the transcript-bound oracle commitment. Its public checkpoint commits to the root, transcript states, challenges, coefficients, positions and ordered salted row hashes. The verifier compiles the guest from its independently selected protocol and parameters. Neither the program nor its constants are supplied by the client. [Guest generator](../adapters/leanvm/masked-client/src/guest.rs) · [Authenticated rows](../adapters/leanvm/masked-client/src/oracle.rs) · [Independent Rust replay](../src/binary/veil/child/checkpoint.rs)

The aligned v2 preimage client uses separate 16-byte leaf and node domains for its stacked oracle. An entire Keccak digest then fits two LeanVM words at every parent. The v1 domains are 18 bytes and require a constrained two-byte shift. Both encodings run 5,321 Keccak permutations for the checkpoint and retain the depth-32 Keccak IMT, 160-bit query target, two random salt fields per row, code rate, and mask sampling. Each has a distinct trusted identity. The adapter accepts v1 with `--original-domains`. [Hash domains](../src/binary/veil/hash.rs) · [Profile selection](../src/binary/veil/child.rs)

| Stacked oracle checkpoint, M2 Pro with four prover threads | Original | Aligned |
|---|---:|---:|
| LeanVM instructions | 6,620,768 | 276,025 |
| Encoded LeanVM proof | 225,868 bytes | 176,200 bytes |
| Proving time across local runs | 11.38–20.63 s | 0.40–1.01 s |

These are measurements for one independently generated, saved client proof per profile, repeated on a shared machine. Times exclude reading the child, preparing the guest and verifying its execution proof. The separate aligned client sample produced a 1,089,788-byte masked proof in 11.69 seconds of native proving. Both clients and saved checkpoints passed verification in fresh processes. Tests alter the root, challenge advice, column evaluations, salted row, path sibling and byte encoding. [Reproduction commands](../README.md#inspect-the-masked-client-verifier-in-leanvm) · [Mutation tests](../adapters/leanvm/masked-client/src/tests.rs)

With `--blend`, the guest uses the same field limbs for the Merkle leaf hash and the row dot product. The two row salts enter the hash. The data columns enter the dot product. The guest derives the batching challenge, replays all 18 quadratic rounds, evaluates the weights of both trace views and all 176 code positions, and checks the terminal equality. A distinct public digest binds the WHIR transcript seed, evaluation point and claimed value. On the same aligned client, the guest executed 799,284 instructions and 5,440 Keccak permutations, producing a 208,080-byte proof in 1.05 s with four threads. The original domains took 9,718,731 instructions and 29.62 s for a 238,048-byte proof. Both saved proofs passed fresh-process verification. Mutating the first round, last round or terminal value failed at the guest’s terminal equality, before it checked the public digest. [Guest sumcheck](../adapters/leanvm/masked-client/src/blend.rs) · [ISA field and weight arithmetic](../adapters/leanvm/masked-client/src/blend.py)

With `--whir`, the guest continues from the blend sumcheck's actual seed, commitment, point and evaluation. It samples the Poly192 challenges in native byte order, checks the grinding witnesses, derives each stratum's query positions, authenticates the base and extension rows under their round commitments, checks the final polynomial and batched weight equation, and reconstructs the claimed value from its three coordinate openings. Its public checkpoint also binds the PCS seal. The Rust importer expands pruned paths. The guest constrains them independently. Mutating rows and siblings after import in the first and last WHIR trees caused guest execution to fail at the corresponding Merkle check. [Guest verification](../adapters/leanvm/masked-client/src/whir.rs) · [Mutation tests](../adapters/leanvm/masked-client/src/tests.rs)

| Complete stacked WHIR checkpoint, four M2 Pro threads | Steps | Keccak permutations | Encoded proof | Proving time |
|---|---:|---:|---:|---:|
| Aligned client, bitwise packing baseline | 19,409,221 | 12,339 | 247,856 bytes | 85.25 s |
| Same aligned client, checked byte lookup table | 6,071,544 | 12,339 | 223,464 bytes | 15.24 s |
| Original client, checked byte lookup table | 14,990,991 | 12,339 | 233,408 bytes | 48.67 s |

The lookup table uses LeanVM's checked exponent windows to reconstruct each 64-bit word. The proof bytes, hash domains and security parameters of the underlying masked client are identical across the two aligned runs. Each timing is one sample on a shared machine and excludes client proving and guest preparation. Both saved lookup proofs verified in fresh processes. These measurements cover the stacked opening. [Byte lookup](../adapters/leanvm/masked-client/src/whir.py) · [LeanVM's window gadget](https://github.com/leanEthereum/leanVM/blob/73c2cc094c0be4a1c5af6ec613e8021c9e16da87/guests/lean_ethereum.py#L827-L835)


The `--products` guest consumes the authenticated stacked seal, replays the product link and checks the dot and Hadamard arguments against the same salted rows. Each terminal sumcheck value has its own complete WHIR opening. On the aligned client this took 19,327,153 instructions, 24,696 Keccak permutations and 76.03 s, and produced a 250,448-byte proof. [Vector verifier](../adapters/leanvm/masked-client/src/vector.rs)

The `--membership` guest also derives the coefficients of the batched AIR relation, checks their dot product with the actual transcript-masked wires, and uses those same coefficients in the mask-vector opening. A reverse pass over the trusted AIR gate graph accumulates the coefficients of every masked wire, including six padding wires. The sole public output is the IMT root. The aligned proof took 30,822,422 instructions, 32,502 Keccak permutations and 184.78 s to produce a 243,488-byte standalone LeanVM proof on four M2 Pro threads. A fresh process verified it with only the public statement and the LeanVM proof and rejected a different IMT root. The timings for wrapping start after generation of the native masked proof and preparation of the ISA guest. [AIR relation](../adapters/leanvm/masked-client/src/endpoint.rs) · [Root-only verification](../adapters/leanvm/masked-client/src/main.rs)

The recursive leaf runs the same complete membership verifier and binds the verified root into the singleton batch digest. Two distinct saved clients each executed 30,829,393 instructions in the recursive leaf. Four threads on a shared M2 Pro took 218.868 s and 278.890 s to produce 244,888-byte and 243,800-byte recursive proofs. Both parent profiles executed 376,732 instructions. The ordinary parent took 0.897 s and occupied 286,416 bytes. The rate-1/32 terminal parent took 7.838 s and occupied 143,044 bytes. Independent verification accepted the ordered list of two roots and rejected the reversal for both saved proofs. The post-import mutation test also rejected changes in the AIR, product and mask messages and openings. [Recursive prover](../adapters/leanvm/recursion/prover.rs) · [Guest tests](../adapters/leanvm/masked-client/src/tests.rs)

A repeat through `cargo prove --backend leanvm-masked -n 2 -j 1 --threads 4 --from-children` took 309.11 s for those same two saved clients. Leaf wrapping accounted for 307.20 s, the ordinary merge for 0.945 s, and native root verification for 164.73 ms. The same 286,416-byte output verified in a fresh CLI process. Separately, `--prepare-children` generated two new masked client proofs in 9.89 s including witness preparation, serialization and verification. Native proving alone took 5.27 s and 3.97 s and produced 1,090,922 and 1,090,691 bytes, respectively. Timings vary with machine load.

The statistical simulator and 128-bit end-to-end knowledge bound remain open. LeanVM uses its upstream 125-bit per-round target for these runs. The masked-pair Solidity measurement covers the terminal polynomial opening and ordered root list. [Ethereum measurements](ethereum-root-verification.md#masked-client-recursion-in-leanvm)

## Relation and trust

For comparison, LeanVM's binary verifier targets 125 bits of soundness per Fiat–Shamir message after grinding. The extension field has 128 bits. Using the same query counts here would require matching its field, code domains, challenge sequence, degree bounds and grinding sites, as well as accounting for our child proofs and recursive composition. A client statistical simulator is an additional requirement. The matched upstream benchmark and native parameter sweep use experimental settings for measurement. [LeanVM verifier](https://github.com/leanEthereum/leanVM/blob/5b43139d50272f996ca884669b1d51555af1f35d/crates/verifier/src/transcript.rs#L83-L94) · [Measured effect of parameters](ethereum-root-verification.md#effect-of-changing-the-security-target) On the actual four-variable 64-client geometry, the native terminal's conditional bound is 121.48 bits for a 125-bit local WHIR target with 17 maximum grinding bits, 124.55 for 128 with 16, and 145.96 for the existing 152 with 16. These calculations include both opening faces, the native AIRs, bus and linked Keccak reductions. The 128-bit classical requirement applies to the complete recursive argument. [Root parameter sweep](ethereum-root-verification.md#effect-of-changing-the-security-target)

The root-only client binds a private preimage to a public IMT root through 33 domain-separated Keccak hashes. The separate record client authenticates the opening of an input record, its tag and a
replacement commitment with the same private u64 quantity. Full-round
Keccak-256 hashes domain-separated byte strings. The AIR constrains all
32 private directions, both record encodings and all three public digests.
Four private Poly64 limbs link the input nonce to its tag, and one limb links
the two quantities. Each limb packs Boolean bits in the polynomial basis.
[Exact relation and byte layout](protocol.md#child-statement)

Proofs can refer to different roots. Accepting roots, rejecting repeat input
tags and appending output commitments are application responsibilities.
A repeated input nonce produces a linkable tag.

Aggregation receives only proofs and public statements. It constrains transcript,
PCS, sumcheck, AIR and consistency verification inside the outer proof. A native
precheck does not replace these constraints. Independent final verification
requires the aggregate, ordered public list and trusted verifier data.

`verifier.key` is checked against an independently trusted digest and authority
identity before use. The key and matching digest cannot both come from an
untrusted prover. The key also fixes the backend, statement format and parameters.
The recursive tree hashes the complete ordered list and constrains the parent
commitment inside the proof. See [tree binding](aggregation-tree.md).

## Parameters and accounting

| Component | Parameters |
|---|---|
| Fields | Poly64 values, Poly192 challenges |
| Hashing | Keccak-256 for commitments and transcripts |
| Child query target | 160 bits; code rate 1/16 |
| Outer PCS | 152-bit target, at most 16 grinding bits, fold 4. The version 11 recursive parent uses rate 1/2 for both its joint arithmetic and Keccak commitment and its preprocessing commitment. |
| Conditional algebraic floor | 144 bits |
| Proximity analysis | Johnson; VEIL binding also capped at half distance |

All active WHIR constructors explicitly select `SecurityAssumption::JohnsonBound`:
[native baseline](../src/binary/engine.rs), [masked child](../src/binary/veil/whir.rs)
and [both aggregate backends](../crates/flock-backend/src/config.rs). At rate
`rho`, the pinned libraries use agreement `1.05 * sqrt(rho)`, or relative distance
`1 - 1.05 * sqrt(rho)`, strictly inside the Johnson radius. The separate
[VEIL binding calculation](../src/binary/veil/parameters.rs) takes the minimum of
that radius and `(1 - rho) / 2`; it must not be replaced by WHIR query counts.

Literature checked 18 November 2026: the pinned Plonky3 Johnson analysis already
uses Dao–Kominers–Thaler's improved finite-rate line-MCA bound. Their
[beyond-Johnson result](https://eprint.iacr.org/2026/2056) requires sufficiently
large characteristic; its Johnson-regime improvement works in every characteristic.
Consequently, it supports the current bound but not a beyond-Johnson radius for
our binary fields. Dao–Kominers–Thaler–Zheng also give
[counterexamples on binary additive domains](https://eccc.weizmann.ac.il/report/2026/237/).
Any future parameter relaxation needs a theorem for the actual domain, challenge
field, combiner and protocol, followed by updated query and composition accounting.

The ledgers include batching, sumchecks, query candidates and relevant PCS/link
terms under uniform challenges. A requested PCS target is not an end-to-end
security guarantee. Composition must charge every child, first aggregate and
recursive merge, including any normalization proof that is later introduced.

The packed recursive parent charges 24 degree-46 product evaluations and its
closing reduction in the checkpoint ledger. The prescribed-opening analysis
includes the arithmetic tables and both Boolean boundary tables. The ledger
uses the product of the candidate bounds for the two linked reductions.
[Packed link accounting](../crates/flock-backend/src/checkpoint_keccak/linked.rs)

The older native baseline's combined upstream floor is 127, not rounded to 128.
That estimate adds the 128-bit hash cap as an error probability. We report the
algebraic union, this estimate and the conventional hash work factor separately;
adding unlike quantities does not establish end-to-end work security. The separately keyed midpoint comparison profile uses a 121-bit conditional floor for native and Solidity benchmarks. The default midpoint verifier enforces a 144-bit floor. [Parameter selection](ethereum-root-verification.md#selecting-the-midpoint-terminal-security-profile)

Keccak-256 has generic classical collision work around 2^128, generic quantum
preimage cost around 2^128 and generic quantum collision query cost around
2^(256/3). This is not a 128-bit post-quantum proof-system claim.

## Child privacy

The compiler masks witness-dependent messages and openings, commits masks before
online challenges, and proves their algebraic consistency. Random oracle padding
supports local hiding arguments. Fresh child randomness is required; reusing
private masks or commitments is unsupported.

For the aligned preimage client, consider the 176 stacked-oracle queries with their positions and the batching coins fixed. Suppose two leaves under the same IMT root produce different trace columns. At the distinct queried positions, evaluate the difference in each stack with the native additive NTT. If there are `d` distinct positions, the first `d` random prefix coefficients can cancel all `d` differences. Their novel-basis polynomials have degrees zero through `d − 1`, so evaluation at distinct field points is invertible. Adding the resulting fixed correction translates uniform pads bijectively. Repeated queries receive the same answer.

The 13 data stacks feed one auxiliary column with a nonzero batching coefficient. Translate that column by the weighted trace correction divided by its coefficient. In characteristic two this cancels the change at every coefficient of the polynomial given to WHIR. The auxiliary correction also vanishes at every queried row. The same construction preserves the disclosed evaluations at the current and successor views. Run `cargo test --locked --release --lib different_preimages_under_one_root -- --ignored` to exercise two distinct preimages, their paths to one root, and a transcript from a genuinely generated proof. This calculation covers the algebraic openings for those fixed verifier choices. Extending it to earlier commitments and adaptively derived choices requires a joint simulator. [Same-root privacy test](../src/binary/veil/child/tests/privacy.rs) · [Coefficient encoding](../src/binary/veil/code.rs)

For an honest aligned preimage proof with fresh uniform verifier coins, the outer masking transcript makes 90 Poly192 draws that reject zero and one. The AIR and stacked oracle use 43 (22 AIR coins, three batching coins, and 18 sumcheck rounds). The product link and linear batch use two. The product vector uses 30, including 12 dot-opening rounds and 13 product-opening rounds. The mask vector uses 15, including 13 dot-opening rounds. A union bound bounds the probability of this particular abort by `90 × 2⁻¹⁹¹` per attempt, or `5,760 × 2⁻¹⁹¹ < 2⁻¹⁷⁸` across 64 attempts. This counts the wrapper’s excluded field values. Hash-query collisions, Fiat–Shamir programming, WHIR grinding and retries need their own accounting. [Native sampling](../src/binary/veil/transcript.rs) · [Vector transcript](../src/binary/veil/vector.rs) · [Opening rounds](../src/binary/veil/whir.rs)

The remaining analysis covers joint simulation, adaptive queries, salted
commitments, other abort events, lifetime randomness/query budgets and
Fiat-Shamir/knowledge composition. A hiding PCS alone is insufficient. The target
joint statistical-distance budget across at most 64 children is 2^-128; no such
bound is currently established. See [privacy target](binary-veil.md#privacy-target).

Reports retain `full_zk_established: false` and `end_to_end_security_bits: null`.
The older privacy benchmarks also retain `acceptance_pass: false`. In `tree-demo`,
`acceptance_pass` refers only to the 64-child recursion test: one merge key across
five levels, independent final verification and negative tests. It does not
certify ZK or end-to-end security. A non-ZK aggregate adds no extra privacy layer
to its child transcripts.

## Backend limits

Flock is an experimental pinned upstream change with local constraint/bus/PCS
adapters. Checkpoint additionally links a committed Keccak GKR argument to
PCS-authenticated arithmetic ports. Both enforce the 144-bit conditional floor;
neither supplies a complete adaptive composition theorem.
[Port-link construction](binary-veil.md#link-to-the-aggregates-native-ports) and
[backend details](../crates/flock-backend/README.md) describe these assumptions.

The local cyclic adapter fixes the verifier layout and authenticates the selected
preprocessing commitment and transcript identity. Count-two inputs use a pinned
first-aggregation authority; larger inputs use the carried merge authority. Counts
strictly decrease, and every input carries the same merge authority as the output.
Final verification derives that authority from its independently trusted key.
This final check is essential: first aggregates deliberately permit arbitrary
authority metadata to avoid a setup cycle. The 64-child run exercises both
branches across five merge levels and rejects a foreign carried authority.
See [cyclic design](aggregation-tree.md).

Relevant references: [native binary recursion](https://plonky3.github.io/Plonky3-recursion/advanced_topics/binary_fields.html),
[VEIL](https://blog.succinct.xyz/veil/), and its
[pinned implementation](https://github.com/succinctlabs/sp1/tree/749b0c63f226063c471a6238a94101f930c14a13/slop/crates/veil).
