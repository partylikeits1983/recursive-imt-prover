# Security scope

This file describes the original Spartan–WHIR/IMT experiment. The separate
[minimal Plonky3 recursion demo](minimal-recursion/README.md) now implements genuine
two-to-one recursion for `y = x² + x`; it has different FRI parameters, is non-ZK,
and does not inherit the client's 116-bit target or establish an IMT transition.

**Not complete, not audited, not suitable for funds. No recursive soundness claim.**
The authorization APIs fail closed. The transition diagnostic is a proof of only the
public-history/append relation; it can be produced without any valid client proof.
Native client verification in the aggregator does not change this fact.

## Actual client mode and parameters

`PoseidonZkProvingKey<QuinticExtension>` / `PoseidonZkProof`, full ZK, SPARK closing,
KoalaBear p=2130706433; extension F[X]/(X^5+X^2-1), about 155 bits. Uses the dedicated
hiding-WHIR committed-relation API, not the no-ZK `Plonky3WhirPcs` path. Default
`FreshMaskBatching::Separate` and `MaskPacking::Off` are retained by `setup` (see pinned
upstream constructors). Masks and client proof randomness use OS-seeded `rand::rng`;
no deterministic proof seed is used. The public hash-vector generator contains no
private witness material.

Configured end-to-end CLIENT target: 116 bits; requested Merkle target: 116;
`SoundnessAssumption::JohnsonBound`, not the conjectural capacity-bound default.
Upstream setup derives stronger component budgets and rejects unsatisfied full-ZK
slack, extension-field and composed security conditions. `ell_zk=3`,
`mask_log_inv_rate=3`. Exact WHIR schedules (logarithms base two):

| Oracle | PoW ceiling | first/rest fold | initial log inverse rate | initial domain reduction |
|---|---:|---|---:|---:|
| Hiding witness | 22 | 4 / 3 | 2 | 3 |
| SPARK fixed value | 9 | 5 / 4 | 1 | 5 |
| SPARK fixed audit | 6 | 8 / 8 | 1 | 8 |
| SPARK reads | 9 | 5 / 4 | 1 | 5 |

Rates for later rounds are derived by upstream; no explicit override.
The complete authenticated derived depth-8 configuration is retained in
[`artifacts/client-derived-config-depth8.json`](artifacts/client-derived-config-depth8.json):
14 outer rounds, 15 inner rounds, witness folding schedule [4,3,3], 88 mask queries,
oracle randomness lengths [108,70,108], starting folding PoW 3 bits, final 108 queries
with 22-bit PoW. SPARK table component targets are 120-bit WHIR and 123-bit Merkle.
Every per-round rate, query count, mask shape, fixed commitment and domain separator
is in that JSON, exported read-only from an authenticated key. A PoW ceiling
is not the actual difficulty at every site. This profile has been setup/prove/verify
tested at depth 8. Other depths are parameterized in the relation, but no full
recursive configuration at any depth is supported. See raw setup/measurement artifacts.

The full-ZK rationale is upstream's implementation of
[Zero-Knowledge IOPPs for Constrained Interleaved Codes](https://eprint.iacr.org/2026/391),
combined with [Spartan](https://eprint.iacr.org/2019/550) and
[WHIR](https://eprint.iacr.org/2024/1586). These references do not prove this repository
correct. No independent audit or formal verification of this implementation has been
performed. Fiat–Shamir and concrete Poseidon assumptions remain cryptographic assumptions;
Johnson proximity bounds are not a proof of every composition step.

## Hash limits and composition

Application hash: width 24, rate 16, capacity eight field elements, digest eight.
Proof transcript: width 16, rate eight, capacity eight. Proof leaf sponge width 24,
rate 16; proof compression width 16; Merkle digests eight elements. All selected
Poseidon2 permutations use the pinned upstream constants; application permutation is
4+23+4 rounds, transcript/compression permutation 4+20+4. See SPEC.md and hash vectors.

Eight KoalaBear elements carry about 247.95 bits; the generic classical birthday limit
is about **123.98 bits**, before union bounds and construction-specific losses.
The upstream validator caps its configured targets at 123 and explicitly disallows
128. The 116-bit setting is not a claim of 128-bit cryptography. Relation/configuration
SHA-256 binding does not raise the proof hash's limit. A bound for two independent
116-bit client errors alone would lose one bit by a union bound, before accounting
for application hashes and the outer argument. No composed batch bound is established.

No quantum-security number is asserted. Quantum collision/query behavior and QROM
Fiat–Shamir analysis must be treated separately; a hash-based or transparent proof
system is not automatically 128-bit post-quantum secure.

## Outer diagnostic

Uses pinned `config::koala_bear()` FRI configuration: KoalaBear base, quartic challenge
extension, Poseidon2 width 16/rate eight, digest eight, log blowup 1, log final polynomial
length 0, max log arity 3, 100 queries, batch PoW 10, commit PoW 0, query PoW 16,
Merkle cap height 3. These are upstream benchmark settings, not a locally established
116/128-bit composed bound. No low-security test profile is silently substituted.
A complete outer profile must derive and record soundness for its final table counts,
lookup arguments, degree bounds and opening batches before being called reference secure.

Outer proving adds **no confidentiality**. It contains public statements and append
paths; a future complete outer would also contain already-ZK child proofs. It must
never contain original client secrets or spent-note paths. The currently proved
transition diagnostic does not even contain child proof witnesses.

## Missing checks and authority

Only field-observe/sample transcript operations and a standalone full-ZK outer
sumcheck component are implemented. The raw-prefix differential harness is not key authority; the separate
`build_pinned_component` constructs the initial prefix from an authenticated fixed
key and binds all 32 child public fields. Neither is a complete verifier. Inner ZK sumcheck, matrix-closing argument, all WHIR
openings, Merkle authentication, canonical query/index derivation and grinding are
NOT constrained recursively. Those omissions are why authorization always fails.
No component result is cast into a verified-child or verified-batch capability.

A completed design must pin all client relation/configuration/fixed commitments in
the circuit and pin the outer program independently of proof metadata. Current FRI
diagnostics retain or rebuild that exact transition program. State prechecks match
the complete trusted history and reject spent/duplicate nullifiers. There is no
successful apply path, persistence or concurrent-writer protocol yet.

Proof/key decoding is bounded, versioned and role-separated, rejects trailing bytes
and noncanonical residues. Applications must still provision key/state files through
an independent trust channel; a prover-provided file is not a trust anchor. Local
same-user processes are not isolated from privileged memory inspection. This PoC
has no smart contract, networking, assets, balances, nullifier accumulator or stateless
ledger claim.
