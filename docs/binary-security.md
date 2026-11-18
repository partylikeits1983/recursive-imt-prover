# Security scope

The active relation is depth-32 binary-field Keccak IMT membership. Children use
experimental statistical masking; aggregates are intentionally non-ZK. The goal
is 128-bit classical security for every proof and efficient recursive merging.
Joint child ZK and end-to-end security have not been established. Formal ZK
analysis is deferred, not an implementation gate. No production or real-funds use.

## Relation and trust

The leaf preimage is `"IMT-KECCAK-LEAF2" || secret_num[32] || nullifier[32]`.
The public nullifier hash is `Keccak256("IMT-KECCAK-NULL1" || nullifier[32])`.
Nodes hash `"IMT-KECCAK-NODE1" || left[32] || right[32]`. Tags are exactly
16 ASCII bytes; hashing is Keccak-256, not SHA3-256. The circuit constrains
bytes, padding, permutations, all 32 private direction bits, the root and the
nullifier hash. Four private Poly64 carry columns bind the exact same nullifier
in the leaf and nullifier-hash preimages. See [protocol](protocol.md).
Binary-field bytes use raw coordinates; integer field embedding would lose bits.

Fixtures include pre-existing notes and later appends, so proof roots differ
from insertion roots. Different roots and repeated statements are valid.
Root-history checks, spending, spent-nullifier tracking and replay prevention are
outside scope. Reusing a nullifier gives the same public hash and is linkable.

Aggregation receives only proofs and public statements. It constrains transcript,
PCS, sumcheck, AIR and consistency verification inside the outer proof. A native
precheck does not replace these constraints. Independent final verification
requires the aggregate, ordered public list and trusted verifier data.

`verifier.key` is checked against an independently trusted digest and authority
identity before use. The key and matching digest cannot both come from an
untrusted prover. The key also fixes the backend, statement format and parameters.
The tree-pair format hashes the complete ordered list and constrains the parent
commitment inside the proof. See [tree binding](aggregation-tree.md).

## Parameters and accounting

| Component | Parameters |
|---|---|
| Fields | Poly64 values, Poly192 challenges |
| Hashing | Keccak-256 for commitments and transcripts |
| Child query target | 160 bits; code rate 1/16 |
| Outer PCS | 152-bit target, at most 16 grinding bits, rate 1/4, fold 4 |
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

The older native baseline's combined upstream floor is 127, not rounded to 128.
That estimate adds the 128-bit hash cap as an error probability. We report the
algebraic union, this estimate and the conventional hash work factor separately;
adding unlike quantities does not establish end-to-end work security. Explicit
weak parameters remain confined to native correctness tests and diagnostic runs.

Keccak-256 has generic classical collision work around 2^128, generic quantum
preimage cost around 2^128 and generic quantum collision query cost around
2^(256/3). This is not a 128-bit post-quantum proof-system claim.

## Child privacy

The compiler masks witness-dependent messages and openings, commits masks before
online challenges, and proves their algebraic consistency. Random oracle padding
supports local hiding arguments. Fresh child randomness is required; reusing
private masks or commitments is unsupported.

The remaining analysis covers joint simulation, adaptive queries, salted
commitments, abort probabilities, lifetime randomness/query budgets and
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
authority metadata to avoid a setup cycle. The eight-child run exercises both
branches and rejects a foreign carried authority. See [cyclic design](aggregation-tree.md).

Relevant references: [native binary recursion](https://plonky3.github.io/Plonky3-recursion/advanced_topics/binary_fields.html),
[VEIL](https://blog.succinct.xyz/veil/), and its
[pinned implementation](https://github.com/succinctlabs/sp1/tree/749b0c63f226063c471a6238a94101f930c14a13/slop/crates/veil).
