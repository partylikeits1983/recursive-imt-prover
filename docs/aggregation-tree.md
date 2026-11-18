# Reusable binary aggregation circuit

The selected design has three circuit types:

1. A depth-32 Keccak IMT child with experimental statistical masking.
2. A first aggregation that verifies two masked child proofs.
3. One merge circuit that verifies two aggregates, including its own outputs.

The merge circuit and verifier key must remain identical at every higher level.
Final native verification needs no fourth circuit. All stages retain Poly64/Poly192,
Keccak, Johnson bounds and the existing conditional security budgets. Aggregate
proofs are non-ZK; formal child ZK and end-to-end 128-bit security remain unproved.

```text
64 children → 32 first aggregates → 16 → 8 → 4 → 2 → 1
                                  same merge circuit/key
```

## Ordered statement

Each node carries a 32-byte digest and one-byte leaf count:

```text
leaf.digest = Keccak256("IMT-AGG-LEAF-V2" || root[32] || nullifier_hash[32])
leaf.count = 1

parent.digest = Keccak256(
    "IMT-AGG-NODE-V2" || left.digest[32] || left.count_u8 ||
                       right.digest[32] || right.count_u8
)
parent.count = left.count + right.count
```

Tags are ASCII without a terminator. Merges constrain equal power-of-two counts,
each at most 32. Doubling uses a binary-coordinate shift, not field addition.
Final verification rehashes the complete ordered `(root, nullifier_hash)` vector.
Roots may differ and repeated statements are permitted.

Two instances of one verifier template authenticate the two input proofs. Each
instance computes the parent using its own authenticated digest and a private
sibling digest. Public roles fix the order; both instances must produce the same
parent. Inconsistent siblings require a Keccak collision.

## Fixed layout

`Prepared::recursive_pair` gives first aggregation and merge the same AIR
equations, table sizes, coordinate encodings, public-input lengths and proof
shape. Gate constants, wire IDs and selectors remain committed preprocessing.
Table capacities are fixed; construction rejects overflow. It also compares the
complete serialized verifier equations and layout before accepting the merge.

For a run of up to 16 input bits with coefficients `s, sX, sX², ...`, where
`X` is the Poly64 polynomial-basis element encoded as `0b10`, the packed
row stores the first coefficient `s`.
It constrains the output to equal the incoming accumulator plus `s` times
the packed word. Active inputs must be bits and unused slots must be zero.
All other coefficients use native arithmetic gates. This reduced the
preprocessing codeword from 268,435,456 to 134,217,728 cells and the combined
initial codewords from 553,648,128 to 419,430,400 cells.
[Layout comparison](../benchmarks/binary/tree-merge/geometric-packing.json).

## Authenticated cyclic authority

`PreparedCyclicMerge` is constructed once from a trusted first-aggregation key.
Its circuit embeds that first authority and carries the merge authority as public
metadata:

```text
authority = (identity[32], preprocessing_commitment[32])
public template = (digest[32], count_u8, role_u8, authority[64])
```

Both template instances carry the same authority. For input count two, the circuit
selects the pinned first authority. For larger inputs it selects the carried
merge authority. Counts are constrained to powers of two and strictly decrease
toward the first aggregation, which verifies actual masked children.

The selected identity seeds the arithmetic and Keccak transcripts. The selected
preprocessing commitment is used in both the transcript and PCS verification.
The product bus, AIR, main and preprocessing openings, sumcheck, and linked Keccak
GKR argument are constrained inside the circuit. There is no unconstrained native
verification result.

First aggregates accept the carried authority as metadata, allowing their key to
be prepared before the merge key exists. Every merge propagates this metadata
unchanged. `CyclicVerifier` derives the expected authority from its independently
trusted final key and supplies it as the public input. Omitting this final check
would allow an untrusted authority and would invalidate the design.

The backend test
`one_verifier_circuit_accepts_distinct_authenticated_preprocessing_keys` checks
real proofs under two different identities and preprocessing commitments with
one verifier circuit. It rejects changed authorities, public statements and
incompatible layouts. This component test does not replace the full tree run.

## Validation and acceptance

The 64-child baseline passed with 64 real child proofs, 32 first aggregates
and 31 merges across five levels. The merge circuit was constructed once and its
key bytes remained identical at every level. They also match the earlier
eight-child run. The final 1,484,866-byte proof verified in a fresh process with
only the final proof, ordered statements and trusted verifier files. Invalid
child statements/proofs, foreign authority, altered statements and damaged
aggregate encodings were rejected.
[Raw run and timing limitations](../benchmarks/binary/tree-merge/cyclic-sixty-four.json).

```sh
# Two merge levels exercise verification of the merge's own output.
cargo run --locked --release --bin tree-demo -- --batch-size 8 --out run/tree8

# Full acceptance: 64 independent children and one merge key at all five levels.
cargo test --locked --release --test cyclic_tree -- --ignored --nocapture

# Independent verification: only final proof, ordered list and trusted key files.
cargo run --locked --release --bin tree-demo -- --verify --out run/tree8
```

`tree-demo` records every proof time, circuit construction count, verifier digest,
geometry, security parameters, environment and process peak RSS. It rejects
invalid child statements, foreign carried authorities, altered roots/nullifier
hashes, order, counts and damaged proof encodings. The 64-child integration test
also copies only final verification artifacts into an isolated directory and
checks fresh-process verification and statement mutations there.

Acceptance requires 64 real children, 32 first aggregates and 31 merges, one
merge construction, identical key bytes throughout, and independent final
verification. Different keys per level do not meet it. Keep resource and security
guards in place. This establishes the correctness baseline; the
[performance targets](development.md#next-work) require further optimization.
