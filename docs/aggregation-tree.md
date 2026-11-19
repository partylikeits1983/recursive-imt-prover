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

The packing table reserves 262,144 rows. Each row replaces up to 16 additions
with coefficients `s, sX, sX², ...`, where `X` is the Poly64 basis element
encoded as `0b10`. The row commits one scale `s` and constrains the output to
the previous accumulator plus `s` times the packed word. Active inputs are
bits and unused inputs are zero. If the table fills, the longest chains take
priority. The remaining operations and their copy constraints use native gates.

The recursive verifier multiplies Poly192 elements as triples of Poly64 words
with `Y³ = Y + 1`. One row checks the three product coefficients and links the
six input words and three outputs to the wire bus. Setup matches each native
gate, wire and coefficient before replacing a nine- or ten-gate sequence. Every
intermediate must occur only within that sequence. Shared wires keep their
external copy constraints. Both templates reserve 131,072 rows for products.

Setup checks each gate's wire IDs, coefficient and operation against its fixed
table layout. For a pair of Boolean selects that swap two inputs, both inputs
fit within the wider of the two output bounds. Constant multiply-add rows
also bound the addend through the equation `addend = output + coefficient * input`.
The prover omits columns whose wire ID and value are both fixed to zero.

When two selects use the same selector and opposite 16-bit inputs, one row
can check both outputs. For selector `s`, inputs `x, y` and outputs `a, b`,
the row enforces `a = y + s(x - y)` and `a + b = x + y`. This is equivalent
to both original equations. The wire bus links all five values. Setup matches
the gate selectors and wire IDs before removing either row. Each template
reserves up to 262,144 pairs and keeps unmatched selects as native gates.

The four-wire table also accepts constant multiply-adds. The five-wire table
can take ordinary multiply-adds when the four-wire table fills. Each operation
keeps its original selector, wire IDs and coefficient in the committed layout.

The arithmetic proof commits the circuit's Keccak wire table once. Each
template contributes 116 columns. For each permutation, consecutive rows hold
the input and output, including 16 byte-swapped limbs. Each template is padded
separately with permutations of the zero state. The committed copy selectors
identify the live circuit wires.

Let `g` select the template, `x` select a call, and `d` select input or
output. These coordinates come from the arithmetic sumcheck. Each limb satisfies

```text
(1 - g) B0(x,d) + g B1(x,d) = (1 - d) Input(g,x) + d Output(g,x)
```

The arithmetic PCS authenticates the left side. The Keccak proof checks a random
combination of the 116 right sides using seven fresh port coordinates. Both
commitments precede the row challenges. The extra row coordinate and one fewer
port coordinate preserve the degree bound used for the linkage check. Snapshot
versions 6 through 8 use this bridge layout. Version 8 uses code rate 1/2 for
the recursive preprocessing commitment. Earlier snapshots keep their original
verification rules.

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

Three eight-child runs compared Merkle commitments inside the aggregate proof.
All used 12 workers, the same Johnson parameters and a binary IMT.

| Proof commitment | Median merge | All seven nodes | Final file |
|---|---:|---:|---:|
| Binary, one root | 10.03 s | 72.38 s | 893,873 B |
| Binary, four-root cap for main and Keccak commitments | 9.85 s | 70.29 s | 895,707 B |
| Four-digest nodes, one root | 14.22 s | 99.89 s | 1,112,019 B |

Four-digest nodes reduced merge-circuit Keccak calls from 41,406 to 32,920.
The arithmetic tables needed to order siblings increased the initial codeword
from 218 million to 419 million cells. The binary timing ranges overlap over
three merges per configuration. The standard prover uses binary commitments
with one root. [Raw measurements](../benchmarks/binary/tree-merge/merkle-commitments-eight.json)
and [earlier prover profiles](../benchmarks/binary/tree-merge/merge-selectors.json).

The integration test verified 64 distinct child proofs, 32 first aggregates
and 31 merges. It used one merge key across all five levels. A fresh process
verified the 909,023-byte aggregate in 112 ms. The median merge took
9.61 s. [Full measurements and validation](../benchmarks/binary/tree-merge/conditional-swaps-sixty-four.json).

```sh
# Two merge levels exercise verification of the merge's own output.
cargo prove -n 8 --keep --out run/tree8

# Full acceptance: 64 independent children and one merge key at all five levels.
cargo test --locked --release --test cyclic_tree -- --ignored --nocapture

# Independent verification: only final proof, ordered list and trusted key files.
cargo prove --verify --out run/tree8
```

`--threads` sets the total Rayon worker count. `-j N` limits concurrent proofs
across the tree and defaults to two. `--parallel-children` caps the leaf slots
and `--parallel-nodes` caps the aggregate slots within that limit. Each parent
becomes ready when both input proofs are saved. The scheduler prioritizes
ready aggregates closest to the root. Each leaf samples its own masks and
the final statement retains input order. The report gives total tree wall
time, overlapping level spans, and node start and finish times measured from
the start of the tree. Imports of sibling proofs can also run concurrently.
The integration test uses four threads by default and accepts an override
through `RAYON_NUM_THREADS`.

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

### Opening a field word

For witness tables whose columns all have the same power-of-two width from 2 to
64 bits, verifier versions 5 through 7 use the low row coordinates for the bits of each word. For a word of width `2^k`, let
`X` be the polynomial basis generator of Poly64. For each bit-position
variable `j`, set `a_j = X^(2^j)` and `q_j = a_j / (1 + a_j)`. Opening the
bit column at the ordinary row point followed by `q_(k-1), ..., q_0` gives
one evaluation. Multiplying it by `product_j (1 + a_j)` recovers the logical
column evaluation, since the resulting weight of bit `i` is exactly `X^i`.
WHIR authenticates this evaluation in both the native and recursive verifiers.
Mixed-width main tables retain coordinate openings. Version 7 divides each
trusted preprocessing column into digits of 2, 8 or 32 bits, capped at the next
power of two of its table's largest column width. For a digit width of `k`,
the verifier opens each digit by the same method and weights digit `j` by
`X^(j*k)`. Setup checks the declared widths and commits zero padding in the last
digit. The verifier selects the encoding from the trusted key and accepts
earlier key versions under their original rules.
