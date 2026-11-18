# Protocol architecture

This prototype proves private membership in a depth-32 Keccak IMT and aggregates
the resulting proofs over Poly64/Poly192 binary fields. Children use experimental
statistical masking. Aggregates are non-ZK. Joint child ZK and end-to-end 128-bit
security remain unestablished; this is research code.

## Child statement

Public: `root[32]`, `nullifier_hash[32]`.
Private: `secret_num[32]`, `nullifier[32]`, `leaf_index: u32`, 32 sibling hashes.

The secret number is an unsigned 256-bit integer encoded in exactly 32
little-endian bytes. The nullifier is a 32-byte string. Fixtures generate both
independently with fresh cryptographic randomness. There is no reduction modulo
a prime, variable-length integer encoding, amount or additional nonce.

With `K = Keccak256` and concatenation `||`, prove:

```text
leaf = K("IMT-KECCAK-LEAF2" || secret_num || nullifier)
nullifier_hash = K("IMT-KECCAK-NULL1" || nullifier)

current = leaf
for level in 0..32:
    (left, right) = (current, sibling[level]) if index_bit[level] == 0
                    else (sibling[level], current)
    current = K("IMT-KECCAK-NODE1" || left || right)
current == root
```

The three tags are distinct 16-byte ASCII strings without terminators. Keccak
uses its original `0x01` suffix, not SHA3's suffix. All preimages fit one rate
block. The index bits are Boolean and private. No insertion root is required:
the fixtures use populated trees and later appends before choosing proof roots.

The public nullifier hash identifies repeated uses of the same nullifier.
The proof authenticates that hash but does not check whether it was used before.
Different roots and repeated valid statements are accepted. Root-history checks,
spent-nullifier storage, action authorization and state transitions belong to a
future application. No on-chain verifier is implemented.

## Small membership AIR

The AIR reuses Plonky3's binary Keccak permutation constraints. It schedules the
leaf hash, 32 parent hashes and the nullifier hash consecutively: 34 permutations,
850 active rows, padded to 1,024. Trusted preprocessing fixes the schedule, domain
tags, padding and output rows. Ordinary next-row constraints link the Merkle path.

Four extra private Poly64 columns carry the nullifier across rows. Each represents
eight consecutive nullifier bytes in the polynomial basis. At the leaf input and
the nullifier-hash input, a linear constraint packs the corresponding 64 Boolean
Keccak input bits into the same carried value. Transition constraints keep that
value constant. Packing is injective because these are exactly the 64 basis
coordinates of Poly64; integer embedding into characteristic two would be wrong.

This binds both hashes to one nullifier with four columns, without a copy bus or
another proof. The existing 128-column stacking still fits the enlarged trace
in the same number of stacks. The extra Keccak permutation does not increase
the padded trace height. All four carry columns remain private and masked.

## Child masking

The child compiler applies VEIL-inspired masking to the verifier's algebraic
messages and proves their consistency. The trace oracle adds independent random
coefficients before committing with Keccak and additive WHIR. Mask commitments
precede online challenges; masked claims and the required product/linear checks
are authenticated together. The original trace and native AIR proof are not
published. Every child uses fresh randomness.

The intended property is statistical zero knowledge under the stated
hash/transcript model. Local mask-transport and hiding tests are evidence for
components, not a joint simulator proof. Adaptive openings, aborts, commitment
hiding and Fiat–Shamir composition still need analysis. Adding a public nullifier
hash changes the statement the simulator is given; it does not make the
underlying nullifier a public witness.

WHIR uses Johnson bounds with a safety margin, Poly192 challenges and the
existing conservative component budgets. VEIL binding retains its separate
half-distance cap. See [security accounting](binary-security.md).

## Three circuit types

1. **Child:** the masked membership relation above.
2. **First aggregation:** constrain two complete child verifiers, with a fixed
   trusted child authority. Consume only proofs and public statements. Produce
   a non-ZK aggregate authenticating their ordered statement commitment.
3. **Recursive merge, planned:** constrain two aggregate verifiers and combine
   their statements. Normalize first aggregates and merges to one proof format,
   then reuse exactly one merge circuit/key at all higher levels.

Statement commitments are:

```text
child.digest = K("IMT-AGG-LEAF-V2" || root[32] || nullifier_hash[32])
child.count = 1
parent.digest = K("IMT-AGG-NODE-V2" ||
                  left.digest[32] || left.count_u8 ||
                  right.digest[32] || right.count_u8)
parent.count = left.count + right.count
```

Balanced merges require equal power-of-two counts and at most 64 total children.
Count addition is constrained as integer doubling, not XOR. Final verification
rehashes the complete ordered list and verifies one proof with independently
trusted data; it needs no child or intermediate proofs. Swapping statements or
changing a root, nullifier hash or count changes the authenticated statement.

The first aggregation is implemented. The complete aggregate-verifier circuit
and a two-verifier outer proof pass small component tests. Reusable merging of
depth-32 IMT aggregates remains unimplemented.
Cyclic merging must authenticate the first-aggregation and merge authorities,
constrain its branch choice, and decrease counts toward actual child proofs.
Native verification followed by an unconstrained acceptance bit is insufficient.
See the [implementation and acceptance plan](aggregation-tree.md).

## Formats

The active statement is exactly 64 bytes: root followed by nullifier hash.
JSON carries two 32-byte arrays and rejects extra or missing fields. Child v6
uses the `IMTVCA06` header. Flock tree-pair v2, checkpoint tree-pair v3, flat
Flock v7 and flat checkpoint v9 bind the relation and trusted configuration.
Old root/amount proofs and keys are incompatible and must be regenerated. Historical measurements retain their
original protocol identifiers and are not measurements of this relation.

Aggregate files use the `IMTPRF01` header and fixed-width little-endian bincode
2.0.1 serialization. This removes variable-integer overhead from field elements;
it does not change transcript messages. Decoding caps input at 16 MiB and
rejects trailing data. Verifier snapshots use v4; regenerate older aggregate
proofs and verifier data after updating. Child encoding is unchanged.

## Validation

The updated child, Flock/checkpoint first aggregates and flat checkpoint
aggregate generate real proofs. Fresh processes verify the aggregates without
original child proofs or witnesses. The release workspace suite passes.
The complete child-verifier circuit rejects modified
root/nullifier-hash bytes and proof data. AIR tests also splice two individually
valid Keccak computations using different nullifiers; the shared carry rejects
that attack.

Each first-aggregation backend passed 22 fresh-process checks, including changed
nullifier hashes, roots, order, counts, proof encodings, keys, authorities and
statement formats. Old root/amount artifacts are rejected. The retained
[measurements](binary-veil.md#nullifier-statement) cover two children, not the
planned higher merge levels.

## What might be publishable?

The membership/nullifier relation is established prior art. For example,
[Tornado Cash's circuit](https://github.com/tornadocash/tornado-core/blob/master/circuits/withdraw.circom)
binds the same private nullifier in a note commitment and a public nullifier hash,
using different hashes and encodings. [Zerocash](https://eprint.iacr.org/2014/349)
is a foundational anonymous-payment reference. Transparent recursion and the
masking approach also have prior art in [Fractal](https://eprint.iacr.org/2019/1076)
and [VEIL](https://eprint.iacr.org/2026/683).

The four-column carry is a straightforward binary-coordinate packing technique,
not a claimed new cryptographic primitive. Shared verifier preprocessing, delayed
Boolean-to-extension-field expansion, and packed sumcheck arithmetic are useful
engineering choices; novelty has not been established.

A reproducible engineering report is worthwhile. Possible research contributions
to investigate are the precise binary-field masking adaptation, the authenticated
Keccak GKR/port link, and bounded cyclic recursion at these parameters. A paper
would need a clear distinction from prior work, a completed construction, security
arguments for any new protocol, and matched-security benchmarks with ablations.
The current evidence supports implementation results, not a claim of a new ZK
theorem or a completed reusable recursive aggregation system.
