# Protocol architecture

This prototype proves private membership in a depth-32 BLAKE3 IMT and aggregates
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

With `H` the first 32 output bytes of unkeyed BLAKE3 and concatenation `||`, prove:

```text
leaf = H("IMT-BLAKE3-LEAF2" || secret_num || nullifier)
nullifier_hash = H("IMT-BLAKE3-NULL1" || nullifier)

current = leaf
for level in 0..32:
    (left, right) = (current, sibling[level]) if index_bit[level] == 0
                    else (sibling[level], current)
    current = H("IMT-BLAKE3-NODE1" || left || right)
current == root
```

The three tags are distinct 16-byte ASCII strings without terminators. The
80-byte leaf and node messages each use two compression blocks. The 48-byte
nullifier message uses one block. The Boolean index bits stay private. The
fixtures populate the tree and append additional notes before choosing roots.
The BLAKE3 protocol uses new roots, nullifier hashes, and proof identities.

The public nullifier hash identifies repeated uses of the same nullifier.
The proof authenticates that hash but does not check whether it was used before.
Different roots and repeated valid statements are accepted. Root-history checks,
spent-nullifier storage, action authorization and state transitions belong to a
future application. No on-chain verifier is implemented.

## Small membership AIR

The AIR reuses Plonky3's binary BLAKE3 compression constraints. It schedules
two rows each for the leaf and 32 parents, then one row for the nullifier hash.
The 67 active rows pad to 128. Trusted preprocessing fixes the compression
schedule, tags, flags, and padding. Next-row constraints bind consecutive
chaining values and link the Merkle path, including the final 16 bytes of a
right child when its digest crosses the block boundary.

Four extra private Poly64 columns carry the nullifier across rows. Each represents
eight consecutive nullifier bytes in the polynomial basis. At the leaf input and
the nullifier-hash input, a linear constraint packs the corresponding 64 Boolean
BLAKE3 message bits into the same carried value. Transition constraints keep that
value constant. Packing is injective because these are exactly the 64 basis
coordinates of Poly64; integer embedding into characteristic two would be wrong.

All four carry columns remain private and masked.

## Child masking

The child compiler applies VEIL-inspired masking to the verifier's algebraic
messages and proves their consistency. The trace oracle adds independent random
coefficients before committing with BLAKE3 and additive WHIR. Mask commitments
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
3. **Recursive merge:** constrain two aggregate verifiers and combine their
   statements. First aggregation and merge now share a fixed verifier layout.
   The cyclic implementation carries authenticated verifier data so one merge
   circuit can verify its own outputs. The 64-child integration test passed all
   five merge levels with the same circuit/key and independent final verification.

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

The merge circuit embeds the complete checkpoint verifier: product bus, AIR,
main/preprocessing PCS, transcript checks and the linked Keccak GKR argument.
It consumes two actual aggregate proofs and statements, with no IMT witnesses.
Two copies of one template each authenticate their source digest and count,
combine it with a sibling digest, and constrain the same parent. Public roles
fix left/right order. Inconsistent sibling digests require a Keccak collision.
The cyclic public layout is `(digest[32], count, role, merge_authority[64])`
twice, with roles 0 and 1. The authority consists of the transcript identity and
preprocessing commitment. Inputs with count two use the pinned first-aggregation
authority; larger inputs use the carried merge authority. Both input proofs must
carry the same authority as the output. Final verification derives the expected
authority from its independently trusted key. Counts strictly decrease toward
the first aggregates and their actual child proofs.

The selected preprocessing commitment is constrained in the transcript and PCS
openings. The selected identity seeds both arithmetic and Keccak verification.
First aggregation permits arbitrary carried authority metadata so its key can
be prepared before the merge key; the final authority check is therefore essential.
Native verification followed by an unconstrained acceptance bit is insufficient.
See the [implementation and acceptance plan](aggregation-tree.md).

## Formats

The active statement is exactly 64 bytes: root followed by nullifier hash.
JSON carries two 32-byte arrays and rejects extra or missing fields. Child v6
uses the `IMTVCA06` header. The first aggregation binds its key to
`experimental-binary-masked-checkpoint-cyclic-pair-v1`. Every higher merge uses
`experimental-binary-checkpoint-cyclic-merge-v1`. Both carry the merge authority
and use the same verifier layout. Flat-batch benchmarks use Flock v7 or
checkpoint v9. Historical measurements identify the protocol used in each run.

Intermediate aggregates use the `IMTPRF01` header followed by fixed-width,
little-endian bincode 2.0.1. The tree prover compresses the final payload with
zlib when that reduces its size. The `IMTPRF02` file contains the header, a
four-byte little-endian payload length and one zlib stream. Verification
accepts either encoding, checks the declared and decoded lengths, rejects
trailing data and caps input and expanded proof size at 16 MiB. Both encodings
carry the same cryptographic transcript.

## Validation

The release suite checks child membership and verifier constraints. The tree demo
also verifies the aggregate in a fresh process using the ordered statements and
trusted verifier data.
The complete child-verifier circuit rejects modified
root/nullifier-hash bytes and proof data. AIR tests also splice two individually
valid Keccak computations using different nullifiers; the shared carry rejects
that attack.

Earlier first-aggregation benchmarks passed 22 fresh-process checks, including changed
nullifier hashes, roots, order, counts, proof encodings, keys, authorities and
statement formats. Old root/amount artifacts are rejected. The retained
[first-aggregation measurements](binary-veil.md#nullifier-statement) cover two children.

The [four-child merge benchmark](binary-veil.md#four-child-tree-merge) records
fresh verification and sixteen rejection checks for the earlier merge circuit.

The cyclic 64-child integration test passes independent final verification with
one merge circuit/key reused at all five higher levels. It rejects invalid child
proofs, altered statements, ordering, counts, proof encodings and a foreign
carried authority. The final key bytes match the earlier eight-child run.
[Raw cyclic run](../benchmarks/binary/tree-merge/cyclic-sixty-four.json).

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
The 64-child acceptance test establishes an implementation result, not a new ZK
theorem. The low-latency proving targets remain unmet.
