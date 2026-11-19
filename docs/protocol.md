# Protocol architecture

This prototype proves private membership in a depth-32 Keccak IMT and aggregates
the resulting proofs over Poly64/Poly192 binary fields. Children use experimental
statistical masking. Aggregates are non-ZK. Joint child ZK and end-to-end 128-bit
security remain unestablished; this is research code.

## Child statement

Each child replaces one private record with another of the same quantity. Its
96 public bytes are the root, input tag and output commitment, in that order.
The witness holds two 32-byte labels, two 32-byte nonces, one unsigned 64-bit
quantity, the 32-bit input position and 32 sibling hashes. Both records use
the same commitment format so the replacement can become a later input.

```text
record(label, nonce, q) = K("IMT-RECORD-OPEN1" || label || nonce || LE64(q))
current = record(input_label, input_nonce, quantity)
for level in 0..32:
    (left, right) = (current, sibling[level]) if index_bit[level] == 0
                    else (sibling[level], current)
    current = K("IMT-KECCAK-NODE1" || left || right)
current == root
K("IMT-RECORD-USED1" || input_nonce) == input_tag
record(output_label, output_nonce, quantity) == output_commitment
```

The domain tags are 16 ASCII bytes. Full-round Keccak-256 uses the original
`0x01` suffix. Every preimage fits one 136-byte rate block. The fixtures draw
independent random labels and nonces. A label is opaque data. Knowledge of the
input opening and authentication path authorizes the replacement in this
model. The application selects accepted roots, checks tag uniqueness and
appends outputs. Reusing a nonce repeats the tag, including across roots.
Anyone who knows a record nonce can predict its tag.
Key-based authorization, encrypted delivery and multi-record balancing are
outside this relation. The public/private split is modeled on an action with
one hidden input and one hidden output. [Orchard circuit](https://github.com/zcash/orchard/blob/main/src/circuit.rs)

## Membership AIR

The child schedules the input record, 32 parents, the input tag and the output
record. Each Keccak permutation takes 25 rows. The 875 active rows fit the
existing 1,024-row trace. Trusted preprocessing fixes the round flags, hash
roles, padding and digest check rows. Boolean path directions link each child
digest to the correct half of the next parent input.

Four private Poly64 columns carry the input nonce between its two preimages.
A fifth carries the quantity between the input and output records. At the
scheduled input rows each limb equals the polynomial-basis packing of 64
Boolean Keccak state bits. These coordinates give a unique 64-bit encoding.
Row transitions force the carries to stay constant. Both records therefore
encode identical quantity bytes, including at zero and the maximum u64.
At each digest output row the AIR packs each eight Boolean coordinates into
one byte and checks it against the corresponding public byte. The masked
native and recursive verifiers both supply 96 byte coordinates in the same order.

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
hiding and Fiat–Shamir composition still need analysis. The simulator receives the root, input tag and output commitment.

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
child.digest = K("IMT-AGG-LEAF-V3" || root[32] || input_tag[32] || output_commitment[32])
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
changing a root, tag, output commitment or count changes the authenticated statement.

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

The JSON statement requires three 32-byte arrays and rejects missing or extra
fields. Child proofs use the `IMTRCA01` header. Rebuild fixtures and verifier
keys for this statement. The first aggregation binds its key to
`experimental-binary-masked-checkpoint-cyclic-pair-v2` and every higher merge
uses `experimental-binary-checkpoint-cyclic-merge-v2`. Flat-batch benchmarks
use Flock v8 or checkpoint v10. Historical measurements identify the protocol used in each run.

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
The complete child-verifier circuit rejects changes to each public field
and to proof data. Splicing valid Keccak traces
with different input nonces or mismatched output quantities fails the AIR checks.

Earlier first-aggregation benchmarks passed 22 fresh-process checks, including changed
nullifier hashes, roots, order, counts, proof encodings, keys, authorities and
statement formats. Old root/amount artifacts are rejected. The retained
[first-aggregation measurements](binary-veil.md#historical-two-field-statement) cover two children.

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
