# Protocol specification v1 and implemented subset

## Status and trust boundary

The intended authorization is two full-ZK Spartan–WHIR client proofs verified in one
fixed Plonky3 circuit, followed by a trusted application state transition. The client
relation and append/history circuit are implemented separately. Their cryptographic
composition is NOT implemented. No state update can succeed. `BLOCKERS.md` enumerates
the exact missing relations; this specification distinguishes intended acceptance from
available diagnostics.

The deployment identifier is the constant eight-limb vector
`[0x494d54, 1, 2026, 11, 16, 0, 0, 1]`. It never changes between batches.
Each secret and each randomness value is an independently sampled vector of eight
uniform KoalaBear elements (about 248 bits per vector). The field modulus is 2130706433.

## Application hash

Profile: `koalabear-poseidon2-width24-rate16-capacity8-digest8-v1`, reusing the pinned
Spartan withdrawal native sponge and its R1CS linear layers. The permutation has width
24, exponent 3, four initial external rounds, 23 internal rounds, four final external
rounds, and the initial external linear layer. Round constants are exactly
`KOALABEAR_POSEIDON2_RC_24_EXTERNAL_INITIAL`, `_INTERNAL`, `_EXTERNAL_FINAL` in the pinned
client Plonky3 revision. `artifacts/hash-vectors.json` includes every constant, default
subtree hash and native test vector. Native/R1CS/P3 differential tests fix the matrix
and constant interpretation.

Sponge state starts with 24 zero field elements. Set state[16]=domain,
state[17]=input length in field elements, state[18]=1. Absorb successive blocks of up to
16 elements ADDITIVELY into the leading rate lanes, permuting after every block.
Unfilled lanes get no addition; no terminator block or extra padding element is added.
For zero input length permute once. Output lanes 0..7. Length is bound in capacity,
so trailing zero elements change the input grammar. Tags: note=0x494d01,
nullifier=0x494d02, tree node=0x494d03. Fixed input lengths are 24/24/16 respectively.

`cm = H_note(ctx || secret || randomness)`.
`nf = H_nullifier(ctx || secret || randomness)`.
`node = H_node(left_digest || right_digest)`.

These application tags do not alter the proof system's Fiat–Shamir transcript.
Proof hashing uses upstream Poseidon2 width-16/rate-8 challenger, width-24/rate-16
leaf sponge and width-16 compression with eight-element digests, preserved exactly.

## Tree and client relation

Fixed binary tree depth d in 1..32 (default 8). EMPTY is eight zero elements and may
never be a real commitment. Default subtree 0 is EMPTY; default h+1 hashes default h
twice. Store only populated `(height, subtree_index)` nodes. Leaf index is a bounded
unsigned integer, paths are leaf-to-root, bit 0 selects the first branch: 0 means the
running node is the LEFT child. All digests are compared over all eight limbs.

The public client vector is ctx[8], membership_root[8], nullifier[8], new_commitment[8].
Private input contains old secret/randomness, a u64 index, d siblings and new
secret/randomness. The R1CS derives both commitments and the nullifier, verifies the
old path, and binds the public outputs. Index synthesis produces 64 Boolean bits;
all bits at or above d are constrained to zero. Thus even an out-of-range input index
is represented by unsatisfiable constraints rather than silently truncated.

Nonempty commitments use witnesses t_i with sum(cm_i * t_i)=1. This equation is
satisfiable exactly when at least one digest limb is nonzero. Inverse hints are always
constrained. Random output authorization is therefore inside the client relation.
Changing the root, output, history choice or batch cannot change a note's nullifier.

## Public batch layout

Fixed size two. Public base-field order (112 elements):

| Offset | Field |
|---|---|
| 0 | version = 1 |
| 1 | fixed depth |
| 2 | ctx[8] |
| 10 | old_root[8] |
| 18 | old_leaf_count, three LE 16-bit limbs |
| 21 | allowed_roots[4][8], newest first |
| 53 | child_roots[2][8] |
| 69 | nullifiers[2][8] |
| 85 | new_commitments[2][8] |
| 101 | new_root[8] |
| 109 | new_leaf_count, three LE 16-bit limbs |

Counts are represented by 33 Boolean bits and reconstructed into the three limbs;
the third limb is one bit. No count arithmetic occurs in a single KoalaBear element.
The wire transport uses u64 counts and rejects values beyond capacity BEFORE mapping
them to fields; nonrepresentable values cannot alias a field statement.

The Plonky3 Statement sink binds every listed public value, using an independently
retained `CircuitVerifier`. The diagnostic fresh process rebuilds the fixed circuit
and preprocessing from its trusted state's depth and compiled configuration; it
never imports a circuit or preprocessing authority from proof metadata. This cold
rebuild cost is explicit. An authorized recursive verifier artifact does not yet exist.

## Implemented transition relation

For each child, four Boolean selectors sum to exactly one; each selector multiplies
all eight coordinate differences against its history entry. Repeated roots are allowed.
For nullifier inequality, constrain sum((nf0_i-nf1_i)*t_i)=1. Both new commitments must
be nonempty. The application still authenticates the ENTIRE allowed-root list from
trusted state; circuit membership alone cannot authenticate history.

Let n be old count, m=n+1, k=m+1. Each increment is a binary ripple carry using Boolean
input bits, XOR arithmetic and product carry; final carry is zero. n,m < 2^d,
k <= 2^d. Bits above d are zero; if k[d]=1 every lower bit must be zero. The consecutive
indices share these constrained count bits.

Using private-to-the-outer-circuit but public-tree append paths p0 and p1:

```
MerkleRoot(EMPTY, n, p0) = old_root
middle = MerkleRoot(new_commitments[0], n, p0)
MerkleRoot(EMPTY, m, p1) = middle
MerkleRoot(new_commitments[1], m, p1) = new_root
new_leaf_count = k
```

The second path must be against the intermediate root. Old commitments remain.
Append witnesses do not include spent-note membership paths or client secrets.

## Intended application acceptance; currently disabled

TrustedState carries fixed ctx, depth, current root/count, four accepted roots,
spent-nullifier set and a trusted outer verifier identifier. History initializes by
repeating the trusted bootstrap root. The demo bootstrap provisions the first two
notes; historical fixtures explicitly provision successive prefix roots of that same
tree, never arbitrary external roots. This fixture provisioning is not proof-driven
state acceptance.

A completed verifier must match state ctx/root/count/history, verify the complete
outer authorization relation against ALL public fields, and reject either spent or
duplicate nullifier. Only then may it commit both nullifiers, root/count and
`[new_root, history[0], history[1], history[2]]` atomically. Any failure must preserve
state. Concurrent/competing updates require serialization or compare-and-swap on old
state; the current executable never writes state. Persistence and successful atomic
application remain unimplemented. This is not a stateless ledger: the note-tree root
does not commit to the spent set.

## Encoding

JSON is an inspection/CLI interchange format: unknown keys and noncanonical digest
limbs reject. JSON bytes themselves are not claimed canonical (whitespace differs).
The proof statement is the exact field vector above.

Binary envelopes are `RIMT`, byte version 1, two zero reserved bytes, one role byte,
then bincode 1.3.3 with fixed-width integers, little endian, no trailing bytes and
256 MiB decoding limit. Role 1=client PK, 2=client VK, 3=client proof,
4=transition diagnostic, 5=batch statement. Canonical re-encoding must match.
Application Digest is eight LE canonical u32 residues. Upstream proof/key field
serialization uses canonical *Montgomery* residues, each strictly below p, exactly
as that upstream revision specifies. It is not cast into the other Plonky3 type.
Binary proof transport is revision-specific; role 4 cannot authorize state.
