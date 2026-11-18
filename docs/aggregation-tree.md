# Reusable binary aggregation circuit

Priority: fast recursion with bounded memory and depth-32 IMT children. Children
retain experimental statistical masking; aggregates need not be ZK. Keep Poly64/Poly192, Keccak,
Johnson bounds and the 128-bit classical target.

Prefer three circuit types for the current proof formats:

1. IMT child: prove private membership.
2. First aggregation: verify two masked children and emit a standard aggregate.
3. Recursive merge: verify two standard aggregates and emit another. Reuse this
   circuit and its key at higher levels, once recursive geometry is stable.

The first aggregation combines children directly, avoiding an extra proof wrapper
per child. Final native verification does not require a fourth circuit.

```text
8 child proofs → 4 first aggregates → 2 merges → 1 final merge
                                       same merge circuit
```

Reusing the exact key requires cyclic recursion: the merge circuit verifies its
own outputs. Reusing Rust source while constructing different circuits/keys per
level is only an intermediate step. Making the first aggregation identical too
is an option if benchmarks justify the larger circuit or normalization cost.

## Fixed-size statement

`src/binary/aggregation_tree.rs` implements the statement binding and its native
binary-field circuit gadgets. `StatementFormat::TreePair` in
`src/binary/veil/aggregate.rs` connects these to the complete masked-child verifier.

Every node carries a 32-byte digest and a one-byte count. Cyclic verifier data
will be additional fixed-size public metadata, authenticated separately:

```text
leaf.digest = Keccak256("IMT-AGG-LEAF-V2" || root[32] || nullifier_hash[32])
leaf.count = 1

parent.digest = Keccak256(
    "IMT-AGG-NODE-V2" || left.digest[32] || left.count_u8 ||
                       right.digest[32] || right.count_u8
)
parent.count = left.count + right.count
```

Tags are ASCII without a terminator. Merges require equal power-of-two counts,
each at most 32. The circuit constrains counts and byte encodings; doubling is a
coordinate shift, not binary-field addition. This first version supports balanced
trees containing 1, 2, 4, 8, 16, 32 or 64 statements, without dummy children.

Final verification receives the complete ordered `(root, nullifier_hash)` vector,
recomputes its tree statement and verifies the proof against that statement.
Roots can differ and repeated statements are permitted. Changing order, count,
root or nullifier hash changes the expected statement. The public list remains available;
only the statement consumed inside recursion has fixed length.

The gadget tests generate proofs of the hash relation at multiple levels using
one key. The `masked-demo --tree-pair` command separately generates two real
masked child proofs, aggregates them and verifies again in a fresh process.

First aggregation reuses two instances of one child-verifier template. Each
instance authenticates its own statement leaf and computes the parent with a
sibling digest. Both bind the same parent; the verifier supplies their distinct
left/right roles. Inconsistent siblings require a Keccak collision. The full
public vector is retained in `statement.json` and hashed during verification.
The trusted format and protocol prevent substitution with an ordered-vector key.

## Making the whole verifier reusable

Three requirements remain:

1. **A common aggregate proof shape.** Masked children and aggregates have
   different verifier relations. The first aggregation should normalize two
   children into the format accepted by recursive merging. It consumes only
   child proofs and statements, never original IMT witnesses. Putting both
   complete verifier relations into every merge can increase cost.
2. **Stable recursive geometry.** Fix or pad trace sizes, PCS rounds, query slots,
   AIR layout and public-input length so verifying two output proofs fits the
   same circuit envelope. This must be measured before committing to the design.
3. **Authenticated verifier data and a base case.** Cyclic proofs must propagate
   the same merge verifier identity, checked against independently trusted data
   by final verification. Only the pinned first-aggregation authority is allowed
   at the bottom of the recursive tree. Never accept an arbitrary verifier key
   from a proof. Constrain the branch selector and counts so each recursive input
   represents strictly fewer leaves; first aggregates must authenticate actual
   child proofs.

The statement digest does not replace verifier-key authentication. Nor does a
native verifier result establish the recursive relation.

Plonky3's pinned native mixed-WHIR verifier freezes preprocessing commitments and
AIR metadata when constructing a circuit. Prepared output authorities can feed a
new layer, but they do not implement a cyclic key interface. Flock and checkpoint
also need recursive adapters for their specific proof formats. Upstream documents
[growth across native layers](https://plonky3.github.io/Plonky3-recursion/advanced_topics/binary_fields.html#not-yet-supported).
Plonky2's [cyclic verifier](https://github.com/0xPolygonZero/plonky2/blob/main/plonky2/src/recursion/cyclic_recursion.rs)
illustrates propagation and final checking of verifier data; it is a design
reference, not a binary-field backend we can substitute here.

SP1 separates [normalization](https://github.com/succinctlabs/sp1/blob/749b0c63f226063c471a6238a94101f930c14a13/crates/recursion/circuit/src/machine/core.rs)
from [recursive compression](https://github.com/succinctlabs/sp1/blob/749b0c63f226063c471a6238a94101f930c14a13/crates/recursion/circuit/src/machine/compress.rs),
with authenticated recursion keys. This supports the architecture, not a speed
claim for our different field/hash/backend. [leanVM](https://github.com/leanEthereum/leanVM/blob/6a828ecf5b17d0dde4a38bf21d4e14b81d2d7f3b/README.md)
is a closer binary-field/Keccak reference: its published 2-to-1 measurement is
146 ms on an M4 Max, but its stated ROM soundness is 125 bits. That result is not
an equivalent-security benchmark for this project's 128-bit target.

## Implementation order

The checkpoint Keccak reduction now has a native Poly64 circuit replaying all
24 cubic sumchecks over Poly192. Its separate fixed-width transcript binds the
complete initial claim and avoids reproducing Postcard's variable-length integer
encoding in the circuit. Existing first-aggregation formats are unchanged.
The transposed linear layer factors by lane and bit; cyclic rotations use two
carry states instead of materializing a dense weight vector.

The native Boolean-WHIR adapter also verifies complete batches across multiple
tables, including successor openings and aligned column blocks. Real-proof tests
check transcript agreement and reject matching forged public/private openings.
`src/binary/checkpoint.rs` now composes the GKR reduction, input closing and
boundary PCS verification in one native circuit. Its deferred ring-switch adapter
checks tensor readings and closes their linear functional in WHIR's first
sumcheck, using the backend's existing protocol. Real proofs pass; modified
commitments, tensors, openings and proof messages fail after witness import.
An actual outer proof also verifies against a separately restored verifier key.
For eight Keccak permutations, its circuit has 616,467 witnesses. One first-proof
sample took 1.21 s to prove and 57 ms to verify (1.25 MB, M2 Pro, four threads).
The full test command's peak RSS was 943 MB; this is not physical footprint.
[Raw component measurement](../benchmarks/binary/checkpoint-keccak/recursive-committed.json).
Arithmetic port links and the full aggregate verifier remain to be composed.
This committed-permutation component is not a merge proof.

Run these component checks with:

```bash
RAYON_NUM_THREADS=4 cargo test --locked --release -p imt-flock-backend \
  checkpoint_keccak::recursive -- --include-ignored --nocapture
cargo test --locked --release --test recursive_trace
RAYON_NUM_THREADS=4 cargo test --locked --release --test checkpoint_recursion \
  -- --include-ignored --nocapture --test-threads=1
```

1. **Retain the child and first aggregation.** Depth is 32. Both are implemented;
   first aggregation constrains two complete masked-child verifiers. Checkpoint
   is the initial tree backend. The root/nullifier-hash relation's warm two-child
   median is 18.926 s; [measurements](binary-veil.md#nullifier-statement).
2. **Implement the checkpoint verifier inside a binary circuit.** Reuse upstream
   native Poly192 sumcheck, product-bus, Boolean WHIR and Keccak gadgets. Add the
   missing coordinate-opening adapter and the Keccak GKR/port-link checks. Test
   each adapter against actual native proofs before composing the whole verifier.
   A reduction without its authenticated PCS boundaries is not an aggregate.
3. **Fix the common aggregate layout.** First aggregation and merge must share
   a bounded proof shape, public layout, hash/PCS parameters and AIR layout.
   Their preprocessing authorities may differ. Measure the merge graph and pad
   both circuits to an envelope that also contains the merge's own output.
4. **Build the reusable merge.** Verify two aggregates and constrain their ordered
   parent digest and equal counts. Inputs of count two must use the pinned first
   authority; larger inputs must use the merge authority. Carry and authenticate
   the merge verifier data through recursion, and check it against trusted data
   in final verification. Counts strictly decrease toward the base case.
5. **Complete the three-circuit acceptance run.** Generate eight real children,
   four first aggregates, two merges and one final merge. Use the exact same
   merge circuit/key at both higher levels. Serialize the final proof, ordered
   statement and trusted verifier data; verify in a fresh process without any
   child or intermediate proofs. Reject altered roots, nullifier hashes, ordering, counts,
   proof data, branch selectors and foreign authorities. Record times and memory.

Completion requires all five steps, not just the first tree level or statement
hashing. Separate keys per merge level are an intermediate diagnostic only.
Stop implementation work once this three-circuit acceptance run and its negative
tests pass. Keep the existing security parameters and resource guards throughout;
native wrapping has previously exceeded the codeword budget.

Compare total work and critical-path latency. Eight children require four first
aggregates and three recursive merges across three dependent levels. A tree is
faster only if smaller circuits and parallelism outweigh those extra proofs and
any wrappers. Record peak memory.
Charge soundness error for every child, wrapper and merge, retaining the 128-bit
classical target and existing caveats. Formal ZK analysis is deferred, not an
implementation gate.
