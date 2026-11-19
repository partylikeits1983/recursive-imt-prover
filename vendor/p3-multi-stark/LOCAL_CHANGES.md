# Local upstream patch

Source: Plonky3 `708900d7a730d6ce4d5421d43e2193f2301920fa` (experimental Flock branch).
Only `src/`, the normalized package manifest, and upstream licenses are vendored.
Dependency revisions remain pinned. Root Cargo patches select this copy only for
the git-based Flock backend; registry Plonky3 child dependencies are unchanged.
The root source fingerprint includes this crate's manifest and all Rust sources.

## Changes

`src/bus/context.rs`: allocate the planned product-bus leaf prefix once, append
one materialized block at a time, and release each temporary block immediately.
This replaces collecting all blocks followed by a full-prefix concatenation.
Leaf values, order, shape, transcript and verifier are unchanged. The peak now
contains the output prefix and at most one temporary block, rather than two
complete prefixes. This is not a bound on total prover memory.

Existing differential tests compare materialized leaves against independently
evaluated AIR rows, including different heights, disjoint declarations,
Boolean storage, activations and boundary selectors.

```sh
cargo test --locked --release --manifest-path vendor/p3-multi-stark/Cargo.toml --target-dir target --lib bus::context::tests
```

The production bus prover now uses `leaf_sources`, backed by deterministic range
reads from the same committed tables. Range reads locate the first intersecting
block by offset and reuse its output buffer. Affine tuple fingerprints read
packed, dense and periodic columns directly. Column selectors retain their exact
field values. Boundary and nonlinear factors use the generic evaluator.
The old full-prefix materializer remains a differential-test reference.
Range tests compare chunk sizes 1/3/7/64 with independent dense AIR rows.

This selects the [GKR regeneration adapter](../p3-gkr/LOCAL_CHANGES.md) through the
[bus compact-source API](../p3-bus/LOCAL_CHANGES.md). Only prover allocation and
computation change; proof serialization and verifier logic are unchanged.

`src/bus/equality.rs` stores each bus-composition equality polynomial as two
factor tables over the leading/trailing coordinates, with the already-bound
prefix absorbed into the leading table. Its size is O(sqrt(trace height)),
instead of one extension-field entry per row. Binding a coordinate multiplies
the prefix by its equality factor; summing a coordinate removes its normalized
factor. No division is used, including when the prefix is zero.
`src/bus/composition.rs` reads those exact weights in place of dense tables.

The bus sumcheck factors the low-coordinate weight out of each endpoint sum.
Scalar and packed boundary selectors select their bound prefix directly on Boolean rows.

Differential tests compare every weight against the original dense polynomial
through binding and summing, including Boolean anchors and zero prefixes.
Existing projected/generic bus tests and commitment-binding tests remain active.
Run all bus tests for this patch:

```sh
cargo test --locked --release --manifest-path vendor/p3-multi-stark/Cargo.toml --target-dir target --features parallel --lib bus::
```

`src/compact.rs`, `src/rounds.rs`, `src/rounds/repr.rs` and
`src/bus/composition.rs`: return unused vector capacity after large polynomial
folds. The upstream in-place fold truncates its evaluations but retains the old
allocation; mixed-height stages can otherwise retain many first-fold buffers
while later stages activate. Buffers smaller than 64 KiB remain in place.
All polynomial values and transcript messages are unchanged. The allocation
regression compares every fold against the dense polynomial and checks retained
capacity; the upstream round and bus suites exercise the affected paths.

`src/keys.rs` and `src/rounds.rs`: derive Serde support for the succinct verifying
key and its existing AIR degree/profile metadata. This serializes the fixed
preprocessing commitment and verifier metadata only, never proving tables.
It does not change aggregate proof encoding, transcript messages or equations.
The application authenticates the complete verifier snapshot before decoding it
and checks its configuration binding, authority identity and algebraic budget.

`src/bus/composition.rs`: committed columns with at least 65,536 rows defer
materializing their first extension-field fold. They retain the borrowed base
column and the first challenge, evaluating the same line on demand. The second
fold writes the quarter-height table directly, avoiding the larger intermediate
allocation. Packed Boolean columns use the existing four-value interpolation
identity. Subsequent folds and affine projections are unchanged.

`src/bus/deferred_tests.rs` compares every remaining evaluation and round with
dense folding for both Poly64/Poly192 and a prime-field extension, including
packed columns and zero/one challenges. Aggregate equations, parameters, proof
encoding and verifier behavior are unchanged.

`src/verifier.rs`: `verify_with_trace_openings` returns the zerocheck point and
authenticated current-row readings only after every PCS, bus and zerocheck
check succeeds. Each table uses the suffix matching its row arity, exactly as
in `trace_suffix`. The existing `verify` calls the same implementation and
discards those readings. Proof encoding, equations and transcript are unchanged.
The application uses this receipt to link its Keccak boundary proof to the
arithmetic proof; an unverified opening is never accepted as a receipt. Backend
tests exercise actual valid arithmetic proofs, altered authenticated values,
changed public values and mismatched Keccak subarguments.

Unused development dependencies removed: `criterion`, `p3-binary-pcs`, `tracing-forest`, `tracing-subscriber`.

`src/bus/composition.rs`: affine declarations that exceed the projection storage
limit now compute quadratic round coefficients directly from their folded
sources. Terms sharing an activation are combined once. Compact projections
use the same coefficient accumulator; nonlinear declarations keep the generic
evaluator. This changes prover work only, with no new full-height tables.
The existing differential test compares every round against generic evaluation,
including Poly64/Poly192, mixed heights, packed columns, selectors, cancellation
and zero/one challenges. For a shorter affine table, the prover weights the two
Boolean endpoints of its first round polynomial to compute its dormant claim,
then reuses those coefficients when the table becomes active. This saves one
full scan. Run the bus tests above.

Ordinary, lookup and sliced constraint folders declare that they discard bus
payloads. AIRs using the deferred bus API can skip those expressions while
retaining every activation constraint. Product-bus evaluation still uses the
complete recorded symbolic declarations. No transcript, degree, opening or
security equation changes.

`src/keys.rs`: expose the existing preprocessing commitment through a read-only
getter so the recursive verifier can pin it as a circuit constant. The key
encoding and native verification equations are unchanged.
