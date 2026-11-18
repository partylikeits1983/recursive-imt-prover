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
reads from the same committed tables. `materialize_block_range` keeps the original
full block height for boundary and periodic selectors, while evaluating only
the requested rows. The packed Boolean affine path also respects that range.
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
