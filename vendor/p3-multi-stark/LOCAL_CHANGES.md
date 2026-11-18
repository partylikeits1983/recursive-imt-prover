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
