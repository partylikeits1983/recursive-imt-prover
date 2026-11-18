# Local upstream patch

Source: Plonky3 `708900d7a730d6ce4d5421d43e2193f2301920fa` (experimental Flock branch).
Only `src/`, the normalized package manifest, and upstream licenses are vendored.
Dependency revisions remain pinned. Root Cargo patches select this copy only for
the git-based Flock backend; registry Plonky3 child dependencies are unchanged.
The root source fingerprint includes this crate's manifest and all Rust sources.

## Changes

`src/ring_switch/bits/reduction.rs`: deferred suffix-bank tensors restrict their
input to the contiguous run selected by leading Boolean **head** coordinates.
Every omitted row has equality weight zero. Prefix coordinates that reach into
the suffix banks are retained in the bank dimension. No verifier, message,
challenge, commitment or security parameter changes.

The added differential test compares every suffix depth and Boolean prefix length
(including all-fixed and no-fixed cases) with dense, separately evaluated banks
over Poly64/Poly192. It exercises zero, nonzero and alternating slot addresses.
Upstream ring-switch tests remain available.

For repeated Poly192 coordinate lookups, the prover groups eight inputs by byte
position once and reuses those indices for every outer equality weight. Each
lookup reads the same subset sums as the scalar implementation. A differential
test covers every tail length and the single-use fallback.

```sh
cargo test --locked --release --manifest-path vendor/p3-sumcheck/Cargo.toml --target-dir target --lib ring_switch::bits
```

Unused development dependencies removed: `criterion`.
