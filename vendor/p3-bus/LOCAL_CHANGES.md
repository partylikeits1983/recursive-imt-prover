# Local upstream patch

Source: Plonky3 `708900d7a730d6ce4d5421d43e2193f2301920fa` (experimental Flock branch).
Only package sources, required README, normalized manifest and upstream licenses
are vendored. All Plonky3 dependencies remain pinned. The root Cargo patches select
these copies only for the git-based Flock backend; registry child dependencies
are unchanged. Source fingerprints include every Rust source and manifest.

`BusPlan::prove_with_leaves` uses deterministic compact leaf sources instead of
materializing both wide extension-field prefixes. It checks each planned length
and the equality of product roots before running the unchanged typed transcript.
It calls the GKR compact-source adapter; bus verification, statement shape,
terminal authentication and security ledger are unchanged.

Differential tests compare proofs and transcript state against `BusPlan::prove`,
including unequal products and both short and long malformed prefixes.

```sh
cargo test --locked --release --manifest-path vendor/p3-bus/Cargo.toml --target-dir target --features parallel --lib argument::tests
```

Unused development dependencies removed: `criterion`.
