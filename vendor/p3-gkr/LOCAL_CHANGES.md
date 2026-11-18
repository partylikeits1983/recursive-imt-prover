# Local upstream patch

Source: Plonky3 `708900d7a730d6ce4d5421d43e2193f2301920fa` (experimental Flock branch).
Only package sources, required README, normalized manifest and upstream licenses
are vendored. All Plonky3 dependencies remain pinned. The root Cargo patches select
these copies only for the git-based Flock backend; registry child dependencies
are unchanged. Source fingerprints include every Rust source and manifest.

`PreparedProductGkr::from_leaves` and `prove_with_leaves` extend the existing
`ProductLeaves` interface to separate trees, retaining the original shape and
transcript. A small adapter batches each tree's round messages with the same
powers as the dense prover. Verification and security parameters are unchanged.

`RegeneratedLeaves` reads deterministic ranges of at most 16,384 leaves, retaining
only the product level two levels above them. Its bottom layer computes the first
sumcheck round from regenerated chunks using upstream `PairSums` and factored
equality weights, then retains the half-size folded prefix for the existing dense
kernel. Missing suffix values are still one; the identity contribution is added
once per tree after chunk sums merge. This changes memory/time, not proof size.
The callback is prover infrastructure and must represent a fixed leaf vector;
terminal values still require commitment authentication by the caller.

Tests compare complete proofs, outputs and subsequent transcript challenges with
the original dense path over BinaryField128 and Poly64/Poly192, heights 0–16,
empty/partial/full prefixes, chunk boundaries, trailing identities, distinct and
shared roots. Upstream proof-byte fixtures and verifier tests are preserved.

```sh
cargo test --locked --release --manifest-path vendor/p3-gkr/Cargo.toml --target-dir target --features parallel --lib
```
