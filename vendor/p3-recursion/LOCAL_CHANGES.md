# Local compatibility changes

Source: Plonky3/Plonky3-recursion revision
`3a69ba61f713c8400b14eb3d8f0e52caa13512c7`, `recursion/` crate.
MIT and Apache-2.0 licenses are included. Other workspace crates remain pinned
to that revision in Cargo dependencies. Workspace metadata/dependencies in
Cargo.toml are expanded so this copy builds independently.

Changes:

- Repository-import whitespace cleanup: remove surplus final blank lines in
  `Cargo.toml` and `LICENSE-APACHE`, and trailing comment whitespace in
  `tests/preprocessing.rs`. No code or license text changes.

- `src/builtin_config/registry.rs`: add portable WHIR security-assumption ID 3
  for the existing native `SecurityAssumption::JohnsonBound`. IDs 1 and 2 retain
  their meanings. The protocol mathematics and query-selection code are unchanged.
- `tests/builtin_config_registry.rs`: accept ID 3 and reject unknown ID 4.
- Apply the salted-MMCS coefficient-binding fix and its tests from upstream
  [PR #484](https://github.com/Plonky3/Plonky3-recursion/pull/484), revision
  `78bd012ba44799913311aa0ab0c00dbb239dc0b7`. Changed files: `src/pcs/mmcs.rs`,
  `tests/mmcs_leaf_hash_binding.rs`, and `tests/zk_hiding_mmcs.rs`.
- `src/challenger/binary.rs`: allow a trusted Keccak hash prefix on every
  challenger refill, matching the masked child's domain-separated native
  transcript. Existing constructors keep the unprefixed behavior. Legacy
  rejection-query continuation tokens reject a prefixed challenger; the
  selected WHIR path uses stratified queries.
- `src/pcs/binary/{whir_domains,whir_kernel,poly_whir_verifier}.rs` and the
  `src/pcs/binary.rs` re-export: optionally authenticate WHIR leaves and nodes
  with distinct, trusted Keccak prefixes. This adapter supports binary trees
  with a single root and preserves the shared-upper-tree optimization. It
  reuses all upstream WHIR arithmetic and query constraints. Prefixes are
  circuit constants, not proof inputs; callers must authenticate the complete
  compiled circuit because the existing input-shape encoding does not include
  these additional domains.
- `src/pcs/binary/{trace_routing,trace_whir,trace_whir_poly}.rs`: replay complete
  column batches across multiple tables and aligned blocks in the native
  carrier. Match the existing native PCS and prime-carrier routing, including
  table separators, selectors and successor openings. Incomplete batches remain
  unsupported. `tests/recursive_trace.rs` in the root workspace checks real
  Poly64/Poly192 proofs, transcript continuation and forged openings.

- `src/pcs/binary/{deferred_whir_poly,poly_whir_input,whir_kernel}.rs`: replay
  the pinned backend's current-only deferred ring switch. Tensor readings are
  constrained and their combined linear functional joins WHIR's first sumcheck;
  its weight is evaluated at the terminal folding point. The packed WHIR engine
  retains all query, PoW and commitment checks. The deferred transcript seed is
  supplied by trusted configuration and bound into the compiled circuit. Existing
  ordinary-opening paths are unchanged. Root `tests/checkpoint_recursion.rs`
  checks real backend proofs, post-import forgeries and an actual outer proof.

The repository's `src/binary/veil/whir/recursive/` component tests import actual
prefixed native proofs, constrain their verification, and reject mutations.
They also exercise the framed transcript and functional sumcheck. The complete
masked-child verifier composes these with AIR replay and inner algebraic checks.
The isolated `crates/flock-backend` adapter proves two such verifiers in one
binary-field proof, measured at IMT depths 16 and 32. Larger batches remain
resource-bound; see the root README for timings and security limitations.

The local copy is necessary because the upstream portable registry rejects
Johnson even though native WHIR supports it. Keep these changes explicit when
updating the dependency; do not silently replace Johnson with capacity bounds.

Unused development dependencies removed: `p3-poseidon2`.
