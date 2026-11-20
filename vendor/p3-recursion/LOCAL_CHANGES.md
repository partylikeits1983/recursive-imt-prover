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
- `src/pcs/binary/coordinate_poly.rs`: expand the trusted current-only arithmetic
  opening schedule into Boolean coordinates, then reconstruct logical Poly192
  evaluations after PCS authentication. Zero-width columns reconstruct zero;
  other columns use exactly their declared low coordinates. Native backend tests
  cover mixed widths, partial/reordered batches and forged openings.

- `src/verifier/binary_poly_whir_multi_stark/coordinate.rs`: compose the existing
  product-bus and zerocheck verifier with coordinate-aware main and preprocessing
  PCS openings. The terminal AIR and bus equations authenticate the returned
  readings. The default entry point takes preprocessing commitments from trusted
  configuration. `verify_native_with_preprocessed` also accepts commitment targets
  authenticated by the enclosing circuit, using them in both the transcript and
  PCS verification. AIR metadata and proof shape remain fixed. The backend's
  `one_verifier_circuit_accepts_distinct_authenticated_preprocessing_keys` test
  verifies real proofs under two keys and rejects changed keys and statements.
  Native witness import shares the transcript reduction and checks its shape.
  Accept caller-supplied resource limits; the backend allows 320 total rounds
  because product GKR counts rounds across radix-four layers. At the supported
  height limit, GKR plus the other reductions need at most 304. Other limits,
  codeword guards and security parameters are unchanged.
- `src/verifier/binary_air.rs` and `binary_air/periodic.rs`: permit trusted periodic
  expressions in current-row bus payloads. Recognize exact row-address and
  wrapping-successor tables and evaluate their multilinear extensions with a
  carry recurrence. Other tables retain dense evaluation; identity encoding is
  unchanged. Differential tests cover Boolean/extension points, a million-row
  table and a corrupted table that must retain dense evaluation.
- `src/pcs/binary/tensor_native_poly.rs`: factor compile-time Boolean selectors
  outside the 192 Frobenius images in closing weights. Traverse the remaining
  prefix in reverse to share trailing row-coordinate products across openings.
  Boolean constants are fixed by every Frobenius map; multiplication order is
  immaterial. Successor carry terms retain their original calculation. Real
  mixed-table/successor proof tests check transcript agreement and forged
  openings. Proof encoding and protocol parameters are unchanged.

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

The coordinate verifier can open uniform 2–64-bit Poly64 columns at a fixed
multilinear suffix and recover each field value with one scaling factor.
The verifier key selects the encoding.

The binary coordinate verifier can open trusted preprocessing in fixed-width
digits. For digit width `k`, it authenticates each digit at the word-opening
point and combines the results using the Poly64 basis weights `X^(j*k)`.
The trusted preprocessing commitment fixes padding to zero. Main witness
columns continue to use their declared coordinate bounds.

The coordinate verifier accepts a trusted auxiliary table schedule on the main
WHIR commitment. The parent circuit supplies the additional points and checks
the returned auxiliary values. AIR and bus verification consume the original
arithmetic openings, and preprocessing continues from the joint PCS transcript.
