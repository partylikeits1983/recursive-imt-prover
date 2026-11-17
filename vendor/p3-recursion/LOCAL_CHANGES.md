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

The local copy is necessary because the upstream portable registry rejects
Johnson even though native WHIR supports it. Keep these changes explicit when
updating the dependency; do not silently replace Johnson with capacity bounds.
