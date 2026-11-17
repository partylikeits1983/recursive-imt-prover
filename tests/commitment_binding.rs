// Run the upstream regressions against the exact local dependency used by this PoC.
#[path = "../vendor/p3-recursion/tests/mmcs_leaf_hash_binding.rs"]
mod leaf_binding;
#[path = "../vendor/p3-recursion/tests/builtin_config_registry.rs"]
mod registry;
