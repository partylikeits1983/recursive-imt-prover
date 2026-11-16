# Last working milestone and exact remaining verifier work

The last working cryptographic paths are:

1. Note witness → full-ZK quintic SPARK proof → pinned native verification, with
   independent clients, replacement authorization and replacement-note key reuse.
2. Two-leaf append/root-history statement → fixed Plonky3 circuit → FRI proof →
   independent retained/rebuilt verifier, with no children at verification time.
3. Actual native proof outer-sumcheck data → a constrained degree-seven full-ZK
   outer-sumcheck component, including derived challenges and final equation.
   Both a raw-prefix differential harness and a prefix fixed from an authenticated
   client key are implemented; altered child public fields reject.

These paths are NOT joined into a sound recursive verifier. The hard blocker is the
missing constraint implementation corresponding to
`spartan-whir/src/protocol.rs::PoseidonZkSpartanProtocolFor::verify_with_compression`
at the exact revision in UPSTREAM.md (roughly lines 2354–2611).

| Native verifier relation/API | Circuit status |
|---|---|
| Fixed key authentication, canonical shape, mode, public input binding | Native only; full circuit key/config pinning missing |
| `observe_poseidon_zk_context`, committed mask shape separator, commitment absorption | Field challenger and fixed-key prefix implemented; later protocol operations missing |
| `verify_outer_zk` degree-seven replay and final equality | Component implemented; no rejection-resampling shape beyond zero retries |
| `p3_sumcheck::zk::ZkVerifier::verify_claim` | Missing masked inner sumcheck, eps/handoff/carry equations |
| `application_relation`, mask covectors, public-half evaluation | Missing |
| `validate_spark_fixed_commitments`, `parse_spark_table_openings` | Missing exact fixed-table commitments and branched transcript reconstruction |
| `verify_spark_batched_memory_product_claims_with_metadata` | Missing layered product sumchecks and tuple compression |
| `finalize_spark_table_openings`, `verify_spark_batched_memory_leaf_claims_with_openings` | Missing plain WHIR openings and table/leaf consistency |
| `HidingWhirVerifier::verify_relation` | Missing carried/application/sumcheck mask groups, code switches, OOD checks, final blinded base-case relation |
| WHIR `sample_uniform_bits`, sample bits, rejection witnesses, PoW | Missing canonical bit decomposition, retry shape and every grinding check |
| WHIR Merkle multiproofs/query authentication | Missing; ordinary application Merkle hashing does not satisfy this relation |
| `verify_and_apply` success / atomic persistence | Disabled until an authoritative complete outer verifier exists |

Full-ZK key fields and helper builders such as `build_poseidon_full_zk_pcs`,
`observe_poseidon_zk_context`, `observe_poseidon_relation_domain_separator` are
`pub(crate)` in upstream. Existing public configuration exporters in
`leanvm_full_zk.rs` show the verifier-facing data but are not a circuit gadget.
The existing public configuration exporter is now used read-only by
`build_pinned_component` to fix the initial context and relation separator without
proof-supplied metadata. `inspect-client` exports the complete derived descriptor
for review (including schedules, mask shapes, SPARK metadata and caps). The next
step is constraining the remaining protocol against this descriptor. Do not patch upstream verifier visibility by making witness-supplied
metadata authoritative. No LeanVM guest/ISA has been introduced here.

Then implement the inner sumcheck and SPARK/WHIR routines over the existing base-wire
quintic and exact transcript gadgets, with bounded supported shapes. Inversion must
remain constrained; uniform-bit queries need canonical base-field decomposition,
not modular truncation. The current no-resampling component must fail closed for
unsupported retries, or be extended with explicit bounded rejection conditions.
Do not mark the two-proof path complete until EVERY native rejection category has
an in-circuit witness-injection test and an independently verified outer proof.

This is substantial missing cryptographic work, not an unavailable external service
or a user approval problem. No VM, native-verifier Boolean, or alternative client
system was substituted. Batch size 4/8, outer WHIR, Lean specification and Ethereum
verification remain deferred as requested.
