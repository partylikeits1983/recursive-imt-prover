# Dependency provenance

The `minimal-recursion` workspace member uses the same pinned Plonky3-recursion
revision, adds `p3-recursion` with its `parallel` feature, and exclusively uses the
official `0.9.0-rc.2` Plonky3 graph. It does not depend on the Spartan client or its
fork. Its trusted aggregation/artifact integration follows upstream's
`recursion/examples/portable_aggregation.rs` (MIT OR Apache-2.0). It uses the
supported quintic `FriRecursionBackendD5` with base-field Poseidon2 tables, complete
stock FRI recursive verification, and `TrustedPreparedAggregation`; it does not
reuse the older fork's incompatible WHIR protocol. No upstream changes are needed.

Inspected 2026-11-16. Cargo.lock is required with `--locked`.

| Component | Exact source |
|---|---|
| Spartan–WHIR | [ethereum/spartan-whir 14d6da4211eda59e65cfd0af5e2dcd89d523edc3](https://github.com/ethereum/spartan-whir/tree/14d6da4211eda59e65cfd0af5e2dcd89d523edc3) |
| Client Plonky3 | [Client-Side-Proving/Plonky3 458ef546a251ab4d9d73c453d24a414334786ca0](https://github.com/Client-Side-Proving/Plonky3/tree/458ef546a251ab4d9d73c453d24a414334786ca0), package version 0.6.0 |
| Circuit / circuit prover | [Plonky3-recursion 3a69ba61f713c8400b14eb3d8f0e52caa13512c7](https://github.com/Plonky3/Plonky3-recursion/tree/3a69ba61f713c8400b14eb3d8f0e52caa13512c7) |
| Outer Plonky3 | Registry crates exactly 0.9.0-rc.2; packaged source commit [fe5e46d755b8a7d9069778361e21b33e5978b377](https://github.com/Plonky3/Plonky3/tree/fe5e46d755b8a7d9069778361e21b33e5978b377), verified from `.cargo_vcs_info.json`; checksums in Cargo.lock |
| Official Plonky3 HEAD inspected | [0d803737b681774186cd283b1fd2d8e493655c82](https://github.com/Plonky3/Plonky3/tree/0d803737b681774186cd283b1fd2d8e493655c82); reference only, not substituted for the outer release |
| Rust | 1.98.1, edition 2024; rustfmt/clippy components pinned by rust-toolchain.toml |

## Compatibility decision

The two dependency graphs coexist. Client arithmetic imports `p3_field` from the
0.6 fork; outer arithmetic imports `p3_field_outer` from 0.9.0-rc.2. There is NO Cargo
patch replacing the fork with the official version. No unsafe cast, transmute,
shared serde type, or assumption that equal crate names imply protocol compatibility.
Base values cross by checked canonical u32 representatives. Application permutation
constants come from the client fork and are converted the same way. Quintic arithmetic
is independently expressed as five base wires modulo X^5+X^2-1 and differentially tested.

Native client proofs retain their original transcript, full-ZK PCS and SPARK types.
The partial transcript gadget is implemented against the CLIENT fork's
`challenger/src/duplex_challenger.rs`: overwrite buffered rate elements, zero remaining
rate on a nonempty absorb, add absorbed length to lane 8, permute, pop outputs in reverse
order. It is not the application additive sponge and is not a stock FRI challenger import.

No upstream files were changed. `src/r1cs.rs` adapts the small linear-combination
builder from Spartan `src/withdrawal.rs`; `gadgets/poseidon.rs` adapts its linear layers.
Native hashing directly calls `withdrawal::hash_fields`. Attribution is retained in
source. The Spartan checkout has no declared license file/manifest license at this
revision; inspect upstream licensing before redistributing derived code. Plonky3 and
recursion publish MIT/Apache-2.0 licenses.

## Relevant inspected APIs

- Spartan `poseidon.rs`: `PoseidonZkProvingKey::setup/prove`, restored-key
  `prepare_for_proving`, `PoseidonZkVerifyingKey::authenticate/verify`.
- `protocol.rs::verify_with_compression`, `sumcheck.rs::verify_outer_zk`,
  `spark.rs` product/leaf/opening checks, `security.rs` composition validation.
- `withdrawal/config.rs` explicit schedules. Local witness schedule increases
  starting log inverse rate from 1 to 2 and PoW ceiling from 7 to 22. Targets remain
  116 bits. The initial unchanged schedule failed hiding slack (256 > 240); rate 2
  with ceilings through 16 still failed (512 > 496). Ceiling 22 validated.
  This is explicit parameter selection, not a transcript or proof-format rewrite.
- Recursion `CircuitBuilder`, `set_statement_exports`, `prepare_circuit`,
  `PreparedCircuitProver::verifier`, and `CircuitVerifier::verify`.
- `inspect-client` and the pinned sumcheck component use the existing public
  verifier configuration exporter read-only. This reuses metadata derivation only;
  no VM guest, bytecode, or guest statement digest is generated.
- The shape-only `PreparedLayer` API is NOT used as verifier authority.
- Circuit proving uses supported FRI `config::koala_bear`, base-field ALU, Statement
  preprocessor/AIR/prover. No custom PCS, VM, ISA, or circuit frontend.

## Circuit compiler integration finding

Directly `connect`ing Public source wires to constants caused the pinned compiler to
assign multiple WitnessChecks creators to the same witness index. The generated proof
failed with `Lookup(TerminalSumNonZero)`; lookup debugging found the zero tuple had net
multiplicity 1176. Local public equalities now use `a+1 = b+1` ALU rows, preserving distinct
Public sources. The relation is unchanged and is covered by actual FRI proof tests.
No lookup constraint or verifier check was disabled. This finding is recorded locally;
no GitHub issue or other external text was posted.
