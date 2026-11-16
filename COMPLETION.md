# Truthful completion checklist

This checklist concerns the original Spartan–WHIR/IMT task. The later requested
[minimal Plonky3 recursion demo](minimal-recursion/README.md) is a separate working
two-child recursive proof pipeline for a simple polynomial relation.

**Overall: INCOMPLETE. No accepted batch authorization or successful state application.**

- [x] Rust repository, pinned toolchain, exact upstream provenance, Cargo.lock.
- [x] Sparse binary incremental Merkle tree, parameterized through depth 32.
- [x] Eight-limb commitments, secrets and randomness; fixed context; nullifier independence.
- [x] Pinned Poseidon2 application profile, native/R1CS/P3 arithmetic and test vectors.
- [x] Real full-ZK quintic Spartan–WHIR SPARK client relation and randomized proofs.
- [x] Native public-input/key binding and adversarial proof tests.
- [x] Fixed Plonky3 history/append circuit with full-digest selection and inequality.
- [x] Bounded count arithmetic, sequential empty-leaf paths, capacity checks.
- [x] Transparent FRI proof of that **transition-only** circuit.
- [x] Independent-process transition-diagnostic verification without child proofs.
- [x] Client workers receive witnesses only through pipes; aggregator receives no secrets.
- [x] Quintic arithmetic and field-observe/sample Fiat–Shamir gadgets differentially tested.
- [x] Full-ZK outer sumcheck component tested on an actual native proof, with an authenticated-key initial transcript and bound child public fields.
- [x] Replacement notes proved using the same client key against reference historical roots.
- [x] Failed authorization attempts preserve state; untrusted history/spent/replay prechecks.
- [x] Five measured component samples after warmup, raw JSON/CSV and median/range report.
- [ ] Complete authenticated Spartan–WHIR recursive relation (see BLOCKERS.md).
- [ ] In-circuit inner sumcheck, SPARK matrix closing and every hiding/plain-WHIR check.
- [ ] In-circuit grinding/query rejection and complete canonical proof-boundary handling.
- [ ] BOTH actual client proofs verified inside one proved fixed outer circuit.
- [ ] Complete independently provisioned outer authorization verifier artifact.
- [ ] Successful atomic verify-and-apply, persisted nullifiers/history and second accepted batch.
- [ ] In-circuit malicious PCS/SPARK/grinding/different-key differential suite.
- [ ] Complete-system benchmark, actual parallel critical path, aggregate-only latency.
- [ ] Per-phase memory, per-component recursive operation/proving cost breakdown.
- [ ] Supported complete configurations at depths 4/8/16/32.
- [ ] Derived full composed soundness budget; 128-bit or quantum security claim.

## Adversarial coverage boundary

| Case | Evidence currently available |
|---|---|
| Wrong secret/path/index/root/output | Direct client R1CS assignment tests, all public coordinates mutated |
| Invalid child proof/public input/key/encoding | Actual native proofs; not full recursive rejection |
| Transcript and sumcheck corruption | Native verifier and actual outer-sumcheck component injection |
| PCS/SPARK/PoW corruption | Native only; recursive coverage missing |
| Root outside history / chosen history | Transition circuit / trusted-state precheck respectively |
| Duplicate nullifier | Transition circuit and state precheck |
| Cross-batch reuse/replay/competing old state | State prechecks; successful application still disabled |
| Wrong append index/nonempty overwrite/stale second path/root/count/overflow | Direct transition assignments and independent dense tree comparison |
| Non-Boolean selectors / multi-limb count encodings | Direct malformed circuit inputs without host preflight |
| Different outer program / mutated final proof or public statement | Retained fixed transition verifier tests; complete authorization program absent |
| Failure changes state | Rejection tests and CLI state-file comparison |

No unchecked item is silently replaced by a mock/native Boolean or by re-proving
client secrets in the outer circuit. The provided default demo/verify/bench interfaces
refuse to describe partial results as successful recursion.
