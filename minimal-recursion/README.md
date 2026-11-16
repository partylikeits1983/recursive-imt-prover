# Minimal Plonky3 recursion

Two independently generated Plonky3 child proofs are verified **inside one proved
Plonky3 circuit**. A fresh process verifies the resulting single proof using an
independently provisioned verifier and the expected public statement.

The leaf relation is deliberately tiny: `y = x² + x` over KoalaBear. The default
children prove `(3, 12)` and `(5, 30)`. The recursive proof binds the ordered
statement `[3, 12, 5, 30]`. All arithmetic is in the field, including wraparound.
This is actual proof verification, not a proof of a native verifier's Boolean.

This package is separate from the incomplete Spartan–WHIR/IMT experiment in the
parent directory. It has no dependency on Spartan–WHIR and makes no IMT, Ethereum,
note-privacy, or zero-knowledge claim. Both proof layers use non-hiding FRI.

## Run

From the repository root:

```sh
cargo run --locked --release -p minimal-recursion -- demo --out run/minimal-demo
cargo test --locked --release -p minimal-recursion
```

Use a new output directory on each run. The demo launches setup, proving, and final
verification in separate processes. Only the final proof is persisted; child
proofs exist in the proving process's memory. `metrics.json` records actual times
and sizes, with preprocessing reported separately. It is a single run, not a
statistical benchmark. Initial compilation is additional.

The same operations can be run separately:

```sh
cargo run --locked --release -p minimal-recursion -- setup --out run/minimal-trusted
cargo run --locked --release -p minimal-recursion -- prove \
  --trusted-dir run/minimal-trusted --out run/minimal-result --left 3 --right 5
cargo run --locked --release -p minimal-recursion -- verify \
  --trusted-dir run/minimal-trusted \
  --statement run/minimal-result/statement.json \
  --proof run/minimal-result/outer.proof
```

`verify` reads only `outer.verifier`, the statement JSON, and `outer.proof`.
The trusted directory must come from your setup, not from an untrusted prover.
Supply the statement you intend to verify; the example has no application state.
Setup uses `(7, 56)` and `(11, 132)` to provision verifier artifacts. Actual proofs
use other statements and must produce byte-identical verifier artifacts. This is
transparent preprocessing, with no trusted-setup secret. Keep the trusted artifact
files unchanged when proving new pairs.

For an explicitly low-security test run:

```sh
cargo run --locked --release -p minimal-recursion -- demo \
  --profile smoke --out run/minimal-smoke
```

## Reused components and parameters

No upstream modifications or new verifier gadgets. The package directly reuses:

- `CircuitBuilder` and `PreparedCircuitProver` for the leaf relation.
- `TrustedPreparedAggregation` for both complete recursive verifiers, fixed child
  preprocessing commitments, and authenticated public-statement concatenation.
- `FriRecursionBackendD5` and upstream Poseidon2/recomposition tables.
- `CircuitVerifier`, portable verifier/proof artifacts, bounded canonical decoding,
  and `PortableVerifier` for independent verification.

Plonky3-recursion is pinned to `3a69ba61f713c8400b14eb3d8f0e52caa13512c7`;
Plonky3 crates use `0.9.0-rc.2`. Rust `1.98.1` and the repository Cargo.lock are
required. The API pattern follows upstream's `portable_aggregation` example
(MIT OR Apache-2.0), with two polynomial-relation children and explicit profiles.

Both layers use KoalaBear `p = 2130706433`, the supported quintic extension,
Poseidon2 width 16/rate 8/eight-element digests, binary Merkle trees, cap height 0,
maximum log folding arity 2, and final polynomial log length 0.

| Setting | Default `reference` | Explicit `smoke` |
|---|---:|---:|
| Log blowup | 2 | 1 |
| FRI queries | 128 | 4 |
| Query grinding | 16 bits | 0 |
| Commit/batch grinding | 0 | 0 |
| Zero knowledge | No | No |

The reference profile does **not yet have a derived 116-bit composed security
bound**. A query count or extension size alone does not establish it. It needs the
actual AIR/lookup/opening dimensions, proven FRI bounds, and composition of both
children with the outer proof. Eight KoalaBear hash limbs have a generic classical
collision ceiling of about 124 bits; there is no quantum-security claim.
The smoke profile is intentionally weak, conspicuously labeled, and used only by
automated functional tests. No timing target automatically reduces parameters.

These are non-hiding proofs of public values, generated separately for different
inputs rather than copied from a fixture. There are no secret seeds or cryptographic
random masks in this example; independent generation does not imply ZK randomization.

## Tests and trust boundary

Tests cover real two-to-one proofs, reuse of one prepared outer circuit with new
inputs, all four outer public fields, ordered children, different child relations,
incorrect leaf arithmetic, malformed/truncated/trailing proof bytes, noncanonical
statements, and fresh-process verification. A separate test mutates recursive
circuit witness arrays after packing an honest proof, bypassing native verification.
The low-level circuit in that test is only a constraint test; production entry
points use the upstream trusted owner to retain verifier authority.

All 16 workspace integration tests pass (four new, twelve existing), along with
strict workspace Clippy and formatting. See [validation evidence](artifacts/verification.txt).

`src/lib.rs` contains the relation, profiles, and upstream integration; `src/main.rs`
contains only CLI orchestration, artifact I/O, and measurements. Full Spartan–WHIR
recursion, ZK, tree transitions, and larger batches remain separate work.

## Measured reference run

One cold run on Apple M2 Pro, macOS 15.2, 16 GiB RAM, four Rayon threads. This is
a functional measurement, not a median or a performance distribution:

| Stage | Time |
|---|---:|
| Independent setup: leaf preprocessing + calibration proofs + outer preprocessing | 446 ms |
| Actual child proving | 3.14 ms + 3.25 ms |
| Outer preparation in proving process | 413 ms |
| Outer trace generation and proving | 919 ms |
| Outer artifact decoding and verification | 23.3 ms |
| Entire demo, including setup and fresh verifier process, excluding compilation | 1.91 s |

Two child proof artifacts total **427,668 bytes**; the final proof is **735,548
bytes**, so this run does not compress them. The independently provisioned outer
verifier artifact is 390 bytes; the expected statement contains 16 canonical field
bytes, plus its JSON wrapper. Process-tree peak RSS reported by `/usr/bin/time -l`
was about 811 MiB. [Raw parameters and measurements](artifacts/reference-run.json)
and [execution log](artifacts/reference-run.log) are included.
