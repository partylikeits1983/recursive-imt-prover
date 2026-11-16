# recursive-imt-poc

**Working minimal recursion demo:** [minimal-recursion](minimal-recursion/README.md)
verifies two actual Plonky3 child proofs inside one Plonky3 circuit, then verifies
the outer proof in a fresh process. Run:

```sh
cargo run --locked --release -p minimal-recursion -- demo --out run/minimal-demo
```

The original **Spartan–WHIR/IMT research prototype remains incomplete**. The material
below describes that original experiment; it has no end-to-end recursive authorization
proof yet. The minimal demo proves a separate polynomial relation, with non-ZK FRI.

Working milestones: real, independently randomized full-ZK Spartan–WHIR/SPARK clients;
a sparse incremental Merkle tree; a fixed Plonky3 circuit proving the two-leaf append and
root-history relation; and independently checked quintic, transcript and full-ZK outer
sumcheck gadgets. The transition proof does **not** verify the client proofs. Native
client verification is a diagnostic prefilter, never a substitute for recursion.

`prove_batch` and `verify_and_apply` fail closed. No executable accepts a transition-only
proof as authorization or writes a new trusted state. See [the completion checklist](COMPLETION.md)
and [the exact missing verifier relations](BLOCKERS.md).

## Run

Rust 1.98.1, exact git revisions and Cargo.lock are pinned. Network access is needed
on the first build. The ignored `upstream/` research checkouts are not build dependencies.

```sh
cargo build --locked --release --bins
cargo test --locked --release
# Generates actual clients, then exits with the missing-recursive-verifier error:
cargo run --locked --release --bin demo -- --depth 8 --out run/incomplete-demo

# Explicitly run the available milestones, including a fresh-process FRI verification:
cargo run --locked --release --bin demo -- --depth 8 \
  --diagnostic-transition-only --out run/diagnostic-demo
# Different historical membership roots of the same reference tree:
cargo run --locked --release --bin demo -- --depth 8 --historical-roots \
  --diagnostic-transition-only --out run/historical-demo

# Always rejects until the full recursive authorization verifier is implemented:
cargo run --locked --release --bin verify -- \
  --state run/diagnostic-demo/state.json \
  --statement run/diagnostic-demo/statement.json \
  --proof run/diagnostic-demo/transition-diagnostic.bin

# Explicit diagnostic verification, leaves state unchanged:
cargo run --locked --release --bin verify -- \
  --state run/diagnostic-demo/state.json \
  --statement run/diagnostic-demo/statement.json \
  --proof run/diagnostic-demo/transition-diagnostic.bin --diagnostic-transition-only

# Component diagnostics, NOT an aggregation benchmark:
cargo run --locked --release --bin bench -- --depth 8 --samples 5 --diagnostic-components
python3 scripts/report.py artifacts/components-depth8.json
```

Use a fresh output directory for each demo. `scripts/reproduce.sh` runs the positive
milestones and checks that ordinary verification fails without changing state.
Client witnesses are sent to separate worker processes through stdin, never saved as
files. The aggregation process gets proofs, public statements and public append paths.
The verification process reads only state, statement and one transition diagnostic.
There is no OS sandbox or protection against privileged process-memory inspection.

## Layout

- `primitives`, `gadgets/poseidon`: the pinned application hash and shared circuit arithmetic.
- `tree`, `statement`, `state`: sparse IMT, canonical statement layout, state prechecks.
- `r1cs`, `client`: note relation, OS-random notes and actual full-ZK SPARK proofs.
- `gadgets/quintic`, `transcript`, `outer_sumcheck`: partial recursive verifier components.
- `outer`: fixed append/history circuit and FRI circuit prover; complete batch entry fails closed.
- `bin`: client worker, demo orchestrator, public-only aggregator, verifier, diagnostic measurements.
- `tests`: direct malformed assignments, native proof mutations, retained-verifier tests.

The client target is **116 composed bits under upstream classical assumptions**, using
Johnson bounds, not 128 bits. There is no claimed security level for a complete composition.
[SECURITY.md](SECURITY.md) explains the hash limit, hiding parameters, FRI configuration,
quantum assumptions and missing checks. No Ethereum deployment or gas estimate is included.

Validation: 12 release tests, `cargo fmt -- --check`, strict Clippy, and the same-root/
historical-root reproduction script pass. See [measured component costs](artifacts/components-depth8.md)
and [verification evidence](artifacts/verification.txt). These results do not establish
recursive authorization, which remains incomplete.
