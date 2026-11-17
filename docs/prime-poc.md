# Archived prime-field PoC

This archived implementation is built only with `--features legacy-prime`.
The active binary work is described in the [main README](../README.md).

A native PoC: users prove knowledge of private notes in an incremental Merkle
tree, and an aggregator combines N hiding proofs into one recursive proof.
The final verifier receives only that proof, the public statement and trusted
verifier configuration. There is no on-chain verifier.

## What is proved

```text
leaf = SHA3-256(secret[32] || nullifier[32] || amount_u64_le)
leaf belongs to the depth-32 IMT with public root R
public claim = (R, amount)
aggregate statement = { roots: [R0, ...], amounts: [amount0, ...] }
```

The secret, nullifier, leaf index and membership path remain private. The amount
is constrained to the value inside the leaf hash. Roots and amounts retain their
order and duplicates; matching vector positions belong to the same user.

The default example adds 128 existing commitments, appends the users' notes, then
adds 8 unrelated commitments before generating paths. Thus the proofs use a
later root, not each user's insertion root. `--historical` adds 8 commitments
before taking each user's path, producing distinct later roots of the same tree.

Children use hiding FRI with masked polynomials, four random codewords and four
salt elements per commitment leaf, seeded by independent CSPRNGs. The aggregate uses
non-hiding WHIR over KoalaBear: it receives already-hiding child proofs and public claims, never
private notes or paths. It does not hide child proofs or public data; note privacy
relies on the child proof system and recursive composition. The private field
named `nullifier` is a commitment input here; replay prevention is not implemented.

Binary-field WHIR recursion currently lacks hiding child support in the pinned
upstream backend. This archived path uses hiding children and prime-field WHIR aggregation.
Regenerate trusted setup after switching from the earlier FRI aggregate backend.

## Run

Requires the pinned Rust toolchain; dependencies and their revisions are locked.
Use fresh output directories.

```sh
cargo run --locked --release --features legacy-prime --bin recursive-imt-prover -- demo --count 2 --amounts 100,200 --out run/two-users
cargo run --locked --release --features legacy-prime --bin recursive-imt-prover -- demo --count 8 --historical --out run/eight-users
```

`--count N` means **N user proofs → one aggregate proof**. Supported counts are
1–64, including odd counts. Depth defaults to 32; `--depth`, `--prefill`, and
`--append-after` configure the tree. `--amounts` accepts one u64 per user;
omitting it gives 100, 200, … . Secrets and nullifiers are independently random
32-byte values, represented as lowercase hex in private input JSON.

The demo deletes private input files before aggregation and child proof files
before final verification. It retains public statements, the outer proof,
trusted verifiers, tree history counts, and timings under `run/`.

Individual stages are also available:

```sh
cargo run --locked --release --features legacy-prime --bin recursive-imt-prover -- setup --count 2 --out run/trusted
cargo run --locked --release --features legacy-prime --bin recursive-imt-prover -- fixtures --count 2 --amounts 100,200 --out run/inputs
for i in 0 1; do
  cargo run --locked --release --features legacy-prime --bin recursive-imt-prover -- client --trusted-dir run/trusted \
    --witness run/inputs/client-$i.json --out run/client-$i
done
cargo run --locked --release --features legacy-prime --bin recursive-imt-prover -- aggregate --trusted-dir run/trusted \
  --children run/client-0 run/client-1 --out run/batch
cargo run --locked --release --features legacy-prime --bin recursive-imt-prover -- verify --trusted-dir run/trusted \
  --statement run/batch/statement.json --proof run/batch/outer.proof \
  --allowed-roots run/inputs/allowed-roots.json
```

These commands retain caller-owned input files. In an application, trusted
verifiers and accepted roots must be provisioned independently of the prover.

## Benchmark

```sh
cargo run --locked --release --features legacy-prime --bin recursive-imt-prover -- benchmark --count 2 --samples 1 --out run/bench-two
cargo run --locked --release --features legacy-prime --bin recursive-imt-prover -- benchmark --counts 1,2,4,8 --samples 3 \
  --historical --out run/benchmark
```

Setup runs once per batch size. Each measured sample uses fresh notes and
separate, sequential client, aggregator and verifier processes. Aggregation
circuit preparation is included in every sample; setup is reported separately.
Within a batch, all child pairs reuse one prepared verifier circuit.
The CLI prints proving and verification time for **each child**, followed by
aggregation preparation, proving, and aggregate verification. Child trace
generation is timed separately; recursive proving includes trace generation.
Aggregate verification includes proof/verifier decoding. Process wall times also
include startup and file I/O. No warmup samples are discarded.

`report.json` records every sample, min/median/max/mean, protocol parameters,
hardware, thread count and a hash of the compiled sources. `children.csv` has every
child's timings; `summary.csv` contains batch medians. Four Rayon threads are the
default; set `RAYON_NUM_THREADS` to override.

The default `reference` profile uses rate 1/4, 128 FRI queries and 16 query-grinding
bits for children. Child reports use Plonky3's **proven
Johnson regime**, including the characteristic-independent improvement in
[DKT26](https://eprint.iacr.org/2026/2056), with the actual AIR, hiding overhead and
batched openings. The analyzed radius stays inside Johnson; no
beyond-Johnson or random-words conjecture is assumed. The report gives the binding
term and per-child round-by-round bound, not a 128-bit security claim.
At depth 32 this model gives 88.8 bits, limited by batched openings.
WHIR aggregates use the **proven Johnson bound**, a target of 88 bits per error term,
rate 1/4, folding factor 4 and at most 16 grinding bits.
No capacity-bound conjecture is selected. `report.json` records both
the child FRI and outer WHIR parameters.
`--profile smoke` uses 4 child queries, an 8-bit WHIR target and no grinding.
This PoC has no established composed security-bit bound.

The [local dependency changes](../vendor/p3-recursion/LOCAL_CHANGES.md) expose Johnson
in the portable WHIR registry and apply the upstream salted-commitment binding fix.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --release --features legacy-prime --test legacy
```

`note` and `statement` define the relation and public encodings; `tree` and
`scenario` build membership inputs; `air` constrains hashes and amounts;
`client`, `aggregation` and `verification` implement proving; `cli` handles files,
processes and measurements. Imports stay at module scope and types precede
implementations. Comments explain protocol invariants.

The leaf message is 72 bytes. Internal nodes hash `"IM" || left[32] || right[32]`;
empty leaves are zero digests. Each claim encodes a root as 16 little-endian u16
limbs and its amount as 4 more, lifted to KoalaBear. Claims are concatenated in
user order. Version-4 statements and trusted setup are incompatible with the
previous preimage-only relation; regenerate setup when changing the relation.
