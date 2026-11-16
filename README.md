# SHA3 preimage recursion PoC

Prove `SHA3-256(preimage) = digest` for independent 32-byte preimages, then
recursively verify **N actual Plonky3 proofs** and verify one final proof in a
fresh process. The final statement binds the complete ordered list of digests.

**This increment uses non-ZK FRI.** The preimage is a private circuit input, but
proofs may leak it. Private inputs alone do not establish zero knowledge. Do not
use real confidential preimages with this configuration.

## Run

Rust 1.98.1 and Cargo.lock are pinned. Run from this directory:

```sh
cargo run --locked --release -- demo --count 2 --out run/sha3-demo
cargo test --locked --release
```

Use a fresh output directory. `--count` supports 1 through 8, including odd sizes.
The count is fixed at setup, not chosen by proof-supplied metadata. Larger counts
need a resource assessment before raising the explicit limit.

The demo launches separate setup, client, aggregation, and verifier processes.
Each client generates a fresh OS-seeded random preimage. No preimage is written to
disk or passed to the aggregator. After aggregation, the demo removes its child
proof files before launching the final verifier. It preserves client timings,
trusted verifier artifacts, the public statement, final proof, and measurements.

For faster, explicitly low-security functional testing:

```sh
cargo run --locked --release -- demo --count 3 --profile smoke --out run/sha3-smoke
```

Run the stages separately when supplying your own **non-confidential test inputs**:

```sh
cargo run --locked --release -- setup --count 2 --out run/trusted
cargo run --locked --release -- client --trusted-dir run/trusted --out run/alice
cargo run --locked --release -- client --trusted-dir run/trusted --out run/bob
cargo run --locked --release -- aggregate --trusted-dir run/trusted \
  --out run/batch --children run/alice run/bob
cargo run --locked --release -- verify --trusted-dir run/trusted \
  --statement run/batch/statement.json --proof run/batch/outer.proof
```

`client --preimage-file FILE` optionally reads exactly 32 raw bytes. Only the
client process opens that file. Otherwise it generates a fresh preimage in memory.
The separate `aggregate` command retains caller-owned child files.

## Circuit and aggregation

The leaf circuit fixes a 32-byte message, applies standard SHA3-256 padding, and
uses the upstream constrained Keccak-f[1600] operation. The state is 100 little-endian
16-bit limbs: 16 private message limbs, suffix `0x06` at limb 16, `0x8000` at limb
67, and zeros elsewhere. The 136-byte rate and 64-byte capacity require one
permutation for this message length. All first 16 output limbs are bound to the
public digest. The Keccak AIR constrains limb bit decompositions and the permutation.

This is **SHA3-256**, not Ethereum's Keccak-256, which uses suffix `0x01`. Tests
check the distinction against a valid same-shape circuit using the other suffix.
Native digest computation uses RustCrypto `sha3`; it does not substitute for any
circuit check. Fixed vectors also match Python/OpenSSL `hashlib.sha3_256`.

Aggregation pairs adjacent nodes using `TrustedPreparedAggregation`, carries an
odd last node to the next level, and repeats until one proof remains. Each merge
verifies both complete child proofs and concatenates their authenticated statements.
For N=1, `TrustedPreparedLayer` still creates an actual recursive proof. For N>1,
there are N-1 merge proofs in the tree. Intermediate proofs are not needed by the
final verifier. This is a tree of fixed circuits, not arbitrary self-recursion or
one circuit whose arity changes after setup.

Statement JSON contains version 1, relation `sha3-256-preimage-32-bytes-v1`, and an
ordered array of lowercase 64-character digest strings. Every digest becomes 16
bounded little-endian u16 limbs, each encoded in a canonical four-byte KoalaBear
field word. The proof binds all 16N field elements. Counts, digest order, and the
relation are authenticated by the trusted verifier and strict statement decoding.
Duplicate digests are allowed: this proves a list of relations, not unique spends.

## Authority and parameters

Setup uses explicitly public deterministic calibration preimages, independently
of the actual clients, to provision the leaf and root verifier artifacts. The
aggregator imports children against the retained leaf authority and requires its
compiled root verifier to match the setup artifact byte-for-byte. A prover-supplied
key or a compatible proof shape cannot select another relation.

`verify` reads only the independently provisioned `outer.verifier`, the expected
statement, and one proof. Provision the trusted directory independently of the
prover, and supply the digest list you intend to verify. There is no application
state, replay protection, IMT, or Ethereum contract in this PoC.

Both layers use the supported KoalaBear quintic configuration, stock Poseidon2
transcripts/Merkle hashing, and FRI. The SHA3 application hash and Poseidon2 proof
hashes are separate. No upstream patches, custom PCS, or custom recursive verifier.

| Parameter | Default `reference` | Explicit `smoke` |
|---|---:|---:|
| KoalaBear modulus | 2130706433 | same |
| Challenge extension | quintic | same |
| Log blowup | 2 | 1 |
| FRI queries | 128 | 4 |
| Query grinding | 16 bits | 0 |
| Commit/batch grinding | 0 | 0 |
| Max log folding arity | 2 | 2 |
| Final polynomial log length | 0 | 0 |
| Merkle cap height | 0 | 0 |
| Proof Poseidon2 width/rate/digest limbs | 16 / 8 / 8 | same |
| Zero knowledge | **No** | **No** |

The reference configuration has **no derived 116-bit composed security bound yet**.
Its bound must include the actual AIR/lookup/opening dimensions and every proof
layer. A query count, extension size, or SHA3 digest length alone does not establish
it. Eight KoalaBear proof-hash limbs have a generic classical collision ceiling of
about 124 bits. No quantum-security level is claimed. Smoke settings are deliberately
weak and never selected automatically to meet a timing target.

## Measurements

Five reference-profile runs after one warmup, N=2, Apple M2 Pro, 16 GiB RAM,
macOS 15.2, four Rayon threads. Each run starts fresh processes and includes cold
circuit preparation; no prepared prover is retained between runs.

| Measurement | Median | Range |
|---|---:|---:|
| Full demo, including setup | 23.12 s | 22.70–25.33 s |
| Setup, including calibration proofs | 11.53 s | 10.86–11.59 s |
| Client proving, ten client samples | 18.07 ms | 14.73–24.22 ms |
| Aggregation, including preparation and checks | 11.73 s | 10.96–13.57 s |
| Outer preparation | 3.35 s | 3.23–3.52 s |
| Outer proving, including trace generation | 8.12 s | 7.41–9.83 s |
| Final proof verification, including decoding | 27.39 ms | 27.05–28.46 ms |
| Two serialized child proofs | 4,227,446 bytes | 4,226,582–4,227,958 |
| Serialized final proof | 964,860 bytes | 954,396–970,428 |

Darwin `/usr/bin/time -l` reported peak RSS of 3.97–4.93 GiB across full runs.
This is not a separate memory measurement for each stage. Final-proof bytes are
smaller in these measurements; no proving-speedup claim is made. Reference timings
for larger batches have not been measured. N=1/2/3/4/8 pass functional tests under
the explicitly low-security smoke profile.

[Raw samples and environment](artifacts/sha3-reference.json) include setup and
client measurements, parameters, compiler/source identifiers, and the command to
repeat with fresh output directories. These are cold-preparation measurements
after warmup, not warm/preprocessed-prover benchmarks.

## Source and validation

- `src/lib.rs`: SHA3 leaf, statements, pinned profiles, trusted recursive aggregation.
- `src/main.rs`: process orchestration, bounded artifact I/O, measurements.
- `tests/`: hash vectors, incorrect preimages/digests, alternate padding/key,
  malformed recursive witnesses, N=1/2/3/4/8, changed order/count, corrupted proofs,
  and fresh-process verification without child files.

Plonky3-recursion is pinned to
[`3a69ba61f713c8400b14eb3d8f0e52caa13512c7`](https://github.com/Plonky3/Plonky3-recursion/tree/3a69ba61f713c8400b14eb3d8f0e52caa13512c7).
Plonky3 crates use `0.9.0-rc.2`, packaged source
[`fe5e46d755b8a7d9069778361e21b33e5978b377`](https://github.com/Plonky3/Plonky3/tree/fe5e46d755b8a7d9069778361e21b33e5978b377).
The integration follows upstream `portable_aggregation` and hash-table recursion
examples, licensed MIT OR Apache-2.0. Keccak-f AIR, FRI verifier gadgets, trusted
owners, statement export, and portable proof/verifier codecs are reused directly.

The superseded Spartan/IMT experiment, arithmetic demo, reports, and unused
research checkouts were removed from the working tree. They remain recoverable
from local Git checkpoint `c71976c`. No forked Spartan dependencies remain.
