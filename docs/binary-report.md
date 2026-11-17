# Native binary Keccak aggregation: research report

## Outcome

The correctness baseline works: independent Keccak IMT membership proofs over
BinaryField128 can be verified inside one fixed binary circuit, aggregated into
one serialized proof, and verified in a new process without any child proofs.
Depths 8, 16 and 32 work. Fixed batches of 1, 2 and 4 were proved; larger tested
batches hit explicit resource limits. The original prime-field PoC is retained.

**The binary children are not ZK. The final acceptance criterion is not met.**
The precise missing supported construction and two implementation routes are
documented in [binary-security.md](binary-security.md). The outer proof may stay
non-ZK once child privacy is implemented.

## Reproducibility

Measurements were made on an Apple M2 Pro with 16 GiB RAM, macOS Darwin 24.2.0,
Rust 1.98.1 / LLVM 22.1.8, release profile, thin LTO, 16 codegen units, no extra
RUSTFLAGS, and **12 Rayon threads**. Normal `cargo run` commands in this repo
default to four threads through `.cargo/config.toml`; set `RAYON_NUM_THREADS=12`
to reproduce the matrix. The earlier `binary-first` smoke run used four threads
and a lower PCS target; it is not part of the comparison below.

The selected dependencies and exact upstream revisions are pinned in Cargo.lock
and listed in the README. Raw reports contain the compiled source fingerprint.
The reports were collected before subsequent CLI diagnostics/summary improvements;
the proving relation and default protocol parameters are unchanged.

```sh
python3 scripts/bench-binary.py --out run/binary-matrix --threads 12 --samples 3
```

The script compiles before measurement, runs cases sequentially, retains failed
cases, and returns a nonzero status if any case fails. It never silently changes
security parameters or falls back to a different proof system.

Each case has one first-proof sample after setup and two warm samples reusing
setup. This is not a cold OS page-cache experiment. Tables below report warm
medians and observed ranges. Two warm samples are insufficient for tight
statistical conclusions. Fixtures, each child witness/prove/verify/encoding,
aggregation, and fresh verification are separately recorded. Encoding currently
performs another native verification because the upstream encoder requires it.
Aggregation wall time includes child decoding/native prechecks, witness work,
proving, output verification and verified encoding. A further decoded outer
verification is timed separately. Critical-path latency also includes fixtures,
sequential client work and output I/O; it excludes setup and the final fresh
process, whose costs are separately reported.

RSS is `getrusage` lifetime process high-water memory, cumulative across setup,
proofs and samples. The child-only matrix isolates the client process workload;
the aggregation process includes retained child keys. These are not allocator
profiles or independent per-stage peaks.

All tables in the next two sections use the same low-security settings:
Johnson bound, PCS target 32 bits, no grinding, dense rate 1/2, packed rate 1/8,
log fold 4. The depth-8 child model reports 29.72 bits and its aggregate model
about 29.19 bits **before recursive composition**. These are not 128-bit results.

## Client measurements

Values pool the 32 warm child proofs from the N=16 child-only case at each depth.
Proof sizes use decimal KB; RAM is the entire child-only process high-water mark.

| Depth | Prove median (range), ms | Native verify median, ms | Proof bytes, range | Peak RAM |
|---|---:|---:|---:|---:|
| 8 | 69.72 (64.06–83.93) | 18.89 | 242,699–244,491 | 230 MiB |
| 16 | 97.55 (84.15–127.41) | 18.61 | 250,699–252,363 | 340 MiB |
| 32 | 172.46 (143.86–247.10) | 19.21 | 268,351–270,911 | 486 MiB |

Client witness generation is usually below a few milliseconds; full raw timings
are retained. All depths were also measured with N=1, 2, 4 and 8. This establishes
fast **non-hiding** membership proving, not fast private membership proving.

## Fixed-batch aggregation

Depth 8, with one complete child verifier per slot:

| N | Setup, s | Aggregation wall median (range), s | Outer verify median (range), ms | Proof bytes, range | Peak RAM |
|---|---:|---:|---:|---:|---:|
| 1 | 0.538 | 4.119 (4.097–4.141) | 22.37 (22.19–22.56) | 343,583–344,895 | 4.25 GiB |
| 2 | 1.042 | 9.554 (9.426–9.681) | 40.15 (23.59–56.71) | 360,687–361,199 | 4.59 GiB |
| 4 | 2.366 | 22.595 (22.489–22.701) | 24.27 (23.97–24.57) | 382,787–383,427 | 6.39 GiB |
| 8 | failed | 536,870,912 initial codeword cells exceed 134,217,728 budget | — | — | 1.96 GiB at rejection |
| 16 | failed | 14,180,366 witnesses exceed 8,388,608 limit | — | — | 3.88 GiB at rejection |

N=4 explicitly raised the codeword budget to 268,435,456. N=8 would require
8 GiB just for the initial 16-byte field cells, before Merkle trees, graph,
proving buffers and other application memory. We did not run that proving
allocation on this 16 GiB machine. These are configured resource failures, not
cryptographic impossibility results.

First aggregation wall times were 4.320, 10.027 and 24.052 seconds for N=1/2/4.
Warm end-to-end critical-path medians were 4.257, 9.822 and 23.118 seconds.
This corresponds to roughly 0.235, 0.204 and 0.173 children/second with sequential
clients. It does not meet the two-proof aggregation target of three seconds.

At depth 16, N=2 aggregation wall was 9.757 s (9.674–9.840), with 22.24 ms
warm outer verification. At depth 32 it was 9.356 s (9.203–9.509), with 29.12 ms
outer verification. Small timing differences between depths are within the
observed run-to-run variability; the larger statements do not prove faster as a
general rule.

Fresh process verification passed for every completed aggregate case. At depth 8,
the final verifier's decode+verify times for N=1/2/4 were 21.48/21.90/24.67 ms,
but process wall times were **0.726/1.381/3.465 seconds** because trusted authority
reconstruction is not yet cached or serialized in a portable native snapshot.
Thus the current cold verifier is materially more expensive than the warm
cryptographic verifier. Its data consists only of the aggregate proof, ordered
statement and trusted configuration/authority identities.

## Separate higher-security experiment

With an 80-bit PCS target, a 16-bit WHIR grinding ceiling and a 64-bit minimum
per-authority floor, depth-8 N=2 completed all three samples and fresh-process
verification. Upstream reported **77.08 bits for the child and 75.20 for the
outer authority**, before recursive composition. This remains below the
requested 128-bit goal and remains non-ZK.

Warm child proving was 90.69 ms (86.83–95.63), and native child verification was
20.85 ms. Aggregation wall was **13.786 s** (13.537–14.035), including 13.523 s
of proving. Decoded outer verification was **26.17 ms** (25.22–27.12). Proofs
were 622,975–623,775 bytes. Setup cost 2.422 s, peak process RSS was 5.20 GiB,
and fresh verification wall time was 2.542 s, of which 26.58 ms was decoding and
proof verification. These measurements have different security parameters and
are intentionally separate from the 32-bit PCS table.

```sh
RAYON_NUM_THREADS=12 cargo run --locked --release --bin bench -- \
  --batch-size 2 --pcs-bits 80 --pow-bits 16 --min-security-bits 64 \
  --max-codeword-cells 268435456 --out run/binary-higher-security
```

## What dominates and what to optimize

One depth-8 membership circuit has 18,174 witness cells. Verifying one child
inside an aggregate requires 890,471; two require 1,776,464. The proof verifier,
including its commitment and transcript Keccak operations, is much larger than
the application relation.

For N=2, median aggregate witness work was 74 ms while outer proof generation
was 9.390 s. Proving dominates circuit construction and trace execution. We have
not separately instrumented Keccak-table proving, WHIR encoding/openings and
zerocheck inside upstream; attribution among those requires a profiler. Calling
this solely a Keccak bottleneck would overstate the evidence.

Priorities:

1. Establish a complete child ZK construction and a supported recursive verifier
   for it before drawing conclusions about private-transaction latency.
2. Reduce recursive commitment/transcript work and product-bus/preprocessing
   geometry. Packed Keccak tables and four-way commitment trees are already used.
3. Export verification-only native authority snapshots so cold verification does
   not reconstruct proving graphs and preprocessing keys.
4. Profile outer proof generation and evaluate the newer upstream memory/encoding
   optimizations under the same parameters. Consider shared preprocessing checks
   or batched openings only with a complete soundness analysis.
5. Evaluate a larger binary challenge field for the 128-bit target. Merely
   increasing the query count cannot remove the current algebraic limits.

## Remaining research questions

**Fixed batch versus recursion tree:** the implementation measures fixed batches.
It reproduces the upstream one-layer native recursion example, but that toy
relation is not an IMT aggregation tree and is not a fair timing comparator.
An aggregation tree for this relation is not implemented, so there is no measured
winner. Fixed-batch limits justify that next experiment. Larger batches currently
have native child-verification measurements instead; these are not advertised
as aggregate proofs.

**Smallest aggregate:** among measured default-parameter depth-8 aggregates, the
smallest is 343,583 bytes for N=1; N=2 is at least 360,687 bytes. This is an
observed minimum, not a proof-size optimum. Smaller low-security smoke proofs
are deliberately excluded. There is no measured 128-bit ZK aggregate size.

**Security parameter failures:** an 80-bit PCS target with zero grinding built a
child authority but failed for the larger recursive geometry. A direct upstream
parameter probe identified `PowBitsExceedBudget`: for example, 23 variables at
packed rate 1/8 require three grinding bits. At target 128, even a 16-variable
rate-1/2 instance requires 36 grinding bits. These immediate WHIR configuration
failures are distinct from the native bus/constraint bounds below 128 bits.
Raw diagnostics are retained. `--pow-bits` now exposes a ceiling up to 16 bits
without silently changing the requested parameters.

**Low-latency private transactions:** not established. Non-ZK clients are fast,
but aggregation already misses the latency targets, and private children remain
unfinished. A persistent verifier can check the current outer proof in tens of
milliseconds. That is promising for native verification but does not establish
the complete privacy protocol's performance or security.

**Ethereum:** no implementation was attempted. A native binary/WHIR verifier
would need canonical transcript/statement encoding, carryless binary-field
arithmetic and reductions, Keccak commitment checks, sumcheck/WHIR verification,
strict resource bounds and a gas/calldata benchmark. Ethereum's Keccak support
helps hashing, but does not automatically make GF(2^128) arithmetic cheap.
The complete ordered public vector has O(N) calldata/processing cost regardless
of proof compression. The current roughly 360–383 KB aggregate proofs also
make calldata significant. Pairing wrappers are excluded from this selected
path, as requested. A smaller proof and a sound ZK child pipeline should precede
work on an Ethereum verifier.

## Raw results and correctness checks

[Raw JSON and diagnostic logs](../benchmarks/binary/raw/) include all client
depth/count cases, completed aggregate cases, resource-limit failures, the
upstream example and the newer ZK reference result. The full source of the
measurement driver is [bench-binary.py](../scripts/bench-binary.py).

Negative tests cover secret, nonce, amount, path, index, root, noncanonical amount
bytes, non-Boolean path bits, malformed/corrupted child and aggregate proofs,
swapped/removed/inserted statements, foreign authorities, tampered Keccak trace
data and changed recursive private proof inputs. Different roots and repeated
valid statements pass. Fresh-process verification and trust-identity rejection
are tested. Full ZK and 128-bit security are explicitly not test claims.

The full release suite passed 37 tests, including the retained prime-field
suite. The five binary tests were rerun after the CLI/security-parameter changes.
Formatting, Clippy with warnings denied, and `git diff --check` also passed.
