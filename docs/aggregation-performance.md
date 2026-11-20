# Under three minutes for 64 prepared children

Measure from reading 64 saved depth-32 record proofs and their ordered statement
to independent verification of one root on the 12-core, 16 GB M2 Pro. The
acceptance threshold is strictly below 180 seconds. Record cold wall time
including key preparation as a second result. One minute remains a stretch goal.

## Native prover review on the M2 Pro

| 64 saved children, in measurement order | Prepared through fresh verification | Including key setup | Peak process RSS |
| --- | ---: | ---: | ---: |
| Previous packed build | 469.21 s | 486.86 s | 5.86 GiB |
| Packed first fold and witness reservation | 474.01 s | 492.59 s | 5.94 GiB |
| First fold, row reuse and shared WHIR tables | 409.81 s | 426.12 s | 6.43 GiB |
| Previous packed build, repeated | 398.91 s | 417.12 s | 6.25 GiB |

Each full replay used 12 Rayon threads and two concurrent parents on AC power.
All four produced the same 948,828-byte root, passed fresh verification and
rejected altered proofs, statements and verifier authority. Other processes were
active on the laptop. The optimized replay fell between the controls, leaving
the full-tree speedup inconclusive.

The packed chi prover keeps the 16-bit lane indices until the first sumcheck
fold. It evaluates the row pair on demand and writes a half-height Poly192
table. At 65,536 permutations the largest dense chi table falls from
150 MiB to 75 MiB. For adjacent equal rows, the prover evaluates the row once
and sums the individual equality weights. A folded pair can share that work
only when its low and high rows both repeat. The two packed Boolean boundary
tables also have WHIR's required layout, so sharing their backing storage
avoids copying 32 MiB per parent. The witness reserves its padded row count
before appending states.

On an isolated 65,536-permutation proof, the first fold alone took
1.107 s versus 1.601 s for the previous prover. In another
interleaved comparison the prover with row reuse took 1.041 s versus
1.343 s, a 22.5% reduction. Both are medians of four
verified proofs per build. Eight-child replays before the WHIR storage change
took 41.78, 42.06, 47.80, 50.49 seconds, in optimized, previous, previous, optimized
order. With the WHIR change included, the optimized eight-child replays took
42.32 s and 45.28 s. The two intervening controls took 40.89 s and 47.13 s.
Each eight-child replay produced the same root for those eight children.

In the optimized full replay, proof generation accounted for
92.2% of the summed first-pair wall time and 94.4% of the summed recursive-merge
wall time. These percentages use each node's own clock because the two workers overlap. [Settings, raw timings and proof digests](../benchmarks/binary/tree-merge/packed-first-fold-m2.json)

## Packed recursive parent on the M2 Pro

The version 11 tree aggregated 64 saved children and independently verified
the root in **373.38 s**. The version 8 run took 579.67 s on the same ordered
inputs. A prior version 8 run took 566.45 s. Across those comparisons, the
protocol, native kernels and node schedule reduced elapsed time by 34.1–35.6%.
Key setup brought the run to 388.06 s. The run proved 32 first pairs under the
first-aggregation key. All 31 higher merges used one recursive key across five
levels. The 948,828-byte compressed proof verified in 96 ms (106 ms including
process launch). Peak process RSS was 6.91 GiB. The machine recorded 8.53 GiB
of swap-outs across all processes during the command, including setup and
rejection checks.

These are single full-tree measurements on a laptop. The final run used
battery power, 12 threads and up to 2 concurrent nodes. A serial run of the
packed joint protocol before the native tuning took 457.46 s. Both produced
byte-identical root proofs. The conditional algebraic estimate was
146.10 bits for each node type under the Johnson analysis.

| Eight identical saved children with the selected schedule | Through fresh verification | Keccak calls per higher merge | Initial codeword cells per node |
| --- | ---: | ---: | ---: |
| 8 · separate openings, scalar chi | 54.53 s | 47,182 | 184,549,376 |
| 9 · joint opening, 1/4 main rate | 52.40 s | 38,204 | 167,772,160 |
| 10 · joint opening, 1/2 main rate | 47.99 s | 44,018 | 100,663,296 |
| 11 · packed chi and native buffer changes | 40.91 s | 43,694 | 100,663,296 |

Each row is one release replay at 12 threads with up to 2 nodes. The fourth
row includes six-round prover checkpoints, fused transposition, ARM carry-less
multiplication and reuse of fold buffers. The full version 11 tree performed
the same statement, proof and authority rejection checks as version 8.

| Threads | Concurrent nodes | Eight-child replay, version 11 |
| ---: | ---: | ---: |
| 8 | 1 | 42.29 s |
| 8 | 2 | 41.77 s |
| 12 | 1 | 47.35 s |
| 12 | 2 | 40.91 s |
| 12 | 3 | 41.20 s |

Every schedule produced the same root proof. The full run averaged
5.93 elapsed seconds per completed parent, against a budget of 2.86 s.
Three minutes requires 2.07× the measured throughput. A four-input
tree would perform 21 proofs instead of 63. Its budget with 10 s of overhead
would be 8.10 s per proof on average. A four-input verifier still needs a
separate circuit and an end-to-end measurement. [Run data and reproduction command](../benchmarks/binary/tree-merge/joint-packed-parent-m2.json)

## Earlier version 8 replays

The version 8 replay took **579.67 s** with eight-state boundary
folding. The previous build took 566.45 s on the same children. Both produced
the same 998,119-byte root proof. Fresh verification took 109 ms, and the
run including key setup took 594.71 s. Each full-tree result is one run under
ordinary laptop load. The 579.67 s run required 3.22× its throughput to reach 180 s.
[Full replay and matched opening trials](../benchmarks/binary/tree-merge/packed-mixed-whir-m2.json) · [Earlier replay](../benchmarks/binary/tree-merge/flock-leanvm-m2.json)

| Prepared 64-child replay | Before compact chi | Compact chi | Eight-state boundary fold |
| --- | ---: | ---: | ---: |
| 32 first aggregations, total node time | 340.24 s | 288.43 s | 292.80 s |
| 31 higher merges, total node time | 330.91 s | 277.56 s | 286.39 s |
| All outer proving, excluding witness and verification | 614.39 s | 512.60 s | 525.73 s |
| Saved children through fresh root verification | 671.61 s | 566.45 s | 579.67 s |

The boundary fold transposes eight states and uses each byte to select a sum
of eight Poly192 weights. On 65,536 states with parent-sized padding, its
median time fell from 3.82 ms to 1.94 ms. Alternating the two binaries on a
saved higher merge gave medians of 9.031 s and 8.995 s. The individual times
overlap, and all eight proofs matched byte for byte. In the 64-child run the
median first aggregation took 8.85 s and the median higher merge took 9.03 s.
The budget allows 2.86 s per node before overhead.

## What transfers from FLOCK and leanVM-b

Archived leanVM-b implements Succinct's Boolean R1CS reduction for BLAKE2s over
the same Poly64 base and cubic Poly192 challenge fields used here. It packs the
Boolean witness into a stack, reduces the hash constraints to evaluations, and
combines ordinary word claims and ring-switched bit claims in one binary WHIR
opening. This gives us a concrete design for retaining WHIR and wide challenges
while borrowing FLOCK's fast prover. [Boolean reduction](https://github.com/leanEthereum/leanVM-b/blob/b7f5ba6ec2dbfd3e46fd0a3343f921db2479b240/crates/flock/src/lib.rs) · [WHIR fields](https://github.com/leanEthereum/leanVM-b/blob/b7f5ba6ec2dbfd3e46fd0a3343f921db2479b240/crates/pcs/src/whir.rs) · [Mixed openings](https://github.com/leanEthereum/leanVM-b/blob/b7f5ba6ec2dbfd3e46fd0a3343f921db2479b240/crates/pcs/src/stack_open.rs)

I ran the authors' benchmarks on this 16 GiB M2 Pro. Each hash batch contains
65,536 independent primitive calls. FLOCK reports its best of three timed
proofs after a verified warm-up. LeanVM reports the mean of five Keccak proofs
after warm-up and checks its proof with its own verifier. Our Keccak numbers
are medians of four release proofs per build in alternating process order.
The 64-child tree uses our linked Keccak prover. The flat masked demo's
`flock` option uses the Plonky3 implementation. The first two rows below
run Succinct's own repository.

| M2 Pro workload | Proving time | What was proved |
| --- | ---: | --- |
| Succinct FLOCK, 8 threads | 0.106 s | 65,536 BLAKE3 compressions |
| Succinct FLOCK, 8 threads | 0.287 s | 65,536 SHA-256 compressions |
| Current leanVM, one 24-round segment | 0.212 s | 65,536 Keccak-f permutations, 237.1 KiB proof |
| Current leanVM, two 12-round segments | 0.216 s | Same permutation count, 225.9 KiB proof |
| Our standalone committed Keccak, before | 2.752 s | 65,536 Keccak-f permutations with Poly192 challenges |
| Our standalone committed Keccak, after | 2.240 s | Same workload and identical proof bytes |

LeanVM also proved a two-input recursive merge of its own prepared proofs in
0.253 s with a 270.5 KiB proof. Verification took 13.64 ms. Each leaf covered
1,400 leanXMSS signatures. Its 12-round checkpoint reduced the standalone Keccak
proof's scalar count from 2,843 to 1,597 and verification from 4.7 to 3.6 ms.
The reduction in work the parent verifies is a reason to try this approach here
even with similar standalone proving times. [LeanVM benchmarks and parameters](https://github.com/leanEthereum/leanVM/blob/161cb67e1b54f7031b2603b8628f467f2ec92fca/README.md#benchmarks)

In FLOCK's field benchmark, four independent scalar GF(2⁸) multiplication
chains took 2.151 ns per element. Its 16-lane NEON kernel took 0.101 ns per
element. Its GF(2¹²⁸) default multiplier delivered 1.962 ns per product, and
its deferred-reduction multiply-accumulate benchmark took 0.623 ns per term.
These are throughput measurements in tight loops. Our dense Poly192 sumcheck
already uses carry-less multiplication and postpones reduction across products.
[FLOCK field benchmark](https://github.com/succinctlabs/flock/blob/dcd17533128a595e475b3dbba56c3dc2ad65161f/crates/flock-prover/benches/field.rs)

The local change exploits the first two multilinear folds of Boolean input.
Each resulting value is one of at most sixteen Poly192 values. The prover
stores a one-byte index for each, groups equal terms before multiplying, and
expands to field elements on the next fold. At this batch size the two-fold
column buffer drops from 600 MiB to 25 MiB. The next fold needs 300 MiB of
dense field elements. Caching the native
round-12 state separately costs 12.5 MiB and avoids replaying the first
twelve rounds for every upper layer. In an alternating test of that additional
change alone, median component time went from 2.142 s to 2.117 s. Both
optimizations preserve the existing transcript. The local midpoint is prover
scratch, while leanVM also authenticates its midpoint to shorten recursion.
[Sumcheck implementation](../crates/flock-backend/src/checkpoint_keccak/rounds.rs) · [Round replay](../crates/flock-backend/src/checkpoint_keccak/mod.rs)

### Packed chi and joint WHIR on the M2 Pro

The component proves one Keccak round or all 24 rounds over Poly64 with
Poly192 challenges. Each group of 16 input bits maps to a polynomial of
degree at most 23. Its raw product has degree at most 46. The prover binds
all 47 product coefficients before sampling the evaluation point for the
cubic sumcheck. The verifier checks their projection against the claimed
chi output. The basis-pair test checks all 256 products. The hash remains
Keccak-256 and the PCS uses the existing additive WHIR parameters.
[Keccak construction](https://github.com/leanEthereum/leanVM/blob/161cb67e1b54f7031b2603b8628f467f2ec92fca/doc/leanvm/body/c-keccak-gkr.tex)

The joint component commits a packed Boolean input table and 25 Poly64
output-word columns. The midpoint variant commits the round-12 states in the
second half of the Boolean table. The verifier authenticates both the read
of the midpoint and the terminal input claim. A fresh segment challenge
combines the two halves only after the prover binds the midpoint claim.
The recursive circuit derives all points from the transcript and checks the
word and bit claims against one WHIR proof. Its public input is the root.

Four alternating release runs per case used 65,536 permutations and 12 Rayon
threads. The single-round control took 0.283 s with scalar chi and 0.274 s
with packed chi. For all 24 rounds, the measurements below include boundary
construction, commitment, GKR and the joint opening. Recursive witness counts
come from building and executing the whole component verifier, including WHIR.

| Keccak component | Median proving | Poly192 scalars outside WHIR | Proof bytes | Recursive witnesses | Recursive Keccak calls |
| --- | ---: | ---: | ---: | ---: | ---: |
| Scalar, 24 rounds | 1.795 s | 2,088 | 249,623 | 1,412,020 | 5,269 |
| Packed, 24 rounds | 1.393 s | 2,936 | 273,859 | 1,511,274 | 5,393 |
| Scalar, authenticated midpoint | 1.910 s | 1,127 | 247,905 | 1,534,891 | 5,581 |
| Packed, authenticated midpoint | 1.368 s | 1,555 | 260,202 | 1,585,164 | 5,645 |

Packing saved 22.4% of native proving time for the 24-round schedule.
Authenticating the midpoint cut the packed scalar count by 47.0%, while the
complete component verifier needed 73,890 additional witnesses. The midpoint
adds a Boolean opening and doubles the input table height. For the packed
midpoint alone, two separate openings proved in 1.279 s and used 411,387
bytes. One joint opening took 1.368 s and used 260,202 bytes. The conditional
algebraic estimates at this batch size ranged from 147.10 to 148.02 bits.

A second matched experiment timed the packed 24-round kernel after fusing the
linear layer with transposition, caching round states every six rounds, and
keeping fold buffers allocated. On the M2 the 47-bit product fits in one ARM
carry-less multiplication. Across four alternating runs per build, the median
for 65,536 permutations went from 1.332 to 1.203 s. The reduction itself went
from 1.112 to 0.990 s. Every proof was 273,859 bytes and passed independent
decoding and verification in the benchmark. The live parent uses all 24 rounds
in one segment. Its recursive verifier also checks the arithmetic bridge.
[Matched component timings](../benchmarks/binary/tree-merge/joint-packed-parent-m2.json)

### Joint openings on a recursive merge

The higher-merge benchmark first proved and verified a 16-child parent using a
saved eight-child subtree in both input positions. It captured the 23 arithmetic
and boundary tables with their 25 prescribed points, then committed and opened
them under a fresh transcript. Both layouts returned all 373 expected values.
The recursive opening circuits accepted both proofs and rejected an altered
public value. Medians below cover five runs per layout in alternating order.

| Affected part of the parent | Separate WHIR | Joint WHIR |
| --- | ---: | ---: |
| Commit and open | 3.074 s | 2.800 s |
| Native verification | 31.15 ms | 32.24 ms |
| Commitments and opening proofs | 507,001 B | 322,538 B |
| Initial codeword cells | 150,994,944 | 134,217,728 |
| Recursive opening-verifier witnesses | 5,206,942 | 4,319,565 |
| Recursive opening-verifier Keccak calls | 11,228 | 6,739 |

The joint opening fits the boundary tables inside the main commitment's
existing power-of-two allocation. It saved 0.274 s in this part of the native
prover and 40.0% of the recursive opening verifier's Keccak calls. The timed
replay excludes preprocessing and the arithmetic and port-link reductions.

The version 8 parent used for this comparison bound separate arithmetic and
checkpoint roots. Version 11 binds one root before the arithmetic and Keccak
challenges and routes both reductions into its opening verifier. The 2.800 s
in the opening replay measures one part of a parent under the older rate.
The 180 s target allows 2.86 s for the entire node before overhead.

The first command below checks the closed component circuit. The second
replays a parent using a saved subtree with its matching verifier identity.
Substitute its directory for `SUBTREE`. [Raw trials and circuit counts](../benchmarks/binary/tree-merge/packed-mixed-whir-m2.json)

```sh
RAYON_NUM_THREADS=12 cargo run --locked --release -p imt-flock-backend --features opening-bench --example packed-keccak -- 16 mid packed joint 1 --recursive
RAYON_NUM_THREADS=12 cargo run --locked --release --features opening-bench --example bench-merge -- SUBTREE SUBTREE --compare-openings --repetitions 5
```

**Move fixed and linear work out of the recursive witness.** FLOCK walks
XOR wiring in reverse to obtain the weighted linear form on inputs and AND
outputs. Start by counting which rows of our arithmetic and fanout tables
implement eligible Boolean wiring. For public preprocessing shared across
nodes, leanVM separately demonstrates how to combine claims about one fixed
polynomial and check the final evaluation natively. Prototype one public
preprocessing block per verifier-key identity. Bind the key, statements,
points and claimed values before batching, and require the fresh root
verifier to evaluate the block. Measure total padded main cells, root
verification time and the cost of accessing the fixed table. [FLOCK circuit walk](https://arxiv.org/html/2607.27491v1#S4) · [Deferred public evaluation](https://github.com/leanEthereum/leanVM/blob/161cb67e1b54f7031b2603b8628f467f2ec92fca/doc/leanvm/body/10-ethereum.tex)

## Record-circuit baseline and three-minute budget

Before the compact Keccak changes, the record circuit took **671.61 s (11 min
12 s)** to aggregate 64 saved children and verify the root. Including key setup
took 687.18 s. This baseline was **3.73×** the time budget. The eight-child
pilot took 82.57 s. Both runs used 12 threads
and one aggregation node at a time.

| Phase in the 64-child replay | Nodes | Total node time | Median per node |
| --- | ---: | ---: | ---: |
| Verify masked children inside first aggregates | 32 | 340.24 s | 10.30 s |
| Prove higher merges | 31 | 330.91 s | 10.47 s |

Generating the outer proofs accounted for 614.39 s, about 91% of elapsed
aggregation time. The 998,119-byte root verified in a fresh process in 115 ms
including process launch. Peak physical footprint was 11.14 GiB and the system
swapped during the run. The previous statement's 750.96 s replay used different
proofs under different machine load. These runs do not isolate a speedup.
[Record replay measurements](../benchmarks/binary/tree-merge/record-replacement.json) · [Previous full replay](#smaller-recursive-commitments)

Even eliminating either aggregation stage leaves more than 330 s. Both
templates commit 184,549,376 initial codeword cells. A first pair uses 51,386
Keccak permutations and a higher merge uses 47,182. The 35 application hashes
per child run before the replay clock starts. Reducing their native cost only
helps aggregation if the resulting proof is cheaper to verify in a circuit.

1. **Attribute the recursive hashes on saved inputs.** Count calls and padded
   instances for WHIR commitment leaves, authentication paths, transcript
   absorption and grinding separately. Time native hashing, linked Keccak
   proving, encoding/folding, arithmetic sumcheck, and reads/import. Use the
   same pair and higher-merge inputs in alternating runs. The Mac reports
   hardware SHA-3 instructions and the default Rust target already enables
   `sha3` and `neon`. A retained merge sample already shows
   `p3_keccak::neon_sha3::hash_many` on CPU together with memory copies, bus
   evaluation and the additive transform. Trace which remaining call sites can
   use that batched kernel. Compare byte-identical outputs when reusing a framing buffer or
   batching equal-length hashes. Keep an optimization only if the full node
   time improves reproducibly. [Domain-prefixed hash adapter](../src/binary/veil/hash.rs)
2. **Reduce the work proved for each WHIR opening.** Count distinct parent
   hashes across paths to each individual commitment and round. The importer
   can expand pruned paths. Measure the remaining duplication after existing
   stratified path sharing. Prototype computing a shared parent once in the
   recursive circuit. Constrain indices, left/right positions, selected digests
   and roots to the original transcript challenges. Count routing gates, padded
   committed cells and peak memory too. A previous four-digest Merkle experiment
   cut merge permutations from 41,406 to 32,920 but increased eight-child
   aggregation from 72.38 to 99.89 s as the fixed layout grew.
   Both record templates currently reserve 65,536 permutation slots. Halving
   the reservation would require saving at least 18,618 calls in a first pair
   and 14,414 in a merge, then rebuilding both keys with the smaller bound.
   Profile the 134,217,728-cell main commitment alongside this change. Even
   halving the 16,777,216-cell hash commitment alone saves only 4.5% of initial
   cells. [Fixed recursive layout](../crates/flock-backend/src/recursive_layout.rs) ·
   [Recursive WHIR importer](../src/binary/veil/whir/recursive.rs) · [Merkle layout measurements](../benchmarks/binary/tree-merge/merkle-commitments-eight.json)
3. **Prototype four-input proof aggregation.** Start with four child verifiers
   in one base proof, then benchmark a four-input merge over actual base proofs.
   Bind every input in order, count and authority. Preserve the canonical binary
   statement digest by computing the same internal pair digests. Compare
   dedicated base and merge layouts against padding both to a common shape.
   Reserve 10 s for reads, encoding and fresh verification. For a serial replay
   the remaining 170 s implies the following budgets. These are experimental
   gates, and a larger node can require more memory and time per input.

   | Proof tree | Nodes | Time budget for measured node costs |
   | --- | ---: | --- |
   | Binary | 63 | 32 pairs + 31 merges, 2.70 s per node on average |
   | Four-input base, binary merges | 31 | 16 base + 15 merge proofs, 5.48 s on average |
   | Four inputs throughout | 21 | 16 base + 5 merge proofs, 8.10 s on average |

   For example, 8 s per four-input base and 8 s per four-input merge gives
   168 s of proving plus 10 s of overhead. Both four-input timings still
   need measurement.
   Stop scaling a layout if the measured weighted sum exceeds budget or if
   it starts swapping. With concurrent nodes, measure shared-machine throughput
   directly. Multiplying single-node throughput by the job count double-counts
   the same CPU cores and memory bandwidth.
4. **Validate at tree scale.** Rebuild saved child fixtures for the record
   statement once. Compare one and two concurrent nodes at 8 and 12 total
   threads on the same eight inputs. Record repeated timings, peak physical
   footprint and swap delta. Promote the best candidate to three 64-child
   replays on AC power with no competing builds. Record the range, cold setup,
   per-level wall times, final proof size and independent verification result.
   Keep the current Johnson analysis, child masking and half-distance cap,
   152-bit outer PCS target, 144-bit conditional floor and grinding cap.
   Any change to rate, folds or number of composition steps needs updated
   error accounting. [WHIR](https://eprint.iacr.org/2024/1586) · [Security parameters](binary-security.md#parameters-and-accounting)

## Which hash to use

**Keep full-round Keccak-256 as the default.** The 24-round permutation has a
long public analysis history and a working linked prover in this tree. The
application uses original Keccak padding. SHA-256 is the longer-established
alternative for a controlled trial. Its 64-byte blocks and mandatory length
padding mean even an unprefixed 64-byte parent needs two compressions. Compare
complete framed hashes at the real message lengths. [Keccak parameters](https://keccak.team/keccak_specs_summary.html) · [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) · [SHA-256 standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

If a second long-established hash merits a gadget prototype, **BLAKE2b-256**
fits both the 80-byte parent and 88-byte record into one 128-byte block. Use the
unkeyed 32-byte digest configuration. Its 12 rounds include 64-bit additions
whose carries must be proved in this binary-field circuit. Count those costs
before investing in a recursive backend. [BLAKE2 specification (2015)](https://www.rfc-editor.org/rfc/rfc7693#section-2.1)

**BLAKE3 remains a proof-commitment experiment.** In the repository's
`blake3-testing` trial, the AIR put all seven rounds of one compression in
one row, including the intermediate word additions and carries. The 16-byte
domain plus two 32-byte children made an 80-byte message, requiring two
64-byte blocks. The previous Keccak AIR used 25 rows for one permutation
and the entire message fit one rate block. The resulting BLAKE3 trace was
128 × 11,669 versus 1,024 × 1,630 for Keccak. The raw matrix has 1.49M cells against 1.67M for Keccak.
Opening two views also incurs costs proportional to width. Stacking 128 columns plus a mask gave 93 oracle columns
versus 14. The BLAKE3 trial had 11,569 verifier products, 34,937 masked
messages and roughly 2.4 MB child proofs. Its two warm child proofs took
13.42 and 17.18 s with other work overlapping. The branch addressed a
Keccak-only prefixed-WHIR restriction after its first setup attempt.
There is no verified recursive BLAKE3 tree timing in that experiment.
[BLAKE3 trial and measurements](https://github.com/partylikeits1983/recursive-imt-prover/blob/fda1c35cbd7d91f7e686d8dd44f263994f242ce7/docs/aggregation-performance.md) · [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)

For a second trial, keep the record hash and Fiat–Shamir transcript fixed and
change only the outer proof commitments in a versioned suite. Measure the
actual MMCS leaf lengths and internal-node framing with native and constrained
known-answer tests. An earlier native M2 batch benchmark measured BLAKE3 at
3.99× Keccak throughput for 64 bytes and 1.86× for the actual 80-byte record-tree
parent. Use the same saved children, measure recursive calls,
commitment cells, memory, and the eight-child replay. A 3× speedup even over
the *entire* 672 s workload would give 224 s. Hash optimizations alone
would have to remove over 73% of total elapsed time to meet 180 s. The four-input experiment tests the additional saving that fewer
recursive proofs could provide.

## Replay precomputed children

```sh
cargo prove --threads 12 -j 2 --prepare-children run/children64
cargo prove --threads 12 -j 2 --parallel-nodes 2 --from-children run/children64 --keep --out run/replay64
```

The preparation command saves 64 verified child proofs and their ordered public
statement. Use `-n 8` on both commands for a shorter gate. Replay starts its
prepared timer before reading the statement. It includes proof reads and imports,
all 63 aggregation nodes, root encoding, file writes and verification in a fresh
process. The report also records cold wall time including circuit and key setup.
Rejection checks run after both timers stop. The live pipelined demo can have
work already completed when its last child arrives. Use replay for the target.
If cold setup consumes too much of the total budget, reuse a resident pair of
prepared proving keys across batches and measure the first batch separately.

An eight-proof replay from the saved 64-proof fixture set took 87.35 s from
inputs to a verified root, or 106.03 s including setup. It used one node at a
time and 12 threads. The 907,834-byte root verified in a second independent
invocation in 104 ms. The pilot exercised two merge levels with the same key.

In the first fixed-input experiment, six baseline merges took 10.44 s at the
median (range 9.69–12.80 s). Passing already evaluated AIR columns to the
preprocessed opening took 10.33 s across three merges. Caching Keccak round
states took 11.15 s across three merges. All produced identical proof bytes.
The Keccak cache improved the standalone 65,536-permutation component median
from 2.73 s to 2.62 s. The merge results did not establish a gain for either
change and both were dropped. The observed variation makes single-merge
seconds-level comparisons unreliable.

## Measured baseline

On an Apple M2 Pro with 16 GiB of RAM, the benchmark generated one child at a
time, then proved one aggregation node at a time. Each proof used 12 Rayon
threads. Independent clients can generate their proofs concurrently. That
shortens the time before aggregation starts.

| Operation | Measured result |
|---|---:|
| Child proving, median | 2.50 s |
| First aggregation, median | 9.74 s |
| Higher merge, median | 9.61 s |
| All 63 aggregation nodes, wall time | 614.92 s |
| Fresh final verification | 112 ms |
| Final proof file | 909,023 bytes |

Reaching one minute on this machine requires about 10.2 times this baseline's
aggregation throughput. The longest chain of six dependent nodes took 60.03 s
when their individual timings were added. [Full benchmark](../benchmarks/binary/tree-merge/conditional-swaps-sixty-four.json)

## Keccak prover change

Each instance round of the checkpoint sumcheck sends evaluations of a cubic.
The prover factors off the equality term and evaluates one endpoint and the
quadratic coefficient of the remaining polynomial. It recovers the other
endpoint from the running sum. For a zero equality coordinate it evaluates
that endpoint directly. This saves work in the packed Keccak chi kernel on
first aggregates and on recursive merges. The verifier reads the existing
wire format. The child circuits and security parameters are the same.

The standalone committed Keccak benchmark, with 65,536 permutations on the
same deterministic input, fell from **2.879 s to 2.608 s** median proving
time (9.4% less time). Each implementation proved six samples. The baseline
ran first and last. Their proof bytes matched.

On the M2 Pro, the 64-child acceptance run took 625.40 s for the aggregation
stages and **625.95 s from ready children to a verified root**. Median first
pair time decreased to 9.55 s and median higher merge time increased to 9.89 s.
Total stage time was 1.7% above the earlier 614.92 s. The six dependent nodes
on the longest path summed to 62.56 s.

The 32 first pairs saved 3.32 s in total (311.39 s to 308.07 s).
Across all 31 higher nodes, elapsed level time rose by 13.80 s (303.53 s
to 317.33 s). Of that increase, 13.08 s appeared inside proof generation.
The full runs used fresh children and did not control machine load or
temperature. Those measurements locate the difference within the prover
but cannot attribute it to a particular kernel.

Replaying the same two eight-child aggregates in both orders produced identical
parent proof bytes in each order. Across four samples per prover, the median
fell from 10.94 s to 10.19 s. The candidate was slower in one input order and
faster in the other. The available measurements do not establish a whole-tree
speedup. [Full tree and fixed-input results](../benchmarks/binary/tree-merge/keccak-running-sum.json)

To replay a merge, save two trees with `cargo prove --keep --out <directory>`.
Supply their output directories with equal
subtree sizes of 4, 8, 16 or 32. The benchmark uses the locally constructed
authority and includes import, witness generation, proving and the prover's
native verification in each `aggregation_wall_ms` sample. Setup and input
file reads occur before timing.

```sh
RAYON_NUM_THREADS=12 cargo run --locked --release --example bench-merge -- run/left run/right --repetitions 3
```

## Smaller recursive commitments

The version 8 recursive preprocessing commitment used rate 1/2 under Johnson.
Its main and linked Keccak commitments used rate 1/4. The higher preprocessing rate
adds queries to the embedded verifier. The five-wire table has room for those
extra gates, and the four-copy Poly64 fanout table uses half as many rows by
assigning overflow to spare slots in the wider fanout tables.

Both recursive node types use 184,549,376 initial codeword cells, down from
218,103,808 (15.4%). Preprocessing cells fell from 67,108,864 to 33,554,432.
The conditional algebraic bounds were 146.22 bits for both node types with
the repository's 144-bit floor.

The control and updated prover each aggregated the same eight precomputed
children on the M2 Pro with one node at a time and 12 Rayon threads. Both runs
used one merge key across two levels and verified the root in a fresh process.
The updated verifier also verified the control's saved bundle.

| Eight-child replay | Previous layout | Updated layout |
|---|---:|---:|
| Prepared inputs to verified root | 91.41 s | 90.63 s |
| Including key setup | 110.92 s | 110.78 s |
| Root proof file | 907,834 B | 998,763 B |
| Peak physical footprint | 11.82 GiB | 11.19 GiB |

The two timings do not establish a speedup. The larger root proof reflects
the extra preprocessing queries.

The updated prover also replayed all 64 saved children with the same thread
and node limits. It took 750.96 s from prepared inputs to a verified root
and 769.15 s including setup. One merge key covered all five merge levels.
The 997,855-byte root verified in a separate invocation in 105 ms. The
rejection checks passed. The 60 s target remains open.

## Prior experiments and the one-minute stretch budget

These experiments use portable Rust on the CPU. Keep the Johnson parameters
and the child masking configuration fixed when comparing implementations.

1. **Time the commitment openings.** A merge profile put the main and
   preprocessing openings together at about 3.2 s. Time ring switching, the
   first WHIR fold and the remaining rounds separately on both first pairs and
   higher merges. The proving key already shares its Merkle tree and source
   tables. Look for repeated scans of the fixed digit columns and cache only
   work independent of the opening point. Test against the same ordered inputs
   and report total node time and peak memory alongside the opening time.
2. **Shrink the fixed recursive layout.** Both node types start with
   134,217,728 main, 33,554,432 preprocessing and 16,777,216 Keccak
   codeword cells. Count live and padded cells per table on both templates.
   Prioritize changes that cross a power-of-two boundary in the stacked
   layout. Benchmark both templates after each change because the reusable
   merge key requires a common shape.
3. **Measure throughput per machine.** Start with one node at a time. Sweep
   8, 10 and 12 Rayon threads on saved pairs, then compare one and two
   concurrent nodes on an eight-child tree using a single shared pool.
   Record elapsed time, physical footprint and swap activity. An older layout
   took 164 s with one node and 230 s with two on eight threads. Compilation
   overlapped part of the two-node run. Use `--parallel-nodes` to vary aggregate
   concurrency while holding the leaf cap fixed. [Earlier scheduling measurements](../benchmarks/binary/tree-merge/paired-scheduling.json)
4. **Test four masked children in the first aggregation.** If parameter and
   layout checks permit it, a 64-child tree would need 16 first aggregations
   and 15 binary merges. Compare measured totals including any change to
   merge cost from the larger common layout. With first-pair time F and
   binary merge time M, a four-child first node can take up to 2F + M to
   break even if M stays fixed, about 29 s at the measured medians. The
   merge circuit currently selects the first verifier for a count of two.
   Bind the four-child base case to its own first verifier and check ordered
   digests, counts and fixed-key recursion at every level.

For the existing binary tree a 60 s single-machine budget gives **0.95 s per
node** before encoding and verification. A 30 s target gives **0.48 s per
node**. Removing all 3.2 s of the profiled opening work would still leave
several seconds per node. Compare the same saved proof bytes and statement
order. Alternating samples help separate code changes from machine load.
Record proof and verifier-key digests, peak physical footprint and swap
deltas alongside the median and range. Use the full 64-child replay to check
all recursive levels.

## Research for larger gains

| Circuit | First measurements | Structural experiment |
|---|---|---|
| Depth-32 masked child | Break out witness, VEIL commitment and additive encoding, sumchecks, openings, and verification. Track child proof bytes and recursive verifier layout. | Find opening and transcript work that the child can compact without changing masking or the statement. Measure the induced first-aggregation time, even though child proving is outside the target. |
| First aggregation of two saved children | Break out import, witness, product bus, AIR sumcheck, commitments, the first WHIR fold, remaining WHIR rounds, and linked Keccak. | Sweep valid Johnson rate and fold schedules and record committed cells and recursive hash work. Compile four masked child verifiers and compare the entire tree cost with the pair path. |
| Reusable merge | Measure the first-authority and self-authority branches and key setup. Inspect live versus padded cells for both recursive templates. | Test arity four with a reusable four-input merge key and an ordered four-child base. Compare a dedicated base layout if selector and common-layout padding dominate. |

Use `bench` for the native non-ZK circuit as a diagnostic control, `masked-demo`
for the ordered aggregate and alternate Flock backend, and `checkpoint-keccak`
to isolate the linked prover's underlying hash reduction. Run the active tree
on every accepted system change.

A four-child base with binary merges needs 31 proving nodes and costs
`16 × F4 + 15 × M2` serially. A four-child base and four-input merges need 21
nodes and cost `16 × F4 + 5 × M4`. The latter gives a 2.86 s average node budget
for 60 s and 1.43 s for 30 s. Before building a new recursive verifier, compile
the candidate layouts and compare padded cells, memory, and the six-level
binary control. Prototype one flat batch as a throughput control and compare
its proof size and peak memory. If verifying every complete transcript in a
recursive circuit still dominates, investigate carrying batched PCS claims to
one decider. WARP is a starting point for transparent accumulation. Check which
committed words the accumulator prover must possess, and whether they can be
derived from the proofs and public statements actually received by the aggregator.
[Linear-Time Accumulation Schemes](https://eprint.iacr.org/2025/753)

### Beyond Johnson

The recent Dao–Kominers–Thaler beyond-Johnson bound needs large characteristic.
Poly64 and Poly192 have characteristic two. Their tighter bound within Johnson
applies in every characteristic and the pinned Plonky3 implementation already
uses it. Dao–Kominers–Thaler–Zheng give binary additive-domain counterexamples,
including results for sparse domains of the kind used by Flock. The VEIL child
binding calculation is also capped by half the minimum distance. Parameter
changes need a concrete bound for each domain, rate, combiner and folding round,
including the 64-child composition. Within-Johnson rate and fold tuning can
still trade encoded cells against query count and recursive verifier size.
[Beyond-Johnson bounds](https://eprint.iacr.org/2026/2056)
· [Binary counterexamples](https://eccc.weizmann.ac.il/report/2026/237/)
· [Repository security accounting](binary-security.md#parameters-and-accounting)

Sunghyeon Jo proves a finite-length result for arbitrary evaluation sets at
fixed inverse rate. A fixed number of extra errors past the exact Johnson
budget gives a relative-radius gain of order `1/N`, where `N` is the
codeword length. One extra position in the main `2^27`-cell codeword contributes
about `7.45e-9` to the relative radius. The general bound on exceptional
challenges is of order `K^6/q` in the code dimension `K` and challenge
field size `q`. Applying it would require concrete error accounting across
the WHIR schedule. Jeronimo's result reaches capacity with fixed slack on
arbitrary evaluation sets over prime fields.
[Fixed steps past Johnson](https://eprint.iacr.org/2026/1432)
· [Capacity over prime fields](https://arxiv.org/abs/2609.05870)

The pinned binary WHIR domain rejects `CapacityBound`. An isolated timing
harness used a separate transcript domain to measure its hypothetical query
schedule on deterministic honest inputs. The harness used the pinned binary
PCS, Keccak, four opening points and 12 threads on the M2 Pro. Each configuration
ran three times, reversing the order on the second pass. The times include
commitment and opening. The byte counts include the serialized opened values
and their PCS proof. The harness verified each opening separately. The results
measure PCS work only and carry no soundness claim for the capacity schedule.

| Packed PCS variables | Code rate | Fold | Schedule | Commit + open median (range) | Opening bytes |
|---:|---:|---:|---|---:|---:|
| 22 | 1/4 | 4 | Johnson | 0.291 s (0.256–0.686 s) | 180,837 |
| 22 | 1/4 | 4 | Hypothetical capacity | 0.282 s (0.266–0.384 s) | 98,997 |
| 24 | 1/4 | 4 | Johnson | 1.101 s (1.040–1.695 s) | 213,674 |
| 24 | 1/4 | 4 | Hypothetical capacity | 1.330 s (0.974–1.837 s) | 114,706 |
| 25 | 1/4 | 4 | Johnson | 3.161 s (1.952–4.062 s) | 222,834 |
| 25 | 1/4 | 3 | Johnson | 4.178 s (3.343–4.925 s) | 254,012 |
| 25 | 1/4 | 3 | Hypothetical capacity | 3.734 s (3.729–4.523 s) | 136,172 |
| 25 | 1/2 | 4 | Johnson | 1.360 s (1.331–2.244 s) | 324,266 |
| 25 | 1/2 | 4 | Hypothetical capacity | 1.377 s (1.279–1.489 s) | 168,090 |

The compared capacity schedules cut opening bytes by 45–48%. The proving
time ranges overlap at each matched shape. At 25 packed variables, rate 1/4
and fold 4, the hypothetical capacity schedule also required 17 grinding bits
against the configured cap of 16.

Grinding trades a prover nonce search for fewer queries and covers residual
error from folding and combining claims. Every tested Johnson schedule with
fold 3 or 4 and rates 1/2, 1/4 or 1/8 needs some folding grinding at the
configured 152-bit PCS target. Taking more queries alone cannot remove that
requirement.

A four-child replay used identical saved Keccak child proofs to try a rate
change within Johnson. The rate-1/4 control took 61.93 s from prepared inputs
to independent verification and produced a 907,196-byte root. Rate 1/2 more
than halved commit-and-open time at 25 packed variables in the isolated PCS
test, while increasing opening size from 222,834 to 324,266 bytes. The full
rate-1/2 build stopped during recursive setup. The width-one, 16-copy fanout
table needed 139,948 rows and had capacity for 131,072. The rate-1/2 replay
yielded no aggregation timing. The preprocessing-only change is measured
above.

The Action–Orbit FRI result uses cyclic evaluation domains and invokes a
dominance conjecture for general inputs. The newer affine-combiner analysis
covers binary fields within the Johnson radius and lowers the error of the
combination step. Its Flock example uses Ligerito row folding. Applying it
here would require affine challenges in WHIR and an analysis of the extra
degree, linear claims, agreement loss and recursive verification cost.
[Action–Orbit FRI](https://eprint.iacr.org/2026/861)
· [Affine Combiners](https://arxiv.org/abs/2611.15128)

### BLAKE3 and Keccak

Keep the full-round record statement fixed across proof-hash experiments so
they can all replay the same record proofs. Prototype a versioned BLAKE3 commitment
suite first for recursive proof Merkle paths. Benchmark the 64-byte internal
nodes and actual PCS leaf lengths independently. Then measure Fiat–Shamir
separately, including absorption, challenge extraction and grinding. The
native and recursive verifiers need matching full BLAKE3 semantics and test
vectors for their exact lengths and framing. A later child variant would need
new proofs and, if it also changes the IMT hash, different IMT roots.

The pinned Flock gadget gives a starting point for the seven-round compression.
The Flock paper reports 661,000 BLAKE3 compressions/s and 252,000 Keccak-f
permutations/s at peak on ten M4 Max cores. The peaks use different batch sizes.
A 64-byte Merkle parent takes one operation in either hash. A 128-byte leaf
takes two BLAKE3 compressions and one Keccak permutation. Compare the complete
prover on both node types and count padded cells before extrapolating from those
primitive throughputs. [Flock benchmarks](https://arxiv.org/html/2607.27491v1#S5.SS1)

The pinned Plonky3 Flock gadgets were also measured on this M2 Pro. Each run
proved and verified `2^14` primitive calls with public inputs and outputs,
eight Rayon threads, five samples and the upstream default Flock parameters.
The table gives witness plus proving time. Both Keccak and BLAKE3 runs bracketed
the SHA-256 run. These timings measure the upstream Flock implementation.

| Primitive | AND gates per call | Median witness + prove |
|---|---:|---:|
| Keccak-f[1600] | 38,400 | 321–324 ms |
| BLAKE3 compression | 10,298 | 106 ms |
| SHA-256 compression | 22,271 | 194 ms |

The corresponding native batched hash benchmark measured a 4.0× BLAKE3
speedup at 64 bytes, 1.9× at 128 bytes and 2.4× at 384 bytes. On the gadget
benchmark BLAKE3 was about 3.0× faster per primitive call. If a hash redesign
sped up one quarter of the existing 625 s tree by 3× while preserving the
layout and other phase costs, total time would be about 521 s. An end-to-end
prototype needs to show smaller committed tables or fewer recursion stages
to put one minute within reach.

Full-round Keccak-256 is the conservative security choice here. Its permutation
underwent the SHA-3 competition and years of public analysis. HashSmash's
SHA3-256 contests use five or six of 24 rounds, and its BLAKE3 contests use one
or two of seven. The scores concern those particular reduced-round targets.
Full BLAKE3 with a 256-bit digest targets 128-bit collision security and merits
a speed experiment. TurboSHAKE256 uses the last 12 Keccak rounds as specified in RFC 9861.
The current conservative benchmark uses the full 24 rounds. [HashSmash](https://www.yukon.org/hashsmash)
· [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final)
· [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
· [RFC 9861](https://www.rfc-editor.org/rfc/rfc9861.html)

## Independent workers

Prepare one copy of each required circuit per worker. Dispatch a parent when
both proofs for its assigned left and right positions arrive. The demo uses
the same dependency rule in a single shared thread pool. The
earlier 64-child node timings simulate 70.15 s on 16 slots and 60.79 s on 32,
with a barrier at each level. Each slot in that calculation has the throughput
of the entire M2 Pro. Worker setup, queueing, transfers and final verification
add to elapsed time. Measure from the arrival of the child proofs through
fresh final verification for a distributed result.

## CPU comparisons

An earlier four-thread comparison on this M2 Pro timed the same first-pair
statement with two Plonky3 backends. Flock's Keccak AIR took 27.94 s and the
checkpoint Keccak argument took 22.27 s, one sample each. Both used the
earlier circuit layout. [Flock pair](../benchmarks/binary/masked-aggregate/tree-pair-flock-d32-n2.json)
· [Checkpoint pair](../benchmarks/binary/masked-aggregate/tree-pair-checkpoint-d32-n2.json)

RISC Zero's `join` verifies two succinct receipts for execution spans and
produces another succinct receipt. Telos measured about 40 s to aggregate
two native RISC Zero proofs on an Intel i9-11900K in 2024. The comparable
operation here is a single higher merge. The circuits, parameters, CPU and
software versions differ. A same-machine comparison would time a prepared
two-receipt join on saved inputs, then repeat over a full tree and time fresh
verification. [RISC Zero recursion](https://dev.risczero.com/api/3.0/recursion)
· [Telos CPU measurement](https://telos.net/post/revealing-plonky2x-the-fastest-proof-aggregator-over-the-babybear-field)

For a protocol-level reference, the WHIR authors report 1.2 s to commit and
open one degree-`2^22` polynomial at their 100-bit setting, with a 63 KiB
opening and 360 µs verification. Our merge also imports and verifies two
child transcripts, proves the recursive constraints and produces several
openings. The paper's timing measures one component of that workload.
[WHIR paper](https://eprint.iacr.org/2024/1586)

[Acceptance test](aggregation-tree.md#validation-and-acceptance) · [Security analysis](binary-security.md)
