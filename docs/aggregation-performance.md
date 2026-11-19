# Under three minutes for 64 prepared children

Measure from reading 64 saved depth-32 record proofs and their ordered statement
to independent verification of one root on the 12-core, 16 GB M2 Pro. The
acceptance threshold is strictly below 180 seconds. Record cold wall time
including key preparation as a second result. One minute remains a stretch goal.

The latest run took **566.45 s (9 min 26 s)**, down from **671.61 s** on the
same saved child proofs. The two runs produced byte-identical 998,119-byte
roots. Fresh-process verification took 112 ms. Including key setup, the latest
run took 582.10 s. Reaching three minutes still requires **3.15×** the latest
throughput. Each build ran the full tree once under ordinary laptop load.
The alternating standalone tests below isolate the Keccak change more closely.
[Measurements, revisions and commands](../benchmarks/binary/tree-merge/flock-leanvm-m2.json)

| Prepared 64-child replay | Before | After |
| --- | ---: | ---: |
| 32 first aggregations, total node time | 340.24 s | 288.43 s |
| 31 higher merges, total node time | 330.91 s | 277.56 s |
| All outer proving, excluding witness and verification | 614.39 s | 512.60 s |
| Saved children through fresh root verification | 671.61 s | 566.45 s |

Peak physical footprint was 11.16 GiB in the latest run and 11.14 GiB in the
earlier run. Both saw system swap activity. The smaller Keccak scratch buffer
helps that phase, while the whole prover still uses most of the machine's
memory budget. The latest medians were 8.94 s per first aggregation and 8.82 s
per higher merge. A 63-node tree allows 2.86 s per node before overhead.

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

Three experiments address different costs in a recursive node.

1. **Pack Keccak's nonlinear layer across 16 permutations.** The active leanVM
   encodes sixteen bits as a binary polynomial of degree at most 23. One
   carry-less multiplication and a linear projection recover all sixteen
   pairwise ANDs. The product has degree at most 46, so it fits the current
   64-bit polynomial basis. The pinned maps passed a local check on all 256
   ordered pairs of basis vectors and 4,096 pseudorandom pairs of 16-bit words.
   Compare a packed chi layer against scalar chi, then port the weighted
   sumcheck with fresh Poly192 challenges.
   Measure a complete 65,536-permutation proof and its in-circuit verifier.
   The active leanVM uses 128-bit challenges and an affine WHIR combiner, so
   its protocol parameters and soundness figures require a separate analysis.
   [Keccak construction](https://github.com/leanEthereum/leanVM/blob/161cb67e1b54f7031b2603b8628f467f2ec92fca/doc/leanvm/body/c-keccak-gkr.tex) · [Field and WHIR implementation](https://github.com/leanEthereum/leanVM/blob/161cb67e1b54f7031b2603b8628f467f2ec92fca/crates/experimental_prover/pcs/src/whir.rs)
2. **Reduce the work verified by the parent.** LeanVM commits the round-12
   state and randomly combines the two 12-round segments, halving the number
   of sequential GKR layers in the verifier. In our prototype, bind the midpoint
   before sampling the segment challenge and authenticate the start, midpoint
   and output against their proper openings and the arithmetic ports. Count
   the additional committed cells against the saved recursive constraints and
   Keccak transcript calls. Benchmark both first aggregation and higher merge
   before selecting a segment length. [Segment construction](https://github.com/leanEthereum/leanVM/blob/161cb67e1b54f7031b2603b8628f467f2ec92fca/doc/leanvm/body/c-keccak-gkr.tex)
3. **Move fixed and linear work out of the recursive witness.** FLOCK walks
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
cargo prove --threads 12 -j 1 --from-children run/children64 --keep --out run/replay64
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

The recursive preprocessing commitment uses rate 1/2 under Johnson. The main
and linked Keccak commitments use rate 1/4. The higher preprocessing rate
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
