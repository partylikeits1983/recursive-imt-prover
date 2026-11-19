# One-minute aggregation for 64 child proofs

The target is 60 seconds from receiving 64 depth-32 Keccak IMT child proofs
to independently verifying one aggregate. The tree has 32 first aggregations
and 31 higher merges. All five higher levels share one merge circuit and key.

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

## Next experiments on the M2 Pro

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
   134,217,728 main, 67,108,864 preprocessing and 16,777,216 Keccak
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
node** before encoding and verification. Even removing
all 3.2 s of the profiled opening work would leave several seconds per node.
Use the 64-child integration test to decide whether to keep a change. Per-node
speed and the six-level dependency path answer different questions.

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
