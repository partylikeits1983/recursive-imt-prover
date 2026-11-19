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

Reaching one minute on this machine requires about 10.2 times the measured
aggregation throughput. The longest chain of six dependent nodes took 60.03 s
when their individual timings were added. [Full benchmark](../benchmarks/binary/tree-merge/conditional-swaps-sixty-four.json)

## Optimization priorities

1. **Distribute independent pairs.** Prepare the first-aggregation and merge
   circuits once per worker. Dispatch each parent as soon as both child proofs
   arrive, preserving their left and right positions. A simulation using the
   recorded node times gives 70.15 s with 16 proving slots and 60.79 s with 32.
   It schedules the longest nodes first within each level and waits for the level
   to finish. Each slot assumes the throughput of the full benchmark machine.
   Transfers, setup and final verification are excluded. At 8 s per node, six
   levels on 32 slots would take 48 s, leaving 12 s for overhead.
2. **Reduce Keccak sumcheck work.** A local prover experiment recovered one
   endpoint of the round polynomial from the running sum. Across four replays
   of the same merge per build, the median linked Keccak proving time fell from
   2.51 s to 2.02 s. All four candidate proofs matched the baseline byte for
   byte. The baseline ran first and overlapped briefly with CPU profiling.
   Alternate the builds on several input pairs, then run the 64-child test.
3. **Reduce commitment-opening time.** Opening the main and preprocessing
   commitments took about 3.2 s combined in a baseline merge replay. Measure
   which work on the fixed preprocessing tables can be reused across proofs.
   Profile the remaining field transforms before choosing kernels to accelerate.

Measure the distributed run from receipt of the child proofs through fresh final
verification, including queueing and transfers. Report cold setup separately.
Record per-node latency, peak memory per worker and final proof size. Keep the
binary fields, Keccak and Johnson parameters fixed. Check that the same merge
key verifies every higher level and that changes to the ordered statements are
rejected. Child statistical ZK and end-to-end 128-bit security remain open.
[Acceptance test](aggregation-tree.md#validation-and-acceptance) · [Security analysis](binary-security.md)
