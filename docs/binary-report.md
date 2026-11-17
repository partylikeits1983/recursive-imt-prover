# Native non-ZK baseline benchmark report

The native binary path aggregates actual child proofs and verifies the resulting
proof in a fresh process using only the aggregate, ordered public statement and
trusted verifier data. **Children are non-ZK and end-to-end 128-bit security is
not established.** This document records the older native baseline. The current
masked-child path has a separate, working single-proof aggregate at depths 16/32;
see the [masked aggregation measurements](binary-veil.md#end-to-end-aggregate).

## Recorded native baseline

Depth 8, two children, three samples: one cold and two warm. Apple M2 Pro,
16 GiB RAM, four Rayon threads, Rust 1.98.1, release with thin LTO and 16 codegen
units. Compilation is excluded. Parameters: Poly64/Poly192, Keccak-256,
Johnson bound, PCS target 152, grinding ceiling 16 and conditional algebraic
floor 144. See [security accounting](binary-security.md) for the limits of those
numbers.

| Operation | Warm median | Warm range |
|---|---:|---:|
| Child prove | 80.47 ms | 60.84–118.45 ms |
| Child verify | 25.26 ms | 24.44–26.65 ms |
| Aggregate prove | 39.094 s | 36.887–41.301 s |
| Aggregation wall | 40.176 s | 38.080–42.273 s |
| Aggregate decode + verify | 36.72 ms | 36.00–37.44 ms |
| Batch critical path | 40.491 s | 38.405–42.578 s |

Setup took 4.707 s. Aggregate proofs were 1.260–1.263 MB, and process peak RSS
was 7.23 GiB. Fresh verification took 4.795 s wall time, including 4.547 s
reconstructing trusted verifier data and 33.68 ms decoding/verifying the proof.
Warm proof verification therefore does not describe cold process latency.

Two warm samples give an initial range, not a reliable latency distribution.
RSS is the lifetime process high-water mark, not an isolated per-stage allocation
measurement. Aggregation exceeds the research latency target. Scaling through
64 children at the final ZK/security configuration remains unmeasured.

## Run current benchmarks

```sh
cargo run --locked --release --bin bench -- \
  --depth 16 --batch-size 2 --samples 3 --out run/bench-two
```

Current child benchmarks cover depths 16 and 32; the older native measurement
above used depth 8. Masked-child and Flock aggregate timings are recorded
separately in [the masking report](binary-veil.md).

Use a fresh output directory. The CLI records child witness/prove/verify times,
aggregate construction/proving/verification, proof sizes, memory, parameters,
environment and a compiled source fingerprint. It verifies the final proof in
a separate process. The [matrix driver](../scripts/bench-binary.py) runs cases
sequentially and preserves explicit failures rather than changing parameters.

## Retained evidence

- [Native two-child report](../benchmarks/binary/v2/native-d8-n2.json).
- [Current direct VEIL reports and parameter failures](../benchmarks/binary/v2).
- [Masked-oracle component reports](../benchmarks/binary/oracle-v1).
- [VEIL methodology, timings and remaining integration](binary-veil.md).

Direct VEIL and oracle-component timings are separate measurements, not ZK
client/aggregation results or an equal-security comparison with the native path.
Obsolete Tower128/v1 runs and duplicate console logs were removed; historical
records remain available at commit `40ac660`.

The next priorities are privacy/security review and profiling the masked
aggregate at identical parameters. An aggregation tree and an Ethereum verifier
are not implemented.
