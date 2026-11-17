# Binary VEIL implementation experiment

This implements and exercises the **inner algebraic argument** for a binary
VEIL port. It is not yet the complete VEIL compiler around MultiStark/WHIR, and
it does not replace the application's non-ZK binary child backend. The existing
aggregator cannot verify this new proof format. Acceptance remains **false**.

The experiment produces real cryptographic proofs of a private Keccak note
preimage or IMT membership, serializes them and verifies them in a fresh
process. Privacy is an **unreviewed adaptation**, not an established full-ZK
claim. No end-to-end 128-bit claim is made. A passing test cannot certify either.

## Reproduce

```sh
cargo build --locked --release --bin veil-demo
RAYON_NUM_THREADS=4 target/release/veil-demo --depth 0 --samples 3 \
  --out run/veil-preimage
RAYON_NUM_THREADS=4 target/release/veil-demo --depth 1 --samples 3 \
  --out run/veil-membership
target/release/veil-demo --verify --out run/veil-membership
target/release/veil-demo --depth 8 --inspect --out run/veil-depth8-geometry
python3 scripts/bench-veil.py --out run/veil-matrix --depths 0 1 8 \
  --threads 4 --samples 3 --max-rss-gib 10
```

Use fresh output directories. Depth zero is one private note-preimage proof;
depth one and above prove actual IMT membership. The statement is the same
ordered `(root, amount)` encoding as the binary baseline. Only the latest sample's
proof and statement are retained. `trusted.json` must be provisioned independently
of the prover in a real deployment. It binds the fixed relation and parameters.

`report.json` records raw measurements, warm median/range, setup, fresh-process
verification, lifetime peak RSS and local coding diagnostics. Compilation is
excluded. Samples are sequential and reuse the relation. The default 2 GiB
retained-commitment budget excludes scratch, relation storage and allocator
overhead; it is not a peak-memory guarantee. `--max-retained-bytes` changes that
resource limit. `--inspect` does not generate a proof.

## Measured direct proofs

Apple M2 Pro, 16 GiB RAM, Rust 1.98.1, release/thin LTO, 16 codegen units,
four Rayon threads, no additional RUSTFLAGS. No compilation ran concurrently
with these measurements. Each row is one cold sample followed by two warm
samples; warm median and min–max are shown. These are **single-child** proofs
with unreviewed privacy and incomplete end-to-end soundness analysis.

| Relation | Warm prove | Warm decode + verify | Proof size | Process peak RSS |
|---|---:|---:|---:|---:|
| Note preimage, one hash | 1.085 s (1.080–1.091) | 254 ms (253–256) | 17.33 MB | 1.18 GiB |
| IMT depth 1 | 2.331 s (2.318–2.344) | 554 ms (536–573) | 34.51 MB | 2.36 GiB |
| IMT depth 8 | 11.895 s (11.484–12.305) | 2.889 s (2.659–3.118) | 139.77 MB | 6.68 GiB |

Cold prove times were 1.145 s, 2.381 s and 13.221 s respectively. Fresh verifier
process wall times, including relation reconstruction, were 0.375 s, 0.815 s
and 3.264 s. The depth-8 run completed all three samples within the supervisor's
10 GiB RSS budget. RSS is a lifetime resident high-water mark, not total allocated
or virtual memory. Do not infer production latency from two warm samples.

Raw reports, supervision records, logs and fresh-process rejection results are
in [`benchmarks/binary/veil`](../benchmarks/binary/veil). They include the compiled
source fingerprint and actual parameters. Cryptographic proof files and private
witnesses are not checked into that directory. These timings are not an
equal-security comparison with the low-security non-ZK baseline.

Validation for this implementation pass: **44 release tests passed**, plus
formatting and all-target Clippy with warnings denied. New tests cover the
additive code, its product code, query-padding rank, the characteristic-two
masking bijection, proof/statement/authority tampering, and incorrect private
Keccak/IMT witnesses. One adversarial test deliberately bypasses the prover's
native precheck and verifies that the proof relation itself rejects the forged
witness. Fresh-process checks also reject changed depth-8 roots/amounts,
noncanonical amounts, mismatched verifier identity and truncated proofs.

## Implemented components

* `code.rs`: interpolation Reed–Solomon encoding on disjoint additive domains,
  using Plonky3 `BasisNtt`. Input and padding are evaluations on a Cantor
  subspace; output is evaluated on a disjoint coset. The product code has twice
  the input dimension. Every unused input position receives fresh randomness.
* `vector.rs`: VEIL-style committed dot-product and Hadamard arguments.
  Commitments reuse Plonky3's `MerkleTreeHidingMmcs`, Keccak-256 and two
  192-bit random salts per leaf. Private commitment data is neither serializable
  nor cloneable; producing its opening proof consumes it.
* `constraints.rs`: masked affine and multiplication constraints, public-input
  binding, multiplication-vector consistency, and the two random tautological
  padding triples needed to hide the three multiplication-vector dot products.
  Affine constants are explicit, not an unconstrained alleged constant wire.
* `transcript.rs`: Keccak Fiat–Shamir with framed labels, lengths, a protocol
  domain and a binding to the complete trusted relation, parameters and ordered
  public vector. It rejects challenges zero and one, with bounded retries.
* `keccak.rs`: a direct translation of **upstream `KeccakBinaryAir::default()`**
  into the inner constraint language, including state Booleanity. Fixed round
  flags, selectors, sponge padding, domain tags, capacity bits and IMT linking
  are constrained. No new Keccak permutation implementation is used.

Arithmetic and masks use `Poly192 = GF(2^192)`. Additive-transform twiddles use
the embedded `Poly64 = GF(2^64)`. All hashing on this path is Keccak-256. The
application tree still hashes 16-byte tags, secret, amount in little endian and
nonce exactly as documented in `binary-security.md`.

The initial target is **160 bits for query-miss probabilities**, using
Plonky3's Johnson radius and finite-field proximity-gap diagnostics. The base
code rate is 1/16; the product code rate is 1/8. These require 83 and 112 queried
rows respectively. The combined product/dot opening uses one 112-row schedule,
and all those rows count against the padding budget. Proofs cannot supply their
own rates, query counts or message dimensions.

## Why this is not the fast final architecture

VEIL applies its inner argument to the relatively small *algebraic verifier
transcript*. The direct experiment instead feeds it an entire Keccak execution
to test the binary port against a real application relation. Consequently it
sends a masked vector and full random linear-combination messages proportional
to that execution. It has no WHIR oracle adapter and loses packed-bit trace
storage. Its time and size must not be represented as the overhead of a complete
VEIL compiler.

For one permutation, the direct relation has 78,400 variables and 78,400
multiplication constraints. At depth 8 it has 705,608 variables and 709,704
multiplication constraints. Just retaining its two committed encodings and
Merkle trees needs approximately 6.12 GiB, before temporary buffers or relation
storage. This is a concrete reason to finish the transcript/oracle adapter
before attempting a recursive verifier for the direct format.

There is no general rule that doubling a proof makes it zero knowledge. Some
specific systems obtain hiding with trace or polynomial padding of roughly
that size. Such bounds depend on the protocol, query schedule and compiler;
they are not an upper bound for arbitrary binary recursion.

## Privacy argument to complete

The local encoding property is algebraic: interpolation from a subspace to a
disjoint coset gives a diagonally scaled Cauchy generator. Every square minor
is nonzero. Any `q` distinct queried coordinates therefore have full rank on
any `q` random padding coordinates and are uniformly distributed independently
of the unpadded message. Tests compare this generator with the NTT and check
small minors. The argument also holds after extension to GF(2^192).

Each witness value is sent as `w + m` with an independently sampled committed
mask. Dot-product blends and the Hadamard residual have additional random
masks; their nonzero challenge coefficients are necessary for hiding. This
alone is not a simulator for the entire correlated view.

For the multiplication-vector claims, append `(r,s,rs)` and
`(r+1,t,(r+1)t)` for independent uniform `r,s,t`. With their powers-of-challenge
weights `a,b`, the three padding contributions are

```text
A = a*r + b*(r+1)
B = a*s + b*t
C = a*r*s + b*(r+1)*t
```

For challenge different from zero and one, `a`, `b`, and `a+b` are nonzero.
The inverse is `r=(A+b)/(a+b)`, `s=((r+1)*B+C)/a`, `t=(C+r*B)/b`.
Thus these three contributions are jointly uniform in characteristic two.
The code tests this inverse. The multiplication commitment is absorbed **before**
sampling the linking challenge, so its vectors cannot adapt to that challenge.

Still required: a complete joint simulator for both commitments, full blends,
product residual, opened rows and authentication paths; explicit conditioning
on rejection-sampled challenges; adaptive queries and commitment-view hiding;
the random-oracle and lifetime leaf/salt budgets; and composition with the
eventual hiding oracle/WHIR adapter. These are security obligations, not claims
that statistical tests establish ZK.

## Soundness and remaining integration

The report's two coding diagnostics exclude the full Hadamard reduction,
candidate-list and extraction losses, algebraic-constraint batching,
Fiat–Shamir compilation, hash assumptions and aggregation composition.
`end_to_end_security_bits` is deliberately null. A 192-bit field and a 160-bit
query target do not discharge those obligations. Keccak-256's conventional
128-bit classical collision limit and its quantum limitations remain unchanged.

The remaining implementation is specific:

1. Introduce the shared VEIL reading/sending/constraint interface at native
   MultiStark's transcript boundary: oracle commitments, product-bus GKR,
   zerocheck/sumcheck, terminal evaluations and opening reductions. Challenges
   must come from the **masked** transcript; masking an already-created ordinary
   proof after the fact is invalid.
2. Implement the binary hiding oracle adapter. Budget every ordinary, batched
   and out-of-domain WHIR query, constrain the connection to the small inner
   proof, and establish simulation for their joint view. Preserve or explicitly
   account for the packed Keccak bit representation.
3. Add a native Poly64/Poly192 recursive verifier for the **complete new format**,
   including the inner argument and oracle links. Bind trusted authority, all
   child public values, count and order. The existing non-ZK native verifier
   does not enforce these additional checks.
4. Analyze the whole composition with a maximum batch size, then benchmark
   the final parameters. Keep the outer argument non-ZK and give it only child
   proofs and public statements.

The existing non-ZK aggregate remains available as a separate correctness
baseline. No Boolean shortcut, witness-sharing API or relabeling of that
aggregate is used to claim completion here.

## Reuse and source pins

Plonky3 and recursion pins are unchanged from the main README. Five existing
Plonky3 crates are now direct dependencies for transforms, MMCS and Keccak.
No new cryptographic dependency or change to the vendored recursion was added.

VEIL source reference:
[`749b0c63f226063c471a6238a94101f930c14a13`](https://github.com/succinctlabs/sp1/tree/749b0c63f226063c471a6238a94101f930c14a13/slop/crates/veil).
The port follows its dot-product, Hadamard and inner-constraint structure, with
the documented binary code, transcript and parameter adaptations. Its original
two-adic encoding and internal 100-bit target are not used. The applicable
[MIT notice](licenses/VEIL-MIT.txt) is retained.

References: [VEIL paper](https://eprint.iacr.org/2026/683),
[authors' overview](https://blog.succinct.xyz/veil/), and
[formal development](https://github.com/succinctlabs/veil-formal-verification).
None of these sources certifies this new Rust adaptation or its parameters.
