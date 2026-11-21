# Ethereum verification cost for the current root proof

The stronger midpoint profile verifies the 64-client native root directly in Solidity for **104,570,178 gas** with the independent row certificate, or **106,637,610 gas** with direct row folds. The comparison profile takes **99,956,986 gas** with direct row folds on the same public statement. These are high-limit local Prague receipts including calldata. The settlement target is **11,000,000 gas**. The separate binary LeanVM terminal below has a measured polynomial-opening cost and still requires onchain execution checks. [Full-root measurements](#selecting-the-midpoint-terminal-security-profile) · [Solidity entry point](../crates/evm-verifier/contracts/imt/NativeAggregateRootVerifier.sol) · [Transaction gas limit](https://eips.ethereum.org/EIPS/eip-7825)

## LeanVM recursion benchmark defaults

`cargo bench --locked --bench leanvm-recursion` runs the experimental binary-field prover at LeanVM commit `73c2cc094c0be4a1c5af6ec613e8021c9e16da87`. It uses the sibling `../leanVM` checkout when available and fetches the pinned commit otherwise. The workload uses 64 distinct synthetic preimages in one growing depth-32 Keccak IMT. Each proof opens a different leaf against a different root. Parents check two child proofs, preserve child order, enforce equal counts and batch the deferred bytecode claims. The native verifier evaluates the final deferred claim against the pinned guest. A second process verifies the saved root against the digest and count computed using the main Rust crate. [Benchmark](../benches/leanvm-recursion.rs) · [Recursive guest](../adapters/leanvm/recursion/imt_guest.py) · [Upstream recursive verifier](https://github.com/leanEthereum/leanVM/blob/73c2cc094c0be4a1c5af6ec613e8021c9e16da87/guests/lean_ethereum.py)

The benchmark defaults to five worker threads (`IMT_THREADS` overrides this), sequential parents, client WHIR rate 1/4 and merge rate 1/2 through the root. All five M2 Pro runs produced a 277,552-byte root. Client time includes synthetic tree and path preparation. Native verification includes the deferred bytecode check with an initialized guest and excludes process startup and decoding.

| M2 Pro run | All 64 clients | All 63 merges | Final merge | Native root verification |
| --- | ---: | ---: | ---: | ---: |
| Initial measurement | 4.622 s | 23.327 s | 0.472 s | 11.825 ms |
| Standalone CLI repeat | 5.198 s | 43.638 s | 0.912 s | 31.444 ms |
| Cargo benchmark | 12.617 s | 31.748 s | 0.732 s | 14.688 ms |
| Reviewed Cargo benchmark repeat | 6.482 s | 40.085 s | 0.843 s | 15.540 ms |
| After adding both optional terminal encodings | 5.578 s | 27.914 s | 0.594 s | 14.867 ms |

| Final WHIR rate, same saved children | Root proof bytes | Final merge in individual runs | Proof-only calldata floor including base gas |
| --- | ---: | ---: | ---: |
| 1/2 (benchmark default) | 277,552 | 0.472–0.912 s | 10,903,180 |
| 1/4 | 197,584 | 1.171 s | 7,803,970 |
| 1/16 | 152,320 | 2.532 s | 6,037,060 |

The smaller rates change the WHIR encoding of the final merge only. All three roots verified against the same application digest and count in separate processes. The gas column prices the serialized proof bytes under EIP-7623. A contract call also carries its ABI and statement, and actual gas depends on verifier execution. Solidity verification of this LeanVM proof format is unmeasured. [Ethereum calldata rules](https://eips.ethereum.org/EIPS/eip-7623)

The default benchmark leaf proves the preimage relation with a non-hiding proof. Its upstream Fiat–Shamir schedule targets 125 bits per round. Production use requires statistically ZK client proofs, a proven 128-bit bound across the recursive argument and a full Ethereum verification receipt under 11 million gas. The repo’s masked-client demo and keyed Solidity profiles use their own proof formats. [LeanVM proof model](https://github.com/leanEthereum/leanVM/blob/73c2cc094c0be4a1c5af6ec613e8021c9e16da87/AGENTS.md#what-this-is) · [LeanVM soundness target](https://github.com/leanEthereum/leanVM/blob/73c2cc094c0be4a1c5af6ec613e8021c9e16da87/crates/verifier/src/transcript.rs#L92-L96) · [Client privacy requirements](binary-security.md#production-acceptance-criteria)

To retain the proofs or try a different final rate, use fresh paths for the build and output. Each `.imt` bundle contains a 32-byte digest, a one-byte count and the serialized proof.

```sh
work=$(mktemp -d)
CARGO_TARGET_DIR="$work/target" python3 adapters/leanvm/recursion/prepare.py --work "$work/src"
bin="$work/target/release/imt-recursion"
"$bin" benchmark --out "$work/batch"
"$bin" merge "$work/batch/left.imt" "$work/batch/right.imt" 4 "$work/compact.imt"
"$bin" verify "$work/compact.imt" dc2c73b09aa834e78f5d05f326e751caffa47c50b7c427e4638cf388e43787f3 64
```

## Masked client recursion in LeanVM

The masked pair uses the pinned recursive program `7158a6b4e17788f1b6a6fef2f16b29ec914155515fa030d55de9531b4d1c5507`. Its leaf branch verifies a serialized masked preimage proof. On the same two saved recursive leaves the ordinary merge took 0.897 s for 286,416 bytes and the terminal merge at rate 1/32 took 7.838 s for 143,044 bytes. Independent native verification accepted each against the ordered two-root list. The bare terminal proof has an EIP-7623 calldata floor of 5,696,980 gas, including transaction base gas. [Client and recursive leaf measurements](binary-security.md#masked-client-verifier-in-leanvm) · [Calldata floor](https://eips.ethereum.org/EIPS/eip-7623)

On local Osaka, Solidity checked the terminal polynomial opening for **16,500,033 gas**, or **16,503,834 gas** with the ordered list of both client roots. These are successful transactions including calldata. The replay rejected 36 modified proof or statement calls and separately rejected swapped, duplicated and truncated lists. The three external inputs are the deferred bytecode evaluation, the opening target and the basis evaluation. Deriving or authenticating them onchain is required for a full verifier. This opening alone costs 5,503,834 gas above the 11M verification budget. The masked-pair profile pins the program, count and trace geometry. [Solidity opening](../crates/evm-verifier/contracts/binary/BinaryTerminalOpenings.sol) · [Checked fixture](../crates/evm-verifier/profiles/binary-masked/test/BinaryMasked.t.sol)

The `checkRootListStackOpening` entry point derives both the opening target and the terminal basis from the transcript. Solidity reconstructs the public memory claims from the root-bound input, evaluates the 64-slice ring switch, and batches the committed columns and OOD claim in native order. A fixed helper contract evaluates the basis over columns sharing a placement or evaluation point. The caller still supplies the deferred bytecode evaluation. A full verifier also needs to check that the values read from the transcript satisfy the VM execution, bus and Keccak identities. [Target](../crates/evm-verifier/contracts/binary/BinaryStackTarget.sol) · [Basis](../crates/evm-verifier/contracts/binary/BinaryStackBasis.sol)

On the same two-client terminal proof, deriving the target cost **19,089,965 gas** for the root-list transaction. Deriving both target and basis cost **24,495,474 gas**. Both receipts include calldata on high-limit local Prague. These transactions exhausted the ordinary Osaka cap. A separately generated valid terminal proof with the children in reverse order used **24,421,271 gas** with its own ordered list. Both native traces produced byte-identical Solidity schedules. Each EVM replay rejected a swapped, duplicated or truncated public list.

Run `FOUNDRY_PROFILE=binary-masked forge test --root crates/evm-verifier` with Foundry 1.5.1 to exercise the saved pair. The Anvil replay accepts its terminal bundle, the instrumented native verifier trace and the CLI's ordered public statements. Add `--derive-stack` to `--roots statement.json` to verify both reductions. To regenerate the static schedule, apply `scripts/binary_terminal/trace.patch` and then `scripts/binary_terminal/stack.patch` from the EVM crate to the prepared native verifier, replay `verify-terminal`, and run `python3 scripts/binary_terminal/profile.py TRACE BUNDLE` from the crate directory.

## Binary LeanVM terminal transcript and opening

The experimental `terminal-merge` command proves the last merge with a domain-separated Keccak-256 hash chain. Its guest verifies both saved 32-client proofs using their original transcript. Two terminal encodings verified natively against the benchmark’s ordered 64-client digest. Regenerating both from the same children produced byte-identical proofs. Their finite Johnson query schedules use the upstream 125-bit per-round target. A security analysis for the modified transcript and a statistically ZK client remain open. [Rust adapter](../adapters/leanvm/recursion/prover.rs) · [Terminal transcript](../adapters/leanvm/recursion/terminal-transcript.patch) · [Narrower first fold and query derivation](../adapters/leanvm/recursion/terminal-compact.patch)

| Terminal WHIR rate | First fold | Root proof bytes | Final merge, matched five-thread run | Transcript, grinding and Merkle checks | Those checks plus full WHIR polynomial opening |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1/16 | 6 variables | 151,616 | 4.680 s | 6,013,000 gas | 19,410,804 gas on high-limit Prague |
| 1/32 | 4 variables | 142,180 | 9.243 s | 5,665,960 gas | **16,497,923 gas on ordinary Osaka** |

All gas figures include calldata. At rate 1/32 the first committed row shrinks from 64 to 16 base-field elements. The verifier checks 141 query draws across five levels, compared with 144 at rate 1/16. Both Merkle-only calls reached their calldata floors. The complete polynomial check at 1/16 exceeded the ordinary transaction cap. Both contracts fit Ethereum’s deployed code-size limit at 15,964 and 15,974 bytes, respectively. The replay rejected 34 altered Merkle calls and 36 altered polynomial-opening calls per encoding. [Solidity entry points](../crates/evm-verifier/contracts/binary/BinaryTerminalOpenings.sol) · [Pinned WHIR verifier](https://github.com/leanEthereum/leanVM/blob/73c2cc094c0be4a1c5af6ec613e8021c9e16da87/crates/verifier/src/whir.rs) · [Calldata floor](https://eips.ethereum.org/EIPS/eip-7623)

The polynomial verifier takes three values from the checked Rust execution: the deferred bytecode evaluation, the opening target and its basis evaluation. Full root settlement requires Solidity to derive or authenticate all three, including the execution, bus, Keccak and ring-switch constraints. The 16.50M receipt covers the opening component alone and already exceeds the 11M target.

The public-roots entry point accepts the 64 IMT roots in client order. Solidity hashes each root with the two reserved zero fields, combines adjacent pairs with their child counts, and binds the result to the polynomial opening. For the exact roots saved by `cargo prove`, this cost **16,602,641 gas** including calldata on ordinary Osaka at rate 1/32. The replay rejected a swap, a duplicate replacing a distinct root, and a truncated list. The externally supplied reduction values and non-hiding client remain part of this experimental path. [Statement encoding](../crates/evm-verifier/contracts/ImtBatchStatement.sol) · [Root-list test](../crates/evm-verifier/test/BinaryTerminal.t.sol)

To replay the transaction with Foundry on the path, use the saved children and isolated build directory from the benchmark commands above. The trace patch records the native intermediate values for the comparison.

```sh
"$bin" terminal-merge "$work/batch/left.imt" "$work/batch/right.imt" "$work/terminal.imt"
git -C "$work/src" apply "$PWD/crates/evm-verifier/scripts/binary_terminal/trace.patch"
(cd "$work/src" && CARGO_TARGET_DIR="$work/target" cargo build --locked --release -p aggregation --bin imt-recursion)
"$bin" verify-terminal "$work/terminal.imt" dc2c73b09aa834e78f5d05f326e751caffa47c50b7c427e4638cf388e43787f3 64 2>"$work/terminal.trace"
(cd crates/evm-verifier && forge build contracts/binary/BinaryTerminalOpenings.sol)
python3 -B crates/evm-verifier/scripts/replay_binary_terminal.py "$work/terminal.imt" "$work/terminal.trace"
python3 -B crates/evm-verifier/scripts/replay_binary_terminal.py "$work/terminal.imt" "$work/terminal.trace" --whir
```

To reproduce the narrower profile, run the following commands with the same instrumented verifier.

```sh
"$bin" terminal-merge "$work/batch/left.imt" "$work/batch/right.imt" 5 "$work/narrow.imt"
"$bin" verify-terminal "$work/narrow.imt" dc2c73b09aa834e78f5d05f326e751caffa47c50b7c427e4638cf388e43787f3 64 2>"$work/narrow.trace"
(cd crates/evm-verifier && FOUNDRY_PROFILE=binary-compact forge test)
python3 -B crates/evm-verifier/scripts/replay_binary_terminal.py "$work/narrow.imt" "$work/narrow.trace" --whir
```

To replay the list-input transaction on the same proof, save the 64-client synthetic CLI run with `cargo prove --keep --out run/pool-roots` and pass `--roots run/pool-roots/statement.json` in place of `--whir` in the last command.

## Selecting the midpoint terminal security profile

The Rust prover exposes `PreparedTerminalMerge::with_midpoint_profile`. Its CLI accepts `terminal-merge --midpoint --security-profile strong` or `comparison`. Omitting the profile keeps the existing strong verifier identity and proof format. Each protocol binds its own identity into preprocessing and the Fiat–Shamir transcript. Ethereum deployments pin the corresponding opening bytecode. An application enforces its security floor by pinning the verifier address. Accepting either address for one settlement rule gives submitters access to the comparison policy.

The same two existing child bundles can produce either root. Give each output its own directory. To produce the strong root, change `comparison` to `strong` and supply a fresh output directory.

```sh
cargo run --release --locked --bin terminal-merge -- \
  "$LEFT_SUBTREE" "$RIGHT_SUBTREE" --child-key "$CYCLIC_KEY" --child-trusted "$CYCLIC_TRUSTED" \
  --midpoint --security-profile comparison --out "$COMPARISON_BUNDLE"
```

| Same 64-client statement | Strong | Comparison |
| --- | ---: | ---: |
| Local WHIR target / maximum grinding bits | 152 / 16 | 125 / 17 |
| Checked conditional terminal bound | 145.96 bits | 121.48 bits |
| WHIR query counts across five sites | 71, 35, 26, 20, 17 | 56, 28, 20, 16, 13 |
| Final merge wall time, one paired run on five threads | 74.66 s | 79.94 s |
| Compressed Rust root proof | 316,380 B | 275,316 B |
| EVM calldata with fixed cap and ring certificate | 314,724 B | 276,164 B |
| Transaction calldata floor | 12,464,520 gas | 10,930,040 gas |
| Complete Solidity transaction, high-limit Prague | 106,637,610 gas | 99,956,986 gas |
| Shared-opening component, inclusive execution | 41,214,059 gas | 35,230,144 gas |

The two deployments rejected each other’s valid proof of the same statement. Rust also rejected both exchanged proofs and relabelled keys. The lower profile reduces the full transaction by 6.26%. The arithmetic and Keccak relation costs 49,670,148 gas and the column reduction 10,039,001 gas for each profile. Those two checks alone consume 59,709,149 execution gas before the polynomial opening or transaction calldata. Reducing the opening query count cannot bring this verifier under 11M. These measurements cover the final merge of two existing 32-client subtrees. The paired wall times exclude setup and include witness import, proving and the prover’s verification. A single comparison on a shared machine does not establish a timing trend. In the bundle report, `summary.terminal_conditional_algebraic_bits` gives the verified terminal bound. The security fields under `geometry` describe the underlying preprocessing configuration.

The parameter search fixes the root geometry and maximum grinding budget, derives each candidate’s query schedule with the finite Johnson bound, and checks the combined terminal algebraic error. It tries local targets 120 through 152 in ascending order at a grinding cap of 16 or 17. At cap 17 the first passing local target is 125 for a 121-bit floor and 132 for a 128-bit floor (128.54 conditional bits). The search reports candidates offline. Deploying a new policy requires a new trusted protocol identity. The strong profile retains a 144-bit conditional acceptance floor. End-to-end 128-bit knowledge soundness also requires the recursive Fiat–Shamir analysis. The client statistical-ZK proof remains open. [Security accounting](binary-security.md#production-acceptance-criteria) · [LeanVM’s per-round parameter derivation](https://github.com/leanEthereum/leanVM/blob/a38d0f16e7816a780fd61967bcc74949f7606ea4/crates/experimental_prover/pcs/src/whir_config.rs)

Run the selector on a saved midpoint root and inspect `selected_parameters` in its JSON output.

```sh
cargo run --release --locked --features opening-bench --example root-opening-trace -- \
  --bundle "$ROOT_BUNDLE" --trusted "$TRUSTED_ROOT" \
  --select-conditional-bits 128 --max-grinding-bits 17 > root-trace.json
```

The normal replay selects the Solidity build from the independently trusted protocol. The `comparison` Foundry profile compiles the same verifier code against its own fixed WHIR constants. To verify the comparison root, supply its trace and trusted metadata to the native replay with the same fixed-cap and ring-certificate flags used for the strong root. The `--save-call` and `--reject-other-profile-call` options exercise cross-profile rejection. [Replay](../crates/evm-verifier/scripts/replay_native_root.py) · [Foundry profiles](../crates/evm-verifier/foundry.toml)

## End-to-end Solidity measurement

| Complete 64-client verification on diagnostic Prague | Calldata | Transaction calldata floor | Receipt gas |
| --- | ---: | ---: | ---: |
| Four-variable folds, original 24-layer proof with upper fixed cap | 339,140 B | 13,441,550 | 169,872,559 |
| Midpoint proof, ordinary Merkle paths | 317,572 B | 12,583,180 | 145,557,171 |
| Midpoint proof, upper fixed cap | **304,708 B** | **12,069,820** | 144,949,216 |
| Midpoint proof, upper fixed cap and ring-weight certificate | 314,724 B | 12,464,520 | 125,731,595 |
| Same certified proof, revised carryless multiplication | 314,724 B | 12,464,520 | 116,642,739 |
| Same proof, strided Merkle reads before the first shared parent | 314,724 B | 12,464,520 | 116,165,184 |
| Same certified proof, shared midpoint round-constant weights and basis sums | 314,724 B | 12,464,520 | **112,455,912** |
| Same native root, independent 19-variable row certificate | 443,108 B | 17,567,030 | **110,459,668** |
| Same native root, row certificate under the shared 26-variable table | 484,292 B | 19,200,290 | 112,062,729 |
| Same native root, both Keccak and fold relations in one WHIR opening | 534,500 B | 21,215,540 | 115,641,889 |
| Strong, factored arithmetic constraints and direct row folds | 314,724 B | 12,464,520 | **106,637,610** |
| Strong, factored arithmetic constraints and independent 19-variable row certificate | 443,108 B | 17,567,030 | **104,570,178** |
| Strong, authenticated row digests with a joint 22-variable certificate | 443,012 B | 17,573,480 | 108,972,714 |
| Comparison, factored arithmetic constraints and direct row folds | 276,164 B | 10,930,040 | **99,956,986** |

The arithmetic verifier now groups bus reads by address prefix and shares the multilinear interpolation across reads. Runs of identical constraints share powers of the challenge in their Horner evaluation. This reduces full extension-field multiplications in the fixed arithmetic program from 4,387 to 2,624. Replaying identical strong and comparison calldata saved 5,905,141 gas on each direct verification. Both runs reproduced all 134 opening claims from Rust. The strong run with the independent row certificate also reproduced those claims and rejected 17 changes to the statement or proof. [Arithmetic compiler](../crates/evm-verifier/scripts/compile_native_air.py) · [Pinned verifier program](../crates/evm-verifier/contracts/imt/NativeAirClosingVerifier.sol)

The midpoint profile commits the input and state after round 12 as the two halves of one bit table. The output occupies its own table. The verifier samples the segment coordinate after absorbing both boundary evaluations. Twelve GKR layers check both halves with their respective round constants. Five authenticated evaluations link the segments to each other and to the arithmetic hash ports. The Rust verifier and Solidity derived identical coordinates and values for all 134 ordered polynomial-opening claims. The certified call rejected all eleven mutations, including changes to the midpoint, the final Keccak layer, the certificate and the WHIR closing. The direct row-fold receipt attributed 55,575,289 gas to arithmetic and Keccak, 10,039,001 gas to column reduction and 41,127,220 gas to the shared opening. [Native reduction](../crates/flock-backend/src/checkpoint_keccak/packed/linked.rs) · [Solidity boundary](../crates/evm-verifier/contracts/imt/NativeKeccakBoundaryVerifier.sol) · [Certificate soundness](#certified-ring-weight-and-complete-keccak-boundary)

The midpoint rounds use the same bit-coordinate weights for the two round constants. Computing the table once per layer and applying its common embedding after combining the constants saves one table construction and one embedding evaluation. In characteristic two the equality-basis entries sum to one, as do the entries of their cyclic correlation. Each split can recover one child product from the known total and its siblings. Together these changes saved **3,709,272 gas** on the direct calculation with identical calldata. [Round verifier](../crates/evm-verifier/contracts/imt/NativeKeccakRounds.sol) · [Native row folds](../crates/evm-verifier/contracts/imt/NativeFold.sol)

The shared Merkle routine reads unpaired paths with a fixed stride until the first level at which two queried nodes can share a parent. The cheapest native receipt fell by **477,555 gas** on identical proof bytes. On the prime-field Keccak component the same change lowered the receipt from **10,336,646 to 9,974,734 gas**. All siblings are still consumed in their original level order and checked against the pinned root. [Merkle implementation](../crates/evm-verifier/contracts/KeccakFrontier.sol) · [Differential path test](../crates/evm-verifier/test/NativeMerkle.t.sol)

A transaction-level opcode trace of the complete certified midpoint verifier counted **6,630 Keccak-256 calls**, or **9,905 Keccak-f permutations** after accounting for input length and padding. The shared opening module contributed 4,608 permutations. This gives a hash workload for an alternative terminal that checks one already aggregated native proof. The direct terminal circuit currently checks two 32-client proofs and uses 43,342 permutations. A proof of the single-native-verifier approach must also enforce native transcript derivation, Poly64/Poly192 arithmetic, all Merkle and algebraic identities, fixed verifier authority, and the expected digest and count. The EVM uses ordinary integer operations to implement its binary-field polynomial arithmetic, so the absence of `MULMOD` in that trace says nothing about guest multiplication cost. A full-root LeanVM cycle count and an EVM receipt for that alternative remain unmeasured. Reproduce with `--hash-profile --ring-certificate --fixed-cap` in the native root replay. [Profiler](../crates/evm-verifier/scripts/verifier_work.py) · [Native replay](../crates/evm-verifier/scripts/replay_native_root.py)

On the same two 32-client subtrees, five M2 Pro threads produced the midpoint proof in 45.33 seconds with 316,380 compressed bytes and 332,791 raw bytes. Four-variable folds without the midpoint took 49.07 seconds with 351,600 compressed bytes in an earlier run. These are individual final-step timings. The client and interior proofs were reused. The midpoint profile retains the Johnson schedule, 152-bit local target and 16-bit maximum grinding. Its calculated terminal algebraic margin is 145.96 bits. The 125-bit local comparison with 17 grinding bits produced 121.48 bits on this geometry. Both calculations condition on the model in the security report. The statistical-ZK and recursive Fiat–Shamir knowledge proofs remain open. [Security accounting](binary-security.md#production-acceptance-criteria)

Sharing the in-place binary Merkle reduction across the two Solidity backends and sorting transcript query offsets directly lowered the certified full receipt from 126,174,918 to 125,731,595 gas on identical calldata. The Rust proof bytes and Fiat–Shamir query order are identical. [Shared Merkle reduction](../crates/evm-verifier/contracts/KeccakFrontier.sol) · [Native query ordering](../crates/evm-verifier/contracts/imt/NativeFold.sol)

The native base-field multiplier packs binary polynomial coefficients into four radix-16 residue classes. A digit can overflow only when both contributing classes contain all sixteen monomials. In that case two known parity bits require correction. Checking for saturated classes saved **9,088,856 gas** on the same complete proof. An independent polynomial long-multiplication test covers all 256 pairs of saturated-class masks and single-bit perturbations. The optimization runs entirely in Solidity. [Native field arithmetic](../crates/evm-verifier/contracts/imt/NativeField.sol) · [Differential tests](../crates/evm-verifier/test/NativeField.t.sol)

Generate the new bundle with `terminal-merge --midpoint` using the same child key and two 32-client bundles as the four-variable comparison. Export its trace with `root-opening-trace`. The replay accepts `--fixed-cap FILE` for the depth-12 fixed cap and `--ring-certificate` for the certified path. Omitting both measures ordinary Merkle paths and the direct ring calculation. [Fixed cap exporter](../examples/root-wiring-cap.rs) · [Replay script](../crates/evm-verifier/scripts/replay_native_root.py)

### Certifying the native WHIR row folds

The complete Solidity verifier authenticates and folds 71 initial rows and 35, 26, 20 and 17 later rows. The initial rows concatenate the main and fixed binary-field coefficients. Each later row contains 16 cubic-extension elements. The alternative module derives the same 22 fold coordinates from the native transcript, authenticates the six Merkle trees, and uses one certified evaluation for each of the 169 rows. It checks the final additive-WHIR equations, all 134 claim points and values, the pinned authority and the caller's batch digest and count. Both complete certificate deployments rejected 17 altered statements or proofs. The 19-variable certificate reduced the shared opening module from 41,127,220 to 36,773,024 execution gas. Solidity reads four little-endian Poly64 words per calldata load when it binds the prime-field fingerprint. The net receipt saving against the direct calculation was **1,996,244 gas**. [Opening module](../crates/evm-verifier/contracts/prime/NativeLiftedOpening.sol) · [Complete root regression](../crates/evm-verifier/test/NativeLiftedRoot.t.sol)

The row proof lifts binary-field products to integer polynomials. For each output limb, let `T` be the integer convolution of the input bits with the derived weight bits, after reducing the cubic extension by `y³=y+1`. At a challenge sampled after commitment the verifier checks `T − C − (X⁶⁴+X⁴+X³+X+1)Q = 2E`. Here `C` is the claimed result and `Q` is a 64-bit polynomial. Three four-bit digits per coefficient encode `E+3`. The resulting coefficient differences have magnitude below 2¹⁴, so equality over the 192-bit prime field implies the required binary parity for an identically zero residual. For a fixed nonzero residual the degree is at most 127. A row-and-limb fingerprint binds the input words and output values, and two sumchecks reduce the range and identity constraints to one committed digit evaluation. Recommitting a changed result and changing the matching public value failed at the first sumcheck round in the native prover. Full recursive knowledge soundness and client statistical ZK remain open. [Witness construction](../crates/evm-verifier/scripts/prime_whir/native_fold_witness.py) · [Solidity constraints](../crates/evm-verifier/contracts/prime/NativeWhirFoldProof.sol)

| Row proof on the same native root | Independent row table | Shared hash and row table |
| --- | ---: | ---: |
| Variables in the commitment | 19 | 26 |
| Standalone Osaka verification, including 64,896 public input bytes | 8,680,956 gas | 10,099,985 gas |
| Standalone calldata | 194,244 B | 235,460 B |
| Standalone rejection cases | 12 | 12 |

The independent row prover and reference verifier took 1.72 s combined on five M2 Pro threads after witness export. For the shared table the driver replayed all 6,630 Keccak opcode inputs from the successful direct root transaction and independently checked every digest. They used 9,905 permutations, padded to 16,384. All 240 queried row preimages occur in the trace. The 2¹⁹ row-witness digits occupy unused lanes of the same 2²⁶-entry checkpoint polynomial. Its commitment took 158.88 s. Its opening took 95.31 s with cached initial Merkle subtrees. The full verifier still checks the Merkle paths and hash computations directly. Replacing them requires constraints binding the absorbed bytes, sponge continuation, Merkle child positions, expected caps and native transcript. Sharing storage gives a common opening target for those constraints. [Trace reconstruction](../crates/evm-verifier/scripts/prime_whir/native_hash_trace.rs) · [Row prover and reference verification](../crates/evm-verifier/scripts/prime_whir/native_fold_lift.rs)

The third deployment checks the 169 folds and all 24 rounds on each of the 16,384 allocated Keccak rows. The Keccak GKR prover took **24.72 s**, followed by **28.53 s** for its endpoint and digit sumchecks. The two reductions derive independent points on the same committed table. WHIR combines their evaluations and its out-of-domain sample with weights 1, γ and γ². The reference verifier checked both forms and the finite Johnson solver retained the 135-bit per-message target for this configuration. The paired opening used **1,784 transcript bytes and 160,904 hint bytes**, taking **96.16 s** on an already committed table. The row-only opening on the same table used 159,048 hint bytes. [Reference WHIR verifier](https://github.com/worldfnd/whir/blob/fe86de76fa5863bb82466c8a91a7f74a60f910ac/src/protocols/whir/verifier.rs) · [Paired opening](../crates/evm-verifier/contracts/prime/NativeTraceJointProof.sol)

The paired component used **13,437,067 gas** for 285,636 calldata bytes on ordinary Osaka and rejected 16 altered calls. Its **11,385,450 gas calldata floor** is above the entire settlement budget. The full native root with this additional check used **115,641,889 gas** and rejected 21 alterations. It still authenticates the 240 source-row hashes, native transcript and Merkle paths directly. The prime-field proof checks each permutation and both digit readings. The cross-row sponge absorption and the native Merkle path wiring remain enforced by the direct verifier. Replacing its input words with authenticated digests requires proving those connections inside the prime-field relation. The source rows account for 64,896 bytes and their 240 Keccak digests would occupy 7,680 bytes before accounting for that proof. [Paired regression](../crates/evm-verifier/test/NativeTraceJoint.t.sol)

A smaller 22-variable table covers the 169 row preimages and their 507 Keccak permutations. A separate Solidity component checks the initial states, rate absorption, capacity continuation, Ethereum padding, all 240 digest outputs, and digit ranges against one opening of that table. On ordinary Osaka its transaction took **8,053,730 gas**, including 143,556 calldata bytes with a 5,735,430 gas floor. It rejected nine altered calls. Independently changing one committed source digit, recomputing the commitment and keeping the original digests failed the Rust sumcheck at the first round. The combined version authenticates all 240 row digests, 507 Keccak permutations and 169 native folds. The complete strong Solidity verifier accepted the 64-client root under high-limit Prague and rejected 26 altered calls. It used 108,972,714 gas. Its calldata floor of 17,573,480 gas exceeds the ordinary Osaka transaction cap. Pass `--joint --save-fixture <fresh-directory>` to generate that certificate. Reproduce with `python3 crates/evm-verifier/scripts/bench_row_sponge_ports.py --trace "$TRACE"`. [Sponge relation](../crates/evm-verifier/contracts/prime/NativeRowSpongePorts.sol) · [Witness and replay](../crates/evm-verifier/scripts/bench_row_sponge_ports.py)

To reproduce with the JSON from `root-opening-trace`, the matching trusted key and the 131,072-byte fixed cap, run from the repository root. The first command exports Keccak witness data from a successful native root call. Include `--hash-trace hashes.json` in the second command to exercise the shared table. Add both `--hash-trace hashes.json` and `--prove-rounds` to generate the paired certificate. The final command checks the complete root and reports both forks.

```sh
python3 crates/evm-verifier/scripts/replay_native_root.py "$TRACE" --trusted "$KEY" --fixed-cap "$CAP" --ring-certificate --export-hash-trace hashes.json
python3 crates/evm-verifier/scripts/bench_native_fold_lift.py --trace "$TRACE" --save-fixture fold-proof
python3 crates/evm-verifier/scripts/replay_native_root.py "$TRACE" --trusted "$KEY" --fixed-cap "$CAP" --ring-certificate --fold-proof fold-proof
```

### Prime-field opening at a higher local target

A separate Osaka transaction verified a dense 22-variable KoalaBear polynomial opening at **16,059,780 gas** with 125,092 bytes of typed calldata. Its calldata floor was 4,394,440 gas. The target was 135 bits for WHIR with the Johnson bound and full 32-byte Keccak Merkle digests, giving 128-bit generic collision strength. The exporter accepted a degree-eight extension, initial rate 1/64, folding factor 4, initial Reed–Solomon domain reduction 3 and a maximum of 20 grinding bits. The query counts were 40, 34, 24 and 18. The upstream quintic checker rejected that same profile because the first folding step required 68 grinding bits. At 26 variables and rate 1/16, the octic checker also accepted a six-then-four folding schedule while the quintic checker required 69 initial grinding bits. These checks concern individual PCS schedules. They do not establish recursive knowledge soundness.

The Rust prover and verifier agreed on their transcript checkpoint. A linked Solidity library authenticates the full-width Merkle rows and computes their folds. The two contracts deployed under standard code-size limits and the verifier rejected a changed commitment and a changed proof. The upstream 10,666,368-gas figure covers a grouped program with different parameters. Its standalone octic reference uses a 100-bit local target and 20-byte Merkle digests. The upstream Spartan prover also caps its eight-element KoalaBear digest configuration at 123 bits. None of these benchmarks prices verification of the IMT relation in a prime field. Reproduce the dense measurement with `python3 crates/evm-verifier/scripts/bench_prime_whir.py`. [Benchmark and pinned changes](../crates/evm-verifier/scripts/bench_prime_whir.py) · [Upstream Solidity receipts](https://github.com/ethereum/sol-whir-p3/blob/b82359ec98e1e3c9f6f39ebf984e7aefb0eeb9be/README.md#latest-measurements) · [Upstream octic parameters](https://github.com/Client-Side-Proving/spartan-whir-export/blob/d533db1ec6ecabfd34535fac12de89f7f81e0423/src/octic_fixture.rs) · [Spartan security cap](https://github.com/ethereum/spartan-whir/blob/14d6da4211eda59e65cfd0af5e2dcd89d523edc3/src/security.rs#L16-L20)

A separate large-prime control tested the older `sol-whir` prototype using only modular field arithmetic and Keccak. With the fork's `ProvableList` switch, local target 135, log-inverse rate 4, fold 3 and 16 maximum grinding bits, the 20-variable honest opening used 6,053,346 gas on Osaka. At 22 variables the call used 6,992,818 gas, of which the transaction calldata floor was 6,393,830. All nine linked libraries deployed under ordinary size limits. The benchmark entry point accepts protocol parameters supplied by its caller. Its reference transcript resets its state on message reads, and its squeeze routines reuse state. These receipts establish an arithmetic and transport cost comparison only. A candidate for the IMT must pin the geometry and opening commitment, bind the application statement and use a cumulative transcript with independent challenges. The current WHIR reference includes finite Johnson bounds and a protocol-, session- and instance-bound transcript. [Historical Rust control](https://github.com/dmpierre/whir/blob/a3c91cea69c505198673775f9a273e1a3d75ef82/src/whir/mod.rs#L196) · [Historical transcript](https://github.com/privacy-ethereum/sol-whir/blob/b719b97b5961ac1c1679383b31e55439a26682f9/src/fs/FiatShamir.sol) · [Current decoding bounds](https://github.com/worldfnd/whir/blob/fe86de76fa5863bb82466c8a91a7f74a60f910ac/src/protocols/params/regime.rs) · [Current transcript](https://github.com/worldfnd/whir/blob/fe86de76fa5863bb82466c8a91a7f74a60f910ac/src/transcript/mod.rs)

### Large-prime opening on the actual terminal checkpoint table

Solidity verified a multilinear opening of the native 64-client root’s Keccak checkpoint table for **7,017,857 gas** on an ordinary Osaka chain. The input to the reference Rust prover came from the two saved 32-client subtrees. Regenerating the midpoint root produced the same compressed proof, with SHA-256 `e7b542444741808a7ac4f003bb4c93de9b0d60da235d63eca4dfe3ff69431004`. The native witness builder checked the input and output wires for 43,342 Keccak permutations and exported 65,536 rows including padding. Each row contains its input, state after round 12 and output. A row occupies 64 prime-field elements. Each checkpoint uses 13 elements to hold pairs of little-endian 64-bit lanes in a 16-element region. The fourth region is zero. This places the three states in one 22-variable multilinear polynomial. [Native witness export](../crates/flock-backend/src/witness.rs) · [Table encoding and Rust verifier](../crates/evm-verifier/scripts/prime_whir/dense_opening.rs)

| Table opened, one evaluation | Rust commitment and opening, five threads | Solidity call bytes | Transaction calldata floor | Osaka receipt |
| --- | ---: | ---: | ---: | ---: |
| Actual terminal checkpoints | 13.11 s | 161,188 | 6,383,620 | **7,017,857** |
| Dense independent field values, seed 42 | 14.55 s | 159,940 | 6,391,300 | 7,025,519 |
| Dense independent field values, seed 43 | 14.27 s | 160,484 | 6,413,450 | 7,028,734 |

The Solidity contract checks the expected commitment, all 22 sumcheck rounds, seven grinding nonces, authenticated rows from seven Merkle trees, the disclosed final vector and the final multilinear identity. Its fixed protocol identifier binds the upstream configuration. Its application instance commits to a context, 22 coordinates and the claimed evaluation before the first challenge. For the checkpoint run the context includes the native verifier key digest and the ordered 33-byte root statement. The replay prices one opening at a reproducible externally supplied point. Each of the three runs rejected ten changes to the statement and proof. [Solidity verifier](../crates/evm-verifier/contracts/prime/PrimeWhirOpeningVerifier.sol) · [Reproduction script](../crates/evm-verifier/scripts/bench_large_prime_opening.py)

The new implementation uses the 254-bit prime as an arithmetic field. The commitments, transcript and grinding use Keccak with 32-byte digests. It pins the current WHIR reference at `fe86de76`, local target 135, finite Johnson decoding, initial rate 1/16, three-variable folds and 16 maximum grinding bits. The 135-bit figure targets individual WHIR steps. The closing check follows the reference verifier’s domain restriction that the final folded polynomial evaluation be nonzero. [Reference verifier](https://github.com/worldfnd/whir/blob/fe86de76fa5863bb82466c8a91a7f74a60f910ac/src/protocols/whir/verifier.rs) · [Parameter bounds](https://github.com/worldfnd/whir/blob/fe86de76fa5863bb82466c8a91a7f74a60f910ac/src/protocols/params/regime.rs) · [Spongefish transcript](https://docs.rs/crate/provekit-spongefish/0.2.0/source/src/instantiations/hash.rs)

For the full root, a prime-field relation must bind the commitment to the two child verifications, enforce their wiring, constrain the packed lanes through every Keccak round, and derive the opening claims from the application statement. The checkpoint receipt leaves a nominal 3,982,143 gas to reach 11M on this input. Constraining those relations can change the number of variables and the proof size. The complete native root still uses the binary-field verifier measured above. [Native recursive relation](../src/binary/aggregation_tree/terminal.rs) · [Production security requirements](binary-security.md#production-acceptance-criteria)

To reproduce, add `--save-keccak-checkpoints` to the `terminal-merge --midpoint` command with the `opening-bench` Cargo feature. Run the following from the repository root with an Osaka-capable Anvil and Forge on `PATH`. Omit `--terminal` to reproduce the seed-42 dense comparison.

```sh
python3 crates/evm-verifier/scripts/bench_large_prime_opening.py --terminal "$TERMINAL_BUNDLE"
```

### Binding the ordered parent to the checkpoint table

A separate Solidity entry point verified the final node’s hash input and 256-bit digest in both native child-verifier instances for **7,133,812 gas** on Osaka. The call carried 160,196 bytes and its calldata floor was 6,362,660 gas. On five M2 Pro threads the Rust commitment and port proof took 13.08 seconds in a separate run that produced the same proof bytes. This is a constraint on the real 64-client root witness. Checking the inner child verifiers and the other Keccak calls remains necessary before this entry point can contribute to settlement. [Node port verifier](../crates/evm-verifier/contracts/prime/TerminalNodePortsVerifier.sol)

The Rust driver reconstructed the two 32-client digests from all 64 public leaf records. Solidity recomputed the ordered parent with Ethereum Keccak and compared it with the supplied parent. For the pinned native verifier key the two copies of that hash call occupy rows 21,670 and 54,438. In this layout the first 16 fields of each row contain the full padded permutation input, the two packed words of the returned digest, and one zero. The driver moves the first two output words into two unused input-region slots. The EVM derives the expected 16 fields itself. [Reference fixture generator](../crates/evm-verifier/scripts/prime_whir/dense_opening.rs)

After fixing the commitment and the application statement, five Fiat–Shamir challenges select an evaluation of the two-by-sixteen port table. One coordinate mixes both child roles and four coordinates mix the 16 fields. The other coordinates select the fixed node row and port region. A discrepancy in any entry gives a nonzero multilinear difference of total degree at most five. For independent uniform challenges its probability of vanishing is at most five divided by the field size. The contract obtains each coordinate by reducing 512 domain-separated hash bits modulo the prime. This calculation concerns the port equality. Commitment binding, Fiat–Shamir and the rest of the recursive argument have their own security requirements.

The contract accepted the genuine witness and rejected eleven mutations, including swapping both children and supplying the correctly recomputed parent for the new order. Reproduce the call with `python3 crates/evm-verifier/scripts/bench_large_prime_opening.py --terminal "$TERMINAL_BUNDLE" --node-ports`. The checked-in regression also runs with `forge test --root crates/evm-verifier --match-contract TerminalNodePortsTest`. [Regression test](../crates/evm-verifier/test/TerminalNodePorts.t.sol)

### Three-round Keccak segments

The Rust prover packs nine 200-byte Keccak states into one 64-element row. Each state takes seven little-endian field elements of at most 240 bits. Each segment holds seven chunks of its input. The eighth column stores one chunk of the last output across the first seven segments. Intermediate states occur once, so the output reading of one segment and the input reading of its successor select the same table entries. The 65,536 rows occupy one 22-variable polynomial. The exporter checked the round-12 and round-24 states of every row against the independently generated native witness. [Packing and linear form](../crates/evm-verifier/scripts/prime_whir/support/segments.rs)

In the first ordinary Osaka measurement the public checkpoint verifier cost **7,787,052 gas**, including **159,268 calldata bytes** with a **6,349,390 gas floor**. The commitment and opening took 15.05 seconds on five M2 Pro threads, excluding table construction. A straightforward loop for the same public Keccak computations used 9,568,252 gas on identical calldata. The optimized verifier computes the two public permutations and checks all nine checkpoints at the two final-node rows and at the 22,194 padding rows via one random evaluation. Two further random evaluations authenticate the input and output tables of all 524,288 segments. Solidity derives the points from the ordered parent, both children, the native key and the commitment. It binds the two claimed readings before sampling their batching coefficient. [Solidity verifier](../crates/evm-verifier/contracts/prime/TerminalSegmentVerifier.sol) · [Keccak round implementation](../crates/evm-verifier/contracts/prime/KeccakSegmentRow.sol)

The genuine fixture passed and thirteen changed statements or messages reverted. In a separate test the reference prover committed a table with a changed intermediate checkpoint at padding row 54,443 and generated a valid WHIR proof of that table’s actual reading. The native WHIR verifier accepted that claim. Solidity derived the expected public value independently and rejected the proof. Run `python3 crates/evm-verifier/scripts/bench_large_prime_opening.py --segments --terminal "$TERMINAL_BUNDLE"` to generate and check the honest proof. [Regression tests](../crates/evm-verifier/test/TerminalSegment.t.sol)

The `--segment-output` entry point also reduces the authenticated output reading of the entire table to 25 Keccak lane-bit claims in the same transaction. All **524,288 segment outputs** contributed. In the first measurement Solidity verified the WHIR proof and the six extra quadratic sumcheck rounds in **8,052,764 gas**, including **160,452 calldata bytes** and a **6,396,630 gas floor**. The 1,184 additional bytes contain twelve sumcheck coefficients and 25 lane claims. The Rust prover computed the bit reduction in **1.20 seconds** using histograms indexed by byte position and value. This timing excludes the commitment and opening. For each of the six bit coordinates the verifier uses the known contribution of that bit to a 240-bit chunk. Every 16-bit block lies in one chunk, so all 25 closing weights factor through the same four low-coordinate evaluations. The returned point and all lane evaluations matched the reference calculation. Fifteen changed statements and proof messages reverted. This equality reduces the packed output claim to bit claims that the permutation proof still has to discharge. [Solidity output reduction](../crates/evm-verifier/contracts/prime/TerminalSegmentOutputVerifier.sol) · [Full-table regression](../crates/evm-verifier/test/TerminalSegmentOutput.t.sol)

A second implementation proves the three Keccak rounds for every segment position in one GKR reduction over the same prime field. It adapts Keccacheck’s seven sumchecks per round, uses a cumulative Keccak transcript and evaluates the round constant as a function of the three segment bits and six bit-position bits. The prover takes evenly spaced rows of the actual exported table, including padded rows, and checks both native checkpoints. Solidity checks every sumcheck identity and returns the final bit point and 25 lane evaluations. They matched the Rust verifier’s direct evaluation from the input bits on every sample. Each Osaka replay also rejected five altered calls. [Solidity reduction](../crates/evm-verifier/contracts/prime/KeccakSegmentReduction.sol) · [Replay and native benchmark](../crates/evm-verifier/scripts/bench_segment_reduction.py) · [Upstream equations](https://github.com/reilabs/keccacheck/blob/ec20ea40fe6be6260e3cdbb96dc5f9cae6bdca00/rust/gkr/src/keccacheck_og/verifier.rs)

| Sampled permutations | Three-round segments | GKR transcript | Native proving, five threads | Solidity call bytes | Osaka reduction gas |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 128 | 1,024 | 48,160 B | 1.35 s | 49,092 B | 2,556,496 |
| 1,024 | 8,192 | 54,976 B | 10.51 s | 55,908 B | 2,789,689 |
| 4,096 | 32,768 | 59,520 B | 91.63 s | 60,452 B | 2,945,143 |

These are individual timing samples. The largest ran alongside a workspace build. For all 65,536 rows, the implemented GKR message schedule gives exactly **2,144 scalars (68,608 bytes)** before endpoint authentication. This is a format calculation. The largest sample in this output-word control covered one sixteenth of the table. A direct expansion of the 25 input lanes into one prime-field element per bit at full size would need 25 GiB before prover scratch space. Run `python3 crates/evm-verifier/scripts/bench_segment_reduction.py --checkpoints "$TERMINAL_BUNDLE/keccak-checkpoints.bin" --rows 128` for the smallest sample in the table. [Reproduction driver](../crates/evm-verifier/scripts/bench_segment_reduction.py) · [Test comparing all returned evaluations](../crates/evm-verifier/test/KeccakSegmentReduction.t.sol)

The linked verifier takes its starting point and all 25 output-lane claims directly from the packed-output reduction. The native prover projected the linear Iota and Rho steps onto nine and six coordinates respectively. For the remaining gates it kept the first four row folds bit-packed before expanding the witness into field elements. On 128 sampled rows, the bit-packed prover and dense prover produced identical messages. On the complete 65,536 rows the round proof contains 1,833 scalars (58,656 bytes). It covers all eight three-round segments, including the 43,342 active permutation rows. The Rust verifier independently evaluated all 25 returned input claims from the original states. [Bit-packed prover](../crates/evm-verifier/scripts/segment_gkr/packed_prefix.rs) · [Linked Solidity verifier](../crates/evm-verifier/contracts/prime/TerminalSegmentRoundsVerifier.sol)

| Same 64-client witness and 135-bit local Johnson target | Initial code rate 1/16 | Initial code rate 1/32 |
| --- | ---: | ---: |
| Rows queried across the seven WHIR levels | 214 | 184 |
| Merkle siblings and queried rows on the wire | 156,952 B | 142,040 B |
| Checkpoint commitment and opening, including packed-output reduction | 14.81 s | 38.79 s |
| Peak physical footprint of the checkpoint prover process | 5.30 GiB | 10.32 GiB |
| Separate three-round GKR prover, all 524,288 segments | 120.34 s | 120.66 s |
| Complete linked call, calldata | 219,172 B | 204,260 B |
| Osaka transaction calldata floor | 8,736,580 gas | 8,151,950 gas |
| Original Osaka receipt, opening plus output reduction plus GKR | 10,469,839 gas | 9,711,617 gas |
| Shared 24/32-byte round verifier | 10,505,083 gas | 9,747,651 gas |
| Same calls after reusing the Spongefish frame buffer | 10,393,501 gas | 9,637,528 gas |
| Same calls with strided reads for unpaired Merkle paths | **9,755,891 gas** | **9,080,519 gas** |

The two checkpoint timings were collected back to back with the same release binary, five M2 Pro threads, and the same exported witness. They exclude constructing the checkpoint vector and checking the proof. The second code rate doubles the initial Reed–Solomon domain and reduces the total query count by 30. Both profiles use full Keccak digests, the same degree bounds and at most 16 grinding bits. Each deployed table verifier fixes its schedule and protocol identifier. The padding row is a constant computed at deployment. The opening verifier reuses powers of the largest domain generator across all seven subgroups. The linked EVM replay matched every returned coordinate and lane evaluation and rejected eight altered calls in each profile. [Reference prover](../crates/evm-verifier/scripts/prime_whir/dense_opening.rs) · [Rate-1/32 verifier parameters](../crates/evm-verifier/contracts/prime/TerminalSegmentOutputVerifierRate32.sol) · [Regression](../crates/evm-verifier/test/TerminalSegmentRounds.t.sol)

The 9,080,519-gas call returns a point and 25 claims about the *input bits*. Settlement still requires authenticating those claims, enforcing that the underlying digits encode bits, and wiring the input/output hash ports to both child verifications. A scalar that packs 240 bits supports a weighted sum with powers-of-two weights. The GKR check returns a different, challenge-dependent weighting of those bits. Opening a second packed scalar at the same row point would leave this difference unchecked. A candidate commitment to small digits would let the verifier check bit extraction and digit range in a single additional sumcheck, at the cost of a larger committed table. The 1,919,481 gas of headroom on this fixture has yet to cover those obligations. The complete root receipt remains at the top of this page.

To regenerate the rate-1/32 proof from the exported midpoint bundle, use an Osaka-capable Anvil. Set `TABLE` to a new directory. For rate 1/16 use `--segment-output` and omit `--rate32`.

```sh
python3 crates/evm-verifier/scripts/bench_large_prime_opening.py \
  --segment-output-rate32 --terminal "$TERMINAL_BUNDLE" --save-fixture "$TABLE"
python3 crates/evm-verifier/scripts/bench_segment_rounds.py \
  --rate32 --table "$TABLE" --checkpoints "$TERMINAL_BUNDLE/keccak-checkpoints.bin"
```

#### Sizing the four-bit input check

A proposed replacement table stores one four-bit digit at each of 28 Boolean coordinates. Sixteen coordinates select the permutation row, three select the segment, five select a lane and four select the digit within that lane. The unused lane slots can hold the final round-24 state. For a committed digit polynomial `D`, the sumcheck can combine the claimed input evaluation with a range check on all digit entries. The four bit-extraction polynomials have degree at most 15. The range polynomial is the product of `D − j` for integers 0 through 15. Multiplying by a multilinear row weight gives degree at most 17 per variable. The closing equation needs one evaluation of `D`. Its commitment would also have to authenticate the packed checkpoint readings and the child hash ports.

The pinned WHIR solver found the following schedules at code rate 1/32, a local target of 135 and a maximum of 16 grinding bits. Both keep 32-byte Merkle digests. The byte estimates count expected opened rows and Merkle siblings, the existing 1,833 round coefficients, and 476 additional digit-sumcheck coefficients. The 192-bit column assumes all field messages are encoded in 24 bytes. The 192-bit round prover and Solidity verifier use this 24-byte encoding. The numbers exclude the WHIR transcript, the final digit evaluation, ABI overhead and recursive arithmetic.

| Proposed digit table | First and later folds | Expected rows and siblings | Estimated subtotal | Initial RS code if fully materialized |
| --- | ---: | ---: | ---: | ---: |
| Current 254-bit prime | 5 and 4 | 192,599 B | 266,487 B | 256 GiB |
| WHIR reference's 192-bit prime | 4 and 5 | 168,388 B | 223,804 B | 192 GiB |

The integrated four-bit measurement below includes the dense opening at the point chosen by the digit check. The recursive child relations require additional constraints. Reproduce the byte estimates with `python3 crates/evm-verifier/scripts/bench_large_prime_opening.py --size-input-digits`. [Parameter sweep](../crates/evm-verifier/scripts/prime_whir/digit_cost.rs) · [Reference fields](https://github.com/worldfnd/whir/blob/fe86de76fa5863bb82466c8a91a7f74a60f910ac/src/algebra/fields.rs)

#### Authenticating both Keccak endpoints

On 512 sampled permutation rows, one Solidity call checks all 24 rounds, both bit evaluations, the digit range, and both public final-node inputs. It returned `true` for **8,837,224 gas** on Osaka with 195,684 calldata bytes and a 7,809,900 gas floor. The earlier 32-byte-only GKR implementation used 9,400,035 gas and the shared scalar-width implementation used 9,430,741 gas before the Spongefish buffer change. The sample includes 170 active and 86 padding rows per child role. The active rows include the actual terminal node in each half. This test omits the other 65,024 permutation rows and the two recursive child verifications. [Solidity entry point](../crates/evm-verifier/contracts/prime/TerminalDigitVerifier.sol) · [Native prover](../crates/evm-verifier/scripts/prime_whir/digit_opening.rs)

Each table entry stores two bits as one digit. A single Merkle commitment binds all nine checkpoints before sampling the Keccak output point. A degree-five sumcheck combines the returned input-bit evaluations, the output-bit evaluations, the range polynomial `D(D−1)(D−2)(D−3)`, and the known node and padding inputs. The closing WHIR proof opens that original commitment once. The digit sumcheck sends 111 field elements (3,552 bytes). The replay rejects ten changes, including a changed final opening and Merkle sibling. [Measurement driver](../crates/evm-verifier/scripts/bench_digit_transitions.py) · [Packaged regression](../crates/evm-verifier/test/TerminalDigit.t.sol)

#### Four-bit digits at full root size

One local Osaka transaction verified the Keccak component on the actual 64-client trace for **9,980,866 gas**, including **221,604 calldata bytes** with an **8,837,070 gas floor**. Solidity checked all 24 rounds, both checkpoint endpoint readings, digit range, and final-node and padding inputs, and returned `true`. It rejected 12 altered calls. The top-level contract still needs to enforce the two recursive child statements and their connections to these permutations. There are **1,019,134 gas** between this component receipt and the 11M aggregate limit. [Solidity entry point](../crates/evm-verifier/contracts/prime/TerminalNibbleVerifier.sol) · [Full-size regression](../crates/evm-verifier/test/NibbleOpening.t.sol)

The calldata floor alone permits at most **54,073 additional nonzero bytes** in this same transaction before reaching 11M. The measured execution budget is tighter. For example, 25 KiB of additional nonzero proof data would consume 409,600 gas of ordinary calldata charges, leaving 609,534 gas for extra execution and any added framing. A separate opening of the present size would exceed the budget. Combining child-arithmetic and hash-port constraints with the existing opening requires binding those claims before its Fiat–Shamir challenges and proving their reduction to the same committed data. [Transaction data pricing](https://eips.ethereum.org/EIPS/eip-7623)

The 192-bit prime-field round prover covered the actual **43,342 Keccak permutations** padded to 65,536 rows. Eight three-round segments per row give 524,288 segments. Solidity returned exactly the native input point and 25 lane evaluations. All 1,833 coefficients are 24 bytes, saving **14,664 bytes (25%)** relative to the earlier 254-bit-field transcript. This measurement leaves endpoint authentication and recursive arithmetic to the enclosing proof. All commitments and challenges use Keccak. The scalar field requires integer modular arithmetic. [Round verifier](../crates/evm-verifier/contracts/prime/KeccakSegmentReduction.sol) · [Native round prover](../crates/evm-verifier/scripts/segment_gkr/benchmark.rs)

| Measured operation | Result |
| --- | ---: |
| Build the full four-bit commitment on five M2 Pro threads | 922.87 s |
| Peak physical footprint of commitment process | 7.40 GiB |
| Keccak GKR proving, same full row set | 97.65 s |
| GKR bytes / standalone call bytes | 43,992 / 45,764 |
| Osaka receipt, standalone GKR reduction | 2,777,478 gas |
| Both digit sumchecks, three threads | 219.90 s, 6,816 B |
| WHIR opening at the final digit point, five threads, uncached initial queried rows | 934.88 s, 2,168 transcript B + 167,400 hint B |
| Combined Osaka receipt, rounds + digit checks + WHIR opening | **9,980,866 gas** |
| Gas inside the two module calls (rounds / WHIR) | 2,032,618 / 3,465,720 |
| Full-size dense WHIR opening at the digit point, as a separate Osaka transaction | 6,811,120 gas, equal to the calldata floor |
| Complete WHIR opening of the 128-row **dense checkpoint sample**, Osaka | 4,815,440 gas, equal to calldata floor |
| Complete WHIR opening at **full arity on a single-coefficient test polynomial**, Osaka | 5,678,005 gas, 172,196 calldata bytes |

The 28-variable digit table has 268,435,456 entries. The first Reed–Solomon code contains 192 GiB of field values. The committer processes 32 cosets, retains one subtree hash per 1,024 rows, and writes 16 MiB of intermediate hashes. Its commitment to the real trace was `0831872856e3e362a1cd7aef4db53045c94a3b1bd914d08ab702d919430a61d9`. Reconstructing five rows in two cosets took 43.04 seconds and produced a 4,328-byte opening that Solidity checked against this root. This read set tests the storage path. Protocol queries come from the WHIR transcript. A smaller dense comparison against the unmodified reference prover reproduced both the root and every opening byte, including duplicate and adjacent queries. Timings are single measurements and other benchmarks ran during part of the commitment run. [Streamed committer](../crates/evm-verifier/scripts/prime_whir/stream_digits.rs) · [Solidity regression](../crates/evm-verifier/test/NibbleOpening.t.sol)

The committer can retain one hash per four leaves with `--cache-quartets`. After that index was built for the two queried cosets (256 MiB on disk), the same five openings took **3.27 seconds**, versus **43.04 seconds** by re-encoding. Their 4,328 bytes matched exactly. Caching all 32 cosets costs 4 GiB. This timing covers the fixed five-row control, and the time to create its two index shards was 75.99 seconds in a separate run. [Cached opening](../crates/evm-verifier/scripts/prime_whir/support/quartets.rs)

The full-arity WHIR verifier fixes 4 initial folds, 5 subsequent folds, query counts 49, 31, 21, 16, 12 and the stage-specific grinding thresholds from the finite Johnson solver. Both the independent WHIR verifier and Solidity accepted the single-coefficient fixture. Its numerous zero calldata bytes lower the receipt. Decoding packed 24-byte rows in one pass reduced that fixture from 7,318,749 gas to 5,805,741 gas. Reusing the transcript scratch buffer reduced it to 5,678,005 gas. Packed row decoding reduced the dense 128-row opening from 6,123,508 gas to 4,815,440 gas. The full-size dense call above verifies the actual table, Keccak rounds and digit constraints together. Recursive verification of the two children remains open on this profile. [Opening verifier](../crates/evm-verifier/contracts/prime/NibbleOpeningVerifier.sol) · [Reference verifier](https://github.com/worldfnd/whir/blob/fe86de76fa5863bb82466c8a91a7f74a60f910ac/src/protocols/whir/verifier.rs)

Two degree-five sumchecks reduce every digit constraint to one evaluation of the committed table. For a digit polynomial `D`, the first sumcheck uses the multilinear extensions of the Boolean-cube values `D`, `D³` and `D⁴`. Every power through 16 is a product of at most four of these three values. This covers the four degree-15 bit polynomials and the degree-16 range polynomial with a multilinear public weight. After binding all three returned evaluations, the verifier samples fresh coefficients and the second sumcheck reduces the batched moment claim to one opening of `D`. The 28-variable proof carries **284 scalars (6,816 bytes)**. The native prover computed and checked both reductions on the full actual witness in **219.90 seconds** on three threads. For 128 rows, the integrated Solidity call checked all rounds, both endpoints, the public node rows, padding, digit range and the WHIR opening for **7,540,738 gas**. It rejected twelve altered statements or messages. [Digit relation](../crates/evm-verifier/scripts/prime_whir/nibble_relation.rs) · [Solidity verifier](../crates/evm-verifier/contracts/prime/TerminalNibbleVerifier.sol)

For the two sumchecks alone, condition on binding to the digit table and fresh independent uniform verifier challenges in the interactive protocol. A false degree-five round message can agree with the correct polynomial on at most five field elements. Over two 28-round sumchecks the union bound is `280 / p`. Compressing three fixed moment errors with three fresh independent linear coefficients contributes at most `1 / p`. These terms cover only sumcheck consistency and moment batching. The complete bound also needs the endpoint and range reductions, Keccak GKR, commitment opening, Fiat–Shamir transformation and recursive composition. The client hiding argument is separate. [Sumcheck soundness, Chapter 4](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf)

The bounded-memory WHIR prover computes the first four folds from sixteen column evaluations of each initial linear form. It commits subsequent folds in cosets and rebuilds only the requested subtrees when opening a cap. On a dense 19-variable witness the entire statement, 1,232-byte transcript and 118,400-byte opening hints matched the unmodified reference prover byte for byte. At full size, the reference verifier accepted the streamed opening, and the driver checked the independently computed opening value against the digit verifier’s required value before the EVM replay. The four separately timed proving stages sum to about 36.3 minutes. They ran with different thread counts and background load. No full terminal speedup has been demonstrated. [Streamed opening prover](../crates/evm-verifier/scripts/prime_whir/stream_opening.rs)

```sh
python3 crates/evm-verifier/scripts/bench_digit_transitions.py --terminal "$TERMINAL_BUNDLE"
python3 crates/evm-verifier/scripts/bench_streamed_digits.py --terminal "$TERMINAL_BUNDLE" --row-bits 7 --check-dense
python3 crates/evm-verifier/scripts/bench_streamed_digits.py --terminal "$TERMINAL_BUNDLE" --row-bits 16 --save-fixture "$DIGIT_TABLE"
python3 crates/evm-verifier/scripts/bench_nibble_opening.py --terminal "$TERMINAL_BUNDLE"
python3 crates/evm-verifier/scripts/bench_nibble_opening.py --terminal "$TERMINAL_BUNDLE" --caps "$DIGIT_TABLE" --row-bits 16
python3 crates/evm-verifier/scripts/bench_nibble_opening.py --profile-control
python3 crates/evm-verifier/scripts/bench_nibble_transitions.py --terminal "$TERMINAL_BUNDLE" --caps "$DIGIT_TABLE" --row-bits 16 --hash-profile
forge test --root crates/evm-verifier --match-contract NibbleOpeningTest
```

### Earlier full-root measurements

| Same ordered 64-client batch | Three-variable folds | Four-variable folds |
| --- | ---: | ---: |
| Final proving time on the same two subtrees, five M2 Pro threads | 164.41 s | 49.07 s |
| Native compressed proof bytes | 351,507 | 351,600 |
| Solidity call bytes | 352,292 | 352,132 |
| Exact calldata floor including transaction base | 13,959,590 gas | 13,959,970 gas |
| First complete direct verification, diagnostic Prague | 179,042,764 gas | 178,254,746 gas |
| Reusing a multiplication table for the repeated challenge and copying row coordinates directly | 174,364,767 gas | 173,576,749 gas |
| Also applying constant multiplications across three field coefficients in parallel | **171,271,357 gas** | **170,483,339 gas** |

The application supplies its expected ordered digest and count. The verifier fixes its module addresses at deployment. Those deployments bind the authority, fixed commitment, bus layout, 19-table AIR, column geometry and WHIR folding schedule. Each supporting contract was deployed under ordinary code-size limits. The transaction checks the bus, arithmetic sumcheck, all 850 bus declarations, the hash-table bridge, 24 Keccak layers, both boundary sumchecks, and the shared polynomial opening through its final identity. It derives every coordinate and value for the 134 ordered bit claims. The caller transmits each underlying opened column value once. The Rust prover uses its native wire format. The replay converts its proof messages into Solidity's ABI after independently verifying each saved bundle in Rust. [Arithmetic closure](../crates/evm-verifier/contracts/imt/NativeAirClosingVerifier.sol) · [Linked Keccak](../crates/evm-verifier/contracts/imt/NativeRootRelation.sol) · [Column reduction](../crates/evm-verifier/contracts/imt/NativeColumnVerifier.sol)

On the four-variable receipt the call tracer attributed 89,242,864 execution gas to the combined arithmetic and Keccak verifier, 10,782,787 to deriving the 134 claims and 64,145,855 to the shared polynomial opening. These are inclusive subcall measurements. The receipt also charges transaction data and the entry contract. The two largest components independently exceed the entire budget.

Both runs matched all 134 claim records byte-for-byte. Changing the digest, count, main cap, a Keccak boundary evaluation, a Keccak round, the shared sumcheck or the final WHIR opening caused the full entry point to revert. The packaged four-variable fixture also exercises the complete call in Foundry. The gas gap and the recursive knowledge-soundness and client statistical-ZK proofs remain production gates. [Foundry regression](../crates/evm-verifier/test/NativeAggregateRoot.t.sol) · [Security criteria](binary-security.md#production-acceptance-criteria)

```sh
forge test --root crates/evm-verifier --match-contract NativeAggregateRootTest
cargo run --locked --release --features opening-bench --example root-opening-trace -- \
  --bundle "$TERMINAL_BUNDLE" --trusted "$TERMINAL_TRUSTED" > /tmp/imt-root-trace.json
python3 crates/evm-verifier/scripts/replay_native_root.py /tmp/imt-root-trace.json \
  --trusted "$TERMINAL_TRUSTED"
```

## Depth-32 preimage batch

Each client proves a statement over one public root and a private 32-byte preimage, index and path. The two 32-client subtrees used the same independently generated verifier key. On five M2 Pro threads with one active proof per tree, the first and second sets of clients averaged 4.75 and 3.45 seconds including witness processing. Their 31 interior aggregates per subtree averaged 10.47 and 8.37 seconds respectively. The terminal proof took 212.14 seconds and its raw encoding occupied 369,916 bytes. The 351,507-byte compressed proof contains 1,395 zero bytes. Its SHA-256 is `773d95e27042c80353ee0ae1e0817b607ff4dc23e667e9e1b79ad9fef757de73`. A fresh Rust process verified it in 12.75 ms after setup, using the expected digest and count independently recomputed with Ethereum Keccak over the 64 ordered public statements. A different count or digest failed. The statement was `6511d0c8c106fecb40fe7050968e08d9a2b2281488404c50e1fe1edca2d7c69640`. The native client simulator and complete security reduction remain open. [Preimage relation](protocol.md#preimage-membership-client) · [Security acceptance criteria](binary-security.md#production-acceptance-criteria)

The same public root and private witness were also proved by the masked native client and a binary LeanVM guest. Both ran all 33 Keccak permutations and checked the root `aebe80472db1879b4fab599fe75727c2d8c201b717e323e5482efea7720327de`. At rate 1/16, warm medians on five threads were **39.7 ms and 96,792 bytes** for LeanVM, and **3.50 seconds and 1,090,328–1,091,797 bytes** for the masked native client. At rate 1/4 the LeanVM guest took 28.7 ms and occupied 128,520 bytes. The guest executed 495 instructions and committed 58,282 words before padding. LeanVM advertises 125-bit classical ROM soundness. This control measures the cost of the relation in its prover. The experiment supplies no statistical-ZK guarantee for the guest. Reproduce with `cargo run --locked --release --manifest-path adapters/leanvm/Cargo.toml --example imt-leaf -- --preimage` and `RAYON_NUM_THREADS=5 cargo run --locked --release --example fixed-leaf -- --preimage`. [Guest code](../adapters/leanvm/imt_preimage.py) · [Native comparison](../examples/fixed-leaf.rs) · [Upstream security target](https://github.com/leanEthereum/leanVM/blob/5b43139d50272f996ca884669b1d51555af1f35d/README.md#security)

Solidity derived the six initial WHIR fold challenges, checked each 8-bit grind, bound the next cap and its two out-of-domain answers, checked the 15-bit query grind, and reproduced all 71 initial query indices. The authenticated witness and fixed rows at those positions folded to the same 71 native extension-field values in the original draw order. All seven Merkle sites together had 4,736 sibling hashes. Mutating either initial cap, the opened rows or their paths caused rejection. [WHIR transcript](../crates/evm-verifier/contracts/imt/NativeWhirInitial.sol) · [Authenticated folds](../crates/evm-verifier/contracts/imt/NativeFold.sol) · [Differential replay](../crates/evm-verifier/scripts/replay_native_openings.py)

| Component on the root-only batch | Transaction gas |
| --- | ---: |
| 134 derived bit claims through first WHIR query generation, with expanded claim records supplied by the harness, Osaka | 9,657,608 |
| Ring state through the first 71 authenticated row folds with both Merkle paths, Osaka | 7,680,756 |
| Same first 71 folds with the upper fixed path read from eight predeployed pages, Osaka | 7,351,708 |
| Ring state through **all 26 WHIR folds**, including all 17 final-oracle consistency checks, single diagnostic Prague transaction | **17,000,048** |
| Ring state through the same 26 WHIR folds with the fixed cap pages, single standard Osaka transaction | **16,494,288** |
| Linked Keccak layers, across 24 separate Osaka component transactions | 55,948,445 |

One Osaka transaction containing the 205,348-byte uncapped-path fold call exhausted its 16,777,216 gas allowance. A local Prague transaction with the same bytecode and calldata completed and returned the same closing sum and challenge digest as Rust. With the upper fixed path in predeployed pages, the complete fold call returned the same result in one ordinary Osaka transaction for **16,494,288 gas**, including 192,324 bytes of calldata. These measurements cover one component of the root. It starts after the ring-switch tensor and stops before the WHIR final weight equation. The complete verifier derives the arithmetic inputs from the expected public statement. The complete Keccak boundary measurement below includes both closing checks. [Combined fold harness](../crates/evm-verifier/test/NativeWhirRounds.t.sol) · [Verifier](../crates/evm-verifier/contracts/imt/NativeWhirRounds.sol)

For the first query, all 71 rows use the same 48 extension-field weights. The verifier tabulates each weight's 256 byte multiples in groups of eight columns. The earlier per-nibble implementation used 8,321,582 gas and the original scalar implementation used 11,197,468 gas on this component. The verifier can also omit 407 of the 1,259 fixed sibling hashes in this proof by authenticating the upper 12 levels against the trusted wiring key at deployment. This saves 13,024 bytes and 329,048 gas on the first-row call. Deploying the eight pages and the benchmark verifier cost 34,487,097 gas in nine ordinary local transactions. Both paths produced identical results and rejected changes to authenticated data. [Field folds](../crates/evm-verifier/contracts/imt/NativeFold.sol) · [Pinned wiring pages](../crates/evm-verifier/contracts/imt/FixedWiringCap.sol)

The five subsequent query sets had 31, 26, 22, 19 and 17 rows. Solidity derived each set from the transcript, authenticated it against the previous commitment and folded the rows in draw order. It also checked all 17 final folds against the transmitted 32-entry polynomial in the additive code's novel basis. The replay compares each stage’s batching challenge, sum, folding point, query addresses and values against Rust. Use `--profile-above-cap` for the separate Prague measurement. Supply `--fixed-cap` to reproduce the deployment and capped first-row call. [Checked Rust trace](../crates/flock-backend/src/terminal_opening/replay/whir_tail.rs) · [Solidity replay](../crates/evm-verifier/scripts/replay_native_openings.py)

```sh
cargo run --locked --release --features opening-bench --example root-wiring-cap -- \
  --child-key "$CYCLIC_KEY" --child-trusted "$CYCLIC_TRUSTED" > /tmp/imt-fixed-cap.bin
cargo run --locked --release --features opening-bench --example root-opening-trace -- \
  --bundle "$TERMINAL_BUNDLE" --trusted "$TERMINAL_TRUSTED" > /tmp/imt-openings.json
python3 crates/evm-verifier/scripts/replay_native_openings.py /tmp/imt-openings.json \
  --fixed-cap /tmp/imt-fixed-cap.bin --profile-above-cap
```

### Complete native polynomial opening in Solidity

The deployable opening verifier pins the merge authority and the fixed wiring root in its constructor. The caller supplies the witness commitment and 134 ordered claims. In the complete root these come from the arithmetic, bus and linked Keccak checks. One call reduces the claims, checks the ring-switch tensor, authenticates both initial oracles and each subsequent query, and enforces the final WHIR equation. A separate immutable contract performs the initial reduction. Both contracts deployed under Ethereum's ordinary code-size limits. [Solidity entry point](../crates/evm-verifier/contracts/imt/NativeBitOpeningVerifier.sol) · [Final equation](../crates/evm-verifier/contracts/imt/NativeWhirClosing.sol)

| Measurement on the same 64 clients | Three-variable folds | Four-variable folds |
| --- | ---: | ---: |
| All 134 supplied claims through the final WHIR identity, one high-limit local Prague transaction | 69,470,702 gas | 68,663,626 gas |
| ABI calldata for this component, including expanded claims and ordinary Merkle paths | 314,724 B | 314,564 B |
| Ring-switch final weight alone, separate local Prague transaction | 24,296,678 gas | 24,296,666 gas |
| Same complete opening call, ordinary Osaka transaction | Exhausted 16,777,216 gas | Exhausted 16,777,216 gas |

The final check multiplies the value of the closing polynomial by the combined constraint weight and compares the result with the transcript's closing sum. Solidity reproduced Rust's ordinary constraint weight, deferred ring weight and final polynomial value separately for both proofs. Changing the last coefficient failed the equation. Deploying with a changed authority or fixed wiring root also rejected the same proof. The Rust exporter reads the fixed root from the authenticated verifier key before replaying the proof. [Rust calculation](../crates/flock-backend/src/terminal_opening/replay/whir_tail.rs) · [Transaction replay](../crates/evm-verifier/scripts/replay_native_identity.py)

A first Solidity implementation multiplied the 192-by-192 binary coefficient matrix directly. A second implementation evaluates the tensor under all 192 Frobenius embeddings and recovers its requested row combination using the trace-dual basis. On identical call data and the same diagnostic harness this reduced gas from 80,060,161 to 69,609,512 on the three-variable proof, and from 79,204,327 to 68,836,374 on the four-variable proof. The pinned deployment above also moves two constant words out of per-proof calldata. LeanVM's binary verifier uses a related product of Frobenius images with 64 terms and a different ring map. Our ring check requires 192 terms for its current equation. Lowering the WHIR query count does not change that computation. The 11M target requires a change to the terminal proof or a substantially cheaper algorithm for that equation as well as smaller calldata. [Native ring weight](../crates/evm-verifier/contracts/imt/NativeRingWeight.sol) · [LeanVM ring map](https://github.com/leanEthereum/leanVM/blob/c5ee9d239e42d0bc8113eb4aee3e2cae5faf1764/crates/verifier/src/ring_switch.rs)

Use the verified trace exported above to reproduce these measurements.

```sh
python3 crates/evm-verifier/scripts/replay_native_identity.py /tmp/imt-openings.json \
  --trusted "$TERMINAL_TRUSTED"
```

### Certified ring weight and complete Keccak boundary

An optional public certificate reduces the cost of checking the same ring weight. Rust generates it from the WHIR verifier’s 32 reading coordinates, 26 fold challenges, eight tensor batching coordinates and claimed weight. On two measured release builds it took about 1 ms to generate for each 64-client proof. Both the platform-independent Rust verifier and the Solidity contract checked the certificate. The Rust terminal verifier also evaluated the original ring equation and agreed on the weight. The test fixture comes from the four-variable root with SHA-256 `52b70ccc55da3d6bbca0b06f910a3d857edc6d0b00fba54511ad12515307d977`. [Rust prover and verifier](../crates/flock-backend/src/terminal_opening/ring_certificate.rs) · [Solidity verifier](../crates/evm-verifier/contracts/imt/NativeRingCertificate.sol)

| Same 64-client batch, full transaction receipts | Three-variable folds | Four-variable folds |
| --- | ---: | ---: |
| Original ring weight, isolated diagnostic Prague call | 24,296,678 gas | 24,296,666 gas |
| Certified ring weight, isolated standard Osaka call | **5,491,264 gas** | **5,491,180 gas** |
| Complete bit opening from 134 supplied claims, direct arithmetic, diagnostic Prague | 69,511,444 gas | 68,725,123 gas |
| Same complete bit opening with the certificate, diagnostic Prague | **50,769,486 gas** | **49,952,622 gas** |
| Verified Keccak argument from the supplied arithmetic row through four boundary evaluations, single diagnostic Prague call | **60,898,373 gas** | **60,898,109 gas** |
| Compressed native proof plus certificate, before ABI framing | 361,515 B | 361,608 B |
| Calldata floor for those combined bytes | 14,434,500 gas | 14,438,160 gas |

The certificate adds 10,008 bytes. The complete opening calldata on the fast profile is 324,644 bytes, including the 134 expanded claim records supplied by the measurement caller. It exhausted the 16,777,216 Osaka transaction cap. The complete Keccak boundary call used 80,292 calldata bytes. It checks the 232 arithmetic row values against the 116 bridge limbs, all 24 packed layers, the 15-round input and 12-round port sumchecks, and the four evaluations at their derived 27-coordinate points. Rust and Solidity agreed on all 108 coordinates. Changing either half of the arithmetic row, a bridge coordinate, a closing proof, the main cap or any of the four evaluations caused rejection. Both measurements are components. The end-to-end measurement above includes arithmetic point, row, evaluation and bit-claim derivation under the expected statement and trusted key. [Opening entry points](../crates/evm-verifier/contracts/imt/NativeBitOpeningVerifier.sol) · [Keccak boundary entry point](../crates/evm-verifier/contracts/imt/NativeKeccakBoundaryVerifier.sol)

The certificate has eight sumcheck rounds over the conjugate index. At each Boolean index, the summand multiplies 26 equality factors, one batched trace-dual weight, and a mask for the 192 valid indices. All 28 factors are multilinear extensions, giving individual degree at most 28. Each round sends 28 field elements. The old sum determines the omitted linear coefficient. After the eight challenges, the prover sends the 192 images of the trace-dual basis under the resulting linear map. A fresh challenge checks the degree-at-most-191 polynomial projection of those images. Solidity derives the expected projection from the public field modulus and the eight challenges. The verified map evaluates each factor at the sumcheck endpoint. [Exact tensor equation](../crates/evm-verifier/contracts/imt/NativeRingWeight.sol) · [Certificate construction](../crates/flock-backend/src/terminal_opening/ring_certificate.rs)

With independent uniform verifier coins, a false ring weight has acceptance probability bounded by `(8 × 28 + 191) / 2^192`, about `2^-183.30`. This follows by applying the sumcheck soundness bound to the product, then the univariate root bound to a false map. A false fixed map differs on at least one coefficient of its projection polynomial. Keccak binds the context, inputs and asserted weight before any round, each polynomial before its challenge, and all map entries before the projection challenge. The stated probability is the interactive algebraic bound. Recursive knowledge soundness, Fiat–Shamir composition in the random-oracle model, grinding budgets and joint client statistical ZK remain release gates. The certificate is experimental. The ordinary verification path remains available. [Sumcheck theorem, Proposition 1.1](https://people.cs.georgetown.edu/jthaler/sumcheck.pdf) · [Production security criteria](binary-security.md#production-acceptance-criteria)

Use a fresh trace from `root-opening-trace` and the matching independently trusted key metadata.

```sh
python3 crates/evm-verifier/scripts/replay_native_identity.py /tmp/imt-openings.json \
  --trusted "$TERMINAL_TRUSTED" --ring-certificate --keccak-boundary
```

### Ordered statement through the arithmetic bus

Solidity derives the arithmetic challenges from the expected ordered 32-byte digest, fixed count of 64, two role-bound public inputs, pinned authority and fixed wiring root, and the witness commitment. It verifies the push and pull product trees with one shared product root, 13 radix-four layers and 156 degree-five sumcheck rounds. The resulting fingerprint, offset, 26 coordinates, two terminal values and next transcript challenge matched the native verifier for both 64-client proofs. The enclosing AIR derives the 19-coordinate opening point from this transcript and checks its closing equation on the committed tables. [Solidity bus verifier](../crates/evm-verifier/contracts/imt/NativeBusVerifier.sol) · [Rust reference](../crates/flock-backend/src/opening_trace/arithmetic.rs)

| Ordinary Osaka transaction | Three-variable folds | Four-variable folds |
| --- | ---: | ---: |
| Verify the statement and reduce the product trees | 5,869,394 gas | 5,869,202 gas |
| Transaction calldata | 21,412 B | 21,412 B |

Four inert contracts hold the 51,656-byte fixed bus domain. The verifier checks their runtime code hashes at deployment. Its own runtime is 6,933 bytes. Changing the expected digest, count, main commitment, wire length, shared product, a sumcheck message or the last child value caused rejection. On the faster root, adding the 19-round AIR reduction to the bus check used 6,343,697 gas on Osaka. Closing the AIR and bus against all 2,070 supplied column readings used 30,583,651 gas in one diagnostic Prague transaction. The shared opening authenticates those readings in the full call. To reproduce this component use `replay_native_identity.py TRACE --trusted TRUST --bus-only`. [Transaction replay](../crates/evm-verifier/scripts/replay_native_identity.py)

## Complete root with one polynomial opening

### Effect of changing the security target

On the actual midpoint root the local target crosses the **conditional terminal algebraic** 128-bit threshold between 131 and 132. With LeanVM's 17-bit query-grinding setting used as the native maximum, the native estimator gives **127.49 bits** at 131 and **128.54 bits** at 132. With a 16-bit maximum the corresponding bounds are 127.59 and 128.53 bits. At 132/17 the native schedule uses 60, 30, 22, 17 and 14 queries. Its expected rows and Merkle siblings total 169,938 bytes, 31,502 bytes below 152/16. The recursive extractor and masked-client privacy proofs still need their own bounds. The default Solidity deployment retains 152/16. The separate comparison deployment checks 125/17. [Native estimator](../crates/flock-backend/src/terminal_opening/integrated.rs) · [Size calculation](../crates/flock-backend/examples/whir-opening-size.rs)

I checked binary LeanVM main at `e3874263` on November 21, 2026. Its transcript, WHIR verifier and finite-bound solver were byte-identical to revision `001c9dc2` in the previous check. Its verifier targets 125 bits per verifier message after grinding. It uses a 128-bit extension, six initial folds, four later folds, 17 query grinding bits and a Johnson-based query schedule. At stacked arity 26 and rate 1/16 the upstream table specifies 55, 32, 23, 18 and 15 queries. The native terminal uses Poly192, six initial folds, three later folds and its own reduction equations. The 10.67M gas LeanVM fixture uses a separate KoalaBear program. A security number for one message or one polynomial opening requires further accounting before it can serve as a security claim for the complete recursive argument. [LeanVM transcript](https://github.com/leanEthereum/leanVM/blob/e387426337d5ebe1269f32dbfa6dc35e8d4c0745/crates/verifier/src/transcript.rs#L83-L94) · [LeanVM WHIR parameters](https://github.com/leanEthereum/leanVM/blob/e387426337d5ebe1269f32dbfa6dc35e8d4c0745/crates/verifier/src/whir.rs#L10-L40)

On the implemented 28-variable four-bit checkpoint opening, the WHIR solver gives the comparison below. The scalar field, code rate 1/32, fold schedule 4 then 5, Keccak digest width and one opening point are held fixed. The listed bytes estimate Merkle siblings and queried field rows only. The solver checks the worst individual WHIR message under its finite Johnson bound.

| Requested local bits | Maximum grinding bits | Queries across five trees | Expected opening hints |
| ---: | ---: | --- | ---: |
| 125 | 17 | 45, 28, 19, 14, 11 | 153,086 B |
| 128 | 16 | 47, 29, 19, 15, 12 | 159,329 B |
| 135 (implemented) | 16 | 49, 31, 21, 16, 12 | 168,388 B |
| 135 | 20 | 48, 30, 20, 15, 12 | 163,177 B |

The 125/17 profile saves an estimated 15,302 bytes against 135/16. Preserving 135 local bits and raising the grinding ceiling saves an estimated 5,211 bytes. The solver rejected 142 and 152 local bits at a 16-bit ceiling on this exact geometry. Each reported saving is a sizing result. The time for nonce search and the end-to-end gas require a proof under the corresponding transcript. Run `bench_large_prime_opening.py --size-input-digits` to reproduce the comparison. [Pinned solver](https://github.com/worldfnd/whir/blob/fe86de76fa5863bb82466c8a91a7f74a60f910ac/src/protocols/whir/config.rs) · [IMT size calculation](../crates/evm-verifier/scripts/prime_whir/digit_cost.rs)

The earlier finite-bound search used the pinned LeanVM revision `5b43139d`. The verifier transcript, WHIR schedule and finite-bound solver files are byte-identical at `001c9dc2`. At stacked arity 26 and code rate 1/16, its `derive_config_with_log_inv_rate` and `validate` reproduced the 125-bit table (143 total queries). With the per-message target raised to 128, the same four WHIR grinding constants produced a validated schedule of **60, 34, 25, 22, 21** (162 total). With the 128-bit target and three extra bits at each WHIR grinding site, the search recovered the original **143 queries**. The latter uses 20 query, 10 fold, 16 batching and 18 out-of-domain grinding bits. Each three-bit increase multiplies the expected nonce-search work at that site by eight. The parameter search analyzes LeanVM's affine-combiner WHIR. Using its result in our sumchecks and client protocol would require a reduction for their equations. [Upstream security calculation](https://github.com/leanEthereum/leanVM/blob/5b43139d50272f996ca884669b1d51555af1f35d/crates/experimental_prover/pcs/src/whir_config.rs) · [Reference table test](https://github.com/leanEthereum/leanVM/blob/5b43139d50272f996ca884669b1d51555af1f35d/crates/experimental_prover/lean_vm_core/tests/verifiers/whir_query_table.rs)

At main revision `241b009a6`, the verifier, experimental PCS, stable PCS, stable Keccak prover and stable VM core directories are byte-for-byte identical to benchmark revision `5b43139d5`. The driver clones the pinned revision, recomputes the query tables, and proves and verifies the same 33-hash client witness under each configuration. Run `python3 adapters/leanvm/bench_whir_security.py https://github.com/leanEthereum/leanVM.git`. [Current LeanVM verifier](https://github.com/leanEthereum/leanVM/blob/241b009a61ba5fde797d1213b5bf76310f0d5060/crates/verifier/src/transcript.rs#L83-L94) · [Benchmark driver](../adapters/leanvm/bench_whir_security.py)

| LeanVM guest at rate 1/16, five prover threads | Warm proving median | Proof bytes | Warm verification median |
| --- | ---: | ---: | ---: |
| Upstream 125-bit per-message target | 27.25 ms | 96,792 | 2.65 ms |
| 128-bit target, original WHIR grinding settings | 37.05 ms | 105,212 | 2.70 ms |
| 128-bit target, three extra grinding bits at each WHIR site | 96.50 ms | 102,664 | 2.60 ms |

These timings are from one comparison run, with four warm samples per row. All three verified the same public root, used 33 Keccak permutations, and rejected a changed public root. The driver validated all 60 rate/arity rows for each configuration. The changes also adjust the degree-dependent `grinding_bits` helper to the selected target. The experiment establishes a per-message WHIR parameter tradeoff and real guest costs. It supplies neither a statistical-ZK client simulator nor a proof of knowledge for the full recursive IMT. For this witness, increasing queries at 128 bits added 8,420 bytes and 9.80 ms over the 125-bit baseline. Increasing the grinding settings then saved 2,548 bytes and added 59.45 ms over the other 128-bit run.

Holding the native terminal's field, tree dimensions, folding schedule and rate fixed isolates the effect of its local WHIR target. The pinned parameter generator supplies the query counts. The byte estimates count expected occupied Merkle nodes under stratified sampling, both initial caps, 48 transmitted initial words per query and later extension-field rows.

| Local WHIR target | Maximum grinding bits | Queries per site | Expected queried rows and sibling hashes |
|---:|---:|---|---:|
| 152 (current) | 16 | 71, 31, 26, 22, 19, 17 | 201,018 B |
| 149 | 16 | 69, 31, 25, 21, 18, 16 | 195,475 B |
| 128 | 16 | 59, 26, 21, 18, 16, 14 | 167,112 B |
| 125 | 16 | 57, 25, 21, 17, 15, 13 | 161,112 B |
| 125 | 17 | 56, 25, 20, 17, 15, 13 | 158,971 B |

Moving the local target from 128 to 125 saves an expected 6,000 bytes in this component, or approximately 240,000 calldata-floor gas if every removed byte is nonzero. Moving the current 152 target to 125 with 17 maximum grinding bits saves an expected 42,047 bytes, about 1.68M gas on that basis. The fresh root exceeds the calldata limit by 3.04M gas, and the arithmetic and Keccak bodies still require verification. The estimates exclude transcript messages, other components, compression changes and execution. The weaker rows are sizing experiments. Run `cargo run --locked -p imt-flock-backend --example whir-opening-size -- --shared-security`. [Sizing tool](../crates/flock-backend/examples/whir-opening-size.rs) · [Composition requirements](binary-security.md#production-acceptance-criteria)

The native security sweep runs the terminal verifier’s algebraic calculation against the actual 64-client statement, AIRs, heights, candidate-list bounds and linked Keccak reduction. Production parameters still require a recursive Fiat–Shamir knowledge bound. The row and sibling sizes below are expected uncompressed WHIR message bytes for four-variable folds. Proximity queries use each candidate’s native schedule.

| Native local WHIR target | Maximum grinding bits | Three-variable profile, conditional bits | Four-variable profile, conditional bits | Four-variable profile, expected row and sibling bytes |
| ---: | ---: | ---: | ---: | ---: |
| 125 | 17 | 121.27 | 121.48 | 159,104 |
| 128 | 16 | 124.22 | 124.55 | 166,755 |
| 135 | 16 | 130.67 | 131.01 | 175,308 |
| 149 | 16 | 143.05 | 143.07 | 196,147 |
| 150 | 16 | 143.99987 | 144.04 | 198,383 |
| 152 | 16 | 145.94 | 145.96 | 201,440 |
| 152 | 20 | 146.00 | 146.00 | 196,147 |

On the faster root, raising maximum grinding to 20 at the same 152-bit target saves an estimated 5,293 bytes in rows and siblings, or about 212k calldata-floor gas at 40 gas per nonzero byte. Lowering the local target to 125 with 17 bits of grinding saves an estimated 42,336 bytes at the cost of a 121.48-bit conditional terminal bound. The production acceptance criteria also cover the recursive tree and client statistical privacy. To reproduce, pass `--security-sweep` to `root-opening-trace` on each verified bundle and run `cargo run --locked -p imt-flock-backend --example whir-opening-size -- --shared-security-four` for opening sizes. [Native bound calculation](../crates/flock-backend/src/terminal_opening/integrated.rs) · [Sizing calculation](../crates/flock-backend/examples/whir-opening-size.rs)

A release build in an isolated checkout proved the same two 32-client subtrees with the four-variable schedule, a 152-bit local target and a 20-bit grinding ceiling. Its protocol identity was `experimental-binary-checkpoint-terminal64-shared-fold4-grind20`. The 16-bit control reproduced the existing proof byte-for-byte. Both native verifiers accepted the same expected digest and count. On five threads, the final proving calls took 43.00 s and 41.06 s in one back-to-back pair. The compressed proof shrank from **351,600 to 346,304 bytes**. Its calldata floor fell by 211,420 gas, from **14,043,270 to 13,831,850**, before adding the ring certificate or ABI framing. One timing pair cannot resolve the speed difference. The 20-bit artifact has SHA-256 `99bbd4f4d356c87ab6f0ef6593cda551a8fed237a776e8cd3372c82c38a8bb4c`. The experiment changes only `MAX_GRIND` and the opt-in four-variable protocol identity in its isolated build. Solidity’s deployed schedules still use the original constants.

### Four-variable folds on the same two subtrees

The opt-in `terminal-merge --four-variable-folds` profile keeps the initial code rate at 1/16, the first six folds, the native 152-bit per-term target, the Johnson bound and the 16-bit grinding budget. It folds four variables per later round and uses log-inverse rates 8, 11, 14 and 17 for the subsequent commitments. Both the prover and the verifier derive the schedule from the trusted protocol identity. The resulting number of encoded extension elements after the initial commitment fell from 1,040,187,392 to 503,316,480. A sweep of 87 admissible schedules using the native parameter calculator identified this candidate. Run `cargo run --locked -p imt-flock-backend --example whir-opening-size -- --shared-schedules` to reproduce the sweep. [Native profile](../crates/flock-backend/src/terminal_opening.rs) · [Parameter search](../crates/flock-backend/examples/whir-opening-size.rs)

| 64-client terminal on the same two 32-client proofs | Three-variable folds | Four-variable folds |
| --- | ---: | ---: |
| Final proving time, back-to-back run with five threads | 164.41 s | **49.07 s** |
| Final proving time, earlier individual runs | 212.14 s | 47.45 s |
| Full compressed native proof | 351,507 B | 351,600 B |
| Full native proof calldata floor | 14,039,430 gas | 14,043,270 gas |
| Conditional algebraic bound for the terminal | 145.94 bits | 145.96 bits |
| All WHIR folds with ordinary paths, single diagnostic Prague transaction | 17,000,048 gas | 18,166,315 gas |
| All WHIR folds with predeployed fixed paths, single Osaka transaction | 16,494,288 gas | Exhausted the 16,777,216 cap |

The faster profile took 70.2% less time in the back-to-back terminal proving calls. Both runs reproduced their respective proofs byte-for-byte. New Rust verifier processes accepted the same independently computed digest and count. Both verifiers rejected the other profile’s proof with their own correct trusted key, and rejected mutations in the uncompressed proof body. The new artifact’s SHA-256 is `52b70ccc55da3d6bbca0b06f910a3d857edc6d0b00fba54511ad12515307d977`. The timing comparison covers the final merge on one workstation. The leaf and interior provers were identical and the input subtrees were reused.

The four-variable schedule opens fewer extension rows, but each row has 16 entries. The EVM folds 98 rows with 15 extension multiplications each, compared with 115 rows with seven each in the three-variable profile. The verifier tabulates multiplication by each shared folding challenge in four-bit digits and reuses the scratch space across query sets. Both profiles reproduce the transcript and final polynomial queries. The extra field arithmetic makes the four-variable profile's measured fold call more expensive even though proving got faster. The full opening measurements above include the final WHIR weight equation. Settlement still requires deriving the claims from the other root arguments onchain. The figures for security cover only the conditional terminal calculation. [Fold implementation](../crates/evm-verifier/contracts/imt/NativeWhirRounds.sol) · [Security scope](binary-security.md#production-acceptance-criteria)

### Native proof construction

The experimental `terminal-merge --shared-opening` profile verifies two existing 32-leaf cyclic proofs. The arithmetic verifier and Keccak reduction generate 134 bit-evaluation claims on the witness and fixed circuit wiring. The sumcheck reduces these claims to one evaluation. A single WHIR proof opens it against both early Merkle roots. The verifier derives the claim locations, role selectors, values and transcript from the two authenticated subarguments. The fixed cap comes from the trusted key. [Integrated prover and verifier](../crates/flock-backend/src/terminal_opening/integrated.rs) · [Final opening](../crates/flock-backend/src/terminal_opening/bound.rs)

| Same two packed-record subtrees, five threads | Separate openings | Shared opening |
| --- | ---: | ---: |
| Compressed 64-leaf proof | 633,632 B | 351,840 B |
| Zero bytes | 2,634 | 1,399 |
| Minimum transaction gas for proof bytes | 25,287,260 | 14,052,630 |
| Final proving call | 37.69 s | 231.58 s, 222.91 s, 202.43 s |

All three shared runs produced the same proof, SHA-256 `7e537d528a0864142a8395a845850fb96679a2d9e8874beab7dbb281304fdf1b`. The third run reused the already committed setup tables. Fresh processes verified the second and third runs in 10.36 and 13.84 ms after setup. It rejected changes to the expected digest, count, authority, main cap, arithmetic payload, shared sumcheck rounds, final evaluation and Merkle path, along with truncated, extended and cross-profile proofs. An Osaka component replay authenticated seven sets of Merkle openings with 257 queried rows and 4,746 siblings. The raw rows and sibling hashes alone have a combined floor of **8,045,010 gas**. Solidity checked the 134-claim reduction with its transcript bound to the native authority and both commitments in **8,421,526 gas**, including the expanded claim records passed by the measurement harness. Checking the 192-by-64 tensor, deriving its batching point, and reproducing the initial WHIR sum and transcript continuation raised this component receipt to **9,581,656 gas**. Mutations across all three tensor limbs were rejected. The linked Keccak verifier used **55,948,553 gas over 24 component transactions**. Those component receipts do not sum to an end-to-end transaction price. The reported 145.94 bits cover a conditional algebraic calculation. The complete knowledge-soundness and client ZK arguments are open. [Security model](binary-security.md) · [Solidity reduction](../crates/evm-verifier/contracts/imt/NativeBitBatch.sol) · [Replay](../crates/evm-verifier/scripts/replay_native_openings.py)

To reproduce from saved subtrees with shared trusted cyclic metadata, use a fresh output directory.

```sh
RAYON_NUM_THREADS=5 cargo run --locked --release --bin terminal-merge -- \
  "$LEFT32" "$RIGHT32" --child-key "$CHILD_KEY" --child-trusted "$CHILD_TRUSTED" \
  --shared-opening --out "$ROOT_OUT"
cargo run --locked --release --bin tree-demo -- --verify --out "$ROOT_OUT" \
  --trusted "$TRUSTED_TERMINAL" --expected-statement "$STATEMENT_HEX"
```

## Dedicated terminal merge

The final circuit verifies two native cyclic child proofs under a fixed verifier identity and preprocessing commitment. Each child must cover 32 leaves. Two instances check the left and right roles against the same ordered parent digest. The verifier fixes the roles and count when translating the application statement to field elements. The new profile uses the exact preprocessing widths for this circuit, compacts copy selectors and uses rate 1/16 for both additive WHIR commitments. The child proofs retain their original keys. [Final circuit](../src/binary/aggregation_tree/terminal.rs) · [Backend profiles](../crates/flock-backend/src/lib.rs)

| Measurement on the same two children | Cyclic root | Dedicated terminal root |
| --- | ---: | ---: |
| Compressed proof | 948,926 B | 633,258 B |
| Calldata floor | 37,861,310 gas | 25,274,400 gas |
| Fixed columns | 963 | 540 |
| Native Keccak permutations | 43,370 | 43,342 |
| Initial main and preprocessing codeword cells | 100,663,296 | 805,306,368 |
| WHIR query draws across both openings | 956 | 358 |
| Conditional algebraic bound from setup | 146.10 bits | 146.04 bits |
| Prepared parent wall time, five threads | 12.0 s, 19.9 s | 111.9 s, 93.6 s, 139.1 s |

All three terminal trials used the ordered digest `2964429ad998ef5885adf5b511002abfb48576cb60338ff76871ee6b97df90c5` and produced the same file (SHA-256 `c9278530d663c4cb863ff92f50873fc31dc99b4815cdee3098ea409d688c43d4`). A fresh verifier accepted the compact and raw encodings and rejected a different digest, count, key metadata, a cyclic proof under the terminal key, mutations at three positions in the raw payload, truncation and trailing bytes. This profile exchanges more prover work for a 33.3% reduction in compressed bytes. Three separate depth-32 client proofs with five threads took 4.46–4.77 seconds each and occupied 1.129 MB each. The client path does not depend on the terminal profile. The setup bounds in the table are conditional and cover the aggregate’s algebraic components. [Security accounting](binary-security.md)

With 64 fresh packed-leaf witnesses, both 32-leaf subtree roots verified under the same trusted key. Their ordered merge produced digest `bb1f97b8866d2c07bf0214c9d87fad6b1e775819dc98cac63467735ef356c27e`, count 64, and proof SHA-256 `1c55168011820182d5d44bded291c352227d116b7300119b967c44c6ca7c3f1b`. The dedicated terminal's proving call took **37.69 s**, the prepared merge took **38.12 s**, and a fresh Rust process verified the result in **112 ms** after setup. The two 32-leaf runs averaged **3.12 and 2.98 s** per client including witness generation and **9.00 and 10.08 s** per interior aggregation. Their scheduled proof trees took 388 and 417 s with one worker and five threads. The ordinary cyclic merge on these exact two child proofs produced **948,522 bytes** and took **15.21 s and 30.02 s** to prove in two runs. Its prepared wall times were 16.01 and 31.13 s. The dedicated terminal proof is 33.2% smaller. Timings varied with load on the five-thread workstation. Packing constraints at the leaves preserves the terminal hash count and encoded table sizes. The two keys have slightly different copy layouts. The 374-byte difference from the earlier terminal proof is under 0.06% and the batches and child authorities differ. [Terminal circuit](../src/binary/aggregation_tree/terminal.rs) · [Cyclic control](../examples/bench-merge.rs)

On four saved client proofs, a single worker with five Rayon threads produced the first two aggregates in 11.83 and 12.06 seconds. Merging those aggregates took 11.96 seconds. These are prepared wall times including witness handling and native verification. The additional terminal trial uses a streaming evaluation of each round polynomial. Over 92,000 degree-three evaluations from the real proof per trial, the median across six alternating trials was 38.41 ms for the previous interpolation and 3.35 ms for the streaming implementation. The third full terminal run produced the identical proof and took 139.1 seconds, so the isolated interpolation gain does not establish a full-prover speedup. [Round interpolator](../vendor/p3-sumcheck/src/generic_degree/util.rs)

### Client proving time

The client encoder now runs its additive transform on the three base-field coordinates of each Poly192 value and evaluates independently on each coset of the input subspace. The scalar extension transform gives identical codewords for both interpolation and coefficient encodings at every tested rate from 1/4 to 1/32. Fresh processes running the old and new binaries verified each other’s depth-32 proofs. The existing aggregator also merged three new client proofs and one original-encoder proof into a four-leaf tree. A fresh process verified its ordered root. The encoding, masking parameters and verifier identity stay the same. [Client encoder](../src/binary/veil/code.rs) · [Codeword comparison](../tests/binary_veil.rs)

On an M2 Pro using five Rayon threads, six whole proofs per version gave a median of **4.54 seconds** for the original client and **3.47 seconds** for the coset implementation. The observed ranges were 3.41–8.87 seconds and 2.83–30.77 seconds respectively on the shared machine. These measurements support a lower sample median and show substantial variation under load. They measure the complete native client proving call after trace construction and exclude setup, serialization and subsequent verification.

An isolated comparison used the same 262,144 Poly192 coefficients and compared all 4,194,304 output words for exact equality on every run. Six alternating executions per implementation gave single-thread medians of 119.83 ms with the original transform and 63.68 ms with the coset transform. With five threads available to one column, the medians were 109.65 ms and 23.30 ms. A complete client proof also encodes several columns concurrently, builds Merkle trees and proves the AIR.

```sh
RAYON_NUM_THREADS=5 cargo run --locked --release --example masked-child -- --samples 6 --out "$FRESH_CLIENT_DIR"
```

### Same depth-32 leaf in the current binary LeanVM

The guest proves the two record openings with the same private 64-bit quantity, the input tag, and 32 ordered Merkle steps with private siblings and direction bits. A 36th Keccak binds the native public triple to its ordered leaf digest. The host independently computes the digest and verifies a decoded proof. Changes to the digest, input nonce, sibling, direction Booleanity and the upper limb of the quantity fail. The native masked leaf exposes the 96-byte triple and its first aggregate performs the digest hash. The timings below used an M2 Pro and five threads. Warm medians exclude one cold sample. [Guest](../adapters/leanvm/imt_leaf.py) · [Benchmark](../adapters/leanvm/examples/imt-leaf.rs) · [Native leaf digest](../src/binary/aggregation_tree.rs)

| Depth-32 implementation | Warm prove | Warm verify | Encoded proof |
| --- | ---: | ---: | ---: |
| Binary LeanVM at rate 1/2 | 34 ms | 4.2 ms | 158,688 B |
| Binary LeanVM at rate 1/4 | 31 ms | 3.5 ms | 118,632 B |
| Binary LeanVM at rate 1/16 | 42 ms | 3.1 ms | 91,884 B |
| Native non-hiding fixed Flock circuit at rate 1/4 | 172 ms | 32 ms | 523,964 B |
| Native non-hiding fixed checkpoint circuit at rate 1/4 | 239 ms | 37 ms | 711,828 B |
| Native masked leaf, original circuit at rate 1/16 | 2.50 s | 413 ms | 1.128–1.130 MB |
| Native masked leaf, packed inputs at rate 1/16 | 2.42 s | 240 ms | 1.091–1.093 MB |

The two non-hiding native controls and the VM used exactly the same synthetic openings, 64-bit quantity, mixed-direction path and ordered leaf digest `cb5b8af51b0221c87384da39871fa4d3fbe6f37a3ff3ff5d3200adb3f3c25856`. All decoded statements verified and changing the tag or digest caused rejection. At the common rate 1/4, our fixed Flock proof already takes about 5.6 times as long and uses 4.4 times the bytes. Its backend produces independent witness and preprocessing openings. The native checkpoint control also has a separate hash subargument in its standard profile. These controls show that privacy alone cannot account for the gap. The masked leaf measurements used independently generated valid IMT paths. Each native prove timing excludes witness generation, and the VM proving API includes execution. [Native fixed-circuit control](../examples/fixed-leaf.rs) · [Synthetic witness](../adapters/leanvm/examples/support/imt.rs)

The guest executed 3,677 instructions including 36 Keccak calls and committed 131,896 words before stack padding. LeanVM handles Keccak's bitwise round function with a dedicated batched GKR prover. Its field for extension elements has 128 bits and upstream targets 125-bit ROM soundness. The native masked leaf uses Poly192, a separate masking protocol and a 1,024-row by 1,631-column field trace. It retains 1,879,048,160 bytes of encoded oracle data. The LeanVM run establishes application correctness on this witness. It does not establish client witness privacy or the project's composition target. The native masking protocol also has an outstanding adaptive zero-knowledge analysis. [Upstream Keccak prover](https://github.com/leanEthereum/leanVM/tree/5b43139d50272f996ca884669b1d51555af1f35d/crates/stable_prover/keccak_gkr) · [Upstream security target](https://github.com/leanEthereum/leanVM/blob/5b43139d50272f996ca884669b1d51555af1f35d/README.md#security) · [Native security accounting](binary-security.md)

The opt-in native circuit selects each child in four 64-bit lanes. It enforces Booleanity of input payload bits at every fresh hash, fixes individual domain and padding bits, and enforces the full Keccak round recurrence. Each round maps Boolean inputs to Boolean outputs. Every dummy state is constrained to zero. This reduces private verifier products from 3,457 to 2,181 and masked messages from 6,761 to 5,485. Both variants still commit the full state trace. The size and timing measurements above used four proofs per native circuit and five per VM rate. The native samples are randomized. The original and packed masked leaf warm median sizes were 1,128,447 and 1,091,669 bytes. Of the latter, the median algebraic component was 708,034 bytes and the oracle was 384,126 bytes. Component medians can come from different samples. A four-leaf run produced two pair proofs and a recursive root. A fresh verifier accepted the ordered statement and the test rejected changed public values, order, count and proof bytes. The programs use different proof formats and the timings are workstation samples.

The native non-hiding batched Keccak component at 64 synthetic slots, two 12-round segments and rate 1/4, took 57 ms to prove at the warm median, verified in 3.6 ms and occupied 113,824 bytes. It checks the committed hash relation and leaves the IMT path links and masking to its caller. The larger native change to benchmark is a fixed leaf circuit using this round argument for the 35 application permutations. Bind each initial state and output to the same masked witness that enforces the 32 path links, both record openings, tag and quantity. The privacy analysis needs to cover each checkpoint opening and the joint transcript. For aggregation, apply the same principle to verifying two fixed child keys, derive repetitive selectors and wiring from the circuit layout, and batch all residual authenticated readings into one opening. The release measurement is an ordinary Solidity transaction verifying the expected 64-leaf ordered digest and count. [Native membership AIR](../src/binary/veil/membership_air.rs) · [Terminal plan](ethereum-terminal-proof-plan.md)

```sh
cargo run --locked --release --manifest-path adapters/leanvm/Cargo.toml --example imt-leaf
RAYON_NUM_THREADS=5 cargo run --locked --release --example fixed-leaf
RAYON_NUM_THREADS=5 cargo run --locked --release --example masked-child -- --packed-lanes --samples 4 --out "$FRESH_CLIENT_DIR"
cargo prove -n 4 -j 1 --threads 5 --packed-lanes --keep --out "$FRESH_TREE_DIR"
```

### Reproduce the terminal merge

For two saved 32-leaf directories, use the independently trusted cyclic metadata and key. The command writes a fresh terminal bundle that the existing standalone verifier can read. Keep the expected terminal key digest under application control.

```sh
cargo run --release --locked --bin terminal-merge -- "$LEFT" "$RIGHT" \
  --child-key "$CYCLIC_KEY" --child-trusted "$CYCLIC_TRUSTED" --out "$TERMINAL_BUNDLE"
cargo prove --verify --out "$TERMINAL_BUNDLE" --trusted "$TERMINAL_TRUSTED" --expected-statement "$STATEMENT_HEX"
```

On Osaka, Solidity authenticated all 358 queried rows of the original terminal proof and rejected all 30 commitment, row and sibling mutations. It now also replays the entire chain of 24 packed Keccak nonlinear layers. The Solidity verifier derives the initial challenge point from the native commitment and bridge transcript, checks the projections, all 552 cubic rounds and their endpoints, and carries the resulting challenge and value into the next layer. The differential replay compared every challenge point, batching scalar and reduced value against the corresponding Rust verification for both 64-leaf fixtures. Mutations in the first, middle and last layer were rejected. The resulting input claim still needs its closing proof and authenticated opening. Settlement also needs the arithmetic verification, bridge authentication and complete WHIR verification. [Solidity round chain](../crates/evm-verifier/contracts/imt/NativeKeccakRounds.sol) · [Real-proof tests](../crates/evm-verifier/test/NativeKeccakRounds.t.sol) · [Osaka replay](../crates/evm-verifier/scripts/replay_native_openings.py)

The cubic interpolation uses shifts and prefix XORs for multiplication by the constants 2 and 1/6. Multiplication in Poly192 accumulates carryless products before reduction. On both fixtures, applying the evaluator to the **552 cubic rounds** with the actual Rust challenges supplied used **6,664,968 execution gas** inside the metered loops, down from 7,285,968. That measurement includes operand decoding and loop control. The complete round chain additionally derives Fiat–Shamir challenges and evaluates the Keccak linear maps and endpoints. [Native arithmetic](../crates/evm-verifier/contracts/imt/NativeField.sol) · [Metering harness](../crates/evm-verifier/test/NativeField.t.sol) · [Verified native trace exporter](../examples/root-opening-trace.rs)

A high-gas Foundry simulation of the full linked round chain on the original fixture consumed **55,266,633 execution gas** in one external call including ABI encoding and return. The previous straight implementation used 59,337,783 gas on that fixture. The optimization composes the two fixed binary projection matrices ahead of time and evaluates each iota constant over only its nonzero positions. On the fresh packed-leaf root, the 24 individual round transactions under standard Osaka rules used **55,948,397 gas in total**, down from 59,644,180. The latter sum includes 24 transaction bases and repeated intermediate calldata. Both measurements end at the Keccak input claim. Neither is a full-root receipt. The calldata floor and execution gas are different accounting measures. [Projection compiler](../crates/evm-verifier/scripts/gen_chi_projection.py) · [Full-chain harness](../crates/evm-verifier/test/NativeKeccakRounds.t.sol)

Together the rows and sibling hashes occupy **302,528 bytes** with 1,207 zero bytes. Sending just those two fields of the openings costs **12,085,910 gas** before execution. All 358 rows and all 6,294 sibling hashes are distinct within their respective sets. In the fresh packed-leaf root the corresponding floor for rows and siblings is 12,105,750 gas. Both exceed the budget with the rest of the proof omitted. The opening protocol itself must change.

The two initial query batches account for 100,544 of those bytes and a 4,030,910-gas floor. Adding only the current main continuation brings that subtotal to 203,232 bytes and 8,125,680 gas. These are byte counts of fields in the measured proof. A protocol with a shared continuation still needs a common evaluation domain, a binding reduction for both oracles, and space for every other argument.

### Sharing the witness and wiring opening

The experiment embeds the two packed polynomials into one 26-variable multilinear polynomial. Each initial encoded row contains 32 witness words, 16 wiring words, and 16 zeros. The verifier authenticates the first two segments against independent Keccak roots and fixes the last segment to zero. The wiring root matches the terminal verification key. The two polynomials share the subsequent WHIR folds. The experiment keeps the 152-bit WHIR configuration target, 16 grinding bits, and initial rate 1/16. [Paired commitment](../crates/flock-backend/src/terminal_opening/mmcs.rs)

On the same two 32-leaf children, native verification checked all 134 original bit readings in one paired opening. The compressed opening alone occupied **385,762 bytes**, with a calldata floor of **15,408,820 gas**. Committing took 55.8 seconds and opening took 328.6 seconds on five M2 Pro threads. The comparison runs in a separate transcript after checking the full native original proof. The witness root was `6eb188a46f730f059590356200608af803cbd679906c9acef80805e3a5acce91` and the independent wiring root was `83a4024a52648ccf42c74109c385d9f3af30633ebc72f7023141c35b469498a8`. Reproduce the measurement by adding `--features opening-bench` to Cargo and `--compare-paired-opening` to the terminal merge command. [Native replay](../crates/flock-backend/src/terminal_opening/replay.rs)

A second experiment reduces all 134 readings to one before ring switching. The verifier absorbs both commitments and all points and values, samples a challenge for the linear combination, checks 32 quadratic sumcheck rounds, then authenticates the surviving value with WHIR. The additional round messages and final value occupy 1,560 bytes. With the same two 32-leaf proofs, the complete shared opening shrank from **385,762 to 207,587 compressed bytes**. Two runs produced the same 217,612-byte raw opening. Commit took 95.7 and 98.2 s, opening took 388.8 and 189.5 s, and verification took 9.1 and 15.1 ms. The runs had different machine load. Add `--reduce-readings` to the paired-opening command. [Native sumcheck](../crates/flock-backend/src/terminal_opening/batch.rs) · [WHIR endpoint verification](../crates/flock-backend/src/terminal_opening/replay.rs)

The new opening's measured calldata floor is **8,299,460 gas**. In the complete original root, removing both original bit openings leaves 152,232 raw bytes. The arithmetic body uses 73,280 raw bytes, the linked Keccak argument and its coefficients use 75,744, and the bridge uses 3,208. Compressing these fields together gives 143,850 bytes and a 5,758,560-gas floor. Concatenating those two separately compressed components would cost **14,037,020 gas** with one transaction base. The actual terminal commitment and transcript differ from the experiment, so this calculation is a sizing estimate. The original complete root has a 25,274,400-gas calldata floor.

Solidity reproduced the Rust reduction endpoint from all 134 records and rejected changes to its transcript prefix, an input record, a round message and the final value. The Osaka receipt was **8,348,973 gas**. The same check used 12,749,128 gas before reusing partial equality products, then 8,890,848 gas before delaying field reduction. The verifier now reuses equality products across coordinate ranges after comparing their actual bytes. The harness takes 106,128 bytes of expanded verifier-derived records as input. A full verifier must construct these from its authenticated transcript and public statement. This receipt covers the batching equation only. The rest of the polynomial opening, the arithmetic equations and all linked Keccak checks still contribute to the final cost. [Solidity reduction](../crates/evm-verifier/contracts/imt/NativeBitBatch.sol) · [Differential replay](../crates/evm-verifier/scripts/replay_native_openings.py)

## Artifact and measurements

At commit `75abd8c`, the release verifier accepted the 64-leaf artifact with SHA-256 `54170085640418381fee36305d003e7ec3218aefae41bff22f8bcfaaaa05e9f7`, matching the checked-in benchmark. One fresh process reported 17.8 ms for setup and 112.0 ms for verification. The trusted verifier key file is 93,702 bytes. The gas calculation gives the verifier that key in advance and omits ABI framing. [Benchmark](../benchmarks/binary/tree-merge/packed-first-fold-m2.json) · [Verifier entry point](../src/binary/aggregation_tree/cyclic.rs)

| Data sent in one transaction | Bytes | Zero bytes | Nonzero bytes | Gas floor including transaction base |
| --- | ---: | ---: | ---: | ---: |
| Saved zlib proof (`IMTPRF02`) | 948,828 | 3,968 | 944,860 | 37,855,080 |
| Accepted uncompressed encoding (`IMTPRF01`) | 1,013,744 | 55,712 | 958,032 | 38,899,400 |
| Saved proof plus 64 tightly packed public statements | 954,972 | 3,994 | 950,978 | 38,100,060 |

The calldata floor for an ordinary call is `21,000 + 10 × zero_bytes + 40 × nonzero_bytes`. The protocol takes the maximum of the floor and the usual gas calculation. A contract would still need to implement the binary-field STARK and additive WHIR verifier, its linked Keccak checks, and the trusted statement binding. Rust verified the entire saved proof. Solidity separately checked its Merkle openings as described below. [Proof codec](../crates/flock-backend/src/proof_codec.rs) · [Joint proof verification](../crates/flock-backend/src/checkpoint.rs)

I cross-checked the byte count with Anvil 1.5.1 and `eth_estimateGas`, sending the exact file as call data to an empty account on localhost. Prague with a 60M allowance gave 37,855,080. Osaka with the mainnet cap rejected the full payload. The first 316,276 bytes alone gave 12,632,020 gas. An all-nonzero payload reaches the cap at 418,905 bytes. Staging these proof bytes unmodified would need at least three transactions, plus a way to authenticate the pieces and run the verifier. A blob can carry the data for offchain readers. Its contents are unavailable as ordinary EVM-readable bytes. [EIP-4844 blob interface](https://eips.ethereum.org/EIPS/eip-4844)

To repeat the native and byte-count checks on the saved run:

```sh
cargo run --locked --release --bin tree-demo -- --verify --out run/joint-parent.c3SjqA/group-final64
python3 - <<'PY'
from pathlib import Path
from hashlib import sha256

proof = Path("run/joint-parent.c3SjqA/group-final64/aggregate.proof").read_bytes()
zeros = proof.count(0)
nonzeros = len(proof) - zeros
print(sha256(proof).hexdigest(), len(proof), zeros, nonzeros)
print(21_000 + 10 * zeros + 40 * nonzeros)
PY
```

## Cost of a succinct outer proof

A way to retain the existing inner proof is to run its verifier in a zkVM offchain and prove that execution. The verifier program would pin the expected merge key and protocol, verify the root proof, and publish the authenticated ordered statement digest and leaf count. The Ethereum contract would pin the program identity and check those public outputs against the batch it accepts. The current root authenticates an ordered list of client statements. Pool state transitions and withdrawal accounting would need to be enforced separately. [Root statement](../src/binary/aggregation_tree.rs) · [RISC Zero on Ethereum](https://dev.risczero.com/api/blockchain-integration/risc-zero-on-eth)

As a reference measurement, I compiled RISC Zero’s 3.1.0 Groth16 verifier (`solc 0.8.28`, optimizer 200 runs, Cancun bytecode target) and deployed it on an isolated Osaka Anvil chain. A direct call to `verify(seal, imageId, journalDigest)` with the upstream valid test receipt used **250,942 gas**, including transaction base and 420 bytes of calldata. The seal was 260 bytes. Changing the journal digest caused the verifier to revert. The measurement excludes deployment, pool execution and data publication. It demonstrates the cost of verifying that class of receipt. The port, guest cycles, proving time and memory for this repository’s verifier remain unmeasured. The Groth16 wrapper also introduces its own trusted setup. [Measured verifier revision](https://github.com/risc0/risc0-ethereum/blob/13754b018482c79c8958e8d9d94de8ed41482ccb/contracts/src/groth16/RiscZeroGroth16Verifier.sol) · [Test receipt](https://github.com/risc0/risc0-ethereum/blob/13754b018482c79c8958e8d9d94de8ed41482ccb/contracts/test/TestReceiptV3_1.sol) · [Trusted setup](https://dev.risczero.com/api/3.0/trusted-setup-ceremony)

## Direct, transparent verification

I decoded the same root using the pinned Rust proof types and counted the fixed-width bincode bytes for each component. The main trace opening occupies **406,021 bytes** and the preprocessing opening **505,180 bytes**, including its option tag. Together they account for **89.9%** of the 1,013,744-byte raw file. Across both openings, the queried rows take 212,528 bytes and the Merkle multiproofs take 403,408 bytes. The encoder already shares authentication paths within each round. The two openings also carry ring-switch reductions of 72,623 and 156,053 bytes respectively. These reductions connect claims about binary trace coordinates to the polynomial being opened. [Proof layout](../crates/flock-backend/src/checkpoint.rs) · [Pinned WHIR opening types](https://github.com/Plonky3/Plonky3/blob/708900d7a730d6ce4d5421d43e2193f2301920fa/whir/src/pcs/proof.rs)

Brotli quality 11, the smallest of the general-purpose codecs I tested, produced **932,790 bytes** with a calldata floor of **37,220,940 gas** before decoding. For comparison I removed the entire contiguous preprocessing opening and compressed the remaining bytes with Brotli. Even this invalid proof fragment took **490,645 bytes** and **19,588,150 gas**. A viable direct design has to improve more than the transport or preprocessing alone.

A fresh native tree after the Keccak weight and Merkle subtree optimizations reused its merge key at all levels. An independent process verified all 64 leaves’ ordered statement from the final proof. The run rejected a foreign authority, incorrect children and ten mutations of the final proof or batch. The generated merge circuit used **43,370 Keccak permutations per two-child merge** versus **43,694** in the saved control. Its compressed root was **948,926 bytes**, with a calldata floor of **37,861,310 gas** (SHA-256 `785d8ae35e94fc0fa0cb6765a8dd2edf12f1b55ea5f64e516a73bb3983609bcb`). The reduction in recursive verifier work left proof transport essentially unchanged.

### Solidity replay of native openings

The Rust tracer records rows, indices, commitments and siblings while the trusted verifier checks the complete saved root against its ordered statement. The Solidity library hashes the serialized rows and reconstructs the pruned binary Keccak tree. Ten ordinary Osaka transactions authenticated five query sites per opening, with 478 query draws each for main and preprocessing. All 956 rows were distinct within their respective sites. The first site used 7,200,460 gas for main and 6,786,170 gas for preprocessing. Changing a commitment, row or sibling independently caused the expected cryptographic rejection at every site (30 negative calls). The traced indices and caps are inputs to this component test. A complete verifier must derive them from the authenticated protocol and its Fiat–Shamir transcript. [Native tracer](../examples/root-opening-trace.rs) · [Solidity library](../crates/evm-verifier/contracts/imt/NativeMerkle.sol)

The 12,604 sibling hashes contain 403,328 raw bytes, including 1,585 zero bytes. Submitting only those bytes in one ordinary transaction would incur a **16,106,570 gas** floor. This excludes rows, the statement, ABI framing and execution. The site receipts are separate transactions. The current opening already prunes shared paths within a site.

The regenerated 64-leaf root also passed all ten opening checks in Solidity, and all 30 altered calls reverted with the expected cryptographic error. Its 12,617 sibling hashes alone cost **16,122,010 gas** in calldata. Both generations independently exceed the full transaction budget from this part of the opening alone.

With the saved bundle in `$BUNDLE` and its independently trusted metadata in `$TRUSTED_JSON`, run the following from the repository root. The exporter checks the whole proof before emitting the trace.

```sh
cargo run --locked --release --features opening-bench --example root-opening-trace -- \
  --bundle "$BUNDLE" --trusted "$TRUSTED_JSON" > /tmp/imt-openings.json
python3 crates/evm-verifier/scripts/replay_native_openings.py /tmp/imt-openings.json
```

### What changing the code rate buys

I ran the repository’s WHIR parameter constructor for the saved root’s main and preprocessing polynomial dimensions (25 and 24 variables), keeping its 152-bit PCS target, Johnson assumption, folding factor of 4 and 16-bit grinding budget. Lower rates encode the same data in a longer codeword. That costs more to construct, but lets the verifier check fewer positions. [Local configuration](../crates/flock-backend/src/config.rs) · [WHIR paper](https://eprint.iacr.org/2024/1586)

| Starting rate | Query draws per opening, all rounds | Modeled raw root size | Initial codeword cells relative to baseline |
| --- | ---: | ---: | ---: |
| 1/2 (current) | 478 | 1,014,080 B | 1× |
| 1/4 | 284 | 817,760 B | 2× |
| 1/8 | 216 | 742,064 B | 4× |
| 1/16 | 179 | 703,312 B | 8× |

Sizes are medians over 128 simulated query schedules per rate (seed 20261120). The model samples each binary stratum, counts the rows and the missing siblings needed to reconstruct each root, and holds the 397,808 remaining bytes fixed. The baseline differs from the real file by 336 bytes. New-rate sizes are projections. A new proof would also reflect changes to small transcript fields. The table provides neither compressed sizes nor EVM execution measurements.

### Cost of committing whole field words

A final PCS could commit Poly64 table entries directly, removing the binary ring-switch messages from its proof. The saved merge geometry contains 48,796,752 main table entries and 96,532,128 fixed preprocessing entries. The two additional Keccak boundary tables have 2²⁷ entries each. The padded arities for whole words are 29 for main and 27 for preprocessing. Even at rate 1/2 their combined initial codewords need 1,342,177,280 cells, exceeding the current prover's 2³⁰-cell budget. [Boundary tables](../crates/flock-backend/src/checkpoint_keccak/linked.rs) · [Prover budget](../crates/flock-backend/src/config.rs)

The sizing example enumerates starting log-inverse rates 1 through 8, initial folds 1 through 6 and subsequent folds 2 through 6. It uses the pinned WHIR constructor, requires the native 152-bit per-term target, Johnson assumption and 16-bit grinding cap, and discards invalid schedules. It computes the expected number of occupied nodes in each binary stratum, counts the missing siblings, and charges only distinct rows and the final polynomial. Under independent random-oracle draws, the smallest projected subtotal for two independent openings is **408,846 bytes** across the schedules tested. This omits all other proof data. The two selected rates would require 17,179,869,184 and 2,147,483,648 initial cells respectively. These are model results for this family of schedules. A real alternative would also need composed security accounting and an EVM transaction measurement.

```sh
cargo run --locked -p imt-flock-backend --example whir-opening-size -- 29 27
```

### What transfers from LeanVM to a fixed IMT circuit

At LeanVM main revision `5b43139`, the checked binary verifier uses one root for a stack of witness columns. A batched bus argument and a table sumcheck reduce the constraints to evaluation claims. The verifier checks the expected public words directly, verifies the Keccak reduction, ring-switches its bit-slice claim, then draws a challenge to combine up to 512 claims. It constructs the combined polynomial weight itself and invokes WHIR once. Our current root already batches readings **within** each commitment and shares Keccak boundary openings with the main arithmetic proof. Its separate preprocessing commitment runs a second WHIR protocol. The earlier 10.67M-gas KoalaBear terminal contract uses a different two-commitment protocol with a shared continuation after the first queries. [Current LeanVM verifier](https://github.com/leanEthereum/leanVM/blob/5b43139d50272f996ca884669b1d51555af1f35d/crates/verifier/src/lib.rs#L256) · [Current batching equation](https://github.com/leanEthereum/leanVM/blob/5b43139d50272f996ca884669b1d51555af1f35d/crates/verifier/src/lib.rs#L146) · [Native IMT composition](../crates/flock-backend/src/checkpoint.rs) · [Earlier two-commitment protocol](../crates/evm-verifier/contracts/leanvm/LeanVmWhir.sol)

The current binary LeanVM workspace implements its own prover, field library, PCS and verifier. Its Cargo lockfile contains no Plonky3 packages. The Ethereum reference in the 10.67M-gas experiment is the separate KoalaBear terminal verifier. Current binary LeanVM groups identical known bytecode words to evaluate them at a challenge point, and its recursive program batches deferred child bytecode obligations for a later check against the known program. Our native terminal circuit uses 43,342 Keccak permutations to check its two child proofs, 10,227,278 paired copy IDs, 262,144 extension products, and 805,306,368 initial encoded cells across witness and wiring. Those hashes arise in recursive verification. Each application leaf itself performs 35 hashes. LeanVM's published 270.5 KiB recursion benchmark aggregates two leanXMSS proofs on an M4 Max. It proves a different recursive statement. [LeanVM workspace](https://github.com/leanEthereum/leanVM/blob/5b43139d50272f996ca884669b1d51555af1f35d/Cargo.lock) · [Fixed bytecode evaluator](https://github.com/leanEthereum/leanVM/blob/5b43139d50272f996ca884669b1d51555af1f35d/crates/verifier/src/bytecode.rs) · [Deferred evaluation](https://github.com/leanEthereum/leanVM/blob/5b43139d50272f996ca884669b1d51555af1f35d/crates/aggregation/src/deferred.rs) · [Upstream recursion benchmark](https://github.com/leanEthereum/leanVM/blob/5b43139d50272f996ca884669b1d51555af1f35d/README.md#recursion)

The reference Solidity verifier operates in an extension of the 31-bit KoalaBear prime field. Its multiplication and reduction use ordinary EVM integer products and modular arithmetic. Our root uses characteristic-two Poly192. EVM integer multiplication propagates carries, so the Solidity library explicitly constructs carryless products for three 64-bit coordinates and reduces them in the extension field. This accounts for an additional execution-cost difference when comparing against the separate 10.67M reference fixture. The end-to-end receipts do not isolate the relative contributions of field choice and proof layout. Current binary LeanVM also uses binary extension arithmetic. Its native CPU timings should be compared separately from that Ethereum reference. [KoalaBear arithmetic](../crates/evm-verifier/contracts/leanvm/LeanVmWhirArithmetic.sol) · [Poly192 arithmetic](../crates/evm-verifier/contracts/imt/NativeField.sol) · [Reference fixture and security parameters](https://github.com/ethereum/sol-whir-p3/blob/b82359ec98e1e3c9f6f39ebf984e7aefb0eeb9be/testdata/leanvm_terminal/GroupedLogupKeccakPow28T6/manifest.json)

The saved merge has 369 main columns and 963 fixed preprocessing columns. Its main coordinate bounds are 66 full words, 258 16-bit words, 44 Boolean columns and one fixed zero. Treating each column as one independent claim would already exceed LeanVM’s 512-claim bound. Derive the claim schedule from the IMT layout, combine claims with shared points and preserve each declared range when changing representations.

There are two concrete changes to test in the final merge.

1. **Make the wiring cheap to evaluate.** LeanVM prepares its fixed bytecode once, omits zero words and groups repeated values in blocks of 16,384. At the challenge point it evaluates the grouped data and checks the answer. For the IMT, constant selectors and affine columns admit exact formulas. Arbitrary copy IDs need an authenticated evaluation. An alternative is to retain distinct fixed and witness roots, bind both before batching, check the initial queries for each, and share the subsequent WHIR folds. On our saved root the first queries for the two oracles already require 342,944 bytes of rows and siblings and a 13,697,510-gas floor. Sharing only the continuation at the current query schedule cannot reach 11M. [Fixed bytecode evaluator](https://github.com/leanEthereum/leanVM/blob/5b43139d50272f996ca884669b1d51555af1f35d/crates/verifier/src/bytecode.rs#L81) · [IMT fixed-column profiler](../crates/flock-backend/src/opening_bench/fixed.rs)
2. **Commit Keccak lanes and derive the outputs.** LeanVM commits 64-bit input lanes and the state after round 12. The bus supplies a claim on output lanes. The GKR proof checks two blocks of twelve rounds together and appends its claims to the shared opening. The IMT release format pays for input and output boundary tables and checks 24 sequential layers. The repository already has a standalone 12-round midpoint experiment. A final-merge port has to take its output claim from the authenticated IMT ports, preserve the byte-swapped limb mappings, bind the intermediate state before drawing the challenge, and keep the native Poly192 security accounting. [LeanVM Keccak bridge](https://github.com/leanEthereum/leanVM/blob/5b43139d50272f996ca884669b1d51555af1f35d/crates/stable_prover/lean_vm_core/src/keccak.rs) · [Current IMT bridge](../crates/flock-backend/src/checkpoint_keccak/ports.rs) · [IMT midpoint experiment](../crates/flock-backend/src/checkpoint_keccak/packed/mod.rs)

On the regenerated merge, **158 of 963 fixed columns were constant** and none of the other 805 were affine in the row-index bits. Grouping repeated nonzero words separately in each column in blocks of 16,384 rows left **43,665,461 positions and 13,507,217 distinct word groups** across 4,014 nonempty blocks. This measures the straightforward column-by-column port of LeanVM’s evaluator. It leaves room for joint evaluation or a different layout. A specialized final circuit should generate regular addresses and selectors from explicit formulas, then measure the cost of authenticating the residual wiring. [Fixed-column profiler](../crates/flock-backend/src/opening_bench/fixed.rs)

I also tested sharing the evaluation across columns at a common point within each table. The evaluator strips off each subtable’s constant term, interns equal residuals and reuses challenge products for translated or swapped branches. A dense Poly192 evaluation checks the construction in a regression test. On the same 96,532,128 cells, one evaluation per table still requires **3,297,916 extension-field products** and **1,447,337 base-word scalings** with this method. These are operation counts for that specific algorithm. They motivate changing how the final circuit assigns wire addresses before paying for an onchain evaluator. [Shared interpolation and test](../crates/flock-backend/src/opening_bench/fixed.rs)

For a joint opening with distinct weights, give the witness and fixed polynomials a common padded domain and a Boolean selector. On its two faces set `Q(0,x)=M(x)`, `Q(1,x)=P(x)`, `W(0,x)=Wm(x)` and `W(1,x)=Wp(x)`. The batched claim is the sum of `Q·W` on the Boolean cube. One degree-two sumcheck round on the selector reduces it to a claim on the polynomial `Q(r,x) = M(x) + r(P(x) + M(x))` in characteristic two. The first authenticated query must open **both** original roots at the protocol-derived positions. Linearity then gives their combined codeword values. Later folds can share an oracle. For this candidate protocol the commitments and all claimed readings must be bound before sampling `r`, and an adapted list-decoding/soundness argument is required for the virtual codeword and the mixed weights. [Native field round](../crates/evm-verifier/contracts/imt/NativeField.sol) · [Reference first-query combination](../crates/evm-verifier/contracts/leanvm/LeanVmWhir.sol)

Because the final merge always verifies two 32-leaf children, its trusted circuit can fix their count, verifying key and left/right statement rule at setup. Interior merges still need the cyclic layout. A terminal key can instead group the final verifier’s repeated operations into tables with predictable addresses for round numbers, query positions and limb offsets. The layout still has to constrain every copy equality presently carried by the fixed wiring. [Current conditional child authority and merge](../src/binary/aggregation_tree/cyclic.rs)

A provisional IMT layout using 64-bit words for the two bit-boundary tables would reduce them from 268,435,456 entries to 4,194,304 lanes. With the other main columns, the stack would have 52,991,056 entries and pad to 2²⁶. At rate 1/16 the native sizing tool projects **161,382 bytes** for that stack’s rows, sibling hashes and final polynomial, using its 152-bit per-term target and 16-bit grinding limit. The initial codeword alone would occupy the entire 2³⁰-cell prover budget. The projection excludes authenticated fixed wiring, the Keccak-to-lane reduction, narrow-column range constraints, other sumchecks and EVM execution. Whole-word commitments must explicitly enforce any bounds previously imposed by the Boolean coordinate representation. Reproduce the size sweep with `whir-opening-size -- 26`. [Encoding bounds](../crates/flock-backend/src/encoding.rs) · [Size model](../crates/flock-backend/examples/whir-opening-size.rs)

LeanVM's binary Fiat–Shamir sponge applies the raw Keccak-f permutation to private sponge state. Ethereum's `KECCAK256` opcode returns a 32-byte padded hash. The native IMT's byte hash challenger and binary Merkle hashes already use this EVM hash directly. Reuse the algebraic reductions while specifying and analyzing the final IMT transcript with its own domain separation. [LeanVM transcript](https://github.com/leanEthereum/leanVM/blob/5b43139d50272f996ca884669b1d51555af1f35d/crates/verifier/src/transcript.rs) · [IMT challenger](../crates/flock-backend/src/config.rs)

I ran LeanVM's standalone Keccak prover at the saved merge workload of **43,694 active permutations**, padded to 65,536, using deterministic synthetic states. Its checked native verifier accepted each proof. The table charges the exact bytes returned by `Proof::to_bytes()`. The Ethereum numbers include base gas and proof calldata only. The binary VM uses a 128-bit extension and targets 125-bit ROM soundness. The IMT uses Poly192 and has a separate 128-bit classical target and a conditional algebraic bound. Its release parameters require their own analysis. [Upstream benchmark](https://github.com/leanEthereum/leanVM/blob/5b43139d50272f996ca884669b1d51555af1f35d/crates/stable_prover/keccak_gkr/src/batch_bench.rs) · [LeanVM security](https://github.com/leanEthereum/leanVM/blob/5b43139d50272f996ca884669b1d51555af1f35d/README.md#security)

| Rounds per segment | Code rate | Transcript scalars | Canonical bytes | Calldata floor |
| ---: | ---: | ---: | ---: | ---: |
| 24 | 1/2 | 2,843 | 243,040 | 9,669,220 |
| 12 | 1/2 | 1,597 | 233,756 | 9,308,450 |
| 24 | 1/16 | 2,843 | 136,364 | 5,430,140 |
| 12 | 1/16 | 1,597 | 120,424 | 4,799,110 |

For the 12-round control, the stack has 22 variables. LeanVM’s rate-1/2 query schedule is 218, 55, 32 and 24 across the four WHIR levels. At rate 1/16 it checks 55, 32, 23 and 18 instead, or 128 query draws total. The existing IMT root uses two 478-draw schedules. The statement sizes, soundness derivations, oracle geometries and degree reductions differ, so the LeanVM counts cannot be substituted directly. [LeanVM query ladder](https://github.com/leanEthereum/leanVM/blob/5b43139d50272f996ca884669b1d51555af1f35d/crates/verifier/src/whir.rs#L35)

The IMT’s own standalone benchmark verified both schedules at 65,536 active permutations, using its Poly192 field and the same joint PCS configuration for both. The full 24-round proof used **2,936 non-PCS scalars and 273,859 bytes**. The midpoint proof used **1,555 non-PCS scalars and 260,202 bytes**. This saves 1,381 scalars (47.0%) and 13,657 serialized bytes (5.0%). Its conditional algebraic bounds were 148.02 and 147.74 bits respectively. The bit-boundary PCS still dominates the encoded proof. These two IMT runs both use dense deterministic inputs and measure their standalone component statement. The LeanVM runs above use a padded input batch, a different field and a different statement.

At the dedicated terminal workload, the two standalone provers consumed the same 43,342 active Keccak inputs, padded to 65,536 slots, with five threads and two 12-round segments. At code rate 1/16, LeanVM produced **117.4 KiB** in **1.48 s**, with **2.9 ms** verification in the matched run. A separate run gave 657 ms proving and 2.4 ms verification. The native prover produced **205,503 bytes** in **5.34 s**, with **7.1 ms** verification. Commitment took 0.80 s, reduction 1.49 s and the opening 3.05 s. At rate 1/4 the native proof was 260,795 bytes and took 1.55 s to prove. The 1/16 runs used very similar numbers of non-PCS scalars (1,597 upstream and 1,555 native). Our scalars take 24 bytes, compared with 16 upstream. Our standalone proof also commits both boundaries. LeanVM gets its output claim from the enclosing VM argument. Upstream's proof contains 92.4 KiB of Merkle openings. The security models and boundary commitments differ. These timings exclude recursive child verification and the application’s private witness masking. [Pinned LeanVM Keccak prover](https://github.com/leanEthereum/leanVM/blob/5b43139d50272f996ca884669b1d51555af1f35d/crates/stable_prover/keccak_gkr/src/batch_bench.rs) · [Native benchmark](../crates/flock-backend/examples/packed-keccak.rs)

```sh
cargo run --manifest-path adapters/leanvm/Cargo.toml --locked --release --example imt-keccak -- "$FRESH_INPUTS"
RAYON_NUM_THREADS=5 cargo run --release --locked -p imt-flock-backend --example packed-keccak -- 16 mid packed joint 1 --log-inv-rate 4 --inputs "$FRESH_INPUTS"
cargo run --release --locked --features opening-bench --example bench-merge -- --profile-fixed-columns
```

### Engineering choice

The dedicated terminal merge has its own proving parameters and trusted key. Reducing its calldata below the release limit now requires an efficient evaluation of the fixed preprocessing polynomial or a smaller authenticated opening for the two oracles. Any replacement must authenticate both sets of claims, preserve the expected child verifier authority, and expose the same ordered batch digest and count. A useful target for the new format is **200 kB of high-entropy calldata** (at most 8,021,000 gas for the calldata floor at that size). Measure execution separately and apply the maximum in EIP-7623. Recheck the composed soundness accounting and measure peak prover memory with the larger codewords. [Terminal circuit](../src/binary/aggregation_tree/terminal.rs) · [Security accounting](binary-security.md)

A published transparent reference, LeanVM’s grouped terminal verifier, used **99,044 calldata bytes** and **10,666,368 transaction gas** for a different proof. Its benchmark used a local Cancun EVM with relaxed deployment limits. Its 62,623-byte runtime exceeds Ethereum’s 24,576-byte contract limit. It illustrates a plausible design using an EVM-oriented final proof. A mainnet implementation needs deployable verifier modules and a fresh measurement on this repository’s statement. [Pinned reference benchmark](https://github.com/ethereum/sol-whir-p3/blob/2f1fecfd4430f205110d202970b262352a46f4e4/README.md#latest-measurements) · [EIP-170 contract size limit](https://eips.ethereum.org/EIPS/eip-170)
