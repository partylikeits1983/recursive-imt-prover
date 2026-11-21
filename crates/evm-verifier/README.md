# EVM verifier

The Solidity verifier checks the native 64-client IMT root against an application-supplied ordered digest and count. The default strong midpoint deployment takes **106,637,610 gas** on high-limit local Prague with the fixed wiring cap and ring certificate. The separately keyed comparison deployment takes **99,956,986 gas** for the same statement. Both exceed the 11M settlement budget. The comparison profile has a 121.48-bit conditional terminal bound. [Root entry points](contracts/imt/NativeAggregateRootVerifier.sol) · [Profile measurements](../../docs/ethereum-root-verification.md#selecting-the-midpoint-terminal-security-profile)

Run `FOUNDRY_PROFILE=comparison forge test --root crates/evm-verifier` from the repository root to exercise the lower-profile Solidity build. The default and comparison suites contain valid 64-client proofs and cross-profile rejection checks. The native Rust prover selects a terminal profile independently of the verification environment. [Rust interface](../../src/binary/aggregation_tree/terminal.rs)

Run `forge test --root crates/evm-verifier --match-contract 'Native((Midpoint)?AggregateRoot|LiftedRoot)Test'` from the repository root to check the packaged roots and row-certificate deployment and rejection of altered inputs. The replay independently compares every Solidity opening claim with Rust. [Regression](test/NativeAggregateRoot.t.sol) · [Full transaction replay](scripts/replay_native_root.py)

The contracts in `contracts/leanvm` and the Rust calldata encoder target the
earlier KoalaBear `GroupedLogupKeccakPow28T6` reference program. Its sample
transaction measures the cost of verifying that program’s own fixture.
[IMT production plan](../../docs/ethereum-terminal-proof-plan.md)

The application can compute the expected native statement with
`ImtBatchStatement.digest64(records)`. Pass 64 ordered 96-byte records, each
containing the membership root, input tag and output commitment. Root-only preimage clients encode the last two fields as 64 zero bytes. The result
is the full 32-byte batch digest, with the count fixed by the library.
Run `forge test --match-contract ImtBatchStatementTest` for the native digest
vector, record order and length checks. [Batch statement library](contracts/ImtBatchStatement.sol)

## Prime-field opening component

In the original Osaka measurement, the fixed 22-variable WHIR verifier accepted one opening of the 64-client terminal’s Keccak checkpoint table on Osaka for 7,017,857 gas. Its public inputs are the expected commitment, context, multilinear point and evaluation. The root application still needs a constraint system that derives those inputs while checking the two child proofs. Run `python3 scripts/bench_large_prime_opening.py --terminal "$TERMINAL_BUNDLE"` on a midpoint bundle exported with `--save-keccak-checkpoints`. [Verifier](contracts/prime/PrimeWhirOpeningVerifier.sol) · [Gas measurements](../../docs/ethereum-root-verification.md#large-prime-opening-on-the-actual-terminal-checkpoint-table)

The original `--node-ports` measurement used 7,133,812 gas to check the final ordered hash input and digest in both copies of the child verifier. Solidity derives the opening point and expected evaluation from the parent, child digests and checkpoint commitment. [Port check](contracts/prime/TerminalNodePortsVerifier.sol) · [Measurement and scope](../../docs/ethereum-root-verification.md#binding-the-ordered-parent-to-the-checkpoint-table)

For the full 64-client checkpoint table, `TerminalSegmentRoundsVerifier.reduceTransitions` verifies the opening and reduces all 24 Keccak rounds to input-bit claims. Its least expensive Osaka transaction used **9,080,519 gas** with the rate-1/32 table verifier. The rate-1/16 control used 9,755,891 gas. The native prover uses a finite Johnson target of 135 bits per WHIR step in both profiles. The settlement verifier still needs commitment checks for the returned input bits and the two recursive child verifications. Run `forge test --match-contract TerminalSegmentRoundsTest` for the packaged calls, including rejection under the wrong rate. [Measurements and reproduction](../../docs/ethereum-root-verification.md#three-round-keccak-segments)

On ordinary Osaka, `TerminalNibbleVerifier.verifyTransitions` verified all 24 Keccak rounds, both endpoints, node and padding inputs, and digit range on the actual 65,536-row table for **9,980,866 gas** (221,604 calldata bytes). This leaves 1,019,134 gas for both child verifications and their hash-port wiring. The strong native root with the separate row certificate costs **104,570,178 gas** on high-limit local Prague. The checkpoint commitment and its opening each took about 15½ minutes on five M2 Pro threads. [Full witness, timings and reproduction](../../docs/ethereum-root-verification.md#four-bit-digits-at-full-root-size)

## LeanVM reference contract interface

Deploy the [generated terminal contract](contracts/leanvm/generated/LeanVmGroupedTerminal_KeccakPow28T6.sol)
with its five linked libraries. Select this contract from trusted application
configuration. Call `verifyForRoot(expectedRoot, proof)` with the root expected by
the application. It returns `true` on success and reverts on failure.
`expectedRoot` consists of eight canonical KoalaBear field elements in program
order. The upstream `verifyGroupedLogupV1(proof)` entry point verifies the root
embedded in the proof and leaves its comparison with application state to its caller.

Build from this directory with `forge build`. The pinned build uses solc 0.8.28
and via-IR optimization. A local replay compiles the source, links the libraries,
deploys them on a fresh Osaka chain, submits the Rust-encoded call, and checks
rejection of eight altered inputs. It requires Cargo, Python 3, solc 0.8.28 and
an Osaka-capable Anvil. Use `--solc` and `--anvil` to select local binaries.

```sh
python3 scripts/replay.py
```

The Rust library exposes `evm_verifier::verify_calldata`. Its inputs are the
eight public field elements and the exporter's `abi.encode(Proof)` bytes. The CLI
accepts the root as eight concatenated big-endian u32s and writes raw Ethereum
calldata to stdout. From this directory, the following encodes the test fixture.

```sh
cargo run --quiet --locked -p evm-verifier -- \
  2f8257a148a1caa160b95abb61e291680fb994f36a34136d1bcf71b7266570ae \
  tests/fixtures/terminal-proof.abi > /tmp/terminal-calldata.bin
```

## Source and fixture

The KoalaBear terminal contracts and proof fixture come from `ethereum/sol-whir-p3` revision
`b82359ec98e1e3c9f6f39ebf984e7aefb0eeb9be` under MIT. This copy exposes
separate libraries for constraint evaluation, Merkle checks and WHIR
verification, moves transcript and opening consumption checks into the WHIR
call frame, and adds the expected-root entry point. The fixture is the upstream
`proof.abi` without modifications. [Upstream source](https://github.com/ethereum/sol-whir-p3/tree/b82359ec98e1e3c9f6f39ebf984e7aefb0eeb9be)
· [Fixture manifest](https://github.com/ethereum/sol-whir-p3/blob/b82359ec98e1e3c9f6f39ebf984e7aefb0eeb9be/testdata/leanvm_terminal/GroupedLogupKeccakPow28T6/manifest.json)
· [Upstream license](contracts/LICENSE-MIT)
