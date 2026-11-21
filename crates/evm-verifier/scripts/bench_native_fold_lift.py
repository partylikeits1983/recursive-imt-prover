"""Prove all native WHIR row folds and optionally the root verifier's Keccak rounds in one opening."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from bench_large_prime_opening import checkout
from prime_whir.native_fold_witness import export
from replay import CRATE, TX_LIMIT, RpcError, rpc, send
from replay_native_openings import abi_bytes, local_chain, word


def generate(trace, fixture, work, hash_trace=None, prove_rounds=False):
    export(trace, fixture)
    whir = work / "whir"
    checkout(whir)
    src = Path(__file__).with_name("prime_whir")
    dest = whir / "src/bin"
    drivers = ["native_fold_lift"]
    modules = ["nibble_gate", "digit_sumcheck", "close_moments"]
    if hash_trace:
        drivers.extend(["native_hash_trace", "stream_digits", "stream_opening"])
        if prove_rounds:
            drivers.append("nibble_relation")
        modules.extend(
            ["checkpoint_digits", "segments", "digits", "digit_columns", "node", "quartets", "nibble_folds", "stream_code"]
        )
    (dest / "support").mkdir(exist_ok=True)
    for driver in drivers:
        shutil.copyfile(src / f"{driver}.rs", dest / f"{driver}.rs")
    for module in modules:
        shutil.copyfile(src / f"support/{module}.rs", dest / f"support/{module}.rs")

    def run(driver, *args):
        subprocess.run(
            ["cargo", "run", "--release", "--locked", "--bin", driver, "--", *args],
            cwd=whir,
            check=True,
            env={**os.environ, "RAYON_NUM_THREADS": "5"},
        )

    fixture = fixture.resolve()
    if hash_trace:
        joint = work.resolve() / "joined"
        cap = joint / "cap"
        run("native_hash_trace", hash_trace.resolve(), fixture, joint)
        run("stream_digits", joint / "table.bin", "14", cap, "--cache-quartets")
        run("native_fold_lift", fixture, cap / "root.bin")
        point = fixture / "opening-point.bin"
        expected = point.read_bytes()[32:] + (fixture / "digit-value.bin").read_bytes()
        if prove_rounds:
            from bench_segment_reduction import generate as generate_rounds

            trace_proof = work.resolve() / "rounds"
            trace_proof.mkdir()
            gkr = trace_proof / "rounds.bin"
            generate_rounds(work / "gkr", joint / "keccak-checkpoints.bin", 16384, gkr, cap, native_trace=True)
            run("nibble_relation", joint / "table.bin", cap, gkr, "14", trace_proof)
            second = trace_proof / "opening-point.bin"
            expected += second.read_bytes()[32:] + (trace_proof / "digit-value.bin").read_bytes()
            run("stream_opening", joint / "table.bin", cap, "14", fixture, point, second)
            attach_rounds(fixture, trace_proof)
        else:
            run("stream_opening", joint / "table.bin", cap, "14", fixture, point)
        if (fixture / "statement.bin").read_bytes()[32:] != expected:
            raise ValueError("Streamed opening disagrees with the derived evaluations on the shared table")
    else:
        run("native_fold_lift", fixture)


def attach_rounds(fixture, trace_proof):
    public = (trace_proof / "rounds.bin.public").read_bytes()
    if len(public) != 32 + (23 + 25) * 24:
        raise ValueError("Wrong GKR geometry for the native root hash trace")
    parts = [
        public[-25 * 24 :],
        (trace_proof / "rounds.bin").read_bytes(),
        (trace_proof / "digits.bin").read_bytes(),
    ]
    if [len(p) for p in parts] != [600, 41400, 6336]:
        raise ValueError("Wrong native trace proof dimensions")
    hints = fixture / "hints.bin"
    hints.write_bytes(b"".join(parts) + hints.read_bytes())


def form_words(fixture):
    words, remainder = divmod((fixture / "statement.bin").stat().st_size, 32)
    if remainder or words not in (21, 28, 55, 70):
        raise ValueError("Unsupported row-fold commitment geometry")
    return words


def deploy_checker(fixture, create):
    words = form_words(fixture)
    if words == 70:
        pcs = create("NibbleOpeningVerifier", "NativeRowTripleOpeningVerifier", b"")
        f = create("NativeWhirFoldProof", "NativeSpongeFoldReduction", word(int(pcs, 16)))
        g = create("KeccakSegmentReduction", "KeccakSegmentReduction192", b"")
        k = create("TerminalNibbleVerifier", "NativeSpongeKeccakReduction", word(int(g, 16)) + word(int(pcs, 16)))
        p = create("NativeRowSpongePorts", "NativeRowSpongePorts", word(int(pcs, 16)))
        return create("NativeDigestRowProof", "NativeDigestRowProof", b"".join(word(int(a, 16)) for a in (f, k, p, pcs)))
    pcs = create(
        "NibbleOpeningVerifier",
        "SampleNibbleOpeningVerifier" if words == 21 else "NativeTraceOpeningVerifier",
        b"",
    )
    folds = create(
        "NativeWhirFoldProof",
        "NativeWhirFoldProof" if words == 21 else "NativeTraceFoldProof",
        word(int(pcs, 16)),
    )
    if words != 55:
        return folds
    gkr = create("KeccakSegmentReduction", "KeccakSegmentReduction192", b"")
    rounds = create(
        "TerminalNibbleVerifier", "NativeTraceKeccakReduction", word(int(gkr, 16)) + word(int(pcs, 16))
    )
    pair = create("NibbleOpeningVerifier", "NativeTracePairOpeningVerifier", b"")
    return create(
        "NativeTraceJointProof",
        "NativeTraceJointProof",
        b"".join(word(int(v, 16)) for v in (folds, rounds, pair)),
    )


def measure(fixture, forge, anvil, export_call=None):
    subprocess.run(
        [forge, "build", "--quiet", "contracts/prime/NativeTraceJointProof.sol", "contracts/prime/NativeDigestRowProof.sol"], cwd=CRATE, check=True
    )
    root = (fixture / "root.bin").read_bytes()
    parts = [
        (fixture / f"{n}.bin").read_bytes() for n in ("draws", "digests" if form_words(fixture) == 70 else "rows", "values", "digits", "proof", "hints")
    ]

    def artifact(file, name):
        return json.loads((CRATE / f"out/{file}.sol/{name}.json").read_bytes())

    contract = artifact("NativeWhirFoldProof", "NativeWhirFoldProof")
    selector = bytes.fromhex(
        contract["methodIdentifiers"]["verifyFolds(bytes32,bytes,bytes,bytes,bytes,bytes,bytes)"]
    )
    offset = 7 * 32
    head = root
    offsets = []
    tail = bytearray()
    for segment in parts:
        offsets.append(4 + offset + 32)
        head += word(offset)
        encoded = abi_bytes(segment)
        tail.extend(encoded)
        offset += len(encoded)
    data = selector + head + tail
    with local_chain(anvil, "osaka") as (url, account):
        tx = {"from": account, "gas": hex(TX_LIMIT)}

        def create(file, name, args):
            return send(url, {**tx, "data": artifact(file, name)["bytecode"]["object"] + args.hex()})[
                "contractAddress"
            ]

        deployed = deploy_checker(fixture, create)
        call = {**tx, "to": deployed, "data": "0x" + data.hex()}
        if rpc(url, "eth_call", [call, "latest"]) != "0x" + word(1).hex():
            raise ValueError("Solidity rejected the honest row proof")
        receipt = send(url, call)
        gas = int(receipt["gasUsed"], 16)
        floor = 21000 + 40 * len(data) - 30 * data.count(0)
        scope = (
            "169 native WHIR folds and 16,384 Keccak permutations"
            if form_words(fixture) == 55
            else "169 native WHIR folds, row digests and 507 Keccak permutations" if form_words(fixture) == 70 else "169 native WHIR folds"
        )
        print(f"{scope}: {gas:,} Osaka gas; {len(data):,} calldata bytes; {floor:,} gas floor.")
        # First and last native stages, the 12-bit carry checks, and the final oracle.
        bad_offsets = [
            4,
            offsets[0],
            offsets[0] + 527,
            offsets[1],
            offsets[1] + (142 * 32 if form_words(fixture) == 70 else 71 * 384),
            offsets[1] + len(parts[1]) - 1,
            offsets[2] + 71 * 24 - 1,
            offsets[2] + 169 * 24 - 1,
            offsets[3],
            offsets[3] + 120 * 19 + 28,
            offsets[4] + 77,
            offsets[5] + len(parts[-1]) - 1,
        ]
        if form_words(fixture) == 70:
            bad_offsets.extend(offsets[5] + k for k in (23, 600, 35520, 40656, 46032))
        if form_words(fixture) == 55:
            bad_offsets += [offsets[5] + k for k in (23, 600, 42000, 48336)]
        for at in bad_offsets:
            bad = bytearray(data)
            bad[at] ^= 1
            try:
                rpc(url, "eth_call", [{**call, "data": "0x" + bad.hex()}, "latest"])
            except RpcError as err:
                if len(err.args[0].get("data", "")) < 10:
                    raise
            else:
                raise ValueError(f"Fold proof accepted changed byte {at}")
        print(f"Rejected {len(bad_offsets)} altered calls.")
    if export_call:
        export_call.write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--trace", type=Path, help="JSON from root-opening-trace on a verified midpoint bundle")
    mode.add_argument("--fixture", type=Path)
    parser.add_argument(
        "--hash-trace",
        type=Path,
        help="co-commit the row proof with Keccak checkpoints from --export-hash-trace",
    )
    parser.add_argument(
        "--prove-rounds",
        action="store_true",
        help="prove the native Keccak rounds and both digit readings in one WHIR opening",
    )
    parser.add_argument("--export-call", type=Path)
    parser.add_argument("--save-fixture", type=Path)
    parser.add_argument("--forge", default="forge")
    parser.add_argument("--anvil", default="anvil")
    args = parser.parse_args()
    if args.prove_rounds and not args.hash_trace:
        parser.error("--prove-rounds requires --hash-trace")
    if args.hash_trace and not args.trace:
        parser.error("--hash-trace requires --trace")
    with tempfile.TemporaryDirectory(prefix="imt-native-fold-lift-") as tmp:
        work = Path(tmp)
        fixture = args.fixture or work / "fixture"
        if args.trace:
            generate(args.trace, fixture, work, args.hash_trace, args.prove_rounds)
        measure(fixture, args.forge, args.anvil, args.export_call)
        if args.save_fixture:
            shutil.copytree(fixture, args.save_fixture)


if __name__ == "__main__":
    main()
