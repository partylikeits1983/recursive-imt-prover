"""Build the 192-bit checkpoint commitment coset by coset and verify the Keccak reduction."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from bench_large_prime_opening import checkout
from bench_segment_reduction import generate as generate_rounds
from replay import CRATE, TX_LIMIT, RpcError, rpc, send
from replay_native_openings import abi_bytes, local_chain, word


def build_commitment(work, bundle, row_bits, dest, dense, cache_quartets):
    whir = work / "whir"
    checkout(whir)
    src = Path(__file__).with_name("prime_whir")
    binary = whir / "src/bin"
    shutil.copyfile(src / "stream_digits.rs", binary / "stream_digits.rs")
    (binary / "support").mkdir(exist_ok=True)
    for name in ("digits.rs", "segments.rs", "node.rs", "digit_columns.rs", "quartets.rs"):
        shutil.copyfile(src / "support" / name, binary / "support" / name)
    subprocess.run(
        [
            "cargo",
            "run",
            "--release",
            "--locked",
            "--bin",
            "stream_digits",
            "--",
            str(bundle.resolve()),
            str(row_bits),
            str(dest.resolve()),
            *(["--check-dense"] if dense else []),
            *(["--cache-quartets"] if cache_quartets else []),
        ],
        env={**os.environ, "RAYON_NUM_THREADS": "5"},
        cwd=whir,
        check=True,
    )


def expanded(data):
    if len(data) % 24:
        raise ValueError("Invalid compact field encoding")
    return b"".join(b"\0" * 8 + data[i : i + 24] for i in range(0, len(data), 24))


def measure(gkr, row_bits, forge, anvil, export_call=None):
    name = "KeccakSegmentReduction192"
    subprocess.run(
        [forge, "build", "--quiet", "contracts/prime/KeccakSegmentReduction.sol"], cwd=CRATE, check=True
    )
    art = json.loads((CRATE / f"out/KeccakSegmentReduction.sol/{name}.json").read_bytes())
    selector = art["methodIdentifiers"]["reduceFromBits(bytes32,uint256[],uint256[25],bytes)"]
    public = Path(f"{gkr}.public").read_bytes()
    result = Path(f"{gkr}.result").read_bytes()
    proof = gkr.read_bytes()
    n = row_bits + 9
    if len(result) != (n + 25) * 24 or len(public) != 32 + len(result):
        raise ValueError("Unexpected field or number of coordinates")
    point = word(n) + expanded(public[32 : 32 + n * 24])
    lanes = expanded(public[32 + n * 24 :])
    data = (
        bytes.fromhex(selector)
        + public[:32]
        + word(28 * 32)
        + lanes
        + word(28 * 32 + len(point))
        + point
        + abi_bytes(proof)
    )
    expected = word(26 * 32) + expanded(result[n * 24 :]) + word(n) + expanded(result[: n * 24])
    with local_chain(anvil, "osaka") as (url, account):
        tx = {"from": account, "gas": hex(TX_LIMIT)}
        addr = send(url, {**tx, "data": art["bytecode"]["object"]})["contractAddress"]
        call = {**tx, "to": addr, "data": "0x" + data.hex()}
        got = bytes.fromhex(rpc(url, "eth_call", [call, "latest"])[2:])
        if got != expected:
            raise RuntimeError("Different input point or lane reading from native Keccak inputs")
        gas = int(send(url, call)["gasUsed"], 16)
        print(
            f"{1<<row_bits:,} permutations, {len(proof):,} GKR bytes, {gas:,} Osaka reduction gas, "
            f"{len(data):,} call bytes, {21_000 + 40*len(data) - 30*data.count(0):,} calldata floor"
        )
        for pos in (4, 4 + 2 * 32 + 31, 4 + 28 * 32 + 63, 4 + 28 * 32 + len(point) + 32, len(data) - 32):
            bad = bytearray(data)
            bad[pos] ^= 1
            try:
                rpc(url, "eth_call", [{**call, "data": "0x" + bad.hex()}, "latest"])
            except RpcError as e:
                if len(e.args[0].get("data", "")) < 10:
                    raise
            else:
                raise RuntimeError(f"accepted changed statement or proof at byte {pos}")
        print("Rejected five changes to the statement or rounds")
        if export_call:
            export_call.write_bytes(data)
            print("Expected ABI result hash", rpc(url, "web3_sha3", ["0x" + expected.hex()]))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--terminal", type=Path)
    source.add_argument("--gkr", type=Path, help="native round file with .public and .result")
    p.add_argument("--row-bits", type=int, choices=range(6, 17), default=16)
    p.add_argument(
        "--check-dense", action="store_true", help="compare with the dense reference (through 1,024 rows)"
    )
    p.add_argument(
        "--cache-quartets",
        action="store_true",
        help="save one Merkle digest per four encoded rows (4 GiB at full arity)",
    )
    p.add_argument("--export-call", type=Path, help="save a verified Solidity call")
    p.add_argument("--save-fixture", type=Path)
    p.add_argument("--forge", default="forge")
    p.add_argument("--anvil", default="anvil")
    args = p.parse_args()
    if args.check_dense and args.row_bits > 10:
        p.error("dense reference control supports at most 1,024 rows")
    with tempfile.TemporaryDirectory(prefix="imt-streamed-digits-") as tmp:
        work = Path(tmp)
        if args.gkr:
            measure(args.gkr, args.row_bits, args.forge, args.anvil, args.export_call)
            return
        dest = work / "fixture"
        build_commitment(work, args.terminal, args.row_bits, dest, args.check_dense, args.cache_quartets)
        gkr = dest / "rounds.bin"
        generate_rounds(
            work / "gkr",
            args.terminal / "keccak-checkpoints.bin",
            1 << args.row_bits,
            gkr,
            dest,
            nibbles192=True,
        )
        measure(gkr, args.row_bits, args.forge, args.anvil, args.export_call)
        if args.save_fixture:
            shutil.copytree(dest, args.save_fixture)


if __name__ == "__main__":
    main()
