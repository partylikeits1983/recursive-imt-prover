"""Verify a 192-bit digit table opening against the pinned WHIR transcript."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from bench_large_prime_opening import checkout
from replay import CRATE, TX_LIMIT, RpcError, rpc, send
from replay_native_openings import abi_bytes, local_chain, word


def measure(fixture, forge, anvil, export_call=None):
    statement = (fixture / "statement.bin").read_bytes()
    proof = (fixture / "proof.bin").read_bytes()
    hints = (fixture / "hints.bin").read_bytes()
    arity = len(statement) // 32 - 2
    if arity not in (19, 28) or len(statement) != 32 * (arity + 2):
        raise ValueError("Unsupported WHIR statement length")
    name = "SampleNibbleOpeningVerifier" if arity == 19 else "NibbleOpeningVerifier"
    artifact = CRATE / f"out/NibbleOpeningVerifier.sol/{name}.json"
    subprocess.run(
        [forge, "build", "--quiet", "contracts/prime/NibbleOpeningVerifier.sol"], cwd=CRATE, check=True
    )
    contract = json.loads(artifact.read_bytes())
    (selector,) = contract["methodIdentifiers"].values()
    coords = word(arity) + statement[32:-32]
    proof_start = 6 * 32 + len(coords)
    hints_start = proof_start + len(abi_bytes(proof))
    head = proof[:32] + statement[:32] + word(6 * 32) + statement[-32:] + word(proof_start) + word(hints_start)
    data = bytes.fromhex(selector) + head + coords + abi_bytes(proof) + abi_bytes(hints)
    with local_chain(anvil, "osaka") as (url, account):
        tx = {"from": account, "gas": hex(TX_LIMIT)}
        verifier = send(url, {**tx, "data": contract["bytecode"]["object"]})["contractAddress"]
        call = {**tx, "to": verifier, "data": "0x" + data.hex()}
        if rpc(url, "eth_call", [call, "latest"]) != "0x" + word(1).hex():
            raise RuntimeError("Solidity rejected the native WHIR opening")
        gas = int(send(url, call)["gasUsed"], 16)
        print(
            f"{arity} variables, {gas:,} Osaka gas, {len(data):,} calldata bytes, "
            f"{21000 + 40 * len(data) - 30 * data.count(0):,} calldata floor"
        )
        for index in (
            4,
            36,
            4 + 127,
            4 + 7 * 32 + 31,
            4 + proof_start + 32 + 55,
            4 + hints_start + 32 + 31,
            4 + hints_start + 32 + len(hints) - 1,
        ):
            corrupted = bytearray(data)
            corrupted[index] ^= 1
            try:
                rpc(url, "eth_call", [{**call, "data": "0x" + corrupted.hex()}, "latest"])
            except RpcError as error:
                if len(error.args[0].get("data", "")) < 10:
                    raise
            else:
                raise RuntimeError(f"Verifier accepted a changed statement or proof byte at {index}")
        print("Rejected seven changed statements or openings")
        if export_call:
            export_call.write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--fixture", type=Path)
    source.add_argument("--terminal", type=Path, help="Generate the 128-row dense reference opening")
    source.add_argument(
        "--profile-control",
        action="store_true",
        help="Full 28-variable schedule on a single nonzero coefficient",
    )
    parser.add_argument(
        "--caps", type=Path, help="Open the saved checkpoint commitment from bench_streamed_digits"
    )
    parser.add_argument("--row-bits", type=int, choices=(7, 16), default=16)
    parser.add_argument(
        "--point", type=Path, help="With --caps, use the supplied context and canonical coordinate words"
    )
    parser.add_argument("--save-fixture", type=Path)
    parser.add_argument("--export-call", type=Path)
    parser.add_argument("--forge", default="forge")
    parser.add_argument("--anvil", default="anvil")
    args = parser.parse_args()
    if args.caps and not args.terminal:
        parser.error("--caps requires --terminal")
    if args.point and not args.caps:
        parser.error("--point requires --caps")
    with tempfile.TemporaryDirectory(prefix="imt-nibble-opening-") as temp:
        root = Path(temp)
        fixture = args.fixture or root / "fixture"
        if not args.fixture:
            whir = root / "whir"
            checkout(whir)
            source = Path(__file__).with_name("prime_whir")
            binary = whir / "src/bin"
            driver = "nibble_profile_control" if args.profile_control else "nibble_opening"
            if args.caps:
                driver = "stream_opening"
                shutil.copyfile(source / "stream_digits.rs", binary / "stream_digits.rs")
            shutil.copyfile(source / f"{driver}.rs", binary / f"{driver}.rs")
            arguments = []
            if args.terminal:
                (binary / "support").mkdir(exist_ok=True)
                support = ["digits.rs", "segments.rs"]
                if args.caps:
                    support += [
                        "nibble_folds.rs",
                        "stream_code.rs",
                        "node.rs",
                        "digit_columns.rs",
                        "quartets.rs",
                    ]
                for name in support:
                    shutil.copyfile(source / "support" / name, binary / "support" / name)
                arguments.append(str(args.terminal.resolve()))
            if args.caps:
                arguments.extend([str(args.caps.resolve()), str(args.row_bits)])
            arguments.append(str(fixture))
            if args.point:
                arguments.append(str(args.point.resolve()))
            subprocess.run(
                ["cargo", "run", "--release", "--locked", "--bin", driver, "--", *arguments],
                cwd=whir,
                check=True,
                env={**os.environ, "RAYON_NUM_THREADS": "5"},
            )
        measure(fixture, args.forge, args.anvil, args.export_call)
        if args.save_fixture:
            shutil.copytree(fixture, args.save_fixture)


if __name__ == "__main__":
    main()
