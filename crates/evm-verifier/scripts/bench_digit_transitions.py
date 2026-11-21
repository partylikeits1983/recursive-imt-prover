"""Prove and price all 24 Keccak rounds and both endpoint checks on 512 terminal rows."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from bench_large_prime_opening import checkout
from bench_segment_reduction import generate as generate_rounds
from verifier_work import report as report_work
from replay import CRATE, TX_LIMIT, RpcError, rpc, send
from replay_native_openings import abi_bytes, local_chain, word

CONTRACT = "TerminalDigitVerifier"


def generate(work, bundle, output):
    whir = work / "whir"
    checkout(whir)
    src = Path(__file__).with_name("prime_whir")
    dest = whir / "src/bin"
    shutil.copyfile(src / "digit_opening.rs", dest / "digit_opening.rs")
    (dest / "support").mkdir(exist_ok=True)
    for name in ("node.rs", "segments.rs", "digits.rs"):
        shutil.copyfile(src / "support" / name, dest / "support" / name)
    command = [
        "cargo",
        "run",
        "--locked",
        "--release",
        "--bin",
        "digit_opening",
        "--",
        str(bundle.resolve()),
        str(output.resolve()),
    ]
    env = {**os.environ, "RAYON_NUM_THREADS": "5"}
    subprocess.run([*command, "prepare"], cwd=whir, env=env, check=True)
    generate_rounds(
        work / "gkr", bundle / "keccak-checkpoints.bin", 512, output / "rounds.bin", output, digits=True
    )
    subprocess.run([*command, "close"], cwd=whir, env=env, check=True)


def measure(fixture, forge, anvil, export_call=None, nibble_row_bits=None, hash_profile=False):
    if nibble_row_bits is None:
        row_bits = 9
        name, file, gkr, pcs, pcs_file = (
            CONTRACT,
            CONTRACT,
            "KeccakSegmentReduction",
            "DigitOpeningVerifier",
            CONTRACT,
        )
    else:
        row_bits = nibble_row_bits
        if row_bits not in (7, 16):
            raise ValueError("Unsupported nibble table arity")
        prefix = "Sample" if row_bits == 7 else ""
        file, pcs_file, gkr = "TerminalNibbleVerifier", "NibbleOpeningVerifier", "KeccakSegmentReduction192"
        name, pcs = prefix + file, prefix + pcs_file
    subprocess.run([forge, "build", "--quiet", f"contracts/prime/{file}.sol"], cwd=CRATE, check=True)
    files = {name: file, pcs: pcs_file, gkr: "KeccakSegmentReduction"}
    artifacts = {
        key: json.loads((CRATE / f"out/{src}.sol/{key}.json").read_bytes()) for key, src in files.items()
    }
    outputs = (fixture / "output-result.bin").read_bytes()
    coords = row_bits + 9
    if len(outputs) != (coords + 25) * 32:
        raise ValueError(f"Expected {coords} coordinates and 25 output lanes")
    head = (fixture / "node.bin").read_bytes() + (fixture / "root.bin").read_bytes() + outputs[coords * 32 :]
    if len(head) != 29 * 32:
        raise ValueError("Invalid digest or lane encoding")
    offset = len(head) + 4 * 32
    segments = []
    offsets = {}
    for part in ("rounds", "digits", "proof", "hints"):
        segment = abi_bytes((fixture / f"{part}.bin").read_bytes())
        offsets[part] = offset
        head += word(offset)
        offset += len(segment)
        segments.append(segment)
    (selector,) = artifacts[name]["methodIdentifiers"].values()
    data = bytes.fromhex(selector) + head + b"".join(segments)
    with local_chain(anvil, "osaka") as (url, account):
        tx = {"from": account, "gas": hex(TX_LIMIT)}

        def deploy(name, args=b""):
            bytecode = artifacts[name]["bytecode"]["object"] + args.hex()
            return send(url, {**tx, "data": bytecode})["contractAddress"]

        rounds = deploy(gkr)
        opening = deploy(pcs)
        verifier = deploy(name, word(int(rounds, 16)) + word(int(opening, 16)))
        call = {**tx, "to": verifier, "data": "0x" + data.hex()}
        if int(rpc(url, "eth_call", [call, "latest"]), 16) != 1:
            raise RuntimeError("Keccak transitions were rejected")
        receipt = send(url, call)
        gas = int(receipt["gasUsed"], 16)
        floor = 21_000 + 40 * len(data) - 30 * data.count(0)
        print(
            f"{1<<row_bits:,} permutations / {8<<row_bits:,} segments, both endpoints and digit range: {gas:,} Osaka gas, "
            f"{len(data):,} calldata bytes, {floor:,} calldata floor"
        )
        if nibble_row_bits is not None:
            trace = rpc(url, "debug_traceTransaction", [receipt["transactionHash"], {"tracer": "callTracer"}])
            modules = {rounds.lower(): "Keccak rounds", opening.lower(): "WHIR"}
            for child in trace["calls"]:
                print(f"{modules[child['to'].lower()]} execution: {int(child['gasUsed'],16):,} gas")
        if hash_profile:
            labels = {
                verifier.lower(): "digit relation",
                rounds.lower(): "Keccak rounds",
                opening.lower(): "WHIR",
            }
            report_work(url, receipt["transactionHash"], labels)
        mutations = {
            "parent": 4,
            "left child": 36,
            "digit commitment": 100,
            "output lane": 163,
            "first Keccak message": 4 + offsets["rounds"] + 63,
            "last Keccak message": 4 + offsets["rounds"] + 31 + (fixture / "rounds.bin").stat().st_size,
            "first digit sumcheck": 4 + offsets["digits"] + 63,
            "claimed digit evaluation": 4 + offsets["digits"] + 31 + (fixture / "digits.bin").stat().st_size,
            "WHIR OOD value": 4 + offsets["proof"] + 95,
            "Merkle path": 4 + offsets["hints"] + 31 + (fixture / "hints.bin").stat().st_size,
        }
        if nibble_row_bits is not None:
            n = row_bits + 12
            mutations["claimed third moment"] = 4 + offsets["digits"] + 32 + 120 * n + 47
            mutations["second sumcheck"] = 4 + offsets["digits"] + 32 + 120 * n + 72 + 23
        for label, index in mutations.items():
            bad = bytearray(data)
            bad[index] ^= 1
            try:
                rpc(url, "eth_call", [{**call, "data": "0x" + bad.hex()}, "latest"])
            except RpcError as error:
                if len(error.args[0].get("data", "")) < 10:
                    raise
            else:
                raise RuntimeError(f"accepted changed {label}")
        print(f"Rejected {len(mutations)} modified statements and proof parts")
        if export_call:
            export_call.write_bytes(data)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    inputs = p.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--terminal", type=Path)
    inputs.add_argument("--fixture", type=Path)
    p.add_argument("--save-fixture", type=Path)
    p.add_argument("--export-call", type=Path)
    p.add_argument("--forge", default="forge")
    p.add_argument("--anvil", default="anvil")
    args = p.parse_args()
    with tempfile.TemporaryDirectory(prefix="imt-digit-transitions-") as tmp:
        work = Path(tmp)
        fixture = args.fixture or work / "fixture"
        if args.terminal:
            generate(work, args.terminal, fixture)
        measure(fixture, args.forge, args.anvil, args.export_call)
        if args.save_fixture:
            shutil.copytree(fixture, args.save_fixture)


if __name__ == "__main__":
    main()
