"""Generate a statement-bound Field256 WHIR proof and verify it on an ordinary Osaka EVM."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from replay import CRATE, TX_LIMIT, RpcError, rpc, send
from replay_native_openings import abi_bytes, local_chain, word

REVISION = "fe86de76fa5863bb82466c8a91a7f74a60f910ac"
CONTRACT = "PrimeWhirOpeningVerifier"


def checkout(root):
    root.mkdir()
    for args in [
        ["init", "--quiet"],
        ["fetch", "--quiet", "--depth", "1", "https://github.com/worldfnd/whir.git", REVISION],
        ["checkout", "--quiet", "--detach", "FETCH_HEAD"],
    ]:
        subprocess.run(["git", *args], cwd=root, check=True)


def generate(root, fixture, seed, terminal=None, node_ports=False, segments=False, segment_output=False, rate32=False):
    checkout(root)
    driver = Path(__file__).with_name("prime_whir") / "dense_opening.rs"
    shutil.copyfile(driver, root / "src/bin/dense_opening.rs")
    (root / "src/bin/support").mkdir(exist_ok=True)
    for source in ("segments.rs", "node.rs"):
        shutil.copyfile(driver.parent / "support" / source, root / "src/bin/support" / source)
    mode = []
    if rate32:
        mode = ["--segment-output-rate32"]
    elif segment_output:
        mode = ["--segment-output"]
    elif segments:
        mode = ["--segments"]
    elif node_ports:
        mode = ["--node-ports"]
    subprocess.run(
        ["cargo", "run", "--locked", "--release", "--bin", "dense_opening", "--", str(fixture), str(seed),
         *([str(terminal.resolve())] if terminal else []), *mode],
        cwd=root, check=True, env={**os.environ, "RAYON_NUM_THREADS": "5"},
    )


def measure(fixture, forge, anvil, export_call=None, node_ports=False, segments=False, segment_output=False, rate32=False):
    contract = "TerminalNodePortsVerifier" if node_ports else CONTRACT
    if segment_output:
        segments = True
        contract = "TerminalSegmentOutputVerifierRate32" if rate32 else "TerminalSegmentOutputVerifier"
    elif segments:
        contract = "TerminalSegmentVerifier"
    subprocess.run([forge, "build", f"contracts/prime/{contract}.sol"], cwd=CRATE, check=True)
    artifact = json.loads((CRATE / f"out/{contract}.sol/{contract}.json").read_bytes())
    selector, = artifact["methodIdentifiers"].values()
    proof = (fixture / "proof.bin").read_bytes()
    hints = (fixture / "hints.bin").read_bytes()
    public = (fixture / "public.bin").read_bytes()
    root_path = fixture / "root.bin"
    root = root_path.read_bytes() if root_path.exists() else proof[:32]
    if root != proof[:32]:
        raise ValueError("prover supplied a different initial commitment")
    head = (fixture / "node.bin").read_bytes() + root if node_ports or segments else root + public
    if segments:
        head += (fixture / "readings.bin").read_bytes()
    bridge = (fixture / "output-bits.bin").read_bytes() if segment_output else b""
    if segment_output and len(bridge) != 37 * 32:
        raise ValueError("invalid output reduction length")
    proof_offset = len(head) + 64 + len(bridge)
    hint_offset = proof_offset + len(abi_bytes(proof))
    data = bytes.fromhex(selector) + head + word(proof_offset) + word(hint_offset) + bridge + abi_bytes(proof) + abi_bytes(hints)
    with local_chain(anvil, "osaka") as (url, account):
        tx = {"from": account, "gas": hex(TX_LIMIT)}
        addr = send(url, {**tx, "data": artifact["bytecode"]["object"]})["contractAddress"]
        call = {**tx, "to": addr, "data": "0x" + data.hex()}
        expected = (fixture / "output-result.bin").read_bytes() if segment_output else word(1)
        result = rpc(url, "eth_call", [call, "latest"])
        if bytes.fromhex(result[2:]) != expected:
            raise RuntimeError("Solidity result differs from the native opening and reduction")
        if segment_output:
            print("Expected ABI result hash", rpc(url, "web3_sha3", [result]))
        receipt = send(url, call)
        gas = int(receipt["gasUsed"], 16)
        print(f"Osaka {contract} verification {gas:,} gas, {len(data):,} call bytes, "
              f"{21_000 + 40*len(data) - 30*data.count(0):,} gas calldata floor")
        mutations = {
            "first sumcheck": 4 + proof_offset + 32 + 64, "final sumcheck": 4 + proof_offset + 32 + len(proof) - 32,
            "grinding nonce": 4 + proof_offset + 32 + 320, "row vector length": 4 + hint_offset + 32,
            "row": 4 + hint_offset + 32 + 8, "final Merkle path": 4 + hint_offset + 32 + len(hints) - 1,
        }
        if node_ports or segments:
            mutations.update({"parent": 4, "left child": 36, "right child": 68, "expected commitment": 100})
        else:
            mutations.update({"expected commitment": 4, "context": 36, "evaluation point": 99, "claimed value": 803})
        if segments:
            mutations.update({"segment input evaluation": 163, "segment output evaluation": 195})
        if segment_output:
            mutations.update({"packed bit sumcheck": 4 + len(head) + 64 + 31,
                              "lane reading": 4 + proof_offset - 1})
        cases = {}
        for label, offset in mutations.items():
            bad = bytearray(data)
            bad[offset] ^= 1
            cases[label] = bad
        if node_ports or segments:
            bad = bytearray(data)
            left, right = data[36:68], data[68:100]
            message = b"IMT-AGG-NODE-V2" + right + bytes([32]) + left + bytes([32])
            parent = bytes.fromhex(rpc(url, "web3_sha3", ["0x" + message.hex()])[2:])
            bad[4:100] = parent + right + left
            cases["reordered children with correct new parent"] = bad
        for label, bad in cases.items():
            try:
                rpc(url, "eth_call", [{**call, "data": "0x" + bad.hex()}, "latest"])
            except RpcError as error:
                detail = error.args[0].get("data", "")
                if not detail.startswith("0x") or len(detail) < 10:
                    raise
            else:
                raise RuntimeError(f"accepted changed {label}")
        print(f"Rejected {len(cases)} changed statements or proof messages.")
        if export_call is not None:
            export_call.write_bytes(data)
        return gas


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--terminal", type=Path, help="prove an opening of a terminal bundle exported with --save-keccak-checkpoints")
    inputs.add_argument("--fixture", type=Path, help="replay an existing reference fixture")
    inputs.add_argument("--size-input-digits", action="store_true", help="size candidate input-digit commitments with the pinned WHIR parameter solver")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--segments", action="store_true", help="authenticate the three-round segment endpoints and public rows")
    modes.add_argument("--segment-output", action="store_true", help="also reduce the packed output to 25 lane-bit claims")
    modes.add_argument("--segment-output-rate32", action="store_true", help="use rate 1/32 for the same packed-output relation")
    modes.add_argument("--node-ports", action="store_true", help="prove the final node hash ports of both child verifier instances")
    parser.add_argument("--export-call", type=Path, help="save the reference call for Foundry tests")
    parser.add_argument("--save-fixture", type=Path, help="save the verified prover files in a new directory")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--forge", default="forge")
    parser.add_argument("--anvil", default="anvil")
    args = parser.parse_args()
    args.segment_output |= args.segment_output_rate32
    if (args.segments or args.segment_output or args.node_ports) and args.terminal is None and args.fixture is None:
        parser.error("the selected profile requires --terminal or a compatible --fixture")
    with tempfile.TemporaryDirectory(prefix="imt-large-prime-") as directory:
        root = Path(directory)
        if args.size_input_digits:
            checkout(root / "whir")
            driver = Path(__file__).with_name("prime_whir") / "digit_cost.rs"
            shutil.copyfile(driver, root / "whir/src/bin/digit_cost.rs")
            subprocess.run(["cargo", "run", "--locked", "--release", "--bin", "digit_cost"], cwd=root / "whir", check=True)
            return
        fixture = args.fixture or root / "fixture"
        if args.fixture is None:
            generate(root / "whir", fixture, args.seed, args.terminal, args.node_ports, args.segments, args.segment_output, args.segment_output_rate32)
        measure(fixture, args.forge, args.anvil, args.export_call, args.node_ports, args.segments, args.segment_output, args.segment_output_rate32)
        if args.save_fixture:
            shutil.copytree(fixture, args.save_fixture)


if __name__ == "__main__":
    main()
