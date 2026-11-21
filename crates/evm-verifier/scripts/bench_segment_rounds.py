"""Replay the linked full-table opening, packed-bit bridge and three Keccak rounds."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from bench_segment_reduction import generate
from replay import CRATE, TX_LIMIT, RpcError, rpc, send
from replay_native_openings import abi_bytes, local_chain, word

TABLE = "TerminalSegmentOutputVerifier"
ROUNDS = "KeccakSegmentReduction"
COMBINED = "TerminalSegmentRoundsVerifier"


def measure(fixture, gkr, forge, anvil, export=None, rate32=False, export_call=None):
    table_name = TABLE + "Rate32" if rate32 else TABLE
    subprocess.run([forge, "build", "--quiet", f"contracts/prime/{COMBINED}.sol", f"contracts/prime/{table_name}.sol"], cwd=CRATE, check=True)
    artifacts = {n: json.loads((CRATE / f"out/{n}.sol/{n}.json").read_bytes()) for n in (table_name, ROUNDS, COMBINED)}
    proof = (fixture / "proof.bin").read_bytes()
    hints = (fixture / "hints.bin").read_bytes()
    head = b"".join((fixture / f"{n}.bin").read_bytes() for n in ("node", "root", "readings"))
    bridge = (fixture / "output-bits.bin").read_bytes()
    public = Path(f"{gkr}.public").read_bytes()
    if len(head) != 6*32 or len(bridge) != 37*32 or public[32:] != (fixture / "output-result.bin").read_bytes():
        raise ValueError("round proof did not start at the packed-output point and lane readings")
    raw = Path(f"{gkr}.result").read_bytes()
    if len(raw) != 50*32:
        raise ValueError("round proof returned the wrong number of input claims")
    expected = word(26*32) + raw[25*32:] + word(25) + raw[:25*32]
    transition = gkr.read_bytes()
    start = len(head) + 3*32 + len(bridge)
    auth = start + len(abi_bytes(proof))
    steps = auth + len(abi_bytes(hints))
    selector, = artifacts[COMBINED]["methodIdentifiers"].values()
    data = bytes.fromhex(selector) + head + word(start) + word(auth) + bridge + word(steps)
    data += abi_bytes(proof) + abi_bytes(hints) + abi_bytes(transition)
    with local_chain(anvil, "osaka") as (url, account):
        tx = {"from": account, "gas": hex(TX_LIMIT)}
        def deploy(name, args):
            init = artifacts[name]["bytecode"]["object"] + args
            return send(url, {**tx, "data": init})["contractAddress"]
        table = deploy(table_name, "")
        rounds = deploy(ROUNDS, "")
        addr = deploy(COMBINED, table[2:].zfill(64) + rounds[2:].zfill(64))
        call = {**tx, "to": addr, "data": "0x"+data.hex()}
        got = rpc(url, "eth_call", [call, "latest"])
        if bytes.fromhex(got[2:]) != expected:
            raise RuntimeError("Solidity output differs from direct evaluation of the committed witness's input bits")
        gas = int(send(url, call)["gasUsed"], 16)
        print(f"Full 524,288-segment reduction {gas:,} gas on Osaka, {len(data):,} calldata bytes, "
              f"{21_000 + 40*len(data) - 30*data.count(0):,} calldata floor")
        for name, i in {"parent": 4, "root": 100, "output reading": 195,
                        "bridge lane": 4+len(head)+64+len(bridge)-1,
                        "opening": 4+start+32+64, "Merkle sibling": 4+auth+32+len(hints)-1,
                        "first round": 4+steps+32+31, "final round": len(data)-1}.items():
            bad = bytearray(data)
            bad[i] ^= 1
            try:
                rpc(url, "eth_call", [{**call, "data":"0x"+bad.hex()}, "latest"])
            except RpcError as e:
                if len(e.args[0].get("data", "")) < 10:
                    raise
            else:
                raise RuntimeError(f"accepted changed {name}")
        print("All eight changed statements and proof parts were rejected.")
        print("Expected ABI result hash", rpc(url, "web3_sha3", [got]))
        if export:
            export.write_bytes(transition)
        if export_call:
            export_call.write_bytes(data)
        return gas


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--table", type=Path, required=True, help="native --segment-output proof directory")
    p.add_argument("--rate32", action="store_true", help="deploy the rate-1/32 table verifier")
    inputs = p.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--checkpoints", type=Path)
    inputs.add_argument("--gkr", type=Path, help="native round proof with .public and .result siblings")
    p.add_argument("--export-rounds", type=Path)
    p.add_argument("--export-call", type=Path, help="save the complete verified call for Foundry")
    p.add_argument("--forge", default="forge")
    p.add_argument("--anvil", default="anvil")
    args = p.parse_args()
    with tempfile.TemporaryDirectory(prefix="imt-linked-rounds-") as tmp:
        gkr = args.gkr or Path(tmp) / "rounds.bin"
        if args.checkpoints:
            generate(Path(tmp)/"keccacheck",args.checkpoints,65536,gkr,args.table)
        measure(args.table, gkr, args.forge, args.anvil, args.export_rounds, args.rate32, args.export_call)


if __name__ == "__main__":
    main()
