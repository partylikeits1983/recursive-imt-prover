"""Price the three-round Keccak GKR reduction, with a direct native endpoint check."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from replay import CRATE, TX_LIMIT, RpcError, rpc, send
from replay_native_openings import abi_bytes, local_chain, word

REFERENCE = "ec20ea40fe6be6260e3cdbb96dc5f9cae6bdca00"
SOURCES = Path(__file__).with_name("segment_gkr")


def generate(root, trace, rows, path, table=None, digits=False, nibbles192=False, native_trace=False):
    subprocess.run(["git", "init", "--quiet", str(root)], check=True)
    subprocess.run(["git", "fetch", "--quiet", "--depth", "1", "https://github.com/reilabs/keccacheck.git", REFERENCE],
                   check=True, cwd=root)
    subprocess.run(["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"], cwd=root, check=True)
    subprocess.run(["git", "apply", str(SOURCES / "three-round.patch")], cwd=root, check=True)
    shutil.copyfile(SOURCES / "Cargo.lock", root / "rust/Cargo.lock")
    shutil.copyfile(SOURCES / "benchmark.rs", root / "rust/benchmark/src/main.rs")
    shutil.copyfile(SOURCES / "segment_sponge.rs", root / "rust/gkr/src/transcript/segment_sponge.rs")
    for source in ("projected.rs", "packed_prefix.rs", "scalar.rs"):
        shutil.copyfile(SOURCES / source, root / "rust/gkr/src" / source)
    subprocess.run(["cargo", "run", "--locked", "--release", "-p", "benchmark", "--no-default-features", *(["--features", "field192"] if nibbles192 or native_trace else []), "--",
                    str(trace.resolve()), str(rows), str(path), *([str(table.resolve())] if table else []), *(["--native-trace"] if native_trace else ["--nibbles192"] if nibbles192 else ["--digits"] if digits else [])], cwd=root / "rust", check=True,
                   env={**os.environ, "RAYON_NUM_THREADS": "5"})


def measure(path, rows, forge, anvil, export):
    name = "KeccakSegmentReduction"
    subprocess.run([forge, "build", "--quiet", f"contracts/prime/{name}.sol"], cwd=CRATE, check=True)
    artifact = json.loads((CRATE / f"out/{name}.sol/{name}.json").read_bytes())
    selector = artifact["methodIdentifiers"]["reduce(bytes32,uint8,uint256[25],bytes)"]
    public = Path(f"{path}.public").read_bytes()
    proof = path.read_bytes()
    n = (rows * 8).bit_length() - 1
    raw_result = Path(f"{path}.result").read_bytes()
    if len(public) != 26 * 32 or len(raw_result) != (n + 6 + 25) * 32:
        raise ValueError("native statement or result length does not match the batch")
    split = 32 * (n + 6)
    expected = word(26 * 32) + raw_result[split:] + word(n + 6) + raw_result[:split]
    data = bytes.fromhex(selector) + public[:32] + word(n) + public[32:] + word(28 * 32) + abi_bytes(proof)
    with local_chain(anvil, "osaka") as (url, account):
        tx = {"from": account, "gas": hex(TX_LIMIT)}
        address = send(url, {**tx, "data": artifact["bytecode"]["object"]})["contractAddress"]
        call = {**tx, "to": address, "data": "0x" + data.hex()}
        result = bytes.fromhex(rpc(url, "eth_call", [call, "latest"])[2:])
        if result != expected:
            raise RuntimeError("input-bit point or lane readings differ from the native direct verifier")
        receipt = send(url, call)
        print(f"{rows} permutations, Osaka reduction {int(receipt['gasUsed'], 16):,} gas, {len(data):,} bytes, "
              f"{21_000 + 40*len(data) - 30*data.count(0):,} calldata floor")
        for i in (4, 99, 4 + 29 * 32 + 31, len(data) - 33, len(data) - 1):
            altered = bytearray(data)
            altered[i] ^= 1
            try:
                rpc(url, "eth_call", [{**call, "data": "0x" + altered.hex()}, "latest"])
            except RpcError as e:
                if not e.args[0].get("data", "").startswith("0x") or len(e.args[0]["data"]) < 10:
                    raise
            else:
                raise RuntimeError(f"accepted changed reduction at byte {i}")
        print("All five changed statements or proof messages rejected.")
        if export:
            export.write_bytes(data)
            print("Expected ABI result hash", rpc(url, "web3_sha3", ["0x" + expected.hex()]))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--checkpoints", type=Path)
    source.add_argument("--fixture", type=Path, help="native proof file accompanied by .public and .result")
    p.add_argument("--rows", type=int, default=128)
    p.add_argument("--export-call", type=Path)
    p.add_argument("--forge", default="forge")
    p.add_argument("--anvil", default="anvil")
    args = p.parse_args()
    if args.rows < 1 or args.rows > 65536 or args.rows & (args.rows - 1):
        p.error("rows must be a power of two between 1 and 65536")
    with tempfile.TemporaryDirectory(prefix="imt-segment-gkr-") as tmp:
        path = args.fixture or Path(tmp) / "proof.bin"
        if args.checkpoints:
            generate(Path(tmp) / "keccacheck", args.checkpoints, args.rows, path)
        measure(path, args.rows, args.forge, args.anvil, args.export_call)


if __name__ == "__main__":
    main()
