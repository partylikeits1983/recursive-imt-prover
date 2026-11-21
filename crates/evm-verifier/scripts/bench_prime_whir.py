"""Benchmark one dense, 22-variable prime-field opening on an ordinary local Osaka EVM."""

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from replay import TX_LIMIT, rpc, send
from replay_native_openings import local_chain

SOURCES = [
    ("export", "Client-Side-Proving/spartan-whir-export", "d533db1ec6ecabfd34535fac12de89f7f81e0423"),
    ("sol-whir", "ethereum/sol-whir-p3", "b82359ec98e1e3c9f6f39ebf984e7aefb0eeb9be"),
    ("sol-whir/lib/solady", "Vectorized/solady", "258f67cc71e39cff307b726939ade17e9d8bcf5c"),
]
PATCHES = Path(__file__).with_name("prime_whir")
NAME = "WhirVerifier8_k22_jb100_lir6_ff4_rsv1"


def run(command, directory):
    subprocess.run(command, cwd=directory, check=True)


def setup(root, forge):
    for folder, repo, revision in SOURCES:
        tree = root / folder
        tree.mkdir(parents=True)
        run(["git", "init", "--quiet"], tree)
        run(["git", "fetch", "--quiet", "--depth", "1", f"https://github.com/{repo}.git", revision], tree)
        run(["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"], tree)
    rust, solidity = root / "export", root / "sol-whir"
    for tree, patch in ((rust, "prover.patch"), (solidity, "solidity.patch")):
        run(["git", "apply", str(PATCHES / patch)], tree)
    fixture = root / "fixture"
    fixture.mkdir()
    subprocess.run(
        ["cargo", "run", "--locked", "--release", "--bin", "imt_prime_fixture", "--", str(fixture)],
        cwd=rust, env={**os.environ, "RAYON_NUM_THREADS": "5"}, check=True,
    )
    shutil.copyfile(fixture / "config.sol", solidity / "src/generated/OcticWhirFixedConfig_k22_jb100_lir6_ff4_rsv1.sol")
    run([forge, "build", f"src/whir/k22_jb100_lir6_ff4_rsv1/{NAME}.sol", "--use", "0.8.28"], solidity)
    return solidity, fixture


def price(solidity, fixture, anvil):
    def artifact(name):
        return json.loads((solidity / f"out/{name}.sol/{name}.json").read_bytes())

    verifier = artifact(NAME)
    rows = artifact("FullWidthRows")
    with local_chain(anvil, "osaka") as (url, account):
        tx = {"from": account, "gas": hex(TX_LIMIT)}
        lib = send(url, {**tx, "data": rows["bytecode"]["object"]})["contractAddress"]
        bytecode = verifier["bytecode"]
        code = bytecode["object"]
        for references in bytecode["linkReferences"].values():
            for item in references["FullWidthRows"]:
                assert item["length"] == 20
                pos = 2 + 2 * item["start"]
                code = code[:pos] + lib[2:] + code[pos + 40:]
        address = send(url, {**tx, "data": code})["contractAddress"]
        selector, = verifier["methodIdentifiers"].values()
        payload = bytes.fromhex(selector) + (fixture / "call-args.bin").read_bytes()
        call = {**tx, "to": address, "data": "0x" + payload.hex()}
        if int(rpc(url, "eth_call", [call, "latest"]), 16) != 1:
            raise ValueError("Solidity rejected the opening")
        receipt = send(url, call)
        print(f"Osaka PCS receipt {int(receipt['gasUsed'], 16):,} gas, {len(payload):,} calldata bytes, "
              f"{21_000 + 40*len(payload) - 30*payload.count(0):,} gas calldata floor")
        for offset in [4, len(payload) - 1]:
            altered = bytearray(payload)
            altered[offset] ^= 1
            rejected = send(url, {**call, "data": "0x" + altered.hex()}, require_success=False)
            if rejected["status"] != "0x0":
                raise ValueError("altered opening accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--forge", default="forge")
    parser.add_argument("--anvil", default="anvil")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="imt-prime-opening-") as temp:
        solidity, fixture = setup(Path(temp), args.forge)
        price(solidity, fixture, args.anvil)


if __name__ == "__main__":
    main()
