"""Build the local verifier and verify the reference terminal proof on a fresh Osaka chain."""

import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import time
from urllib.request import Request, urlopen


CRATE = Path(__file__).resolve().parents[1]
ENTRY = "LeanVmGroupedTerminal_KeccakPow28T6"
FIXTURE = CRATE / "tests/fixtures/terminal-proof.abi"
FIXTURE_SHA256 = "3ee88465bdac9d8db620258d8347748851d0aa8d892ffe92ae26f4704a214a59"
EXPECTED_ROOT = "2f8257a148a1caa160b95abb61e291680fb994f36a34136d1bcf71b7266570ae"
TX_LIMIT = 2**24


def compile_contracts(solc):
    sources = {
        path.relative_to(CRATE).as_posix(): {"content": path.read_text()}
        for path in (CRATE / "contracts").rglob("*.sol")
    }
    libraries = ["LeanVmAir", "LeanVmGroupedLogUp", "LeanVmMerkle", "LeanVmWhir", "TerminalWeights"]
    selection = {
        f"contracts/leanvm/{name}.sol": {
            Path(name).name: ["evm.bytecode", "evm.deployedBytecode.object"]
        }
        for name in [*libraries, f"generated/{ENTRY}"]
    }
    settings = {
        "evmVersion": "cancun", "viaIR": True, "optimizer": {"enabled": True, "runs": 833},
        "outputSelection": selection,
    }
    compilation = subprocess.check_output(
        [solc, "--standard-json"], text=True,
        input=json.dumps({"language": "Solidity", "sources": sources, "settings": settings}),
    )
    result = json.loads(compilation)
    for error in result.get("errors", []):
        if error["severity"] == "error":
            raise RuntimeError(error["formattedMessage"])
    return {
        name: output["evm"] for source in result["contracts"].values() for name, output in source.items()
    }


class RpcError(Exception):
    pass


def rpc(url, method, params, *, timeout=30):
    request = Request(url, data=json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode(), headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=timeout) as response:
        result = json.load(response)
    if "error" in result:
        raise RpcError(result["error"])
    return result["result"]


def send(url, transaction, *, require_success=True):
    tx_hash = rpc(url, "eth_sendTransaction", [transaction])
    for _ in range(100):
        receipt = rpc(url, "eth_getTransactionReceipt", [tx_hash])
        if receipt:
            if require_success and receipt["status"] != "0x1":
                raise RuntimeError(f"Transaction failed: {tx_hash}")
            return receipt
        time.sleep(0.05)
    raise TimeoutError(tx_hash)


def replay(url, sender, calldata, contracts):
    deployed = {}
    base = {"from": sender, "gas": hex(TX_LIMIT)}
    deployment_gas = 0

    def deploy(name):
        nonlocal deployment_gas
        if name in deployed:
            return deployed[name]
        artifact = contracts[name]["bytecode"]
        code = artifact["object"]
        for library_refs in artifact["linkReferences"].values():
            for library, offsets in library_refs.items():
                address = deploy(library).removeprefix("0x")
                for offset in offsets:
                    start = 2 * offset["start"]
                    assert len(address) == 2 * offset["length"]
                    code = code[:start] + address + code[start + len(address):]
        init_size = len(bytes.fromhex(code))
        assert init_size <= 49152
        receipt = send(url, {**base, "data": "0x" + code})
        address = receipt["contractAddress"]
        runtime = rpc(url, "eth_getCode", [address, "latest"])
        size = len(bytes.fromhex(runtime[2:]))
        assert size == len(contracts[name]["deployedBytecode"]["object"]) // 2 <= 24576
        gas = int(receipt["gasUsed"], 16)
        print(f"{name}: {size} runtime bytes, {init_size} initcode bytes, {gas} deployment gas")
        deployment_gas += gas
        deployed[name] = address
        return address

    destination = deploy(ENTRY)
    print(f"Total one-time deployment gas: {deployment_gas}")
    tx = {**base, "to": destination, "data": "0x" + calldata.hex()}
    assert int(rpc(url, "eth_call", [tx, "latest"]), 16) == 1
    receipt = send(url, tx)
    print(f"verifyForRoot: {int(receipt['gasUsed'], 16)} gas, {len(calldata)} calldata bytes")

    # The first two tuple fields are dynamic bytes. The next eight words are the application root.
    def word(offset):
        return int.from_bytes(calldata[offset:offset + 32], "big")

    head = 4 + word(4 + 8 * 32)
    transcript = head + word(head)
    openings = head + word(head + 32)
    changes = [
        ("expected root", 4 + 31, "APPLICATION_ROOT"),
        ("embedded root", head + 95, "APPLICATION_ROOT"),
        ("both application roots", head + 95, "SUMCHECK_IDENTITY"),
        ("transcript", transcript + 32 + 1024, "SUMCHECK_IDENTITY"),
        ("opening", openings + 32 + 4096, "MERKLE_ROOT"),
        ("last opening", openings + 31 + word(openings), "MERKLE_ROOT"),
        ("extra opening byte", openings + 31, "UNUSED_OPENINGS"),
        ("extra transcript byte", transcript + 31, "UNUSED_TRANSCRIPT"),
    ]
    for label, offset, reason in changes:
        altered = bytearray(calldata)
        if label.startswith("extra"):
            altered[offset] += 1
        else:
            altered[offset] ^= 1
        if label == "both application roots":
            altered[4 + 31] ^= 1
        try:
            rpc(url, "eth_call", [{**tx, "data": "0x" + altered.hex()}, "latest"])
        except RpcError as error:
            if reason not in str(error):
                raise
            print(f"Rejected {label}: {reason}")
        else:
            raise AssertionError(f"Accepted altered {label}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--solc", default="solc", help="solc 0.8.28")
    parser.add_argument("--anvil", default="anvil", help="Anvil with Osaka support")
    args = parser.parse_args()
    if hashlib.sha256(FIXTURE.read_bytes()).hexdigest() != FIXTURE_SHA256:
        raise ValueError("Unexpected reference fixture")
    contracts = compile_contracts(args.solc)
    calldata = subprocess.check_output(
        ["cargo", "run", "--quiet", "--locked", "-p", "evm-verifier", "--", EXPECTED_ROOT, FIXTURE],
        cwd=CRATE,
    )
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    node = subprocess.Popen([args.anvil, "--host", "127.0.0.1", "--port", str(port),
                             "--hardfork", "osaka", "--silent"])
    try:
        for _ in range(100):
            try:
                accounts = rpc(url, "eth_accounts", [])
                break
            except OSError:
                if node.poll() is not None:
                    raise RuntimeError("Anvil exited during startup")
                time.sleep(0.05)
        else:
            raise TimeoutError("Local Anvil startup")
        replay(url, accounts[0], calldata, contracts)
    finally:
        node.terminate()
        node.wait(timeout=10)


if __name__ == "__main__":
    main()
