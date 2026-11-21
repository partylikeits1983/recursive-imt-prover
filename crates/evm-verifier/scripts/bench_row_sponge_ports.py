"""Prove the Keccak sponge wiring of the strong native root's authenticated WHIR rows."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from bench_large_prime_opening import checkout
from prime_whir.native_fold_witness import export
from replay import CRATE, TX_LIMIT, RpcError, rpc, send
from replay_native_identity import tuple_of_dynamic
from replay_native_openings import abi_bytes, local_chain, word
from replay_native_root import address_arg, artifact, deploy


def generate(trace, work, fixture, joint=False):
    whir = work / "whir"
    checkout(whir)
    sources = Path(__file__).with_name("prime_whir")
    dest = whir / "src/bin"
    (dest / "support").mkdir(exist_ok=True)
    for name in ("native_fold_lift", "nibble_relation", "native_row_sponge", "native_row_ports", "stream_digits", "stream_opening"):
        shutil.copyfile(sources / f"{name}.rs", dest / f"{name}.rs")
    for module in ("checkpoint_digits", "segments", "close_moments", "digit_sumcheck", "nibble_gate",
                   "digit_columns", "digits", "node", "quartets", "nibble_folds", "stream_code"):
        shutil.copyfile(sources / f"support/{module}.rs", dest / f"support/{module}.rs")

    def run(driver, *args):
        subprocess.run(["cargo", "run", "--release", "--locked", "--bin", driver, "--", *args],
                       cwd=whir, env={**os.environ, "RAYON_NUM_THREADS": "5"}, check=True)

    folds = work / "folds"
    witness = work / "witness"
    cap = witness / "cap"
    export(trace, folds)
    run("native_row_sponge", folds, witness)
    run("stream_digits", witness / "table.bin", "10", cap, "--cache-quartets")
    if joint:
        from bench_segment_reduction import generate as generate_rounds
        keccak = work / "keccak"
        keccak.mkdir()
        ports = work / "ports"
        gkr = keccak / "rounds.bin"
        generate_rounds(work / "gkr", witness / "keccak-checkpoints.bin", 512, gkr, cap, native_trace=True)
        run("nibble_relation", witness / "hash-digits.bin", cap, gkr, "9", keccak)
        run("native_row_ports", witness, ports)
        run("native_fold_lift", folds, cap / "root.bin", witness / "digests.bin")
        parts = [folds, keccak, ports]
        run("stream_opening", witness / "table.bin", cap, "10", fixture, *(p / "opening-point.bin" for p in parts))
        package_joint(fixture, folds, keccak, ports, witness)
        return
    run("native_row_ports", witness, fixture)
    point = fixture / "opening-point.bin"
    run("stream_opening", witness / "table.bin", cap, "10", fixture, point)
    if (fixture / "statement.bin").read_bytes()[32:] != point.read_bytes()[32:] + (fixture / "digit-value.bin").read_bytes():
        raise ValueError("The Keccak sponge reduction and committed table disagree on the final evaluation")
    shutil.copyfile(cap / "root.bin", fixture / "root.bin")
    shutil.copyfile(witness / "digests.bin", fixture / "digests.bin")


def package_joint(fixture, folds, keccak, ports, witness):
    readings = b"".join((part / "opening-point.bin").read_bytes()[32:] + (part / "digit-value.bin").read_bytes()
                        for part in (folds, keccak, ports))
    if (fixture / "statement.bin").read_bytes()[32:] != readings:
        raise ValueError("The three reductions did not open their claimed values on the same table")
    hints = fixture / "hints.bin"
    gkr = keccak / "rounds.bin"
    prefix = [Path(f"{gkr}.public").read_bytes()[-600:], gkr.read_bytes(),
              (keccak / "digits.bin").read_bytes(), (ports / "digits.bin").read_bytes()]
    if [len(p) for p in prefix] != [600, 34920, 5136, 5376]:
        raise ValueError("Incorrect row digest proof geometry")
    hints.write_bytes(b"".join(prefix) + hints.read_bytes())
    for name in ("root", "draws", "values", "digits"):
        shutil.copyfile(folds / f"{name}.bin", fixture / f"{name}.bin")
    shutil.copyfile(witness / "digests.bin", fixture / "digests.bin")


def measure(fixture, forge, anvil):
    subprocess.run([forge, "build", "--quiet", "contracts/prime/NativeRowSpongePorts.sol"], cwd=CRATE, check=True)
    root = (fixture / "root.bin").read_bytes()
    digests, digits, proof, hints = [(fixture / f"{name}.bin").read_bytes()
                                     for name in ("digests", "digits", "proof", "hints")]
    if len(root) != 32 or len(digests) != 240 * 32 or proof[:32] != root:
        raise ValueError("Expected a shared table commitment and 240 row digests")
    tag = bytes.fromhex(artifact("NativeRowSpongePorts", "NativeRowSpongePorts")["methodIdentifiers"]["verifyPorts(bytes32,bytes,bytes,bytes,bytes)"])
    parts = [abi_bytes(part) for part in (digests, digits, proof, hints)]
    data = tag + tuple_of_dynamic(parts, root)
    with local_chain(anvil, "osaka") as (url, account):
        tx = {"from": account, "gas": hex(TX_LIMIT)}
        pcs = deploy(url, tx, "NibbleOpeningVerifier", "NativeRowSpongeOpeningVerifier", b"")
        ports = deploy(url, tx, "NativeRowSpongePorts", "NativeRowSpongePorts", address_arg(pcs))
        call = {**tx, "to": ports, "data": "0x" + data.hex()}
        if rpc(url, "eth_call", [call, "latest"]) != "0x" + word(1).hex():
            raise ValueError("Solidity rejected the honest row sponge proof")
        gas = int(send(url, call)["gasUsed"], 16)
        floor = 21_000 + 40 * len(data) - 30 * data.count(0)
        print(f"507 sponge inputs and 240 digests: {gas:,} Osaka gas, {len(data):,} bytes, {floor:,} calldata floor")
        offsets = [4 + int.from_bytes(data[36 + 32*i:68 + 32*i], "big") + 32 for i in range(4)]
        # Cover both main/fixed leaves and the later WHIR rounds, both sumchecks, commitment and query path.
        changed = [4, *(offsets[0] + i for i in (0, 32, 142 * 32, len(digests) - 1)),
                   offsets[1], offsets[1] + len(digits) - 1, offsets[2] + 32, offsets[3] + len(hints) - 1]
        for at in changed:
            mutated = bytearray(data)
            mutated[at] ^= 1
            try:
                rpc(url, "eth_call", [{**call, "data": "0x" + mutated.hex()}, "latest"])
            except RpcError as err:
                if len(err.args[0].get("data", "")) < 10:
                    raise
            else:
                raise ValueError(f"Accepted modified sponge proof byte {at}")
        print(f"Rejected {len(changed)} changed statements and proofs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--trace", type=Path, help="verified strong midpoint trace from root-opening-trace")
    mode.add_argument("--fixture", type=Path, help="previously generated proof directory")
    parser.add_argument("--joint", action="store_true", help="also prove all Keccak rounds and native row folds")
    parser.add_argument("--save-fixture", type=Path)
    parser.add_argument("--forge", default="forge")
    parser.add_argument("--anvil", default="anvil")
    args = parser.parse_args()
    if args.save_fixture and not args.trace:
        parser.error("--save-fixture requires --trace")
    with tempfile.TemporaryDirectory(prefix="imt-row-sponge-") as temporary:
        work = Path(temporary).resolve()
        fixture = args.fixture
        if args.trace:
            fixture = (args.save_fixture or work / "fixture").resolve()
            fixture.mkdir(parents=True, exist_ok=False)
            generate(args.trace, work, fixture, args.joint)
        if (fixture / "draws.bin").is_file():
            from bench_native_fold_lift import measure as measure_joint
            measure_joint(fixture, args.forge, args.anvil)
        else:
            measure(fixture, args.forge, args.anvil)


if __name__ == "__main__":
    main()
