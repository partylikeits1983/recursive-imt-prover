"""Verify a native IMT root in a single EVM transaction and compare its intermediate claims to Rust."""

import argparse
import json
import os
from pathlib import Path
import subprocess

from compile_native_columns import compile_columns
from replay import CRATE, TX_LIMIT, RpcError, rpc, send
from replay_native_identity import (
    deploy_arithmetic,
    deploy_pages,
    field_words,
    tuple_of_dynamic,
    whir_proof,
)
from replay_native_openings import abi_bytes, local_chain, word


COMPARISON = "experimental-binary-checkpoint-terminal64-shared-fold4-midpoint-comparison-v1"


def artifact(file, name, out="out"):
    return json.loads((CRATE / out / f"{file}.sol/{name}.json").read_bytes())


def deploy(url, tx, file, name, args, out="out"):
    contract = artifact(file, name, out)
    code = contract["bytecode"]["object"] + args.hex()
    return send(url, {**tx, "data": code})["contractAddress"]


def selector(file, name):
    (value,) = artifact(file, name)["methodIdentifiers"].values()
    return bytes.fromhex(value)


def address_arg(address):
    return word(int(address, 16))


def relation_parts(doc):
    air = doc["arithmetic_prefix"]
    prefix = doc["linked_prefix"]
    layers = b"".join(bytes.fromhex(x["wire"]) for x in doc["chi_layers"])
    return [
        bytes.fromhex(air["product_wire"]),
        bytes.fromhex(air["sumcheck_wire"]),
        bytes.fromhex("".join(air["columns"])),
        bytes.fromhex(prefix["output"] + (prefix.get("midpoint") or "") + prefix["coefficients"]),
        layers[47 * 24 :],
        bytes.fromhex("".join(doc["linked_closing"]["wires"])),
    ]


def transaction(tx, address, data):
    return {**tx, "to": address, "data": "0x" + data.hex()}


def root_inputs(doc, fixed_cap=False, certificate=b"", digests=None):
    statement = bytes.fromhex(doc["statement"])
    cap = bytes(doc["openings"][0]["roots"][0])
    header = statement[:32] + word(statement[32]) + cap
    parts = relation_parts(doc)
    relation_proof = tuple_of_dynamic([abi_bytes(x) for x in parts])
    batch = abi_bytes(bytes.fromhex(doc["shared_bit_batch"]["proof"]) + certificate)
    opening_proof, _ = whir_proof(doc, fixed_cap, digests)
    return header, parts, relation_proof, batch, opening_proof


def replay(url, tx, doc, key, opening_name, fork, fixed_cap=None, certified=False, hash_profile=False, hash_trace=None, fold_proof=None, other_profile_call=None):
    air = doc["arithmetic_prefix"]
    _, arithmetic = deploy_arithmetic(url, tx, key, air)
    midpoint = bool(doc["linked_prefix"].get("midpoint"))
    prefix = "NativeMidpoint" if midpoint else "Native"
    relation_name = prefix + "RootRelation"
    relation = deploy(url, tx, "NativeRootRelation", relation_name, key[:32] + address_arg(arithmetic))
    columns_name = prefix + "ColumnVerifier"
    page = deploy_pages(url, tx, compile_columns(air["key"]))
    columns = deploy(url, tx, "NativeColumnVerifier", columns_name, page)
    opening_key = key
    if fixed_cap is not None:
        if len(fixed_cap) != 4096 * 32:
            raise ValueError("invalid fixed cap length")
        opening_name = opening_name.replace("NativeBitOpening", "NativeCappedBitOpening")
        opening_key += deploy_pages(url, tx, fixed_cap)
    if certified:
        opening_name = "NativeCappedCertifiedBitOpeningVerifierFour"
    opening_file = "NativeBitOpeningVerifier"
    digests = None
    if fold_proof is not None:
        from bench_native_fold_lift import deploy_checker, form_words
        checker = deploy_checker(fold_proof, lambda file, name, args: deploy(url, tx, file, name, args))
        opening_name = opening_file = "NativeLiftedOpening"
        if form_words(fold_proof) == 70:
            digests = (fold_proof / "digests.bin").read_bytes()
            opening_name = "NativeDigestOpening"
        opening_key += address_arg(checker)
    opening_out = "out-comparison" if doc["protocol"] == COMPARISON else "out"
    opening = deploy(url, tx, opening_file, opening_name, opening_key, opening_out)
    root_name = prefix + "AggregateRootVerifier"
    verifier = deploy(
        url, tx, "NativeAggregateRootVerifier", root_name, b"".join(map(address_arg, [relation, columns, opening]))
    )

    certificate = b""
    if certified:
        closing = doc["shared_bit_batch"]["ring_switch"]["initial_fold"]["tail"]["closing"]
        certificate = bytes.fromhex(closing["ring_certificate"])
    if fold_proof is not None:
        certificate += b"".join((fold_proof / f"{n}.bin").read_bytes() for n in
                                ("root", "values", "digits", "proof", "hints"))
    header, parts, relation_proof, batch, opening_proof = root_inputs(doc, fixed_cap is not None, certificate, digests)
    root_selector = selector("NativeAggregateRootVerifier", root_name)
    data = root_selector + tuple_of_dynamic([relation_proof, batch, opening_proof], header)
    call = transaction(tx, verifier, data)

    if fork == "prague":
        call_relation = transaction(
            tx,
            relation,
            selector("NativeRootRelation", relation_name) + tuple_of_dynamic([relation_proof], header),
        )
        result = bytes.fromhex(rpc(url, "eth_call", [call_relation, "latest"])[2:])
        stride = 28 if midpoint else 27
        points = b"".join(field_words(p).ljust(stride * 32, b"\0") for p in doc["linked_closing"]["points"])
        if (
            len(result) != 21 * 32 + len(points)
            or result[: 19 * 32] != field_words(air["air_point"])
            or result[21 * 32 :] != points
        ):
            raise ValueError(
                "connected arithmetic and Keccak relation derived different opening points than Rust"
            )
        args = tuple_of_dynamic([abi_bytes(parts[2])], result[: 20 * 32] + points)
        derived = bytes.fromhex(
            rpc(
                url,
                "eth_call",
                [transaction(tx, columns, selector("NativeColumnVerifier", columns_name) + args), "latest"],
            )[2:]
        )
        expected = bytes.fromhex(doc["shared_bit_batch"]["claims"])
        encoded = word(32) + abi_bytes(expected)
        if (
            len(derived) != len(encoded)
            or derived[:64] != encoded[:64]
            or derived[64 + len(expected) :] != encoded[64 + len(expected) :]
        ):
            raise ValueError("column verifier returned an incorrectly encoded claim list")
        if derived != encoded:
            at = next(
                i
                for i, (a, b) in enumerate(zip(derived[64 : 64 + len(expected)], expected, strict=True))
                if a != b
            )
            raise ValueError(
                f"column reduction differs from Rust at claim {at // (33 * 24)}, field {(at // 24) % 33}"
            )
        print(
            "All 134 derived claim points and values match the independently verified native root.",
            flush=True,
        )

    floor = 21_000 + 40 * len(data) - 30 * data.count(0)
    if fork == "osaka" and floor > TX_LIMIT:
        print(f"Osaka transaction calldata floor {floor:,} exceeds the {TX_LIMIT:,} transaction gas cap.", flush=True)
        return
    receipt = send(url, call, require_success=False)
    gas = int(receipt["gasUsed"], 16)
    print(
        f"{fork} verifyRoot status {int(receipt['status'], 16)}, {gas:,} gas, {len(data):,} calldata bytes, "
        f"{floor:,} calldata floor",
        flush=True,
    )
    if fork == "osaka":
        if int(receipt["status"], 16) == 0 and gas < TX_LIMIT:
            # An inner call can exhaust its 63/64 allowance, leaving gas for the outer revert.
            try:
                rpc(url, "eth_call", [call, "latest"])
            except RpcError as error:
                if error.args[0].get("data", "0x") not in ("0x", ""):
                    raise
        return
    if receipt["status"] != "0x1" or int(rpc(url, "eth_call", [call, "latest"]), 16) != 1:
        raise ValueError("complete root verifier rejected the native proof")
    traces = rpc(url, "debug_traceTransaction", [receipt["transactionHash"], {"tracer": "callTracer"}])
    modules = {
        address.lower(): label
        for address, label in [
            (relation, "arithmetic and Keccak"),
            (columns, "column reduction"),
            (opening, "shared opening"),
        ]
    }
    for child in traces["calls"]:
        print(f"  {modules[child['to'].lower()]} inclusive execution: {int(child['gasUsed'], 16):,} gas")

    if hash_profile:
        from verifier_work import report
        report(url, receipt["transactionHash"], {**modules, verifier.lower(): "root entry", arithmetic.lower(): "arithmetic AIR"})

    if hash_trace is not None:
        from verifier_work import export_hashes
        export_hashes(url, receipt["transactionHash"], hash_trace)

    # Independently alter the public digest, count, main commitment, first
    # boundary value, one Keccak message, a shared reduction and the PCS closing.
    def offset(buf, i):
        return int.from_bytes(buf[i : i + 32], "big")

    rel = 4 + offset(data, 4 + 3 * 32)
    pcs = 4 + offset(data, 4 + 5 * 32)
    mutations = [
        4,
        67,
        68,
        rel + offset(data, rel + 2 * 32) + 32 + 615 * 24,
        rel + offset(data, rel + 4 * 32) + 32,
        4 + offset(data, 4 + 4 * 32) + 32,
        pcs + offset(data, pcs + 4 * 32) + 32,
    ]
    if certified:
        mutations.append(4 + offset(data, 4 + 4 * 32) + 32 + 65 * 24)
    if midpoint:
        # Alter the midpoint either in its first transcript absorption or in the
        # committed boundary readings. Also alter a message in the final layer.
        mutations.extend([
            rel + offset(data, rel + 3 * 32) + 32 + 24,
            rel + offset(data, rel + 2 * 32) + 32 + 617 * 24,
            rel + offset(data, rel + 4 * 32) + 32 + len(parts[4]) - 1,
        ])
    if fold_proof is not None:
        start = 4 + offset(data, 4 + 4 * 32) + 32 + (65 + 1 + 8 * 28 + 192) * 24
        mutations.extend([start, start+32, start+32+71*24, start+4088, start+8744, start+8744+(fold_proof / "proof.bin").stat().st_size])
        from bench_native_fold_lift import form_words
        if form_words(fold_proof) == 70:
            hints = start + 8744 + (fold_proof / "proof.bin").stat().st_size
            mutations.extend(hints + k for k in (23, 600, 35520, 40656, 46032))
            paired = pcs + offset(data, pcs + 2 * 32)
            for field in range(4):
                mutations.append(paired + offset(data, paired + field * 32) + 32)
        if form_words(fold_proof) == 55:
            hints = start + 8744 + (fold_proof / "proof.bin").stat().st_size
            mutations.extend(hints + k for k in (23, 600, 42000, 48336))
    for pos in mutations:
        wrong = bytearray(data)
        wrong[pos] ^= 1
        try:
            rpc(url, "eth_call", [transaction(tx, verifier, wrong), "latest"])
        except RpcError as error:
            if len(error.args[0].get("data", "")) < 10:
                raise
        else:
            raise ValueError(f"mutated root proof accepted at calldata offset {pos}")
    if other_profile_call is not None:
        if data[:68] != other_profile_call[:68] or data == other_profile_call:
            raise ValueError("cross-profile comparison requires a different proof of the same public statement")
        try:
            rpc(url, "eth_call", [transaction(tx, verifier, other_profile_call), "latest"])
        except RpcError as error:
            if len(error.args[0].get("data", "")) < 10:
                raise
        else:
            raise ValueError("verifier accepted the other profile's root")
        print("The deployment rejected the other profile's proof of the same root.", flush=True)
    print(f"All {len(mutations)} changes to the public statement and proof were rejected.", flush=True)
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--trusted", type=Path, required=True)
    parser.add_argument("--forge", default="forge")
    parser.add_argument("--anvil", default="anvil")
    parser.add_argument("--solc", default="0.8.28")
    parser.add_argument("--fold-proof", type=Path, help="use a proof from bench_native_fold_lift on the same verified rows")
    parser.add_argument("--reject-other-profile-call", type=Path, help="check that this deployment rejects another profile's verified calldata for the same statement")
    parser.add_argument("--save-call", type=Path, help="write calldata after successful verification and rejection tests")
    parser.add_argument("--export-hash-trace", type=Path, help="export Keccak preimages and results of the successful native root call")
    parser.add_argument("--hash-profile", action="store_true", help="count Keccak-f and modular verifier operations")
    parser.add_argument("--ring-certificate", action="store_true", help="verify the ring weight by its public certificate")
    parser.add_argument("--fixed-cap", type=Path, help="authenticate the public upper twelve fixed-tree levels at setup")
    parser.add_argument(
        "--export-fixtures", type=Path, help="save the verified four-variable call and public key pages"
    )
    args = parser.parse_args()
    doc = json.loads(args.trace.read_bytes())
    trust = json.loads(args.trusted.read_bytes())
    if (
        doc["protocol"] != trust["protocol"]
        or doc["verifier_digest"] != bytes(trust["verifier_digest"]).hex()
    ):
        raise ValueError("mismatched native trace and verifier key")
    profiles = {
        COMPARISON: "NativeBitOpeningVerifierFour",
        "experimental-binary-checkpoint-terminal64-shared-v1": "NativeBitOpeningVerifier",
        "experimental-binary-checkpoint-terminal64-shared-fold4-midpoint-v1": "NativeBitOpeningVerifierFour",
        "experimental-binary-checkpoint-terminal64-shared-fold4-experiment": "NativeBitOpeningVerifierFour",
    }
    opening_name = profiles[trust["protocol"]]
    if args.export_fixtures and (trust["protocol"] == COMPARISON or opening_name != "NativeBitOpeningVerifierFour" or args.fixed_cap):
        parser.error("the packaged root fixture uses four-variable folds")
    if args.ring_certificate and (not args.fixed_cap or opening_name != "NativeBitOpeningVerifierFour"):
        parser.error("the certified root deployment uses a fixed cap and four-variable folds")
    if args.fold_proof and (trust["protocol"] == COMPARISON or not args.ring_certificate or not doc["linked_prefix"].get("midpoint")):
        parser.error("the fold certificate requires the certified midpoint profile")
    key = bytes.fromhex(trust["identity"] + doc["trusted_wiring_root"])
    build = [args.forge, "build", "--quiet", "--root", str(CRATE), "--use", args.solc]
    subprocess.run(build, check=True, env={**os.environ, "FOUNDRY_PROFILE": "default"})
    if trust["protocol"] == COMPARISON:
        subprocess.run([*build, str(CRATE / "contracts/imt/NativeBitOpeningVerifier.sol")], check=True,
                       env={**os.environ, "FOUNDRY_PROFILE": "comparison"})
    for fork, limit in (("osaka", TX_LIMIT), ("prague", 250_000_000)):
        with local_chain(args.anvil, fork, max(60_000_000, limit)) as (url, account):
            checked = replay(url, {"from": account, "gas": hex(limit)}, doc, key, opening_name, fork,
                             args.fixed_cap.read_bytes() if args.fixed_cap else None, args.ring_certificate, args.hash_profile, args.export_hash_trace, args.fold_proof,
                             args.reject_other_profile_call.read_bytes() if args.reject_other_profile_call else None)
            if checked and args.save_call:
                args.save_call.write_bytes(checked)
            if checked and args.export_fixtures:
                from compile_native_air import compile_key

                root_key = doc["arithmetic_prefix"]["key"]
                args.export_fixtures.mkdir(parents=True, exist_ok=True)
                for name, data in [
                    ("root-call", checked),
                    ("air-program", compile_key(root_key)[3]),
                    ("column-geometry", compile_columns(root_key)),
                ]:
                    midpoint = doc["linked_prefix"].get("midpoint")
                    if midpoint and name == "air-program":
                        continue
                    prefix = "terminal-midpoint" if midpoint else "terminal"
                    (args.export_fixtures / f"{prefix}-{name}.bin").write_bytes(data)


if __name__ == "__main__":
    main()
