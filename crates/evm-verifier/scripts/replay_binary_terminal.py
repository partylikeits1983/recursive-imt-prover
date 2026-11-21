"""Price the binary IMT terminal opening on Osaka and exercise its statement and proof bindings."""

import argparse
import json
from pathlib import Path

from binary_terminal.profile import artifact_directory, profile
from replay import TX_LIMIT, rpc, send
from replay_native_openings import abi_bytes, local_chain, word
from replay_native_root import artifact, deploy


def replay_roots(bundle, trace, statement, anvil, derive_target=False, derive_basis=False):
    saved, _, _, header, _, _ = profile(trace, bundle)
    children = statement["children"]
    if len(children) != bundle[32] or any(
        bytes(c["input_tag"]) != bytes(32) or bytes(c["output_commitment"]) != bytes(32) for c in children
    ):
        raise ValueError("expected the root-only CLI statements for this batch")
    roots = [bytes(c["root"]) for c in children]
    if any(len(root) != 32 for root in roots):
        raise ValueError("invalid IMT root width")
    out = artifact_directory(saved["iv"], header[-1])
    name = "BinaryTerminalOpenings"
    methods = artifact(name, name, out)["methodIdentifiers"]
    method = "checkRootListOpening"
    if derive_basis:
        method = "checkRootListStackOpening"
    elif derive_target:
        method = "checkRootListStackTarget"
    (selector,) = (bytes.fromhex(v) for k, v in methods.items() if k.startswith(method + "("))
    reductions = b"" if derive_basis else word(saved["basis"])
    if not (derive_basis or derive_target):
        reductions = word(saved["target"]) + reductions
    head_size = 96 + len(reductions)

    def calldata(ordered):
        root_list = word(len(ordered)) + b"".join(ordered)
        return (
            selector
            + word(head_size)
            + bytes.fromhex(saved["deferred"]).ljust(32, b"\0")
            + reductions
            + word(head_size + len(root_list))
            + root_list
            + abi_bytes(bundle[33:])
        )

    for fork, limit in (("prague", 100_000_000), ("osaka", TX_LIMIT)):
        with local_chain(anvil, fork, limit) as (url, account):
            tx = {"from": account, "gas": hex(limit)}
            address = deploy(url, tx, name, name, b"", out)

            def call(ordered, required):
                return send(
                    url,
                    {**tx, "to": address, "data": "0x" + calldata(ordered).hex()},
                    require_success=required,
                )

            receipt = call(roots, fork == "prague")
            print(
                f"{fork} {method} status {receipt['status']}, {int(receipt['gasUsed'], 16):,} gas including calldata."
            )
            if fork == "prague":
                expected_osaka = int(receipt["gasUsed"], 16) <= TX_LIMIT
                for altered in ([roots[1], roots[0], *roots[2:]], [roots[1], *roots[1:]], roots[:-1]):
                    if call(altered, False)["status"] != "0x0":
                        raise ValueError("accepted changed IMT roots")
            elif (receipt["status"] == "0x1") != expected_osaka:
                raise RuntimeError("unexpected ordinary Osaka result")


def replay(bundle, trace, anvil, whir):
    saved, _, phases, header, _, point = profile(trace, bundle)
    digest, count, wire = bundle[:32], bundle[32], bundle[33:]
    out = artifact_directory(saved["iv"], header[-1])
    methods = artifact("BinaryTerminalOpenings", "BinaryTerminalOpenings", out)["methodIdentifiers"]
    name = "checkWhir" if whir else "checkOpenings"
    (sel,) = (v for k, v in methods.items() if k.startswith(name + "("))
    reductions = word(saved["target"]) + word(saved["basis"]) if whir else b""
    proof_start = 164 + len(reductions)
    encoded = bytearray(
        bytes.fromhex(sel)
        + digest
        + word(count)
        + bytes.fromhex(saved["deferred"]).ljust(32, b"\0")
        + reductions
        + word(128 + len(reductions))
        + abi_bytes(wire)
    )
    # The stream and five phase frontiers are used in the negative cases below.
    vm = 8 + 16 * point
    stream = vm + 4
    offsets = [
        ("digest", 4),
        ("count", 67),
        ("deferred value", 68),
        ("point arity", proof_start),
        ("deferred point", proof_start + 8),
        ("stream length", proof_start + vm),
        ("table shape", proof_start + stream),
        ("rate", proof_start + stream + 16 * 7),
    ]
    cursor = stream + 16 * int.from_bytes(wire[vm:stream], "little") + 4
    for i, phase in enumerate(phases):
        n = phase["queries"]
        depth = phase["depth"]
        pos = set(phase["positions"])
        fields = cursor + 4 + 4 * n
        row_words = int.from_bytes(wire[fields + 8 : fields + 12], "little")
        rows = fields + 12
        siblings = rows + len(pos) * 8 * row_words
        offsets.extend(
            [
                (f"cap {i}", proof_start + stream + 16 * phase["cap"]),
                (f"query {i}", proof_start + cursor + 4),
                (f"row width {i}", proof_start + fields + 8),
                (f"row {i}", proof_start + rows),
                (f"path {i}", proof_start + siblings),
            ]
        )
        cursor = siblings
        for _ in range(depth):
            cursor += 32 * sum((p ^ 1) not in pos for p in pos)
            pos = {p >> 1 for p in pos}
    assert cursor == len(wire)
    if whir:
        offsets.extend([("opening target", 131), ("terminal basis", 163)])
    fork, limit = ("prague", 100_000_000) if whir else ("osaka", TX_LIMIT)
    with local_chain(anvil, fork, limit) as (url, account):
        tx = {"from": account, "gas": hex(limit)}
        address = deploy(url, tx, "BinaryTerminalOpenings", "BinaryTerminalOpenings", b"", out)
        call = {**tx, "to": address, "data": "0x" + encoded.hex()}
        assert int(rpc(url, "eth_call", [call, "latest"]), 16) == 1
        receipt = send(url, call)
        used = int(receipt["gasUsed"], 16)
        floor = 21000 + 40 * len(encoded) - 30 * encoded.count(0)
        print(
            f"{name} used {used:,} {fork} gas, {len(encoded):,} call bytes, {floor:,} calldata floor.",
            flush=True,
        )
        for label, off in offsets:
            encoded[off] ^= 1
            bad = send(url, {**call, "data": "0x" + encoded.hex()}, require_success=False)
            if bad["status"] != "0x0":
                raise ValueError(f"Accepted changed {label}")
            encoded[off] ^= 1
        # The ABI decoder accepts padding. Extend the declared proof itself with an extra byte.
        length_word = proof_start - 32
        extra = encoded[:length_word] + abi_bytes(wire + b"\0")
        trailing = send(url, {**call, "data": "0x" + extra.hex()}, require_success=False)
        if trailing["status"] != "0x0":
            raise ValueError("Accepted trailing proof data")
        print(f"Rejected {len(offsets) + 1} altered calls.")
    if whir:
        with local_chain(anvil, "osaka") as (url, account):
            tx = {"from": account, "gas": hex(TX_LIMIT)}
            address = deploy(url, tx, "BinaryTerminalOpenings", "BinaryTerminalOpenings", b"", out)
            ordinary = send(url, {**tx, "to": address, "data": "0x" + encoded.hex()}, require_success=False)
            print(
                f"Ordinary Osaka status {ordinary['status']}, charged {int(ordinary['gasUsed'], 16):,} gas."
            )
            if (int(ordinary["status"], 16) == 1) != (used <= TX_LIMIT):
                raise RuntimeError("ordinary Osaka result disagrees with the measured transaction cost")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("trace", type=Path, help="transcript trace from a successful native verify-terminal")
    parser.add_argument("--anvil", default="anvil")
    parser.add_argument("--whir", action="store_true", help="also check the complete WHIR polynomial opening")
    parser.add_argument("--derive-target", action="store_true", help="derive the stack target onchain for --roots")
    parser.add_argument("--derive-stack", action="store_true", help="derive both the target and basis onchain for --roots")
    parser.add_argument(
        "--roots",
        type=Path,
        help="check the polynomial opening against the ordered roots in CLI statement.json",
    )
    args = parser.parse_args()
    if (args.derive_target or args.derive_stack) and not args.roots:
        parser.error("onchain stack derivation requires --roots")
    if args.roots:
        replay_roots(
            args.bundle.read_bytes(), args.trace.read_text(), json.loads(args.roots.read_text()), args.anvil,
            args.derive_target, args.derive_stack
        )
    else:
        replay(args.bundle.read_bytes(), args.trace.read_text(), args.anvil, args.whir)
