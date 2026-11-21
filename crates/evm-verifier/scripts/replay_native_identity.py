"""Price the 64-client shared bit-opening verifier and cross-check the final identity."""

import argparse
import json
from pathlib import Path
import subprocess

from replay import CRATE, TX_LIMIT, RpcError, rpc, send
from replay_native_openings import abi_bytes, abi_records, calldata, local_chain, lower_path_count, word


def tuple_of_dynamic(parts, static=b""):
    cursor = len(static) + 32 * len(parts)
    offsets = []
    for part in parts:
        offsets.append(word(cursor))
        cursor += len(part)
    return static + b"".join(offsets + parts)


def rows_and_path(site, levels=None, digests=None):
    _, siblings, rows, _, _ = calldata(b"", site)
    if digests is not None:
        draws, leaves = digests
        unique = {}
        for index, leaf in zip(draws, leaves, strict=True):
            if unique.setdefault(index, leaf) != leaf:
                raise ValueError("Conflicting digests for the same authenticated leaf")
        if set(site["indices"]) != set(unique):
            raise ValueError("Row digests do not match the trace addresses")
        rows = b"".join(unique[i] for i in sorted(unique))
    if levels is not None:
        siblings = siblings[:32 * lower_path_count(site["indices"], levels)]
    return abi_bytes(rows), word(len(siblings) // 32) + siblings


def whir_proof(doc, fixed_cap=False, digests=None):
    bits = doc["shared_bit_batch"]
    ring = bits["ring_switch"]
    first = ring["initial_fold"]
    tail = first["tail"]
    sites = doc["openings"]
    initial = "".join(first["ood_answers"])
    nonces = first["pow_witnesses"] if first["pow_bits"] else [""] * len(first["messages"])
    for pair, nonce in zip(first["messages"], nonces, strict=True):
        initial += "".join(pair) + nonce
    initial += first["next_cap"] + "".join(first["round_answers"]) + first["query_witness"]
    groups = [None] * len(sites)
    if digests is not None:
        if len(digests) != 240 * 32:
            raise ValueError("Expected the 240 strong-profile row digests")
        leaves = [digests[i:i + 32] for i in range(0, len(digests), 32)]
        early = first["query_indices"]
        used = 2 * len(early)
        groups = [(early, leaves[:used:2]), (early, leaves[1:used:2])]
        for step in tail["steps"]:
            indices = step["indices"]
            groups.append((indices, leaves[used:used + len(indices)]))
            used += len(indices)
        if used != len(leaves):
            raise ValueError("Incorrect number of native row digests")
    rows0, path0 = rows_and_path(sites[0], digests=groups[0])
    rows1, path1 = rows_and_path(sites[1], 12 if fixed_cap else None, groups[1])
    steps = []
    for step, site, group in zip(tail["steps"], sites[2:], groups[2:], strict=True):
        wire = bytes.fromhex(step["fold"]["wire"] + step["next_message"] + step["next_witness"])
        steps.append(tuple_of_dynamic([abi_bytes(wire), *rows_and_path(site, digests=group)]))
    closing = bytes.fromhex(tail["final_fold"]["wire"])
    proof = tuple_of_dynamic([
        abi_bytes(bytes.fromhex(ring["rows"])), abi_bytes(bytes.fromhex(initial)),
        tuple_of_dynamic([rows0, rows1, path0, path1]), abi_records(steps), abi_bytes(closing),
    ])
    return proof, closing


def encode(doc, selector, certificate):
    bits = doc["shared_bit_batch"]
    tail = bits["ring_switch"]["initial_fold"]["tail"]
    sites = doc["openings"]
    proof, closing = whir_proof(doc)
    main_cap = bytes(sites[0]["roots"][0])
    parts = [abi_bytes(bytes.fromhex(bits["claims"])), abi_bytes(bytes.fromhex(bits["proof"])), proof]
    extra = abi_bytes(certificate) if certificate else b""
    if extra:
        parts.append(extra)
    body = selector + tuple_of_dynamic(parts, main_cap)
    last_scalar = len(body) - len(extra) - (-len(closing) % 32) - 1
    expected = b"".join(word(int.from_bytes(bytes.fromhex(tail["closing"][k]), "little"))
                        for k in ("ordinary_weight", "ring_weight", "final_value"))
    return body, last_scalar, expected


def price_ring(url, tx, key, doc, certificate, anvil, fixture):
    bits = doc["shared_bit_batch"]
    ring = bits["ring_switch"]
    fold = ring["initial_fold"]
    tail = fold["tail"]
    contract = json.loads((CRATE / "out/NativeBitOpeningVerifier.sol/NativeBitClaimReduction.json").read_bytes())
    address = send(url, {**tx, "data": contract["bytecode"]["object"]})["contractAddress"]
    selector, = contract["methodIdentifiers"].values()
    caps = key[:32] + bytes(doc["openings"][0]["roots"][0]) + key[32:]
    args = tuple_of_dynamic([abi_bytes(bytes.fromhex(data)) for data in (bits["claims"], bits["proof"], ring["rows"])], caps)
    output = rpc(url, "eth_call", [{**tx, "to": address, "data": "0x" + selector + args.hex()}, "latest"])
    carry = bytes.fromhex(output[2:])
    if len(carry) != 43 * 32:
        raise ValueError("wrong bit reduction output length")
    draw = list(fold["fold_point"])
    for step in tail["steps"]:
        draw.extend(step["fold"]["point"])
    draw.extend(tail["final_fold"]["point"])
    if len(draw) != 26:
        raise ValueError("wrong folding randomness length")
    packed = b"".join(word(int.from_bytes(bytes.fromhex(s), "little")) for s in draw)
    contract = json.loads((CRATE / "out/NativeWhirOpening.t.sol/NativeRingWeightTest.json").read_bytes())
    address = send(url, {**tx, "data": contract["bytecode"]["object"]})["contractAddress"]
    selector = contract["methodIdentifiers"]["weight(uint192[32],uint192[26],uint192[8])"]
    args = carry[:32*32] + packed + carry[34*32:42*32]
    call = {**tx, "to": address, "data": "0x" + selector + args.hex()}
    expected = int.from_bytes(bytes.fromhex(tail["closing"]["ring_weight"]), "little")
    if int(rpc(url, "eth_call", [call, "latest"]), 16) != expected:
        raise ValueError("standalone ring-switch weight differs from the native verifier")
    gas = int(send(url, call)["gasUsed"], 16)
    print(f"Ring-switch final weight alone: {gas:,} component transaction gas")
    if certificate:
        artifact = json.loads((CRATE / "out/NativeRingCertificate.sol/NativeRingCertificate.json").read_bytes())
        selector, = artifact["methodIdentifiers"].values()
        args += word(len(args) + 32) + abi_bytes(certificate)
        with local_chain(anvil, "osaka") as (node, account):
            tx = {"from": account, "gas": hex(TX_LIMIT)}
            address = send(node, {**tx, "data": artifact["bytecode"]["object"]})["contractAddress"]
            call = {**tx, "to": address, "data": "0x" + selector + args.hex()}
            if int(rpc(node, "eth_call", [call, "latest"]), 16) != expected:
                raise ValueError("certificate gave the wrong ring weight")
            gas = int(send(node, call)["gasUsed"], 16)
            print(f"Certified ring weight alone on Osaka: {gas:,} gas, {len(certificate):,} certificate bytes")
            if fixture:
                fixture.write_bytes(bytes.fromhex(selector) + args)
            start = len(args) - (-len(certificate) % 32) - len(certificate)
            for at in (0, 32*32, 58*32, start, start+24, start+24+7*28*24, start+24+8*28*24, start+len(certificate)-1):
                changed = bytearray(args)
                changed[at + (31 if at < start else 0)] ^= 1
                try:
                    rpc(node, "eth_call", [{**call, "data": "0x" + selector + changed.hex()}, "latest"])
                except RpcError as exc:
                    if exc.args[0].get("data") != rpc(node, "web3_sha3", ["0x" + b"InvalidRingCertificate()".hex()])[:10]:
                        raise
                else:
                    raise ValueError("accepted a different ring input, claim, sumcheck or map")


def field_words(data):
    raw = bytes.fromhex(data)
    if len(raw) % 24:
        raise ValueError("incomplete Poly192 element")
    return b"".join(word(int.from_bytes(raw[i:i+24], "little")) for i in range(0, len(raw), 24))


def deploy_pages(url, tx, payload):
    page = json.loads((CRATE / "out/FixedWiringCap.sol/WiringPage.json").read_bytes())
    addresses = []
    for start in range(0, len(payload), 16384):
        data = payload[start:start+16384].ljust(16384, b"\x00")
        code = page["bytecode"]["object"] + (word(32) + abi_bytes(data)).hex()
        addresses.append(send(url, {**tx, "data": code})["contractAddress"])
    return b"".join(word(int(addr, 16)) for addr in addresses)


def price_bus(url, tx, key, doc):
    native = doc["arithmetic_prefix"]
    domain = bytes.fromhex(native["bus_domain"])
    if len(domain) != 51656:
        raise ValueError("incorrect terminal bus geometry")
    artifact = json.loads((CRATE / "out/NativeBusVerifier.sol/NativeBusVerifier.json").read_bytes())
    addresses = deploy_pages(url, tx, domain)
    args = key + addresses
    code = artifact["bytecode"]["object"] + args.hex()
    address = send(url, {**tx, "data": code})["contractAddress"]
    selector, = artifact["methodIdentifiers"].values()
    statement = bytes.fromhex(doc["statement"])
    cap = bytes(doc["openings"][0]["roots"][0])
    wire = bytes.fromhex(native["product_wire"])
    body = bytes.fromhex(selector) + statement[:32] + word(statement[32]) + cap + word(128) + abi_bytes(wire)
    call = {**tx, "to": address, "data": "0x" + body.hex()}
    result = bytes.fromhex(rpc(url, "eth_call", [call, "latest"])[2:])
    expected = b"".join(field_words(native[k]) for k in ("fingerprint", "offset", "product_point", "product_values"))
    if len(result) != len(expected) + 64 or result[:-64] != expected:
        raise ValueError("bus fingerprint, offset, point or terminal claims differ from Rust")
    digest, used = result[-64:-32], int.from_bytes(result[-32:], "big")
    if used > 4:
        raise ValueError("invalid bus transcript cursor")
    next_words = []
    for _ in range(3):
        if used == 4:
            digest = bytes.fromhex(rpc(url, "web3_sha3", ["0x" + digest.hex()])[2:])
            used = 0
        next_words.append(int.from_bytes(digest[24-8*used:32-8*used], "big"))
        used += 1
    if b"".join(w.to_bytes(8, "little") for w in next_words).hex() != native["next_challenge"]:
        raise ValueError("bus returned a different native transcript")
    gas = int(send(url, call)["gasUsed"], 16)
    errors = {rpc(url, "web3_sha3", ["0x" + s.hex()])[:10]
              for s in (b"InvalidBusShape()", b"InvalidBusLayer(uint256)")}
    # Alter the expected digest, count, commitment, length, shared product, a middle
    # sumcheck, and the last layer's child claims.
    for i in [4, 67, 68, 163, 164, 164 + 12000, 164 + len(wire) - 1]:
        changed = bytearray(body)
        changed[i] ^= 1
        try:
            rpc(url, "eth_call", [{**call, "data": "0x" + changed.hex()}, "latest"])
        except RpcError as exc:
            if exc.args[0].get("data", "")[:10] not in errors:
                raise
        else:
            raise ValueError("bus accepted a changed statement, commitment or product argument")
    print(f"Ordered public statement through bus product: {gas:,} Osaka transaction gas, {len(body):,} calldata bytes")


def deploy_arithmetic(url, tx, key, native):
    from compile_native_air import compile_key

    constants, ops, out, code = compile_key(native["key"])
    if (constants, ops, out) != (100, 11335, 13609):
        raise ValueError("unrecognized terminal arithmetic program")
    name = "NativeAirClosingVerifier"
    artifact = json.loads((CRATE / f"out/{name}.sol/{name}.json").read_bytes())
    args = key + deploy_pages(url, tx, bytes.fromhex(native["bus_domain"])) + deploy_pages(url, tx, code)
    address = send(url, {**tx, "data": artifact["bytecode"]["object"] + args.hex()})["contractAddress"]
    return artifact, address


def price_arithmetic(url, tx, key, doc, fork):
    native = doc["arithmetic_prefix"]
    artifact, address = deploy_arithmetic(url, tx, key, native)
    statement = bytes.fromhex(doc["statement"])
    header = statement[:32] + word(statement[32]) + bytes.fromhex(doc["linked_prefix"]["cap"])
    bus = bytes.fromhex(native["product_wire"])
    air = bytes.fromhex(native["sumcheck_wire"])
    columns = bytes.fromhex("".join(native["columns"]))
    selector = lambda f: bytes.fromhex(next(v for k,v in artifact["methodIdentifiers"].items() if k.startswith(f+"(")))
    def body(method, parts):
        return selector(method) + tuple_of_dynamic([abi_bytes(x) for x in parts], header)
    def call(wire):
        return {**tx, "to": address, "data": "0x"+wire.hex()}
    for method, parts in [("reduceArithmetic",[bus,air]), ("verifyArithmetic",[bus,air,columns])]:
        wire = body(method,parts)
        receipt = send(url, call(wire), require_success=False)
        gas = int(receipt["gasUsed"],16)
        if int(receipt["status"],16) == 0:
            if fork == "osaka" and gas == TX_LIMIT:
                print(f"{method} exhausted the {gas:,} Osaka limit")
                continue
            raise ValueError(f"{method} rejected the arithmetic proof on {fork}")
        returned = bytes.fromhex(rpc(url,"eth_call",[call(wire),"latest"])[2:])
        if method == "reduceArithmetic":
            returned = returned[34*32:]
        expected = b"".join(field_words(native[k]) for k in ("air_challenges","air_point","final_sum"))
        if returned[:-64] != expected:
            raise ValueError("arithmetic claim differs from Rust")
        print(f"{method} on {fork}: {gas:,} gas, {len(wire):,} calldata bytes")
        if method == "verifyArithmetic":
            # Mutate the claimed sum, a late round and main/fixed column readings.
            for index,at in [(1,0), (1,len(air)-1), (2,0), (2,619*24), (2,len(columns)-1)]:
                wrong = list(parts)
                value = bytearray(wrong[index]); value[at] ^= 1; wrong[index] = value
                try:
                    rpc(url,"eth_call",[call(body(method,wrong)), "latest"])
                except RpcError as exc:
                    err = exc.args[0].get("data","")[:10]
                    expected_errors = {rpc(url,"web3_sha3",["0x"+e.hex()])[:10] for e in
                                       (b"InvalidArithmeticSum()", b"InvalidArithmeticColumns()")}
                    if err not in expected_errors:
                        raise
                else:
                    raise ValueError("arithmetic verifier accepted an altered proof")


def price_keccak_boundary(url, tx, authority, doc):
    native = doc["linked_closing"]
    header = doc["linked_prefix"]
    prefix = bytes.fromhex("".join(header[k] for k in ("authority", "cap", "bridge", "output", "coefficients")))
    layers = b"".join(bytes.fromhex(layer["wire"]) for layer in doc["chi_layers"])[47*24:]
    parts = [bytes.fromhex(native["arithmetic_point"]), bytes.fromhex(native["bridge_row"]), prefix,
             layers, bytes.fromhex("".join(native["wires"]))]
    expected = b"".join(field_words(p) for p in native["points"])
    cap = bytes(doc["openings"][0]["roots"][0])
    evals = field_words(native["evaluations"])
    artifact = json.loads((CRATE / "out/NativeKeccakBoundaryVerifier.sol/NativeKeccakBoundaryVerifier.json").read_bytes())
    address = send(url, {**tx, "data": artifact["bytecode"]["object"] + authority.hex()})["contractAddress"]
    selector, = artifact["methodIdentifiers"].values()
    cursor, offsets, encoded = 10*32, [], []
    for part in parts:
        offsets.append(cursor)
        encoded.append(abi_bytes(part))
        cursor += len(encoded[-1])
    body = bytes.fromhex(selector) + cap + b"".join(map(word, offsets)) + evals + b"".join(encoded)
    call = {**tx, "to": address, "data": "0x"+body.hex()}
    result = rpc(url,"eth_call",[call,"latest"])
    if result != "0x"+expected.hex():
        raise ValueError("Keccak verifier derived different boundary points than the verified root")
    gas = int(send(url, call)["gasUsed"],16)
    for offset in [4, 4+offsets[0]+32+48, 4+offsets[1]+32, 4+offsets[1]+32+116*24,
                   4+offsets[2]+32+64, 4+offsets[4]+32, 4+offsets[4]+32+31*24,
                   4+offsets[4]+32+len(parts[4])-1] + [4+32*(6+i)+31 for i in range(4)]:
        wrong = bytearray(body)
        wrong[offset] ^= 1
        try:
            rpc(url,"eth_call",[{**call,"data":"0x"+wrong.hex()},"latest"])
        except RpcError as exc:
            expected_errors = [rpc(url,"web3_sha3",["0x"+s.hex()])[:10] for s in (b"InvalidBridge()", b"InvalidClosing()")]
            if exc.args[0].get("data") not in expected_errors:
                raise
        else:
            raise ValueError("accepted an altered Keccak bridge, closing or boundary evaluation")
    print(f"Arithmetic row through 24 Keccak layers, both closings and four boundary evaluations: "
          f"{gas:,} diagnostic transaction gas, {len(body):,} calldata bytes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--trusted", required=True, type=Path, help="trusted native root-key metadata")
    parser.add_argument("--forge", default="forge")
    parser.add_argument("--anvil", default="anvil")
    parser.add_argument("--solc", default="0.8.28")
    parser.add_argument("--ring-certificate", action="store_true", help="use the experimental ring-weight certificate")
    parser.add_argument("--export-ring-call", type=Path, help="save the verified standalone certificate call as a Foundry fixture")
    parser.add_argument("--keccak-boundary", action="store_true", help="replay the full linked Keccak argument against the arithmetic row")
    parser.add_argument("--arithmetic-only", action="store_true", help="replay the bus, AIR reduction and closing equation")
    parser.add_argument("--bus-only", action="store_true", help="replay the statement-bound arithmetic bus on standard Osaka")
    args = parser.parse_args()
    if args.export_ring_call and not args.ring_certificate:
        parser.error("--export-ring-call requires --ring-certificate")
    doc = json.loads(args.trace.read_bytes())
    trust = json.loads(args.trusted.read_bytes())
    if doc["protocol"] != trust["protocol"] or doc["verifier_digest"] != bytes(trust["verifier_digest"]).hex():
        raise ValueError("trace does not match the selected trusted verifier")
    names = {"experimental-binary-checkpoint-terminal64-shared-v1": "NativeBitOpeningVerifier",
             "experimental-binary-checkpoint-terminal64-shared-fold4-experiment": "NativeBitOpeningVerifierFour"}
    name = names[trust["protocol"]]
    certificate = b""
    if args.ring_certificate:
        name = name.replace("NativeBit", "NativeCertifiedBit")
        certificate = bytes.fromhex(doc["shared_bit_batch"]["ring_switch"]["initial_fold"]["tail"]["closing"]["ring_certificate"])
    # The Rust exporter reads this root from the independently digest-checked
    # verifier key before replaying the proof.
    key = bytes.fromhex(trust["identity"] + doc["trusted_wiring_root"])
    if len(key) != 64:
        raise ValueError("invalid constructor key")
    if bytes.fromhex(doc["statement"])[32:] != b"\x40":
        raise ValueError("expected a 64-client trace")
    subprocess.run([args.forge, "build", "--quiet", "--root", str(CRATE), "--use", args.solc], check=True)
    if args.arithmetic_only:
        for fork, limit in [("osaka", TX_LIMIT), ("prague", 150_000_000)]:
            with local_chain(args.anvil, fork, max(60_000_000,limit)) as (url,account):
                price_arithmetic(url, {"from":account,"gas":hex(limit)}, key, doc, fork)
        return
    if args.bus_only:
        with local_chain(args.anvil, "osaka", 60_000_000) as (url, account):
            price_bus(url, {"from": account, "gas": hex(TX_LIMIT)}, key, doc)
        return
    artifact = json.loads((CRATE / f"out/NativeBitOpeningVerifier.sol/{name}.json").read_bytes())
    (selector,) = artifact["methodIdentifiers"].values()
    body, mutation, expected = encode(doc, bytes.fromhex(selector), certificate)
    for fork, limit in [("osaka", TX_LIMIT), ("prague", 150_000_000)]:
        with local_chain(args.anvil, fork, max(60_000_000, limit)) as (url, account):
            tx = {"from": account, "gas": hex(limit)}
            address = send(url, {**tx, "data": artifact["bytecode"]["object"] + key.hex()})["contractAddress"]
            call = {**tx, "to": address, "data": "0x" + body.hex()}
            receipt = send(url, call, require_success=False)
            gas = int(receipt["gasUsed"], 16)
            if fork == "osaka" and gas == limit and int(receipt["status"], 16) == 0:
                print(f"Osaka bit claims through closed WHIR opening exhausted {limit:,} gas")
                continue
            result = rpc(url, "eth_call", [call, "latest"])
            if int(receipt["status"], 16) != 1 or result != "0x" + expected.hex():
                raise ValueError(f"{fork} closing weights or final value differ from verified Rust trace")
            for at in (0, 32):
                wrong_key = bytearray(key)
                wrong_key[at] ^= 1
                other = send(url, {**tx, "data": artifact["bytecode"]["object"] + wrong_key.hex()})["contractAddress"]
                try:
                    rpc(url, "eth_call", [{**call, "to": other}, "latest"])
                except RpcError as exc:
                    if exc.args[0].get("data") != rpc(url, "web3_sha3", ["0x" + b"WrongEndpoint()".hex()])[:10]:
                        raise
                else:
                    raise ValueError("accepted the opening under a different authority or wiring root")
            changed = bytearray(body)
            changed[mutation] ^= 1
            try:
                rpc(url, "eth_call", [{**call, "data": "0x" + changed.hex()}, "latest"])
            except RpcError as exc:
                error = b"InvalidRingCertificate()" if certificate else b"WrongIdentity()"
                if exc.args[0].get("data") != rpc(url, "web3_sha3", ["0x" + error.hex()])[:10]:
                    raise
            else:
                raise ValueError("accepted a mutated final sumcheck coefficient")
            print(f"{fork} bit claims through closed WHIR opening: {gas:,} gas; {len(body):,} calldata bytes. "
                  "Rust ordinary weight, ring weight and final value match; closing mutation rejected.")
            price_ring(url, tx, key, doc, certificate, args.anvil, args.export_ring_call)
            if args.keccak_boundary:
                price_keccak_boundary(url, tx, key[:32], doc)
            break


if __name__ == "__main__":
    main()
