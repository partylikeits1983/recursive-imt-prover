"""Replay every authenticated native WHIR Merkle opening on local Osaka, one opening per call."""

import argparse
from collections import Counter
from contextlib import contextmanager
import json
from pathlib import Path
import socket
import subprocess
import time

from replay import CRATE, TX_LIMIT, RpcError, rpc, send


def word(value):
    return value.to_bytes(32, "big")


def abi_bytes(blob):
    return word(len(blob)) + blob + bytes(-len(blob) % 32)


def calldata(selector, opening):
    (width, height), = opening["dimensions"]
    cap, = opening["roots"]
    if height <= 0 or height.bit_count() != 1 or width <= 0 or len(cap) != 32:
        raise ValueError("invalid tree geometry in trace")
    records = {}
    for index, encoded in zip(opening["indices"], opening["rows"], strict=True):
        row = bytes.fromhex(encoded)
        if len(row) != 8 * width or not 0 <= index < height:
            raise ValueError("invalid row in trace")
        if records.setdefault(index, row) != row:
            raise ValueError("inconsistent duplicate query in trace")
    indices = sorted(records)
    packed = b"".join(records[i] for i in indices)
    leaves = word(len(indices)) + b"".join(map(word, indices))
    rows = word(len(packed)) + packed + bytes(-len(packed) % 32)
    siblings = b"".join(map(bytes, opening["siblings"]))
    offsets = [6 * 32, 6 * 32 + len(leaves), 6 * 32 + len(leaves) + len(rows)]
    data = (selector + bytes(cap) + word(height.bit_length() - 1) + word(8 * width)
            + b"".join(map(word, offsets)) + leaves + rows
            + word(len(siblings) // 32) + siblings)
    mutations = {"commitment": 4, "row": 4 + offsets[1] + 32}
    if siblings:
        mutations["sibling"] = 4 + offsets[2] + 32
    return data, siblings, packed, len(indices), mutations


def replay_openings(url, account, artifact, openings):
    transaction = {"from": account, "gas": hex(TX_LIMIT)}
    code = artifact["bytecode"]["object"]
    transaction["to"] = send(url, {**transaction, "data": code})["contractAddress"]
    selector = bytes.fromhex(artifact["methodIdentifiers"]["checkOpening(bytes32,uint256,uint256,uint256[],bytes,bytes32[])"])
    totals = Counter()
    for site, opening in enumerate(openings):
        data, siblings, rows, distinct, mutations = calldata(selector, opening)
        # The harness returns no data and reverts on rejection.
        call = {**transaction, "data": "0x" + data.hex()}
        if rpc(url, "eth_call", [call, "latest"]) != "0x":
            raise ValueError(f"unexpected return data at site {site}")
        receipt = send(url, call)
        for field, offset in mutations.items():
            changed = bytearray(data)
            changed[offset] ^= 1
            try:
                rpc(url, "eth_call", [{**call, "data": "0x" + changed.hex()}, "latest"])
            except RpcError as err:
                # InvalidMerkleOpening(). RPC, ABI and out-of-gas errors must fail the replay.
                if err.args[0].get("data") != "0xc8eb82c4":
                    raise
            else:
                raise ValueError(f"site {site} accepted a changed {field}")
        gas = int(receipt["gasUsed"], 16)
        totals.update(queries=len(opening["indices"]), unique_rows=distinct, siblings=len(siblings) // 32,
                      sibling_bytes=len(siblings), sibling_zero_bytes=siblings.count(0),
                      row_bytes=len(rows), row_zero_bytes=rows.count(0))
        print(f"site {site:2}: {len(opening['indices']):3} queries, {len(siblings)//32:4} siblings, {gas:9,} gas")
    # The per-site receipts include repeated ABI and transaction overhead. This distinct
    # lower bound charges only the legacy proof's raw siblings, once, in ONE transaction.
    size = totals["sibling_bytes"]
    zeros = totals["sibling_zero_bytes"]
    totals["sibling_calldata_floor"] = 21_000 + 10 * zeros + 40 * (size - zeros)
    totals["rows_and_siblings_calldata_floor"] = (
        totals["sibling_calldata_floor"] + 40 * totals["row_bytes"] - 30 * totals["row_zero_bytes"]
    )
    print(json.dumps(totals, sort_keys=True))


def replay_keccak_prefix(url, account, prefix):
    artifact = json.loads((CRATE / "out/NativeKeccak.t.sol/NativeKeccakTest.json").read_bytes())
    tx = {"from": account, "gas": hex(TX_LIMIT)}
    tx["to"] = send(url, {**tx, "data": artifact["bytecode"]["object"]})["contractAddress"]
    selector = bytes.fromhex(artifact["methodIdentifiers"]["checkPrefix(bytes)"])
    data = b"".join(bytes.fromhex(prefix[field]) for field in ("authority", "cap", "bridge", "output", "coefficients"))
    body = selector + word(32) + abi_bytes(data)
    call = {**tx, "data": "0x" + body.hex()}
    point = bytes.fromhex(prefix["output_point"])
    if len(point) != 27 * 24:
        raise ValueError("incorrect native output point length")
    encoded = b"".join(word(int.from_bytes(point[i:i+24], "little")) for i in range(0, len(point), 24))
    point_hash = bytes.fromhex(rpc(url, "web3_sha3", ["0x" + encoded.hex()])[2:])
    expected = point_hash + word(int.from_bytes(bytes.fromhex(prefix["first_sum"]), "little"))
    if rpc(url, "eth_call", [call, "latest"]) != "0x" + expected.hex():
        raise ValueError("linked Keccak challenge or first chi claim differs from native verification")
    receipt = send(url, call)
    print(f"linked Keccak output point and first chi claim: {int(receipt['gasUsed'], 16):,} gas")
    if "round_polys" in prefix:
        cubic = b"".join(bytes.fromhex(prefix[k]) for k in ("first_sum", "round_polys", "chi_values"))
        first = abi_bytes(data)
        selector = bytes.fromhex(artifact["methodIdentifiers"]["checkLayer(bytes,bytes)"])
        wire = selector + word(64) + word(64 + len(first)) + first + abi_bytes(cubic)
        receipt = send(url, {**tx, "data": "0x" + wire.hex()})
        print(f"linked Keccak first layer through cubic endpoint: {int(receipt['gasUsed'], 16):,} gas")


def replay_bit_batch(url, account, trace, root_context=None, first_openings=None, capped=None, four=False):
    artifact = json.loads((CRATE / f"out/NativeBitBatch.t.sol/NativeBitBatchTest{'Four' if four else ''}.json").read_bytes())
    tx = {"from": account, "gas": hex(TX_LIMIT)}
    tx["to"] = send(url, {**tx, "data": artifact["bytecode"]["object"]})["contractAddress"]
    selector = bytes.fromhex(artifact["methodIdentifiers"]["check(bytes,bytes,bytes)"])
    prefix, claims, proof, point = [bytes.fromhex(trace[k]) for k in ("prefix", "claims", "proof", "endpoint")]
    if len(point) != 32*24 or len(proof) != 65*24 or not claims or len(claims) % (33*24):
        raise ValueError("invalid terminal bit-batch trace")
    parts = [abi_bytes(x) for x in (prefix, claims, proof)]
    offsets = [96, 96+len(parts[0]), 96+len(parts[0])+len(parts[1])]
    body = selector + b"".join(word(n) for n in offsets) + b"".join(parts)
    mutation_offsets = [4+32+offset for offset in offsets] + [4+32+offsets[-1]+len(proof)-1]
    if root_context is not None:
        authority, main_cap, fixed_cap = root_context
        selector = bytes.fromhex(artifact["methodIdentifiers"]["checkTerminal(bytes32,bytes32,bytes32,bytes,bytes)"])
        header = bytes.fromhex(authority + main_cap + fixed_cap)
        if len(header) != 96:
            raise ValueError("invalid shared root authority or commitments")
        offsets = [160,160+len(parts[1])]
        body = selector + header + b"".join(map(word, offsets)) + parts[1] + parts[2]
        mutation_offsets = [4,36,68,4+offsets[0]+32,4+offsets[1]+32,4+offsets[1]+32+len(proof)-1]
    call = {**tx, "data": "0x" + body.hex()}
    encoded = b"".join(word(int.from_bytes(point[i:i+24], "little")) for i in range(0,len(point),24))
    expected = bytes.fromhex(rpc(url,"web3_sha3",["0x"+encoded.hex()])[2:]) + word(int.from_bytes(proof[-24:],"little"))
    if rpc(url,"eth_call",[call,"latest"]) != "0x"+expected.hex():
        raise ValueError("batch endpoint differs from Rust")
    gas = int(send(url,call)["gasUsed"],16)
    wrong_endpoint = rpc(url, "web3_sha3", ["0x" + b"WrongEndpoint()".hex()])[:10]
    for offset in mutation_offsets:
        changed = bytearray(body)
        changed[offset] ^= 1
        try:
            rpc(url, "eth_call", [{**call, "data": "0x" + changed.hex()}, "latest"])
        except RpcError as err:
            if err.args[0].get("data") != wrong_endpoint:
                raise
        else:
            raise ValueError("accepted a changed batch statement or proof")
    print(f"bit opening reduction: {len(claims)//(33*24)} readings, {len(proof)} proof bytes, {gas:,} component transaction gas")

    if "ring_switch" in trace:
        if root_context is None:
            raise ValueError("ring switch requires the native root context")
        ring = trace["ring_switch"]
        rows = bytes.fromhex(ring["rows"])
        if len(rows) != 192 * 8:
            raise ValueError("wrong ring-switch tensor size")
        signature = "checkTerminalTensor(bytes32,bytes32,bytes32,bytes,bytes,bytes)"
        selector = bytes.fromhex(artifact["methodIdentifiers"][signature])
        offsets = (192, 192 + len(parts[1]), 192 + len(parts[1]) + len(parts[2]))
        body = selector + header + b"".join(map(word, offsets)) + parts[1] + parts[2] + abi_bytes(rows)
        call = {**tx, "data": "0x" + body.hex()}
        expected_ring = expected + b"".join(word(int.from_bytes(bytes.fromhex(ring[k]), "little")) for k in ("sum", "next_challenge"))
        if rpc(url, "eth_call", [call, "latest"]) != "0x" + expected_ring.hex():
            raise ValueError("native ring-switch claim or Fiat-Shamir continuation differs from Rust")
        checked_gas = int(send(url, call)["gasUsed"], 16)
        wrong = rpc(url, "web3_sha3", ["0x" + b"WrongTensor()".hex()])[:10]
        for i in (0, 512, 1024, len(rows) - 1):
            changed = bytearray(body)
            changed[4 + offsets[2] + 32 + i] ^= 1
            try:
                rpc(url, "eth_call", [{**call, "data": "0x" + changed.hex()}, "latest"])
            except RpcError as error:
                if error.args[0].get("data") != wrong:
                    raise
            else:
                raise ValueError("accepted a changed ring-switch tensor")
        print(f"bit reduction and deferred ring-switch starting sum: {checked_gas:,} component transaction gas")
        if "initial_fold" in ring:
            return replay_initial_fold(url, tx, artifact, header, parts[1:], rows, ring, first_openings, capped, four)


def replay_initial_fold(url, tx, artifact, binding, claims_and_batch, rows, ring, first_openings, capped, four):
    fold = ring["initial_fold"]
    if len(fold["ood_answers"]) != 2 or fold["pow_bits"] != 8 or len(fold["messages"]) != 6:
        raise ValueError("unexpected terminal WHIR fold geometry")
    packed = b"".join(bytes.fromhex(a) for a in fold["ood_answers"])
    for (h0, h_inf), witness in zip(fold["messages"], fold["pow_witnesses"], strict=True):
        packed += bytes.fromhex(h0 + h_inf + witness)
    parts = [*claims_and_batch, abi_bytes(rows), abi_bytes(packed)]
    offsets, cursor = [], 7 * 32
    for part in parts:
        offsets.append(cursor)
        cursor += len(part)
    signature = "checkInitialFold(bytes32[3],bytes,bytes,bytes,bytes)"
    selector = bytes.fromhex(artifact["methodIdentifiers"][signature])
    body = selector + binding + b"".join(map(word, offsets)) + b"".join(parts)
    call = {**tx, "data": "0x" + body.hex()}
    scalar_word = lambda s: word(int.from_bytes(bytes.fromhex(s), "little"))
    point = b"".join(map(scalar_word, fold["fold_point"]))
    digest = bytes.fromhex(rpc(url, "web3_sha3", ["0x" + point.hex()])[2:])
    expected = digest + scalar_word(fold["sum"]) + scalar_word(fold["next_challenge"])
    if rpc(url, "eth_call", [call, "latest"]) != "0x" + expected.hex():
        raise ValueError("initial WHIR fold differs from the native verifier")
    gas = int(send(url, call)["gasUsed"], 16)
    print(f"bit reduction through the six initial WHIR folds: {gas:,} component transaction gas")
    # A changed witness can still pass an 8-bit grind. It must then produce a different endpoint.
    for i in (0, 24, 48, 96, len(packed) - 1):
        changed = bytearray(body)
        changed[4 + offsets[-1] + 32 + i] ^= 1
        try:
            result = rpc(url, "eth_call", [{**call, "data": "0x" + changed.hex()}, "latest"])
        except RpcError as err:
            if err.args[0].get("data") != rpc(url, "web3_sha3", ["0x" + b"InvalidProofOfWork()".hex()])[:10]:
                raise
        else:
            if result == "0x" + expected.hex():
                raise ValueError("changed WHIR fold reproduced the accepted endpoint")

    if (fold["query_pow_bits"], fold["stratified"], fold["log_query_domain"], len(fold["round_answers"])) != (15, True, 24, 2):
        raise ValueError("unexpected terminal query parameters")
    section = bytes.fromhex(fold["next_cap"] + "".join(fold["round_answers"]) + fold["query_witness"])
    signature = "checkInitialQuery(bytes32[3],bytes,bytes,bytes,bytes)"
    selector = bytes.fromhex(artifact["methodIdentifiers"][signature])
    body = selector + binding + b"".join(map(word, offsets)) + b"".join(parts[:-1]) + abi_bytes(packed + section)
    call = {**tx, "data": "0x" + body.hex()}
    indices = b"".join(map(word, fold["query_indices"]))
    query_hash = bytes.fromhex(rpc(url, "web3_sha3", ["0x" + indices.hex()])[2:])
    expected_query = digest + scalar_word(fold["sum"]) + bytes.fromhex(fold["next_cap"]) + query_hash
    result = bytes.fromhex(rpc(url, "eth_call", [call, "latest"])[2:])
    if len(result) != 160 or result[:128] != expected_query:
        raise ValueError("WHIR queries differ from authenticated native row positions")
    ring_block = result[128:]
    gas = int(send(url, call)["gasUsed"], 16)
    print(f"bit reduction through first WHIR query generation: {gas:,} component transaction gas")
    for i in (0, 32, 56, 80):
        changed = bytearray(body)
        changed[4 + offsets[-1] + 32 + len(packed) + i] ^= 1
        try:
            result = rpc(url, "eth_call", [{**call, "data": "0x" + changed.hex()}, "latest"])
        except RpcError as err:
            if err.args[0].get("data") != rpc(url, "web3_sha3", ["0x" + b"InvalidProofOfWork()".hex()])[:10]:
                raise
        else:
            if result == "0x" + (expected_query + ring_block).hex():
                raise ValueError("changed commitment, OOD answer or PoW reproduced the native queries")
    if "folded_rows" in fold:
        args = (url, tx["from"], ring_block, scalar_word(ring["sum"]), packed + section, first_openings[:2], fold["folded_rows"], four)
        encoded = replay_first_rows(*args)
        capped_args = replay_first_rows(*args, capped=capped) if capped else None
        if "tail" in fold:
            return replay_tail(url, tx["from"], encoded, fold["tail"], first_openings[2:], four, capped, capped_args)


def deploy_fixed_cap(url, account, root, cap, four):
    if len(cap) != 4096 * 32:
        raise ValueError("expected 4096 fixed subtree roots")
    tx = {"from": account, "gas": hex(TX_LIMIT)}
    page = json.loads((CRATE / "out/FixedWiringCap.sol/WiringPage.json").read_bytes())
    page_code = bytes.fromhex(page["bytecode"]["object"].removeprefix("0x"))
    pages, costs = [], []
    for pos in range(0, len(cap), 16384):
        payload = page_code + word(32) + abi_bytes(cap[pos:pos+16384])
        receipt = send(url, {**tx, "data": "0x" + payload.hex()})
        pages.append(word(int(receipt["contractAddress"], 16)))
        costs.append(int(receipt["gasUsed"], 16))
    harness = json.loads((CRATE / f"out/FixedWiringCap.t.sol/CappedFoldHarness{'Four' if four else ''}.json").read_bytes())
    creation = bytes.fromhex(harness["bytecode"]["object"].removeprefix("0x"))
    data = creation + bytes.fromhex(root) + b"".join(pages)
    for offset in (len(creation), len(creation) + 32 + 31):
        bad = bytearray(data)
        bad[offset] ^= 1
        try:
            rpc(url, "eth_call", [{**tx, "data": "0x" + bad.hex()}, "latest"])
        except RpcError as e:
            selector = rpc(url, "web3_sha3", ["0x" + b"InvalidWiringCap()".hex()])[:10]
            if e.args[0].get("data") != selector:
                raise
        else:
            raise ValueError("constructor accepted a different fixed root or page")
    receipt = send(url, {**tx, "data": "0x" + data.hex()})
    costs.append(int(receipt["gasUsed"], 16))
    print(f"fixed cap deployment: {sum(costs):,} gas in nine transactions, largest {max(costs):,}")
    return receipt["contractAddress"]


def lower_path_count(indices, levels):
    nodes = set(indices)
    siblings = 0
    for _ in range(levels):
        siblings += sum((i ^ 1) not in nodes for i in nodes)
        nodes = {i >> 1 for i in nodes}
    return siblings


def replay_first_rows(url, account, block, ring_sum, section, openings, folded, four, capped=None):
    artifact = json.loads((CRATE / f"out/NativeFold.t.sol/NativeFoldTest{'Four' if four else ''}.json").read_bytes())
    tx = {"from": account, "gas": hex(TX_LIMIT)}
    tx["to"] = capped or send(url, {**tx, "data": artifact["bytecode"]["object"]})["contractAddress"]
    sig = "checkFirstRows(bytes32[2],bytes32,uint192,bytes,(bytes,bytes,bytes32[],bytes32[]))"
    selector = bytes.fromhex(artifact["methodIdentifiers"][sig])
    rows, paths, caps = [], [], b""
    for i, op in enumerate(openings):
        _, siblings, packed, _, _ = calldata(b"", op)
        if capped and i == 1:
            total = len(siblings)
            siblings = siblings[:32 * lower_path_count(op["indices"], 12)]
            print(f"fixed Merkle opening omits {total-len(siblings):,} bytes from {total:,} sibling bytes")
        rows.append(abi_bytes(packed))
        paths.append(word(len(siblings)//32) + siblings)
        caps += bytes(op["roots"][0])
    parts = rows + paths
    cursor, offsets = 128, []
    for part in parts:
        offsets.append(cursor)
        cursor += len(part)
    encoded = abi_bytes(section)
    opening_offset = 192 + len(encoded)
    body = selector + caps + block + ring_sum + word(192) + word(opening_offset) + encoded
    body += b"".join(map(word, offsets)) + b"".join(parts)
    call = {**tx, "data": "0x" + body.hex()}
    expected = b"".join(word(int.from_bytes(bytes.fromhex(v), "little")) for v in folded)
    result = rpc(url, "web3_sha3", ["0x" + expected.hex()])
    if rpc(url, "eth_call", [call, "latest"]) != result:
        raise ValueError("authenticated first-row folds differ from Rust")
    gas = int(send(url, call)["gasUsed"], 16)
    for offset in [4, 36] + [4 + opening_offset + start + 32 for start in offsets]:
        changed = bytearray(body)
        changed[offset] ^= 1
        try:
            rpc(url, "eth_call", [{**call, "data": "0x" + changed.hex()}, "latest"])
        except RpcError:
            continue
        raise ValueError("accepted a changed cap, row or sibling")
    kind = " with fixed cap pages" if capped else ""
    print(f"WHIR from verified ring state through authenticated first-row folds{kind}: {gas:,} component transaction gas")
    return body[4:]


def replay_tail(url, account, first_args, tail, sites, four, capped, capped_args):
    artifact = json.loads((CRATE / f"out/NativeWhirRounds.t.sol/NativeWhirRoundsHarness{'Four' if four else ''}.json").read_bytes())
    tx = {"from": account, "gas": hex(TX_LIMIT)}
    tx["to"] = send(url, {**tx, "data": artifact["bytecode"]["object"]})["contractAddress"]
    methods = artifact["methodIdentifiers"]

    def query(sig, args):
        data = bytes.fromhex(methods[sig]) + args
        call = {**tx, "data": "0x" + data.hex()}
        result = bytes.fromhex(rpc(url, "eth_call", [call, "latest"])[2:])
        return result, call

    def get_bytes(encoded):
        start = int.from_bytes(encoded[:32], "big")
        length = int.from_bytes(encoded[start:start+32], "big")
        if start + 32 + length > len(encoded):
            raise ValueError("truncated Solidity carry")
        return encoded[start+32:start+32+length]

    def digest(raw):
        return bytes.fromhex(rpc(url, "web3_sha3", ["0x" + raw.hex()])[2:])

    def scalars(items):
        return b"".join(word(int.from_bytes(bytes.fromhex(x), "little")) for x in items)

    signature = "fromRing(bytes32[2],bytes32,uint192,bytes,(bytes,bytes,bytes32[],bytes32[]))"
    carry = get_bytes(query(signature, first_args)[0])
    records = []
    for stage, (step, op) in enumerate(zip(tail["steps"], sites, strict=True)):
        if op["indices"] != step["indices"]:
            raise ValueError("native late query positions disagree")
        fold = step["fold"]
        wire = bytes.fromhex(fold["wire"] + step["next_message"] + step["next_witness"])
        _, siblings, rows, _, _ = calldata(b"", op)
        parts = [abi_bytes(wire), abi_bytes(rows), word(len(siblings)//32) + siblings]
        offsets = [96, 96 + len(parts[0]), 96 + len(parts[0]) + len(parts[1])]
        record = b"".join(map(word, offsets)) + b"".join(parts)
        records.append(record)
        head = word(stage) + word(96) + word(96 + len(abi_bytes(carry)))
        sig = "advance(uint256,bytes,(bytes,bytes,bytes32[]))"
        result, call = query(sig, head + abi_bytes(carry) + record)
        indices = step["indices"] + [0] * (71-len(step["indices"]))
        expected = scalars([step["alpha"], fold["sum"]]) + digest(scalars(fold["point"]))
        expected += digest(b"".join(map(word,indices))) + digest(scalars(step["folded_rows"]))
        if result[32:192] != expected:
            raise ValueError(f"WHIR fold or authenticated query values differ at stage {stage}")
        carry = get_bytes(result)
        gas = int(send(url, call)["gasUsed"], 16)
        for offset in [offsets[0]+32+x for x in (0,len(bytes.fromhex(fold["wire"])),len(wire)-1)] + [offsets[1]+32, offsets[2]+32]:
            changed = bytearray(record)
            changed[offset] ^= 1
            call_bytes = bytes.fromhex(call["data"][2:])
            bad = call_bytes[:-len(record)] + changed
            try:
                got = rpc(url, "eth_call", [{**call,"data":"0x"+bad.hex()},"latest"])
            except RpcError:
                continue
            if got == "0x" + result.hex():
                raise ValueError(f"altered WHIR round {stage} reproduced its endpoint")
        print(f"WHIR continuation {stage+1}: {len(step['indices'])} authenticated rows, {gas:,} component transaction gas")
    wire = bytes.fromhex(tail["final_fold"]["wire"])
    parts = abi_bytes(carry), abi_bytes(wire)
    args = word(64) + word(64 + len(parts[0])) + b"".join(parts)
    result, call = query("finish(bytes,bytes)", args)
    expected = scalars([tail["final_fold"]["sum"]]) + digest(scalars(tail["final_fold"]["point"]))
    if result != expected:
        raise ValueError("final WHIR transcript or sum differs")
    gas = int(send(url, call)["gasUsed"], 16)
    print(f"WHIR closing sumcheck transcript: {gas:,} component transaction gas")
    witnesses = abi_records(records)
    signature = "allFolds(bytes32[2],bytes32,uint192,bytes,(bytes,bytes,bytes32[],bytes32[]),(bytes,bytes,bytes32[])[],bytes)"
    selector = bytes.fromhex(methods[signature])
    def combined(initial):
        # The two original dynamic fields move two ABI words forward.
        offsets = [int.from_bytes(initial[i:i+32], "big") + 64 for i in (128, 160)]
        later = len(initial) + 64
        header = initial[:128] + b"".join(map(word, offsets + [later, later+len(witnesses)]))
        return selector + header + initial[192:] + witnesses + abi_bytes(wire)

    uncapped = None
    for label, address, initial in [("both Merkle paths", tx["to"], first_args), ("fixed cap pages", capped, capped_args)]:
        if address is None:
            continue
        body = combined(initial)
        call = {**tx, "to": address, "data": "0x" + body.hex()}
        receipt = send(url, call, require_success=False)
        gas = int(receipt["gasUsed"], 16)
        if int(receipt["status"], 16) == 1:
            if rpc(url, "eth_call", [call, "latest"]) != "0x" + expected.hex():
                raise ValueError("combined WHIR transcript differs from native verification")
            print(f"all WHIR folds from ring state with {label} in one Osaka transaction: {gas:,} gas, {len(body):,} calldata bytes")
        elif gas == TX_LIMIT:
            print(f"all WHIR folds from ring state with {label} exhausted the {TX_LIMIT:,} Osaka transaction allowance")
            if address == tx["to"]:
                uncapped = artifact["bytecode"]["object"], body, expected
        else:
            raise ValueError(f"combined WHIR fold call failed after {gas:,} gas")
    return uncapped


def abi_records(records):
    pointers = []
    cursor = 32 * len(records)
    for record in records:
        pointers.append(word(cursor))
        cursor += len(record)
    return word(len(records)) + b"".join(pointers + records)



def profile_cubics(url, account, layers):
    if len(layers) != 24:
        raise ValueError("expected all 24 Keccak rounds of a terminal proof")
    artifact = json.loads((CRATE / "out/NativeField.t.sol/NativeFieldTest.json").read_bytes())
    tx = {"from": account, "gas": hex(TX_LIMIT)}
    tx["to"] = send(url, {**tx, "data": artifact["bytecode"]["object"]})["contractAddress"]
    selector = bytes.fromhex(artifact["methodIdentifiers"]["profileCubicRounds(bytes)"])
    metered = []
    for encoded in layers:
        wire = selector + word(32) + abi_bytes(bytes.fromhex(encoded))
        call = {**tx, "data": "0x" + wire.hex()}
        metered.append(int(rpc(url, "eth_call", [call, "latest"]), 16))
    print(f"552 cubic evaluations with Rust challenges, field arithmetic and operand decoding: {sum(metered):,} execution gas")


def replay_round_chain(url, account, doc):
    layers = doc["chi_layers"]
    if len(layers) != 24 or len(doc["chi_cubics"]) != 24:
        raise ValueError("expected complete root Keccak transcript")
    artifact = json.loads((CRATE / "out/NativeKeccakRounds.t.sol/NativeKeccakRoundsTest.json").read_bytes())
    methods = artifact["methodIdentifiers"]
    first = bytes.fromhex(methods["reduceFirst(bytes,bytes)"])
    step = bytes.fromhex(next(v for k, v in methods.items() if k.startswith("reduceNext(")))
    tx = {"from": account, "gas": hex(TX_LIMIT)}
    tx["to"] = send(url, {**tx, "data": artifact["bytecode"]["object"]})["contractAddress"]
    header = doc["linked_prefix"]
    prefix = bytes.fromhex("".join(header[k] for k in ("authority", "cap", "bridge", "output", "coefficients")))
    state = None
    receipts = []
    for index, (layer, encoded) in enumerate(zip(layers, doc["chi_cubics"], strict=True)):
        wire = bytes.fromhex(layer["wire"])
        cubic = bytes.fromhex(encoded)
        if len(wire) != 120 * 24 or len(cubic) != 94 * 24:
            raise ValueError("invalid packed layer encoding")
        if index == 0:
            if wire[:47*24] != bytes.fromhex(header["coefficients"]):
                raise ValueError("inconsistent first coefficients")
            body = first + word(64) + word(64 + len(abi_bytes(prefix))) + abi_bytes(prefix) + abi_bytes(wire[47*24:])
        else:
            body = step + state + word(len(state) + 32) + abi_bytes(wire)
        call = {**tx, "data": "0x" + body.hex()}
        state = bytes.fromhex(rpc(url, "eth_call", [call, "latest"])[2:])
        point = [cubic[(4+4*j)*24:(5+4*j)*24] for j in range(23)]
        expected = b"".join(word(int.from_bytes(x, "little"))
                            for x in [bytes.fromhex(layer["beta"]), bytes.fromhex(layer["value"]), *point])
        if len(state) != 28*32 or state[2*32:-32] != expected or state[-32:] != word(23-index):
            raise ValueError(f"round {23-index} differs from the native Fiat-Shamir transcript")
        receipts.append(int(send(url, call)["gasUsed"],16))
        if index in (0, 10, 23):
            bad = bytearray(body)
            # Last 8 bytes can be ABI padding; change a high byte of the actual third chi value.
            payload_len = len(wire) - (47*24 if index == 0 else 0)
            padding = -payload_len % 32
            bad[-padding-1] ^= 1
            try:
                rpc(url, "eth_call", [{**call, "data": "0x" + bad.hex()}, "latest"])
            except RpcError as error:
                if error.args[0].get("data") != rpc(url, "web3_sha3", ["0x" + b"InvalidChiEndpoint()".hex()])[:10]:
                    raise
            else:
                raise ValueError(f"accepted altered round {23-index}")
    print(f"all 24 linked native Keccak layers through final input claim: {sum(receipts):,} gas across 24 component transactions, first={receipts[0]:,}, last={receipts[-1]:,}")


@contextmanager
def local_chain(anvil, fork, gas_limit=60_000_000):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    node = subprocess.Popen([anvil, "--host", "127.0.0.1", "--port", str(port), "--hardfork", fork, "--gas-limit", str(gas_limit), "--silent"])
    try:
        for _ in range(100):
            try:
                accounts = rpc(url, "eth_accounts", [])
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise TimeoutError("Local Anvil startup")
        yield url, accounts[0]
    finally:
        node.terminate()
        try:
            node.wait(timeout=10)
        except subprocess.TimeoutExpired:
            node.kill()
            node.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path, help="output of the root-opening-trace example")
    parser.add_argument("--bit-batch", type=Path, help="verified shared-opening bit-batch trace")
    parser.add_argument("--fixed-cap", type=Path, help="depth-12 cap exported from the terminal setup")
    parser.add_argument("--forge", default="forge")
    parser.add_argument("--anvil", default="anvil")
    parser.add_argument("--profile-above-cap", action="store_true", help="price an Osaka out-of-gas fold call on a fresh Prague chain")
    parser.add_argument("--solc", default="0.8.28")
    args = parser.parse_args()
    doc = json.loads(args.trace.read_bytes())
    if not doc["openings"] or bytes.fromhex(doc["statement"])[32:] != b"\x40":
        raise ValueError("expected a traced 64-leaf native root")
    subprocess.run([args.forge, "build", "--quiet", "--root", str(CRATE), "--use", args.solc], check=True)
    artifact = json.loads((CRATE / "out/NativeMerkle.t.sol/NativeMerkleTest.json").read_bytes())
    capped_call = None
    with local_chain(args.anvil, "osaka") as (url, account):
        replay_openings(url, account, artifact, doc["openings"])
        if doc.get("shared_bit_batch"):
            first, second = doc["openings"][:2]
            main = bytes(first["roots"][0]).hex()
            fixed = bytes(second["roots"][0]).hex()
            if doc["linked_prefix"]["cap"] != main:
                raise ValueError("arithmetic and shared opening disagree on the witness cap")
            ring = doc["shared_bit_batch"].get("ring_switch", {})
            if "initial_fold" in ring:
                fold = ring["initial_fold"]
                if any(site["indices"] != fold["query_indices"] for site in (first, second)):
                    raise ValueError("first transcript queries differ from the two authenticated openings")
                if bytes(doc["openings"][2]["roots"][0]).hex() != fold["next_cap"]:
                    raise ValueError("first fold commitment differs from the next authenticated opening")
            four = doc.get("protocol") == "experimental-binary-checkpoint-terminal64-shared-fold4-experiment"
            capped = deploy_fixed_cap(url, account, fixed, args.fixed_cap.read_bytes(), four) if args.fixed_cap else None
            capped_call = replay_bit_batch(url, account, doc["shared_bit_batch"], (doc["linked_prefix"]["authority"], main, fixed), doc["openings"], capped, four)
        if args.bit_batch:
            replay_bit_batch(url, account, json.loads(args.bit_batch.read_bytes()))
        if doc.get("linked_prefix"):
            replay_keccak_prefix(url, account, doc["linked_prefix"])
        if doc.get("chi_layers"):
            replay_round_chain(url, account, doc)
        if doc.get("chi_cubics"):
            profile_cubics(url, account, doc["chi_cubics"])
    if args.profile_above_cap and capped_call is not None:
        code, body, expected = capped_call
        with local_chain(args.anvil, "prague") as (url, account):
            tx = {"from": account, "gas": hex(60_000_000)}
            contract = send(url, {**tx, "data": code})["contractAddress"]
            call = {**tx, "to": contract, "data": "0x" + body.hex()}
            if rpc(url, "eth_call", [call, "latest"]) != "0x" + expected.hex():
                raise ValueError("combined Prague fold call differs from the checked native endpoint")
            gas = int(send(url, call)["gasUsed"], 16)
            print(f"all WHIR folds from ring state in one diagnostic Prague transaction: {gas:,} gas, {len(body):,} calldata bytes")



if __name__ == "__main__":
    main()
