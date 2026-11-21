"""Compile the checked verifier's wire/challenge schedule for one terminal geometry."""

import argparse
import json
import re
from itertools import groupby
from pathlib import Path
if __package__:
    from .execution import compile_tables
else:
    from execution import compile_tables


BENCHMARK_PROGRAM = "d3b8643b2ab18eaaf550327bd359080272c9d893615939039134780d419621a5"
MASKED_PROGRAM = "7158a6b4e17788f1b6a6fef2f16b29ec914155515fa030d55de9531b4d1c5507"


def artifact_directory(program, rate):
    if program == MASKED_PROGRAM and rate == 5:
        return "out-binary-masked"
    if program == BENCHMARK_PROGRAM and rate in (4, 5):
        return "out-binary-compact" if rate == 5 else "out"
    raise ValueError("unsupported terminal program and rate")


def basis_geometry(points, samples, stack_log):
    # Resolve coordinates of the trusted native layout to transcript operands at compile time.
    # Ambiguous samples cannot be used to generate verifier code.
    operands = {0: 0, 1: 1}
    for step, _, value in samples:
        if value in operands:
            raise ValueError("ambiguous challenge in layout trace")
        operands[value] = step + 2
    columns = []
    selectors = {1}
    groups = {}
    for kind, start, coords in points:
        if kind == "ood" and kind in groups:
            continue
        width = len(coords)
        assert width <= stack_log and start % (1 << width) == 0
        selector = (1 << (stack_log - width)) + (start >> width)
        assert selector < 2 << (stack_log - width)
        selectors.add(selector)
        prefix = tuple(operands[c] for c in coords)
        if kind == "column":
            columns.append((prefix, selector))
        else:
            assert kind not in groups
            groups[kind] = (prefix, selector)
    assert len(groups["ood"][0]) == stack_log
    columns.append(groups["ood"])
    encode = lambda xs: b"".join(x.to_bytes(2, "big") for x in xs)
    # The opening polynomial is evaluated by Horner in reverse native claim order.
    program = bytearray()
    for prefix, group in groupby(reversed(columns), lambda item: item[0]):
        slots = [slot for _, slot in group]
        program.extend(bytes([len(prefix), len(slots)]) + encode(prefix) + encode(slots))
    parents = set()
    for selector in selectors:
        while selector > 1:
            selector >>= 1
            parents.add(selector)
    runs = bytearray()
    for width, nodes in groupby(sorted(parents), int.bit_length):
        for _, consecutive in groupby(enumerate(nodes), lambda item: item[1] - item[0]):
            block = [n for _, n in consecutive]
            runs.extend(bytes([stack_log - width]) + encode([block[0], block[-1] + 1]))
    ring_prefix, ring_slot = groups["ring"]
    return dict(basis_program=program.hex(), ring_point=encode(ring_prefix).hex(), ring_slot=ring_slot,
                selector_program=runs.hex(), selectors=(max(selectors) | 1) + 1)


def profile(trace, bundle):
    point = int.from_bytes(bundle[33:41], "little")
    vm = bundle[41 + 16 * point :]
    scalars = int.from_bytes(vm[:4], "little")
    stream = vm[4 : 4 + 16 * scalars]
    phases = []
    tape = bytearray()
    consumed = pending = 0
    ground = False
    samples = []
    saved = {}
    target_ranges = []
    basis_points = []
    for line in trace.splitlines():
        if not line.startswith("PROFILE "):
            continue
        _, kind, body = line.split(" ", 2)
        if kind == "deferred":
            saved["deferred"] = body
        elif kind == "basis_point":
            role, start, coordinates = body.split(" ", 2)
            basis_points.append((role, int(start), json.loads(coordinates)))
        elif kind == "raw_target":
            start, count = map(int, body.split())
            if target_ranges and sum(target_ranges[-1]) == start:
                target_ranges[-1][1] += count
            else:
                target_ranges.append([start, count])
        elif kind == "ood_target":
            # The first OOD claim is batched into the stack. Later OOD claims are internal to WHIR.
            saved.setdefault(kind, int(body))
        elif kind in ("slice_target", "output_target"):
            saved[kind] = int(body)
        elif kind in ("public_target", "map_target"):
            saved[kind] = (len(samples), int(body))
        elif kind in ("target", "basis"):
            a, b = map(int, body.split())
            saved[kind] = a | b << 64
        elif kind == "init":
            iv, public = map(json.loads, re.findall(r"\[[^]]+\]", body))
            saved.update(iv=bytes(iv).hex(), public=bytes(public).hex())
        elif kind == "folds":
            phases.append({"folds": int(body), "start_sample": len(samples)})
        elif kind == "query":
            phases[-1]["depth"], phases[-1]["queries"] = map(int, body.split())
            phases[-1]["query_sample"] = len(samples)
        elif kind == "open":
            raw, positions = map(json.loads, re.findall(r"\[[^]]+\]", body))
            root = bytes(raw)
            cap = stream.index(root)
            assert cap % 16 == 0 and stream.find(root, cap + 1) < 0
            phase = phases[-1]
            phase.update(cap=cap // 16, positions=positions)
        elif kind in ("grind", "sample"):
            offset, *args = map(int, body.split())
            assert consumed <= offset <= scalars
            while consumed < offset:
                assert not ground
                if pending == 4:
                    tape.append(4)
                    pending = 0
                pending += 1
                consumed += 1
            if kind == "grind":
                (bits,) = args
                assert not ground and 1 <= bits <= 31
                if pending == 4:
                    tape.append(4)
                    pending = 0
                tape.append((bits << 3) + pending + 1)
                consumed += 1
                pending = 0
                ground = True
            else:
                if not ground:
                    tape.append(pending)
                    pending = 0
                ground = False
                samples.append((len(tape) - 1, offset, args[0] | (args[1] << 64)))
    assert not ground and consumed == scalars and pending == 0
    if basis_points:
        saved.update(basis_geometry(basis_points, samples, 24))
    if target_ranges:
        for k in ("public_target", "map_target"):
            index, offset = saved[k]
            assert samples[index][1] == offset
            saved[k] = samples[index][0]
            if k == "map_target":
                assert [x[0] for x in samples[index:index + 17]] == list(range(saved[k], saved[k] + 17))
        saved["raw_target"] = b"".join(
            n.to_bytes(2, "big") for span in target_ranges for n in span
        ).hex()
    for phase in phases:
        start = phase["start_sample"]
        fold_samples = samples[start : start + 2 * phase["folds"]]
        phase["fold_samples"] = [s[0] for s in fold_samples]
        phase["after_folds"] = fold_samples[-1][1]
        q = phase["query_sample"]
        depth, count = phase["depth"], phase["queries"]
        per = 128 // depth
        count_samples = (count + per - 1) // per
        first = samples[q][0]
        assert [s[0] for s in samples[q : q + count_samples]] == list(range(first, first + count_samples))
        ids = [(samples[q + i // per][2] >> (i % per * depth)) & ((1 << depth) - 1) for i in range(count)]
        assert ids == phase["positions"]
        phase["query_hash"] = first
    assert phases[0]["cap"] == 8
    for a, b in zip(phases, phases[1:]):
        assert a["after_folds"] == b["cap"]
    header = [int.from_bytes(stream[16 * i : 16 * i + 16], "little") for i in range(8)]
    if "PROFILE cpu_tables " in trace:
        saved["tables"] = compile_tables(trace, samples, [(n - 1).bit_length() for n in header[1:-1]])
    return saved, tape, phases, header, scalars, point


def source(trace, bundle):
    saved, tape, phases, h, scalars, point = profile(trace, bundle)
    artifact_directory(saved["iv"], h[-1])
    assert h[0] == 20 and len(phases) == 5
    initial = 6 if h[-1] == 4 else 4
    assert [p["folds"] for p in phases] == [initial, 4, 4, 4, 4]
    heights = [(x - 1).bit_length() for x in h[1:-1]]
    count = bundle[32]
    if saved["iv"] == MASKED_PROGRAM:
        assert (count, point, heights) == (2, 25, [17, 18, 16, 17, 14, 14])
    else:
        assert (count, point, heights) == (64, 23, [17, 18, 16, 17, 15, 14])
    lines = [
        "// SPDX-License-Identifier: MIT",
        "pragma solidity ^0.8.28;",
        "",
        "// Generated from the pinned Rust verifier. The schedule contains operation sizes and offsets only.",
        "library BinaryTerminalProfile {",
        f"    bytes32 internal constant PROGRAM = 0x{saved['iv']};",
        f"    uint8 internal constant COUNT = {count};",
        f"    uint8 internal constant POINT_LOG = {point};",
        f"    bytes6 internal constant TABLE_HEIGHTS = 0x{bytes(heights).hex()};",
        f"    uint256 internal constant RATE_LOG = {h[-1]};",
        f"    uint256 internal constant FIRST_FOLD = {initial};",
        f"    uint256 internal constant TAIL = {24 - initial - 16};",
        f"    uint256 internal constant SCALARS = {scalars};",
        f"    uint256 internal constant OOD_VALUE = {saved['ood_target']};",
        f"    uint256 internal constant PUBLIC_CHALLENGE = {saved['public_target']};",
        f"    uint256 internal constant OUTPUT_VALUE = {saved['output_target']};",
        f"    uint256 internal constant SLICES = {saved['slice_target']};",
        f"    uint256 internal constant RING_CHALLENGES = {saved['map_target']};",
        f'    bytes internal constant TARGET_RANGES = hex"{saved["raw_target"]}";',
        f'    bytes internal constant BASIS_GROUPS = hex"{saved["basis_program"]}";',
        f'    bytes internal constant BASIS_PARENTS = hex"{saved["selector_program"]}";',
        f'    bytes internal constant RING_POINT = hex"{saved["ring_point"]}";',
        f"    uint256 internal constant RING_SELECTOR = {saved['ring_slot']};",
        f"    uint256 internal constant SELECTORS = {saved['selectors']};",
        *saved["tables"],
        f'    bytes internal constant HASH_STEPS =\n        hex"{tape.hex()}";',
        "",
        "    // Cap scalar offset, first query hash, Merkle depth and number of draws.",
        "    function phase(uint256 i) internal pure returns (uint256, uint256, uint256, uint256) {",
    ]
    for i, p in enumerate(phases):
        lines.append(
            f"        if (i == {i}) return ({p['cap']}, {p['query_hash']}, {p['depth']}, {p['queries']});"
        )
    lines += [
        "        revert();",
        "    }",
        "",
        "    // First alpha hash and scalar position immediately after the phase folds.",
        "    function foldPosition(uint256 i) internal pure returns (uint256, uint256) {",
    ]
    for i, phase in enumerate(phases):
        first = phase["fold_samples"][0]
        assert phase["fold_samples"] == [first + 3 * j + k for j in range(phase["folds"]) for k in (0, 1)]
        lines.append(f"        if (i == {i}) return ({first}, {phase['after_folds']});")
    lines.extend(["        revert();", "    }", "}", ""])
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    print(source(args.trace.read_text(), args.bundle.read_bytes()), end="")
