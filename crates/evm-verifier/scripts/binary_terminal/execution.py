"""Compile the pinned VM's bus placements, instruction forms and transcript indices."""

import json


def u16(value):
    return value.to_bytes(2, "big")


def compile_tables(trace, samples, heights):
    sample = 0
    layers = bytearray()
    blocks = bytearray()
    framework = bytearray()
    prior = 0
    plan = {}

    def first(index, count):
        start = samples[index][0]
        assert [r[0] for r in samples[index:index + count]] == list(range(start, start + count))
        return start

    for line in trace.splitlines():
        if not line.startswith("PROFILE "):
            continue
        _, tag, body = line.split(" ", 2)
        if tag == "sample":
            sample += 1
        elif tag == "fingerprint":
            plan["finger"] = first(sample, 17)
        elif tag == "grand_start":
            plan["grand"], plan["depth"] = map(int, body.split())
        elif tag == "grand_layer":
            step, offset = map(int, body.split())
            assert step in (1, 2) and offset == samples[sample][1]
            a = first(sample, 1 + prior)
            y = first(sample + 1 + prior, step)
            layers.extend(bytes([step]) + u16(a) + u16(y))
            prior += step
        elif tag == "raw_target" and "memory" not in plan:
            plan["memory"], count = map(int, body.split())
            assert count == 4
            plan["slot"] = first(sample, 4)
        elif tag == "cpu_xi":
            plan["xi"] = first(sample, max(heights) + 1)
        elif tag == "cpu_tables":
            offset, rest = body.split(" ", 1)
            specs, jump = map(json.loads, rest.split(" | "))
            assert [n for _, n in specs] == [0, 0, 0, 0, 2, 0]
            plan.update(cpu=int(offset), widths=bytes(w for w, _ in specs), jump=bytes(jump))
        elif tag == "bus_framework":
            side, height, at = map(int, body.split())
            assert at % (1 << height) == 0
            if side == 0:
                framework.extend(bytes([height]) + at.to_bytes(4, "big"))
            else:
                assert side == 1
                assert bytes([height]) + at.to_bytes(4, "big") in framework
        elif tag == "bus_block":
            side, owner, height, at, rest = body.split(" ", 4)
            side, owner, height, at = map(int, (side, owner, height, at))
            assert height == heights[owner] and at % (1 << height) == 0
            terms, padding = map(json.loads, rest.split(" | "))
            nonzero = [(i, x) for i, x in enumerate(padding) if x]
            blocks.extend(bytes([side, owner]) + u16(at >> height) + bytes([len(terms), len(nonzero)]))
            for slot, scale, *indices in terms:
                assert len(indices) <= 2 and (side != 2 or slot == 0)
                args = [i + 1 for i in indices] + [0] * (2 - len(indices))
                blocks.extend(bytes([slot]) + u16(scale) + bytes(args))
            for slot, value in nonzero:
                blocks.extend(bytes([slot]) + value.to_bytes(8, "big"))
    assert prior == plan["depth"] and len(framework) == 15
    plan.update(layers=layers, blocks=blocks, framework=framework)
    out = []
    for key, value in plan.items():
        name = "BUS_" + key.upper()
        if isinstance(value, int):
            out.append(f"    uint256 internal constant {name} = {value};")
        else:
            out.append(f'    bytes internal constant {name} = hex"{value.hex()}";')
    return out
