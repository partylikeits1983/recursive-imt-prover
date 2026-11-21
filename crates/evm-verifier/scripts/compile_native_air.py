"""Lower the trusted shared terminal AIR and bus closing equation to field operations."""

import argparse
from functools import cache
from itertools import groupby
import json
from pathlib import Path


def base_mul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = (a << 1) ^ (0x1000000000000001B if a >> 63 else 0)
        b >>= 1
    return result


class Program:
    def __init__(self, inputs):
        self.inputs = inputs
        self.nodes = []
        self.memo = {}
        self.constants = {0: 0, 1: 1}

    def node(self, op, a, b=0):
        key = (op, a, b)
        if key not in self.memo:
            self.memo[key] = self.inputs + len(self.nodes)
            self.nodes.append(key)
        return self.memo[key]

    def const(self, value):
        if value in (0, 1):
            return value
        pos = self.node("constant", value)
        self.constants[pos] = value
        return pos

    def add(self, a, b):
        if a == b:
            return 0
        if not a or not b:
            return a or b
        if a in self.constants and b in self.constants:
            return self.const(self.constants[a] ^ self.constants[b])
        return self.node("add", min(a, b), max(a, b))

    def mul(self, a, b):
        if not a or not b:
            return 0
        if a == 1 or b == 1:
            return b if a == 1 else a
        if a in self.constants and b in self.constants:
            return self.const(base_mul(self.constants[a], self.constants[b]))
        if a == b:
            return self.node("square", a)
        # Every Boolean constraint v*(v+1) is a square and an XOR in characteristic two.
        for value, other in ((a, b), (b, a)):
            if other >= self.inputs and self.nodes[other - self.inputs] == ("add", 1, value):
                return self.add(self.node("square", value), value)
        if a in self.constants:
            return self.node("scale", b, a)
        if b in self.constants:
            return self.node("scale", a, b)
        return self.node("mul", min(a, b), max(a, b))

    def product(self, items):
        value = 1
        for x in items:
            value = self.mul(value, x)
        return value

    def total(self, items):
        value = 0
        for x in items:
            value = self.add(value, x)
        return value

    def compile(self, output):
        # Eliminate unused nodes, then pack public constants ahead of operations.
        needed = set()
        pending = [output]
        while pending:
            i = pending.pop()
            if i < self.inputs or i in needed:
                continue
            needed.add(i)
            op, a, b = self.nodes[i - self.inputs]
            if op != "constant":
                pending.extend((a, b))
        remap = {i: i for i in range(self.inputs)}
        constants = bytearray()
        ops = bytearray()
        tags = {"add": 1, "mul": 2, "square": 3, "scale": 4}
        for i in sorted(needed):
            op, a, _ = self.nodes[i - self.inputs]
            if op == "constant":
                remap[i] = len(remap)
                constants.extend(a.to_bytes(8, "big"))
        for i in sorted(needed):
            op, a, b = self.nodes[i - self.inputs]
            if op != "constant":
                remap[i] = len(remap)
                tag = 5 if op == "mul" and a == 2 else tags[op]
                right = remap[b]
                if op == "scale":
                    factor = self.constants[b]
                    if factor.bit_count() == 1 and factor.bit_length() <= 61:
                        tag, right = 6, factor.bit_length() - 1
                    elif (factor & (factor + 1)) == 0 and factor.bit_length().bit_count() == 1:
                        tag, right = 7, factor.bit_length().bit_length() - 1
                ops.extend(bytes([tag]) + remap[a].to_bytes(2, "big") + right.to_bytes(2, "big"))
        return len(constants) // 8, len(ops) // 5, remap[output], bytes(constants + ops)


def decoded_rows(g, regions, source, basis):
    rows = []
    off = 0
    for region in regions:
        width = region["committed"]
        raw = source[off : off + width]
        if len(raw) != width:
            raise ValueError("incomplete committed row")
        off += width
        columns = []
        start = 0
        stride = region["digit_bits"]
        for bits in region["widths"]:
            count = (bits + stride - 1) // stride
            v = g.total(g.mul(raw[start + i], g.const(basis[i * stride])) for i in range(count))
            columns.append(g.mul(v, g.const(region["scale"])))
            start += count
        if max(1, start) != width:
            raise ValueError("inconsistent column encoding")
        rows.append(columns)
    if off != len(source):
        raise ValueError("unused committed columns")
    return rows


def expression(g, encoded, variables):
    nodes = []
    for entry in encoded:
        ((kind, args),) = entry.items()
        if kind == "Leaf":
            if isinstance(args, str):
                v = variables[args]
            elif "Constant" in args:
                v = g.const(args["Constant"])
            else:
                var = args["Variable"]
                col = var["entry"]
                if isinstance(col, dict):
                    ((col, shift),) = col.items()
                    if shift != {"offset": 0}:
                        raise ValueError("unsupported row offset")
                v = variables[col][var["index"]]
        elif kind in ("Add", "Sub"):
            v = g.add(nodes[args["x"]], nodes[args["y"]])
        elif kind == "Neg":
            v = nodes[args["x"]]
        elif kind == "Mul":
            v = g.mul(nodes[args["x"]], nodes[args["y"]])
        else:
            raise ValueError(f"unrecognized expression node {kind}")
        nodes.append(v)
    return nodes[-1]


def fold_addresses(g, entries, coordinates):
    """Evaluate a sparse multilinear table, sharing activations across adjacent entries."""
    # Each entry is an activation times a payload. Missing addresses have value zero.
    # The final coordinate chooses between even and odd addresses.
    for coordinate in reversed(coordinates):
        parents = {}
        for parent in sorted({address >> 1 for address in entries}):
            left = entries.get(2 * parent)
            right = entries.get(2 * parent + 1)
            if left is None or right is None:
                factor, value = left if right is None else right
                selector = g.add(1, coordinate) if right is None else coordinate
                node = factor, g.mul(selector, value)
            else:
                lf, lv = left
                rf, rv = right
                if lf == rf:
                    factor = lf
                else:
                    factor, lv, rv = 1, g.mul(lf, lv), g.mul(rf, rv)
                node = factor, g.add(lv, g.mul(coordinate, g.add(lv, rv)))
            parents[parent] = node
        entries = parents
    if set(entries) != {0}:
        raise ValueError("invalid bus prefix address")
    return g.mul(*entries[0])


def compile_key(key):
    # The first 105 registers comprise the field constants 0/1, transcript
    # challenges, the two row points and the application digest bytes.
    alpha, beta, lam, offset = range(2, 6)
    fingerprint, tau, point, bus_point = range(6, 9), range(9, 28), range(28, 47), range(47, 73)
    digest = list(range(73, 105))
    g = Program(105 + 619 + 1451)
    main = decoded_rows(g, key["main"][:19], list(range(105, 105 + 615)), key["basis"])
    fixed = iter(decoded_rows(g, key["fixed"], list(range(105 + 619, g.inputs)), key["basis"]))
    # Repeated constraints contribute an affine Horner map. Squaring the map
    # doubles the number of copies, including when alpha is zero or one.
    @cache
    def repeat_weights(n):
        if n == 1:
            return alpha, 1
        power, total = repeat_weights(n // 2)
        total = g.mul(total, g.add(1, power))
        power = g.mul(power, power)
        if n & 1:
            power, total = g.mul(alpha, power), g.add(1, g.mul(alpha, total))
        return power, total

    variables = []
    sums = []
    for i, height in enumerate(key["heights"]):
        suffix = point[-height:]
        first = g.product(g.add(1, v) for v in suffix)
        last = g.product(suffix)
        periodic = []
        if key["periodic"][i]:
            cur = nxt = 0
            carry = 1
            for bit, coord in enumerate(reversed(suffix)):
                cur = g.add(cur, g.mul(coord, g.const(1 << bit)))
                nxt = g.add(nxt, g.mul(g.add(coord, carry), g.const(1 << bit)))
                carry = g.mul(carry, coord)
            periodic = [cur, nxt]
        cols = next(fixed) if key["fixed_widths"][i] else []
        if len(cols) != key["fixed_widths"][i]:
            raise ValueError("incorrect fixed row width")
        vars_ = {
            "IsFirstRow": first,
            "IsLastRow": last,
            "IsTransition": g.add(1, last),
            "Main": main[i],
            "Preprocessed": cols,
            "Public": digest + [0] + digest + [1],
            "Periodic": periodic,
        }
        variables.append(vars_)
        local = 0
        terms = (expression(g, expr, vars_) for expr in key["constraints"][i])
        for term, run in groupby(terms):
            n = sum(1 for _ in run)
            if n < 4:
                for _ in range(n):
                    local = g.add(g.mul(alpha, local), term)
            else:
                power, total = repeat_weights(n)
                local = g.add(g.mul(power, local), g.mul(total, term))
        sums.append(local)
    if next(fixed, None) is not None:
        raise ValueError("unused fixed table")
    ordinary = 0
    for local in reversed(sums):
        ordinary = g.add(g.mul(beta, ordinary), local)

    weights = [1]
    for v in fingerprint:
        weights = [term for w in weights for term in (g.mul(w, g.add(1, v)), g.mul(w, v))]
    by_height = {}
    for share in key["shares"]:
        i = share["air"]
        h = key["heights"][i]
        n = share["prefix_variables"]
        if h + n != len(bus_point):
            raise ValueError("inconsistent terminal share")
        factors = [offset, 1] + [weights[j] for j in share["domain_slots"]]
        factors.extend(
            g.mul(weights[j], expression(g, e, variables[i])) for j, e in enumerate(share["payload"])
        )
        active = expression(g, share["activation"], variables[i]) if share["activation"] is not None else 1
        entries = by_height.setdefault((h, share["pull"]), {})
        address = share["prefix_index"]
        payload = g.total(factors)
        if address in entries:
            factor, other = entries[address]
            if factor == active:
                payload = g.add(other, payload)
            else:
                payload = g.add(g.mul(factor, other), g.mul(active, payload))
                active = 1
        entries[address] = active, payload
    bus = 0
    for (h, pull), entries in by_height.items():
        v = fold_addresses(g, entries, bus_point[:len(bus_point) - h])
        eq = g.product(g.add(1, g.add(a, b)) for a, b in zip(bus_point[-h:], point[-h:]))
        term = g.product([v, eq, g.product(point[:-h]), lam if pull else 1])
        bus = g.add(bus, term)
    eq = g.product(g.add(1, g.add(a, b)) for a, b in zip(tau, point))
    return g.compile(g.add(g.mul(eq, ordinary), g.mul(lam, bus)))


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("trace", type=Path)
    cli.add_argument("out", type=Path)
    args = cli.parse_args()
    key = json.loads(args.trace.read_bytes())["arithmetic_prefix"]["key"]
    constants, operations, result, code = compile_key(key)
    args.out.write_bytes(code)
    print(f"{constants} constants, {operations} operations, result register {result}, {len(code)} bytes")
