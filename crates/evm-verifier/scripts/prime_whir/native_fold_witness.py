"""Lift every WHIR row fold of a verified four-variable native root into integer polynomial equations."""

from pathlib import Path
import json

MODULUS = (1 << 64) | 0x1B
MASK = (1 << 64) - 1
# Native cubic y^3 = y+1. Components are in increasing polynomial degree.
TERMS = (((0, 0), (1, 2), (2, 1)), ((0, 1), (1, 0), (1, 2), (2, 1), (2, 2)), ((0, 2), (1, 1), (2, 0), (2, 2)))
COUNTS = (71, 35, 26, 20, 17)
ROW_NIBBLES = 2048


def quotient(product):
    result = 0
    while product.bit_length() > 64:
        shift = product.bit_length() - 65
        product ^= MODULUS << shift
        result ^= 1 << shift
    return result, product


def expand(word, stride):
    return sum(((word >> i) & 1) << (stride * i) for i in range(64))


def parity_polynomial(packed, stride):
    return sum(((packed >> (stride * i)) & 1) << i for i in range(127))


def multiply(a, b):
    wide = [expand(x, 10) for x in a]
    other = [expand(x, 10) for x in b]
    return tuple(
        quotient(parity_polynomial(sum(wide[i] * other[j] for i, j in terms), 10))[1] for terms in TERMS
    )


def weights(draws):
    values = [(1, 0, 0)]
    for draw in draws:
        high = [multiply(v, draw) for v in values]
        values = [tuple(x ^ y for x, y in zip(v, h)) for v, h in zip(values, high)] + high
    return values


def limbs(data):
    return tuple(int.from_bytes(data[i : i + 8], "little") for i in range(0, len(data), 8))


def nibbles(n, width):
    return [(n >> (4 * i)) & 15 for i in range(width)]


def lift_row(data, column_weights, scalar_input, output):
    native_words = limbs(data)
    table = bytearray(ROW_NIBBLES)
    for j, word in enumerate(native_words):
        table[1152 + 16 * j : 1168 + 16 * j] = bytes(nibbles(word, 16))
    cells = (
        [(v, 0, 0) for v in native_words] if scalar_input else list(zip(*[iter(native_words)] * 3, strict=True))
    )
    if len(cells) != len(column_weights) or len(native_words) != 48:
        raise ValueError("Incorrect native row width")
    # Thirteen bits separate integer coefficients. Even the densest coordinate
    # gets at most 5*16*64=5120 contributions (48*64 for the scalar matrix).
    wide = [tuple(expand(x, 13) for x in cell) for cell in cells]
    for coordinate, terms in enumerate(TERMS):
        total = sum(a[i] * w[j] for a, w in zip(wide, column_weights, strict=True) for i, j in terms)
        q, c = quotient(parity_polynomial(total, 13))
        if c != output[coordinate]:
            raise ValueError("Lifted row disagrees with the independently verified native fold")
        table[1920 + 16 * coordinate : 1936 + 16 * coordinate] = bytes(nibbles(c, 16))
        table[1968 + 16 * coordinate : 1984 + 16 * coordinate] = bytes(nibbles(q, 16))
        # M(X)Q(X)+C(X), using integer polynomial arithmetic.
        rhs = expand(q, 13) * sum(1 << (13 * e) for e in (0, 1, 3, 4, 64)) + expand(c, 13)
        for k in range(128):
            diff = ((total >> (13 * k)) & 8191) - ((rhs >> (13 * k)) & 8191)
            if diff % 2 or not 0 <= diff // 2 + 3 < 4096:
                raise ValueError("Invalid integer parity certificate")
            for digit, value in enumerate(nibbles(diff // 2 + 3, 3)):
                table[(3 * coordinate + digit) * 128 + k] = value
    return table


def matrices(doc):
    if doc["protocol"] != "experimental-binary-checkpoint-terminal64-shared-fold4-midpoint-v1":
        raise ValueError("Expected the verified midpoint terminal profile")
    fold = doc["shared_bit_batch"]["ring_switch"]["initial_fold"]
    sites = doc["openings"]
    if len(sites) != 6 or sites[0]["indices"] != sites[1]["indices"]:
        raise ValueError("Incorrect native matrix commitments or positions")
    first_rows = [a + b for a, b in zip(sites[0]["rows"], sites[1]["rows"], strict=True)]
    yield fold["fold_point"], fold["query_indices"], fold["folded_rows"], sites[0]["indices"], first_rows
    for step, site in zip(fold["tail"]["steps"], sites[2:], strict=True):
        yield step["fold"]["point"], step["indices"], step["folded_rows"], site["indices"], site["rows"]


def export(trace, destination):
    doc = json.loads(Path(trace).read_bytes())
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    packed = bytearray()
    raw_rows = bytearray()
    challenges = bytearray()
    results = bytearray()
    weight_bytes = bytearray()
    for stage, (point, indices, outputs, unique, rows) in enumerate(matrices(doc)):
        if len(indices) != COUNTS[stage] or len(point) != (4 if stage else 6) or set(indices) != set(unique):
            raise ValueError("Unexpected query geometry")
        raw = {}
        for idx, row in zip(unique, rows, strict=True):
            data = bytes.fromhex(row)
            if raw.setdefault(idx, data) != data:
                raise ValueError("Conflicting duplicate authenticated row")
        draws = [limbs(bytes.fromhex(v)) for v in point]
        w = weights(draws)[:48] if stage == 0 else weights(draws)
        weight_bytes += b"".join(x.to_bytes(8, "little") for v in w for x in v)
        wide = [tuple(expand(x, 13) for x in v) for v in w]
        challenges += b"".join(bytes.fromhex(v) for v in point)
        for idx, value in zip(indices, outputs, strict=True):
            data = raw[idx]
            out = bytes.fromhex(value)
            packed += lift_row(data, wide, stage == 0, limbs(out))
            raw_rows += data
            results += out
    empty = lift_row(bytes(384), [(0, 0, 0)] * 48, True, (0, 0, 0))
    packed += empty * (256 - sum(COUNTS))
    (destination / "table.bin").write_bytes(packed)
    (destination / "rows.bin").write_bytes(raw_rows)
    (destination / "draws.bin").write_bytes(challenges)
    (destination / "values.bin").write_bytes(results)
    (destination / "weights.bin").write_bytes(weight_bytes)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    export(args.trace, args.destination)
