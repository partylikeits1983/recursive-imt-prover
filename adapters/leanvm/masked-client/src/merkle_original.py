# Split a lane into six low bytes and two high bytes. Checking both pieces
# prevents high bits from cancelling a neighboring digest or domain byte.
def shift_lane(w):
    bits = StackBuf(64)
    hint_decompose_bits(bits, w, 64)
    lo = 0
    for i in unroll(0, 48):
        assert bits[i] * bits[i] == bits[i]
        lo += (2 ** i) * bits[i]
    hi = 0
    for i in unroll(0, 16):
        b = bits[i + 48]
        assert b * b == b
        hi += (2 ** i) * b
    assert w == lo + 281474976710656 * hi
    return lo * 65536, hi


# Both digests start two bytes into a lane in the native 18-byte node domain.
def oracle_parent(a, b, side):
    a0, a1 = limbs(a)
    a2, a3 = limbs(b)
    c0, e0 = shift_lane(a0)
    v1, e1 = shift_lane(a1)
    v2, e2 = shift_lane(a2)
    v3, c4 = shift_lane(a3)
    c1 = v1 + e0
    c2 = v2 + e1
    c3 = v3 + e2
    sibling = StackBuf(2)
    hint_witness(sibling, "sibling")
    edges, s1 = limbs(sibling[0])
    s2, s3 = limbs(sibling[1])
    s0, s4 = shift_lane(edges)
    # A Boolean side selects which child occupies each half of the preimage.
    x0 = side * (s0 + c0)
    x1 = side * (s1 + c1)
    x2 = side * (s2 + c2)
    x3 = side * (s3 + c3)
    x4 = side * (s4 + c4)
    y = 18446744073709551616
    out = StackBuf(2)
    keccak_cells([NODE_PREFIX, c0 + x0 + y * (c1 + x1), c2 + x2 + y * (c3 + x3), c4 + x4 + s0 + x0 + y * (s1 + x1), s2 + x2 + y * (s3 + x3), s4 + x4], out, len=82)
    return out[0], out[1]
