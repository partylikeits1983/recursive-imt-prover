def aligned_parent(a, b, side):
    sibling = StackBuf(2)
    hint_witness(sibling, "sibling")
    x = side * (sibling[0] + a)
    y = side * (sibling[1] + b)
    out = StackBuf(2)
    keccak_cells([NODE_PREFIX, a + x, b + y, sibling[0] + x, sibling[1] + y], out)
    return out[0], out[1]
