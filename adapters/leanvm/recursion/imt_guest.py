# Appended to the pinned upstream child-verification and deferred-claim routines.
# The Rust driver hashes the same statements independently.
def main():
    n = hint_witness("count")
    seed = StackBuf(2)
    hint_witness(seed, "fs_seed")
    app = StackBuf(2)
    defer = HeapBuf(DEFER_STMT_CELLS)
    if n == 1:
        root0, root1 = imt_path()
        leaf0, leaf1 = imt_hash_leaf(root0, root1)
        app[0] = leaf0
        app[1] = leaf1
        for j in unroll(0, BYTECODE_VARS):
            defer[GEN ** j] = 0
        leaf_value = hint_witness("leaf_defer")
        defer[GEN ** DEFER_STMT_BC_VALUE] = leaf_value
    else:
        half = hint_witness("child_count")
        assert (half + 1) * (half + 2) * (half + 4) * (half + 8) * (half + 16) * (half + 32) == 0
        assert n == half * 2
        pair = StackBuf(4)
        hint_witness(pair, "child_digests")
        parent0, parent1 = imt_hash_pair(pair[0], pair[1], pair[2], pair[3], half)
        app[0] = parent0
        app[1] = parent1
        tabs = exponent_tables()
        child_pi = HeapBuf(4)
        fresh = HeapBuf(2 * DEFER_SIZE)
        carried = HeapBuf(2 * DEFER_STMT_CELLS)
        for i in unroll(0, 2):
            xc = GEN ** i
            cc = carried * xc ** DEFER_STMT_CELLS
            hint_witness(cc[0:DEFER_STMT_CELLS], "child_defer")
            a, b = statement_digest(seed[0], seed[1], pair[2 * i], pair[2 * i + 1], half, 0, 0, 0, cc)
            child_pi[xc * xc] = a
            child_pi[xc * xc * GEN] = b
            verify_sub(a, b, seed[0], seed[1], tabs, fresh * xc ** DEFER_SIZE)
        aggregate_claims(GEN ** 2, child_pi, fresh, carried, defer, tabs * GEN ** WIN_TAB_AT)
    p0, p1 = statement_digest(seed[0], seed[1], app[0], app[1], n, 0, 0, 0, defer)
    public = GEN ** 0
    assert public[1] == p0
    assert public[GEN] == p1
    return
