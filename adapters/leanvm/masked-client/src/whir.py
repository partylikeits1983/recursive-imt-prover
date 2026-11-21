# LeanVM's recursion guest reconstructs words from range-checked lookup windows.
def pcs_byte_table():
    tabs = HeapBuf(256)
    for i in unroll(0, 256):
        tabs[GEN ** i] = const(i)
    return tabs


def pcs_bytes(tabs, word):
    parts = StackBuf(8)
    hint_windows_exponent(parts, word, 0, 8, 8)
    bytes = StackBuf(8)
    rebuilt = 0
    for j in unroll(0, 8):
        index = parts[j]
        assert log(index) < 256
        bytes[j] = tabs[index]
        rebuilt += (2 ** (8 * j)) * bytes[j]
    assert rebuilt == word
    return bytes


def pcs_split(tabs, w, low: Const):
    bytes = pcs_bytes(tabs, w)
    lo = 0
    hi = 0
    for j in unroll(0, low):
        lo += (2 ** (8 * j)) * bytes[j]
    for j in unroll(low, 8):
        hi += (2 ** (8 * (j - low))) * bytes[j]
    return lo, hi


# The native byte challenger pops its 32-byte digest in reverse order.
def pcs_reverse_word(tabs, w):
    bytes = pcs_bytes(tabs, w)
    reversed = 0
    for j in unroll(0, 8):
        reversed += (2 ** (8 * (7-j))) * bytes[j]
    return reversed


def pcs_equal(a: StackBuf(3), b: StackBuf(3)):
    for j in unroll(0, 3):
        assert a[j] == b[j]


@inline
def pcs_mac(a: StackBuf(3), b: StackBuf(3), c: StackBuf(3)):
    product = times(a, b)
    result = plus(product, c)
    return result


def pcs_reduce(claim: StackBuf(3), zero: StackBuf(3), infinity: StackBuf(3), r: StackBuf(3)):
    rp = ext(1 + r[0], r[1], r[2])
    linear = pcs_mac(rp, infinity, claim)
    reduced = pcs_mac(r, linear, zero)
    return reduced
