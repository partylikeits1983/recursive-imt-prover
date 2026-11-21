from snark_lib import *


@inline
def limbs(word):
    parts = StackBuf(2)
    hint_f128_limbs(parts, word)
    assert_in_k(parts[0], parts[1])
    assert word == parts[0] + 18446744073709551616 * parts[1]
    return parts[0], parts[1]


@inline
def check_byte(value):
    bits = StackBuf(8)
    hint_decompose_bits(bits, value, 8)
    v = 0
    for b in unroll(0, 8):
        assert bits[b] * bits[b] == bits[b]
        v += (2 ** b) * bits[b]
    assert v == value
    return


@inline
def poly192_mul(a0, a1, a2, b0, b1, b2):
    # Coefficients in Poly64, reduced modulo y^3 + y + 1.
    p0 = a0 * b0
    p1 = a0 * b1 + a1 * b0
    p2 = a0 * b2 + a1 * b1 + a2 * b0
    p3 = a1 * b2 + a2 * b1
    p4 = a2 * b2
    return p0 + p3, p1 + p3 + p4, p2 + p4


def query_index(value, low: Const):
    bits = StackBuf(64)
    hint_decompose_bits(bits, value, 64)
    word = 0
    for b in unroll(0, 64):
        assert bits[b] * bits[b] == bits[b]
        word += (2 ** b) * bits[b]
    assert word == value
    out = 0
    for b in unroll(0, low):
        out += (2 ** b) * bits[b]
    return out
