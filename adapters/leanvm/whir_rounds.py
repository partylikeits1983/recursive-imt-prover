from snark_lib import *


@inline
def poly192_mul(a0, a1, a2, b0, b1, b2):
    # Coefficients in Poly64, reduced modulo y^3 + y + 1.
    p0 = a0 * b0
    p1 = a0 * b1 + a1 * b0
    p2 = a0 * b2 + a1 * b1 + a2 * b0
    p3 = a1 * b2 + a2 * b1
    p4 = a2 * b2
    return p0 + p3, p1 + p3 + p4, p2 + p4


@inline
def pack(lo, hi):
    assert_in_k(lo, hi)
    return lo + 18446744073709551616 * hi


def main():
    initial = StackBuf(3)
    hint_witness(initial, "initial")
    x0 = initial[0]
    x1 = initial[1]
    x2 = initial[2]
    # Keccak256("IMT-RDE1" || initial claim), with each coefficient little-endian.
    digest = StackBuf(2)
    keccak([pack(3550319000990010697, x0), pack(x1, x2)], [0, 0], digest, len=32)
    for i in unroll(0, 4):
        msg = StackBuf(9)
        hint_witness(msg, "round")
        a0 = msg[0]
        a1 = msg[1]
        a2 = msg[2]
        b0 = msg[3]
        b1 = msg[4]
        b2 = msg[5]
        r0 = msg[6]
        r1 = msg[7]
        r2 = msg[8]
        # Evaluation basis in characteristic two: h(r) = a + r * (claim + b * (r + 1)).
        t0, t1, t2 = poly192_mul(b0, b1, b2, r0 + 1, r1, r2)
        u0, u1, u2 = poly192_mul(r0, r1, r2, x0 + t0, x1 + t1, x2 + t2)
        x0 = a0 + u0
        x1 = a1 + u1
        x2 = a2 + u2
        next_digest = StackBuf(2)
        tail = StackBuf(4)
        tail[0] = pack(b1, b2)
        tail[1] = pack(r0, r1)
        tail[2] = pack(r2, x0)
        tail[3] = pack(x1, x2)
        keccak(digest, [pack(a0, a1), pack(a2, b0)], next_digest, tail=tail)
        digest = next_digest
    public = GEN ** 0
    public[1] = digest[0]
    public[GEN] = digest[1]
    return
