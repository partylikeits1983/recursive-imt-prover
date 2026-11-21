# Evaluate the coefficient functional's codeword term at a Cantor-domain point.
def vector_generator(x, p, n: Const):
    w = ext(1, 0, 0)
    for j in unroll(0, n):
        r = p * GEN ** (3 * (n - 1 - j))
        f = x + 1
        part = ext(1 + r[1] * f, r[GEN] * f, r[GEN ** 2] * f)
        w = times(w, part)
        x = x * x + x
    return w
