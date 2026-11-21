# Elements of the client's cubic extension, represented by three K limbs.
@inline
def ext(a, b, c):
    out = StackBuf(3)
    out[0] = a
    out[1] = b
    out[2] = c
    return out


@inline
def plus(a: StackBuf(3), b: StackBuf(3)):
    out = ext(a[0] + b[0], a[1] + b[1], a[2] + b[2])
    return out


@inline
def times(a: StackBuf(3), b: StackBuf(3)):
    c0, c1, c2 = poly192_mul(a[0], a[1], a[2], b[0], b[1], b[2])
    out = ext(c0, c1, c2)
    return out


# Keep this assertion in its own function so differential tests can distinguish
# an invalid sumcheck from a mismatch at the final public digest.
def check_blend_endpoint(claim: StackBuf(3), expected: StackBuf(3)):
    for k in unroll(0, 3):
        assert claim[k] == expected[k]


# Bind both pieces before a serialized field crosses a Keccak lane boundary.
def split_lane_bytes(w, low_bytes: Const):
    bits = StackBuf(64)
    hint_decompose_bits(bits, w, 64)
    lo = 0
    for i in unroll(0, 8 * low_bytes):
        assert bits[i] * bits[i] == bits[i]
        lo += (2 ** i) * bits[i]
    hi = 0
    for i in unroll(0, 64 - 8 * low_bytes):
        bit = bits[8 * low_bytes + i]
        assert bit * bit == bit
        hi += (2 ** i) * bit
    assert w == lo + (2 ** (8 * low_bytes)) * hi
    return lo, hi


# Evaluate one additive-code generator at the sumcheck point. The bit order in
# the position and the prefix variable order in the point are opposite.
def generator_weight(q, point: StackBuf(BLEND_VARS * 3)):
    bits = StackBuf(ORACLE_HEIGHT)
    hint_decompose_bits(bits, q, ORACLE_HEIGHT)
    position = 0
    x = CANTOR_SHIFT
    for j in unroll(0, ORACLE_HEIGHT):
        assert bits[j] * bits[j] == bits[j]
        position += (2 ** j) * bits[j]
        x += CANTOR[j] * bits[j]
    assert position == q
    result = ext(1, 0, 0)
    for j in unroll(0, BLEND_VARS):
        k = 3 * (BLEND_VARS - 1 - j)
        linear = x + 1
        part = ext(1 + point[k] * linear, point[k+1] * linear, point[k+2] * linear)
        result = times(result, part)
        x = x * x + x
    return result


# The second view uses the native repeat-last successor, including its last-row term.
def view_weight(air: StackBuf(AIR_VARS * 3), point: StackBuf(BLEND_VARS * 3), theta: StackBuf(3), beta: StackBuf(3)):
    one = ext(1, 0, 0)
    scale = one
    for j in unroll(0, BLEND_VARS - STACK_VARS - AIR_VARS):
        r = ext(point[3*j], point[3*j+1], point[3*j+2])
        scale = times(scale, r)
    power = theta
    for i in unroll(0, STACK_VARS):
        j = 3 * (BLEND_VARS - AIR_VARS - 1 - i)
        r = ext(point[j], point[j+1], point[j+2])
        increment = plus(one, power)
        scaled = times(r, increment)
        factor = plus(one, scaled)
        scale = times(scale, factor)
        power = times(power, power)
    same = one
    carry = one
    done = ext(0, 0, 0)
    omega = one
    for i in unroll(0, AIR_VARS):
        j = 3 * (AIR_VARS - 1 - i)
        k = 3 * (BLEND_VARS - 1 - i)
        p = ext(air[j], air[j+1], air[j+2])
        r = ext(point[k], point[k+1], point[k+2])
        delta = plus(p, r)
        eq = plus(one, delta)
        same = times(same, eq)
        keep = times(done, eq)
        np = plus(one, p)
        nr = plus(one, r)
        settle = times(np, r)
        settled = times(carry, settle)
        done = plus(keep, settled)
        propagate = times(p, nr)
        carry = times(carry, propagate)
        both = times(p, r)
        omega = times(omega, both)
    nxt = plus(done, omega)
    weighted = times(beta, nxt)
    combined = plus(same, weighted)
    out = times(scale, combined)
    return out
