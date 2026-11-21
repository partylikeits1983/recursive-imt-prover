from snark_lib import *


@inline
def record(label0, label1, nonce0, nonce1, quantity, out):
    # 16-byte IMT-RECORD-OPEN1, two 32-byte fields and a little-endian u64.
    keccak([65538576797446287510752437405134114121, label0], [label1, nonce0], out, tail=[nonce1, quantity, 0, 0], len=88)
    return


@inline
def split_byte(word):
    # The application's 15-byte leaf domain shifts the public triple by a byte.
    bits = StackBuf(128)
    hint_decompose_bits(bits, word, 128)
    lo_byte = 0
    hi_byte = 0
    lo_tail = 0
    hi_tail = 0
    for i in unroll(0, 8):
        a = bits[i]
        b = bits[64 + i]
        assert a * a == a
        assert b * b == b
        lo_byte += a * (2 ** i)
        hi_byte += b * (2 ** i)
    for i in unroll(8, 64):
        a = bits[i]
        b = bits[64 + i]
        assert a * a == a
        assert b * b == b
        lo_tail += a * (2 ** (i - 8))
        hi_tail += b * (2 ** (i - 8))
    # F128 is a quadratic extension of F64. Its second basis element is
    # encoded at bit 64 and differs from the 64th field power of x.
    assert lo_byte + lo_tail * 256 + 18446744073709551616 * (hi_byte + hi_tail * 256) == word
    return lo_byte, lo_tail + hi_byte * (2 ** 56) + 18446744073709551616 * hi_tail


def main():
    fields = StackBuf(9)
    hint_witness(fields, "record")
    q = fields[8]
    assert_in_k(q, q)
    current = StackBuf(2)
    record(fields[0], fields[1], fields[2], fields[3], q, current)
    tag = StackBuf(2)
    keccak([65486654068402336836188215634822450505, fields[2]], [fields[3], 0], tag, len=48)
    replacement = StackBuf(2)
    record(fields[4], fields[5], fields[6], fields[7], q, replacement)
    for i in unroll(0, 32):
        path = StackBuf(3)
        hint_witness(path, "path")
        d = path[2]
        assert d * d == d
        sw0 = d * (current[0] + path[0])
        sw1 = d * (current[1] + path[1])
        parent = StackBuf(2)
        keccak([65491825763772255628445596004585327945, current[0] + sw0], [current[1] + sw1, path[0] + sw0], parent, tail=[path[1] + sw1, 0, 0, 0], len=80)
        current = parent
    # Keccak256("IMT-AGG-LEAF-V3" || root || input_tag || output_commitment).
    lo0, hi0 = split_byte(current[0])
    lo1, hi1 = split_byte(current[1])
    lo2, hi2 = split_byte(tag[0])
    lo3, hi3 = split_byte(tag[1])
    lo4, hi4 = split_byte(replacement[0])
    lo5, hi5 = split_byte(replacement[1])
    out = StackBuf(2)
    shift = 1329227995784915872903807060280344576
    keccak([266555014021361508878334600726990153 + lo0 * shift, hi0 + lo1 * shift], [hi1 + lo2 * shift, hi2 + lo3 * shift], out, tail=[hi3 + lo4 * shift, hi4 + lo5 * shift, hi5, 0], len=111)
    public = GEN ** 0
    public[1] = out[0]
    public[GEN] = out[1]
    return
