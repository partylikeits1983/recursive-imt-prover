from snark_lib import *


def main():
    secret = StackBuf(2)
    hint_witness(secret, "preimage")
    current = StackBuf(2)
    # Little-endian encoding of IMT-PREIMAGE-V01 followed by the private 32 bytes.
    keccak([65383149916604384474373506209089342793, secret[0]], [secret[1], 0], current, len=48)
    for i in unroll(0, 32):
        path = StackBuf(3)
        hint_witness(path, "path")
        d = path[2]
        assert d * d == d
        sw0 = d * (current[0] + path[0])
        sw1 = d * (current[1] + path[1])
        parent = StackBuf(2)
        # IMT-KECCAK-NODE1 followed by the ordered 32-byte children.
        keccak([65491825763772255628445596004585327945, current[0] + sw0], [current[1] + sw1, path[0] + sw0], parent, tail=[path[1] + sw1, 0, 0, 0], len=80)
        current = parent
    public = GEN ** 0
    public[1] = current[0]
    public[GEN] = current[1]
    return
