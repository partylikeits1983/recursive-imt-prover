// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeField as F} from "./NativeField.sol";

/// Evaluate the ring-switch tensor over two copies of Poly192 using its 192
/// Frobenius embeddings. For T = sum e_i tensor t_i, embedding j returns
/// P_j = sum e_i^(2^j) t_i. Trace-dual basis elements d_i recover t_i as
/// sum_j d_i^(2^j) P_j. The requested result batches t_i at the given point.
library NativeRingWeight {
    // In GF(2)[x]/(x^64+x^4+x^3+x+1), (x^2+1)^(-1).
    uint64 private constant INV_DERIVATIVE = 0x5555555555555552;

    /// Coefficients at indices 0..3 among the 64 low-coordinate equality weights.
    function firstFour(uint192[8] memory batching) private pure returns (uint192[4] memory w) {
        uint192 prefix = 1;
        for (uint256 d = 2; d < 6; ++d) {
            prefix = F.mul(prefix, 1 ^ batching[d]);
        }
        uint192 even = F.mul(prefix, 1 ^ batching[6]);
        uint192 odd = prefix ^ even;
        w[0] = F.mul(even, 1 ^ batching[7]);
        w[1] = w[0] ^ even;
        w[2] = F.mul(odd, 1 ^ batching[7]);
        w[3] = w[2] ^ odd;
    }

    /// Batched dual of the Poly64 monomial basis at each conjugate x.
    /// For modulus f, the ith dual is (sum_{k>i} f_k x^(k-1-i))/f'(x).
    /// The leading monomial factors over the six index bits. Only indices
    /// 0..3 have corrections from x^4+x^3+x+1.
    function baseDual(uint192[8] memory batching) private pure returns (uint192[64] memory dual) {
        uint192[4] memory w = firstFour(batching);
        uint64 x = 2;
        uint64 inv = INV_DERIVATIVE;
        for (uint256 j; j < 64; ++j) {
            uint64 power = x;
            uint192 leading = 1;
            for (uint256 d = 8; d > 2; --d) {
                uint192 bit = batching[d - 1];
                leading = F.mul(leading, bit ^ F.scale(1 ^ bit, power));
                power = F.square64(power);
            }
            // w0(x^3+x^2+1) + w1(x^2+x) + w2(x+1) + w3.
            uint192 tail = F.scale(w[0], x) ^ w[0] ^ w[1];
            tail = F.scale(tail, x) ^ w[1] ^ w[2];
            tail = F.scale(tail, x) ^ w[0] ^ w[2] ^ w[3];
            dual[j] = F.scale(leading ^ tail, inv);
            x = F.square64(x);
            inv = F.square64(inv);
        }
    }

    /// For y^3+y+1, the trace-dual basis to [1,y,y^2] is [1,y^2,y].
    /// Degrees 3 and 64 are coprime, so the 192 dual basis elements are the
    /// products of those for GF(8) and GF(2^64). Index 3 in the high two bits
    /// is zero padding and contributes no dual element.
    function cubicDual(uint192[8] memory batching) private pure returns (uint192[3] memory dual) {
        uint192 low = 1 ^ batching[1];
        uint192 w0 = F.mul(1 ^ batching[0], low);
        uint192 w1 = (1 ^ batching[0]) ^ w0;
        uint192 w2 = low ^ w0;
        uint192 y = uint192(1) << 64;
        for (uint256 j; j < 3; ++j) {
            uint192 next = F.square(y);
            dual[j] = w0 ^ F.mul(w1, next) ^ F.mul(w2, y);
            y = next;
        }
    }

    /// Raising a field element to 2^64 fixes all three Poly64 coefficients
    /// and maps y to y^2 and y^2 to y^2+y.
    function conjugate(uint192 a) private pure returns (uint192) {
        uint192 hi = uint64(a >> 128);
        uint192 mid = uint64(a >> 64);
        return uint192(uint64(a)) | (hi << 64) | ((mid ^ hi) << 128);
    }

    function evaluate(uint192[32] memory reading, uint192[26] memory draw, uint192[8] memory batching)
        internal
        pure
        returns (uint192 result)
    {
        uint192[64] memory base = baseDual(batching);
        uint192[3] memory cubic = cubicDual(batching);
        uint192[192] memory values;
        for (uint256 j; j < 192; ++j) {
            values[j] = F.mul(base[j % 64], cubic[j % 3]);
        }
        // Each embedding maps 1 + a tensor 1 + 1 tensor b to 1 + a^(2^j) + b.
        for (uint256 d; d < 26; ++d) {
            uint192 a = reading[d];
            uint192 off = 1 ^ draw[25 - d];
            for (uint256 j; j < 64; ++j) {
                uint192 c = conjugate(a);
                values[j] = F.mul(values[j], a ^ off);
                values[j + 64] = F.mul(values[j + 64], c ^ off);
                values[j + 128] = F.mul(values[j + 128], conjugate(c) ^ off);
                a = F.square(a);
            }
        }
        for (uint256 j; j < 192; ++j) {
            result ^= values[j];
        }
    }
}
