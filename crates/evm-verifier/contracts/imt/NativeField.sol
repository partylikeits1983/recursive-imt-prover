// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// Arithmetic for the native IMT verifier. Poly192 packs its constant Poly64
/// coefficient in the low 64 bits followed by the coefficients of y and y².
library NativeField {
    function wideMul64(uint64 a, uint64 b) internal pure returns (uint256 product) {
        assembly ("memory-safe") {
            // Split the binary coefficients into their four residue classes modulo four.
            // A product of two 64-bit words fits in 128 bits. Pack two independent products
            // into the low and high halves of one EVM MUL.
            let a0 := and(a, 0x1111111111111111)
            let a1 := and(a, 0x2222222222222222)
            let a2 := and(a, 0x4444444444444444)
            let a3 := and(a, 0x8888888888888888)
            let b01 := or(and(b, 0x1111111111111111), shl(128, and(b, 0x2222222222222222)))
            let b23 := or(and(b, 0x4444444444444444), shl(128, and(b, 0x8888888888888888)))
            // For row i keep exponents i mod 4 in the low half and i+1 mod 4 in the high half.
            let p0 :=
                and(xor(mul(a0, b01), mul(a2, b23)), 0x2222222222222222222222222222222211111111111111111111111111111111)
            let p1 :=
                and(xor(mul(a1, b01), mul(a3, b23)), 0x4444444444444444444444444444444422222222222222222222222222222222)
            let p2 :=
                and(xor(mul(a2, b01), mul(a0, b23)), 0x8888888888888888888888888888888844444444444444444444444444444444)
            let p3 :=
                and(xor(mul(a3, b01), mul(a1, b23)), 0x1111111111111111111111111111111188888888888888888888888888888888)
            let packed := xor(xor(p0, p1), xor(p2, p3))
            product := and(xor(packed, shr(128, packed)), 0xffffffffffffffffffffffffffffffff)
            // A radix-16 digit can overflow only when both residues contain all 16
            // monomials. At the central digit the convolution is 16, followed by
            // 15 and 14. Carry propagation toggles parity in the two following digits.
            function fullResidues(v) -> flags {
                v := and(v, shr(32, v))
                v := and(v, shr(16, v))
                v := and(v, shr(8, v))
                flags := and(15, and(v, shr(4, v)))
            }
            let fa := fullResidues(a)
            if fa {
                let fb := fullResidues(b)
                let flips := xor(and(fb, sub(0, and(fa, 1))), and(shl(1, fb), sub(0, and(shr(1, fa), 1))))
                flips := xor(flips, and(shl(2, fb), sub(0, and(shr(2, fa), 1))))
                flips := xor(flips, and(shl(3, fb), sub(0, shr(3, fa))))
                product := xor(product, xor(shl(64, flips), shl(68, flips)))
            }
        }
    }

    function reduceWide(uint256 product) internal pure returns (uint64 output) {
        assembly ("memory-safe") {
            // x^64 = x^4 + x^3 + x + 1.
            function fold(high) -> value {
                value := xor(xor(high, shl(1, high)), xor(shl(3, high), shl(4, high)))
            }
            let reduced := xor(and(product, 0xffffffffffffffff), fold(shr(64, product)))
            output := and(xor(reduced, fold(shr(64, reduced))), 0xffffffffffffffff)
        }
    }

    function mul64(uint64 a, uint64 b) internal pure returns (uint64) {
        return reduceWide(wideMul64(a, b));
    }

    /// Karatsuba multiplication in Poly64[y] / (y³ + y + 1).
    function mul(uint192 a, uint192 b) internal pure returns (uint192) {
        uint64 a0 = uint64(a);
        uint64 a1 = uint64(a >> 64);
        uint64 a2 = uint64(a >> 128);
        uint64 b0 = uint64(b);
        uint64 b1 = uint64(b >> 64);
        uint64 b2 = uint64(b >> 128);
        // The binary-field reduction is linear. Accumulate the wide products
        // modulo y³+y+1 before reducing each of the three surviving coefficients.
        uint256 c0 = wideMul64(a0, b0);
        uint256 c1 = wideMul64(a1, b1);
        uint256 c2 = wideMul64(a2, b2);
        uint256 c01 = wideMul64(a0 ^ a1, b0 ^ b1);
        uint256 c02 = wideMul64(a0 ^ a2, b0 ^ b2);
        uint256 c12 = wideMul64(a1 ^ a2, b1 ^ b2);
        uint256 common = c0 ^ c1;
        return uint192(reduceWide(common ^ c2 ^ c12)) | (uint192(reduceWide(c01 ^ c0 ^ c12)) << 64)
            | (uint192(reduceWide(c02 ^ common)) << 128);
    }

    /// Multiplication by a fixed challenge as a linear map on 48 four-bit
    /// digits. Each entry already includes its polynomial and cubic basis
    /// positions, so evaluating the map needs only table reads and XOR.
    function multiplierTable(uint192 challenge) internal pure returns (uint192[] memory table) {
        table = new uint192[](48 * 16);
        assembly ("memory-safe") {
            function xtime(v) -> z {
                let high := and(shr(63, v), 0x100000000000000010000000000000001)
                z := xor(and(shl(1, v), 0xfffffffffffffffefffffffffffffffefffffffffffffffe), mul(high, 27))
            }
            let p := add(table, 32)
            for { let limb := 0 } lt(limb, 3) { limb := add(limb, 1) } {
                let v := challenge
                for { let n := 0 } lt(n, 16) { n := add(n, 1) } {
                    let two := xtime(v)
                    let four := xtime(two)
                    let eight := xtime(four)
                    mstore(p, 0)
                    mstore(add(p, 32), v)
                    mstore(add(p, 64), two)
                    mstore(add(p, 96), xor(v, two))
                    for { let src := p } lt(src, add(p, 128)) { src := add(src, 32) } {
                        let a := mload(src)
                        mstore(add(src, 128), xor(a, four))
                        mstore(add(src, 256), xor(a, eight))
                        mstore(add(src, 384), xor(xor(a, four), eight))
                    }
                    p := add(p, 512)
                    v := xtime(eight)
                }
                // y^3 = y + 1 in the native extension.
                let high := and(shr(128, challenge), 0xffffffffffffffff)
                challenge := xor(
                    and(shl(64, challenge), 0xffffffffffffffffffffffffffffffffffffffffffffffff),
                    xor(high, shl(64, high))
                )
            }
        }
    }

    /// table comes from multiplierTable. Enumerate the low word first.
    function multiplyFixed(uint192[] memory table, uint192 value) internal pure returns (uint192 product) {
        assembly ("memory-safe") {
            function term(p, v, bit) -> t { t := mload(add(p, shl(5, and(shr(bit, v), 15)))) }
            let p := add(table, 32)
            for { let end := add(p, 24576) } lt(p, end) { p := add(p, 4096) } {
                let lo :=
                    xor(
                        xor(term(p, value, 0), term(add(p, 512), value, 4)),
                        xor(term(add(p, 1024), value, 8), term(add(p, 1536), value, 12))
                    )
                let hi :=
                    xor(
                        xor(term(add(p, 2048), value, 16), term(add(p, 2560), value, 20)),
                        xor(term(add(p, 3072), value, 24), term(add(p, 3584), value, 28))
                    )
                product := xor(product, xor(lo, hi))
                value := shr(32, value)
            }
        }
    }

    // In characteristic two, squaring doubles each bit's polynomial exponent.
    function square64(uint64 a) internal pure returns (uint64 result) {
        assembly ("memory-safe") {
            let x := and(a, 0xffffffffffffffff)
            x := and(or(x, shl(32, x)), 0x00000000ffffffff00000000ffffffff)
            x := and(or(x, shl(16, x)), 0x0000ffff0000ffff0000ffff0000ffff)
            x := and(or(x, shl(8, x)), 0x00ff00ff00ff00ff00ff00ff00ff00ff)
            x := and(or(x, shl(4, x)), 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f)
            x := and(or(x, shl(2, x)), 0x33333333333333333333333333333333)
            x := and(or(x, shl(1, x)), 0x55555555555555555555555555555555)
            function fold(h) -> v {
                v := xor(xor(h, shl(1, h)), xor(shl(3, h), shl(4, h)))
            }
            let reduced := xor(and(x, 0xffffffffffffffff), fold(shr(64, x)))
            result := and(xor(reduced, fold(shr(64, reduced))), 0xffffffffffffffff)
        }
    }

    function square(uint192 a) internal pure returns (uint192) {
        // y⁴ reduces to y²+y in the native cubic extension.
        uint64 high = square64(uint64(a >> 128));
        return uint192(square64(uint64(a))) | (uint192(high) << 64) | (uint192(square64(uint64(a >> 64)) ^ high) << 128);
    }

    /// Evaluation-basis WHIR round. The enclosing transcript derives r after observing h0 and hInf.
    function sumcheckRound(uint192 claim, uint192 h0, uint192 hInf, uint192 r) internal pure returns (uint192) {
        return h0 ^ mul(r, claim ^ mul(hInf, r ^ 1));
    }

    function scale(uint192 v, uint64 factor) internal pure returns (uint192) {
        return uint192(mul64(uint64(v), factor)) | (uint192(mul64(uint64(v >> 64), factor)) << 64)
            | (uint192(mul64(uint64(v >> 128), factor)) << 128);
    }

    /// Multiply each Poly64 coefficient by x^k for 1 <= k <= 60. The
    /// overflow has degree at most 59, so a single reduction by x^4+x^3+x+1
    /// fits in each 64-bit lane. The trusted AIR program fixes k.
    function scaleMonomial(uint192 v, uint256 k) internal pure returns (uint192 out) {
        assembly ("memory-safe") {
            let mask := mul(sub(shl(k, 1), 1), 0x100000000000000010000000000000001)
            let high := and(shr(sub(64, k), v), mask)
            let low := and(shl(k, v), not(mask))
            out := xor(low, xor(xor(high, shl(1, high)), xor(shl(3, high), shl(4, high))))
        }
    }

    /// A run of 2^levels one bits factors as (1+x)(1+x²)(1+x⁴)...
    function scaleOnes(uint192 v, uint256 levels) internal pure returns (uint192) {
        for (uint256 i; i < levels; ++i) {
            v ^= scaleMonomial(v, 1 << i);
        }
        return v;
    }

    // Apply the same Poly64 linear map to all three separated coefficients.
    function timesX(uint192 v) internal pure returns (uint192 out) {
        assembly ("memory-safe") {
            let ones := 0x000000000000000100000000000000010000000000000001
            let top := and(shr(63, v), ones)
            out := xor(shl(1, xor(v, shl(63, top))), mul(top, 0x1b))
        }
    }

    function divideBySix(uint192 v) internal pure returns (uint192 out) {
        assembly ("memory-safe") {
            let ones := 0x000000000000000100000000000000010000000000000001
            // First divide each lane by x using x^64 + x^4 + x^3 + x + 1.
            v := and(v, 0xffffffffffffffffffffffffffffffffffffffffffffffff)
            let lsb := and(v, ones)
            let q := xor(shr(1, xor(v, lsb)), mul(lsb, 0x800000000000000d))
            // Division by x+1 is a prefix XOR. For odd parity, add the
            // prefix XOR of the low modulus bits 0x1b, which equals 0x09.
            function prefixStep(a, n, mask) -> b { b := xor(a, shl(n, and(a, mask))) }
            q := prefixStep(q, 1, 0x7fffffffffffffff7fffffffffffffff7fffffffffffffff)
            q := prefixStep(q, 2, 0x3fffffffffffffff3fffffffffffffff3fffffffffffffff)
            q := prefixStep(q, 4, 0x0fffffffffffffff0fffffffffffffff0fffffffffffffff)
            q := prefixStep(q, 8, 0x00ffffffffffffff00ffffffffffffff00ffffffffffffff)
            q := prefixStep(q, 16, 0x0000ffffffffffff0000ffffffffffff0000ffffffffffff)
            q := prefixStep(q, 32, 0x00000000ffffffff00000000ffffffff00000000ffffffff)
            out := xor(q, mul(and(shr(63, q), ones), 9))
        }
    }

    /// Cubic through h(0), h(1)=h(0)+claim, h(2), h(3) in the polynomial basis.
    function cubic(uint192 claim, uint192 h0, uint192 h2, uint192 h3, uint192 r) internal pure returns (uint192) {
        // At both 2 and 3, x²+x equals 6. Factor h as h0+claim*x+(x²+x)*(u*x+v).
        uint192 diff = h2 ^ h3 ^ claim;
        uint192 u = divideBySix(diff);
        uint192 v = divideBySix(h2 ^ h0 ^ timesX(claim ^ diff));
        return h0 ^ mul(r, claim ^ v ^ mul(r, u ^ v ^ mul(r, u)));
    }
}
