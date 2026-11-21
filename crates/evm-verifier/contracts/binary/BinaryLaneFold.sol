// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// Combine adjacent lanes in place. Hoist the three Karatsuba multiplier decompositions out of the lane loop.
library BinaryLaneFold {
    function fold(uint256[64] memory lanes, uint256 outputs, uint256 scale, bool base) internal pure {
        assembly ("memory-safe") {
            function flags(a) -> f {
                a := and(a, shr(32, a))
                a := and(a, shr(16, a))
                a := and(a, shr(8, a))
                f := and(15, and(a, shr(4, a)))
            }
            function prepare(p, b) {
                mstore(p, or(and(b, 0x1111111111111111), shl(128, and(b, 0x2222222222222222))))
                mstore(add(p, 32), or(and(b, 0x4444444444444444), shl(128, and(b, 0x8888888888888888))))
                mstore(add(p, 64), flags(b))
            }
            function product(p, a) -> v {
                let b01 := mload(p)
                let b23 := mload(add(p, 32))
                let a0 := and(a, 0x1111111111111111)
                let a1 := and(a, 0x2222222222222222)
                let a2 := and(a, 0x4444444444444444)
                let a3 := and(a, 0x8888888888888888)
                let z :=
                    xor(
                        and(
                            xor(mul(a0, b01), mul(a2, b23)),
                            0x2222222222222222222222222222222211111111111111111111111111111111
                        ),
                        and(
                            xor(mul(a1, b01), mul(a3, b23)),
                            0x4444444444444444444444444444444422222222222222222222222222222222
                        )
                    )
                z := xor(
                    z,
                    xor(
                        and(
                            xor(mul(a2, b01), mul(a0, b23)),
                            0x8888888888888888888888888888888844444444444444444444444444444444
                        ),
                        and(
                            xor(mul(a3, b01), mul(a1, b23)),
                            0x1111111111111111111111111111111188888888888888888888888888888888
                        )
                    )
                )
                v := and(xor(z, shr(128, z)), 0xffffffffffffffffffffffffffffffff)
                let fb := mload(add(p, 64))
                if fb {
                    let fa := flags(a)
                    let flips := xor(and(fb, sub(0, and(fa, 1))), and(shl(1, fb), sub(0, and(shr(1, fa), 1))))
                    flips := xor(
                        flips,
                        xor(and(shl(2, fb), sub(0, and(shr(2, fa), 1))), and(shl(3, fb), sub(0, shr(3, fa))))
                    )
                    v := xor(v, xor(shl(64, flips), shl(68, flips)))
                }
            }
            function reduce(v) -> out {
                let h := shr(64, v)
                h := xor(h, xor(shr(63, h), xor(shr(61, h), shr(60, h))))
                out := and(xor(v, xor(xor(h, shl(1, h)), xor(shl(3, h), shl(4, h)))), 0xffffffffffffffff)
            }
            let p := mload(0x40)
            let sl := and(scale, 0xffffffffffffffff)
            let sh := shr(64, scale)
            prepare(p, sl)
            prepare(add(p, 96), sh)
            if iszero(base) { prepare(add(p, 192), xor(sl, sh)) }
            let dst := lanes
            for { let src := lanes } lt(src, add(lanes, shl(6, outputs))) { src := add(src, 64) } {
                let a := mload(src)
                let r := mload(add(src, 32))
                if a {
                    let lo := product(p, a)
                    switch base
                    case 1 { r := xor(r, or(reduce(lo), shl(64, reduce(product(add(p, 96), a))))) }
                    default {
                        let ah := shr(64, a)
                        let hi := product(add(p, 96), ah)
                        let mid := xor(xor(lo, hi), product(add(p, 192), xor(a, ah)))
                        r := xor(r, or(reduce(xor(lo, hi)), shl(64, reduce(xor(mid, shl(1, hi))))))
                    }
                }
                mstore(dst, r)
                dst := add(dst, 32)
            }
        }
    }
}
