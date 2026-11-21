// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WhirField} from "./WhirTranscript.sol";

/// Eight three-round inputs and one final Keccak-f[1600] output. Seven 240-bit
/// scalars hold a 200-byte little-endian state. Segment s's eighth slot holds
/// chunk s of the final output, with the last slot reserved as zero.
library KeccakSegmentRow {
    bytes private constant CONSTANTS =
        hex"00000000000000010000000000008082800000000000808a8000000080008000000000000000808b000000008000000180000000800080818000000000008009000000000000008a00000000000000880000000080008009000000008000000a000000008000808b800000000000008b8000000000008089800000000000800380000000000080028000000000000080000000000000800a800000008000000a8000000080008081800000000000808000000000800000018000000080008008";

    function row(bytes memory input) internal pure returns (uint256[64] memory words) {
        require(input.length == 200);
        uint256[25] memory a;
        for (uint256 i; i < 25; ++i) {
            uint256 raw;
            assembly ("memory-safe") { raw := mload(add(add(input, 32), shl(3, i))) }
            a[i] = uint64(WhirField.reverse(raw));
        }
        bytes memory constants = CONSTANTS;
        uint256[5] memory c;
        uint256[25] memory b;
        bytes memory packed = new bytes(224);
        for (uint256 segment; segment <= 8; ++segment) {
            for (uint256 i; i < 25; ++i) {
                uint256 le = WhirField.reverse(a[i]);
                assembly ("memory-safe") { mstore(add(add(packed, 32), shl(3, i)), le) }
            }
            for (uint256 i; i < 7; ++i) {
                uint256 raw;
                assembly ("memory-safe") { raw := mload(add(add(packed, 32), mul(30, i))) }
                uint256 slot = segment == 8 ? 8 * i + 7 : 8 * segment + i;
                words[slot] = uint240(WhirField.reverse(raw));
            }
            if (segment == 8) break;
            for (uint256 k = segment * 3; k < segment * 3 + 3; ++k) {
                uint256 rc;
                assembly ("memory-safe") { rc := shr(192, mload(add(add(constants, 32), shl(3, k)))) }
                round(a, b, c, rc);
            }
        }
    }

    function round(uint256[25] memory a, uint256[25] memory b, uint256[5] memory c, uint256 rc) private pure {
        assembly ("memory-safe") {
            function rol64(v, n) -> r { r := or(and(shl(n, v), 0xffffffffffffffff), shr(sub(64, n), v)) }
            // Lane x + 5*y occupies one EVM word. Theta adds one correction per column.
            for { let x := 0 } lt(x, 160) { x := add(x, 32) } {
                let col := add(a, x)
                mstore(
                    add(c, x),
                    xor(
                        xor(mload(col), mload(add(col, 160))),
                        xor(mload(add(col, 320)), xor(mload(add(col, 480)), mload(add(col, 640))))
                    )
                )
            }
            // Rho and Pi send (x,y) to (y, (2*x+3*y) mod 5).
            function moveLane(src, dst, n, d) { mstore(dst, rol64(xor(mload(src), d), n)) }
            {
                let d := xor(mload(add(c, 128)), rol64(mload(add(c, 32)), 1))
                moveLane(a, b, 0, d)
                moveLane(add(a, 160), add(b, 512), 36, d)
                moveLane(add(a, 320), add(b, 224), 3, d)
                moveLane(add(a, 480), add(b, 736), 41, d)
                moveLane(add(a, 640), add(b, 448), 18, d)
            }
            {
                let d := xor(mload(c), rol64(mload(add(c, 64)), 1))
                moveLane(add(a, 32), add(b, 320), 1, d)
                moveLane(add(a, 192), add(b, 32), 44, d)
                moveLane(add(a, 352), add(b, 544), 10, d)
                moveLane(add(a, 512), add(b, 256), 45, d)
                moveLane(add(a, 672), add(b, 768), 2, d)
            }
            {
                let d := xor(mload(add(c, 32)), rol64(mload(add(c, 96)), 1))
                moveLane(add(a, 64), add(b, 640), 62, d)
                moveLane(add(a, 224), add(b, 352), 6, d)
                moveLane(add(a, 384), add(b, 64), 43, d)
                moveLane(add(a, 544), add(b, 576), 15, d)
                moveLane(add(a, 704), add(b, 288), 61, d)
            }
            {
                let d := xor(mload(add(c, 64)), rol64(mload(add(c, 128)), 1))
                moveLane(add(a, 96), add(b, 160), 28, d)
                moveLane(add(a, 256), add(b, 672), 55, d)
                moveLane(add(a, 416), add(b, 384), 25, d)
                moveLane(add(a, 576), add(b, 96), 21, d)
                moveLane(add(a, 736), add(b, 608), 56, d)
            }
            {
                let d := xor(mload(add(c, 96)), rol64(mload(c), 1))
                moveLane(add(a, 128), add(b, 480), 27, d)
                moveLane(add(a, 288), add(b, 192), 20, d)
                moveLane(add(a, 448), add(b, 704), 39, d)
                moveLane(add(a, 608), add(b, 416), 8, d)
                moveLane(add(a, 768), add(b, 128), 14, d)
            }
            // Chi uses only the five lanes in its own row.
            for { let y := 0 } lt(y, 800) { y := add(y, 160) } {
                let src := add(b, y)
                let dst := add(a, y)
                let v0 := mload(src)
                let v1 := mload(add(src, 32))
                let v2 := mload(add(src, 64))
                let v3 := mload(add(src, 96))
                let v4 := mload(add(src, 128))
                mstore(dst, xor(v0, and(not(v1), v2)))
                mstore(add(dst, 32), xor(v1, and(not(v2), v3)))
                mstore(add(dst, 64), xor(v2, and(not(v3), v4)))
                mstore(add(dst, 96), xor(v3, and(not(v4), v0)))
                mstore(add(dst, 128), xor(v4, and(not(v0), v1)))
            }
            mstore(a, xor(mload(a), rc))
        }
    }
}
