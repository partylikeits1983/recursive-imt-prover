// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BinaryNovelColumns} from "./BinaryNovelColumns.sol";
import {BinaryExtension as E} from "./BinaryExtension.sol";

library BinaryNovel {
    /// Four output coordinates per word. Expand each four-bit map once per verification.
    function tables() internal pure returns (uint256[] memory out) {
        bytes memory columns = BinaryNovelColumns.COLUMNS;
        out = new uint256[](27 * 16);
        assembly ("memory-safe") {
            let col := add(columns, 32)
            let end := add(col, mload(columns))
            let block_ := add(out, 32)
            for {} lt(col, end) { block_ := add(block_, 512) } {
                for { let size := 32 } lt(size, 512) { size := shl(1, size) } {
                    let v := mload(col)
                    col := add(col, 32)
                    for { let i := 0 } lt(i, size) { i := add(i, 32) } {
                        mstore(add(add(block_, size), i), xor(v, mload(add(block_, i))))
                    }
                }
            }
        }
    }

    function evaluate(uint256[] memory table, uint256 query, uint256 mu, uint256[24] memory values) internal pure {
        assembly ("memory-safe") {
            let block_ := add(table, 32)
            for { let group := 0 } iszero(gt(shl(2, group), mu)) { group := add(group, 1) } {
                let packed := 0
                let x := shr(shl(2, group), query)
                for { let n := group } lt(n, 7) { n := add(n, 1) } {
                    packed := xor(packed, mload(add(block_, shl(5, and(x, 15)))))
                    block_ := add(block_, 512)
                    x := shr(4, x)
                }
                let dest := add(values, shl(7, group))
                let lanes := 4
                for { let i := 0 } lt(i, lanes) { i := add(i, 1) } {
                    mstore(add(dest, shl(5, i)), and(packed, 0xffffffffffffffff))
                    packed := shr(64, packed)
                }
            }
        }
    }

    function block4(uint256[20] memory c, uint256 i, uint64 x, uint64 y) private pure returns (uint256) {
        return c[i] ^ E.mulBase(c[i + 1], x) ^ E.mulBase(c[i + 2] ^ E.mulBase(c[i + 3], x), y);
    }

    /// Evaluate the transmitted coefficient prefix in the normalized additive basis.
    function polynomial(uint256[20] memory c, uint256[24] memory w, uint256 length) internal pure returns (uint256) {
        uint64 x = uint64(w[0]);
        uint64 y = uint64(w[1]);
        uint256 low = block4(c, 0, x, y);
        if (length == 4) return low;
        if (length == 6) return low ^ E.mulBase(c[4] ^ E.mulBase(c[5], x), uint64(w[2]));
        low ^= E.mulBase(block4(c, 4, x, y), uint64(w[2]));
        if (length == 8) return low;
        uint256 next = block4(c, 8, x, y) ^ E.mulBase(block4(c, 12, x, y), uint64(w[2]));
        return low ^ E.mulBase(next, uint64(w[3])) ^ E.mulBase(block4(c, 16, x, y), uint64(w[4]));
    }
}
