// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeMidpointPolicy as Policy} from "./NativeMidpointPolicy.sol";

import {NativeMerkle} from "./NativeMerkle.sol";
import {NativeField} from "./NativeField.sol";
import {NativeWhirInitial} from "./NativeWhirInitial.sol";

/// WHIR folds a queried row by evaluating its multilinear extension at the
/// transcript's suffix-fold challenges in reverse draw order.
library NativeFold {
    error InvalidFoldGeometry();

    /// The MMCS uses sorted unique rows. WHIR uses all samples in draw order.
    function queryOrder(uint256[71] memory draws)
        internal
        pure
        returns (uint256[] memory unique, uint256[71] memory ranks)
    {
        return queryOrder(draws, 71);
    }

    function queryOrder(uint256[71] memory draws, uint256 count)
        internal
        pure
        returns (uint256[] memory unique, uint256[71] memory ranks)
    {
        if (count == 0 || count > draws.length) revert InvalidFoldGeometry();
        uint256[71] memory order;
        unique = new uint256[](count);
        // Sort byte offsets into the original draws. The same offsets then address ranks,
        // including every occurrence of a repeated query.
        assembly ("memory-safe") {
            let end := shl(5, count)
            for { let offset := 0 } lt(offset, end) { offset := add(offset, 32) } {
                let index := mload(add(draws, offset))
                let dest := offset
                for {} dest {} {
                    let prev := mload(add(order, sub(dest, 32)))
                    if iszero(gt(mload(add(draws, prev)), index)) { break }
                    mstore(add(order, dest), prev)
                    dest := sub(dest, 32)
                }
                mstore(add(order, dest), offset)
            }
            let n := 0
            let previous := not(0)
            for { let pos := 0 } lt(pos, end) { pos := add(pos, 32) } {
                let offset := mload(add(order, pos))
                let index := mload(add(draws, offset))
                if or(iszero(n), iszero(eq(index, previous))) {
                    n := add(n, 1)
                    mstore(add(unique, shl(5, n)), index)
                    previous := index
                }
                mstore(add(ranks, offset), sub(n, 1))
            }
            mstore(unique, n)
        }
    }

    struct Opening {
        bytes mainRows;
        bytes fixedRows;
        bytes32[] mainPath;
        bytes32[] fixedPath;
    }

    /// Authenticate both initial oracles at the transcript-derived locations.
    /// Return evaluations in WHIR order for the next round's constraints.
    function firstRows(
        bytes32[2] memory caps,
        NativeWhirInitial.Fold memory fold,
        NativeWhirInitial.Query memory query,
        Opening calldata opening
    ) internal pure returns (uint192[71] memory values) {
        (uint256[] memory indices, uint256[71] memory ranks) = queryOrder(query.indices, Policy.FIRST_COUNT);
        uint192[] memory point = new uint192[](6);
        for (uint256 i; i < 6; ++i) {
            point[5 - i] = fold.point[i];
        }
        uint192[] memory folded = verifyPaired(
            caps, 24, indices, point, opening.mainRows, opening.fixedRows, opening.mainPath, opening.fixedPath
        );
        for (uint256 i; i < Policy.FIRST_COUNT; ++i) {
            values[i] = folded[ranks[i]];
        }
    }

    /// point is in evaluation order, most significant Boolean coordinate first.
    function weights(uint192[] memory point) internal pure returns (uint192[] memory eq) {
        if (point.length == 0 || point.length > 6) revert InvalidFoldGeometry();
        eq = new uint192[](1 << point.length);
        eq[0] = 1;
        uint256 used = 1;
        for (uint256 d = point.length; d != 0; --d) {
            uint192 r = point[d - 1];
            // All high branches together have weight r.
            uint192 rest = r;
            uint256 last = used - 1;
            for (uint256 i; i < last; ++i) {
                uint192 high = NativeField.mul(eq[i], r);
                eq[i + used] = high;
                eq[i] ^= high;
                rest ^= high;
            }
            eq[last + used] = rest;
            eq[last] ^= rest;
            used *= 2;
        }
    }

    /// Read little-endian Poly64 words. For a paired initial matrix the
    /// witness uses weights 0..31 and fixed wiring uses 32..47. The remaining
    /// sixteen cells are fixed zero and require no calldata.
    function baseRows(bytes calldata rows, uint192[] memory columnWeights, uint256 start, uint256 width)
        internal
        pure
        returns (uint192[] memory values)
    {
        if (
            width == 0 || start > columnWeights.length || width > columnWeights.length - start
                || rows.length % (8 * width) != 0
        ) {
            revert InvalidFoldGeometry();
        }
        uint256 count = rows.length / (8 * width);
        values = new uint192[](count);
        if (count == 0) return values;
        // Each byte of a Poly64 selects one multiple of the shared column
        // weight. Reuse eight columns of tables across every authenticated row.
        // Keep the eight byte-position sums between column groups, then apply
        // Horner's rule in x^8 once per row.
        assembly ("memory-safe") {
            function xtime(a) -> z {
                let top := and(shr(63, a), 0x100000000000000010000000000000001)
                z := xor(and(shl(1, a), 0xfffffffffffffffefffffffffffffffefffffffffffffffe), mul(top, 27))
            }
            function shiftByte(a) -> z {
                let top := and(shr(56, a), 0xff00000000000000ff00000000000000ff)
                z := xor(
                    and(shl(8, a), 0xffffffffffffff00ffffffffffffff00ffffffffffffff00),
                    xor(xor(top, shl(1, top)), xor(shl(3, top), shl(4, top)))
                )
            }
            function lookup(t, w, idx) -> v { v := mload(add(t, shl(5, byte(idx, w)))) }
            let sums := mload(0x40)
            let tables := add(sums, shl(8, count))
            // Temporary memory after the free pointer can contain old scratch data.
            for { let p := sums } lt(p, tables) { p := add(p, 32) } { mstore(p, 0) }
            for { let col := 0 } lt(col, width) { col := add(col, 8) } {
                let used := sub(width, col)
                if gt(used, 8) { used := 8 }
                for { let j := 0 } lt(j, used) { j := add(j, 1) } {
                    let t := add(tables, shl(13, j))
                    mstore(t, 0)
                    let power := mload(add(add(columnWeights, 32), shl(5, add(start, add(col, j)))))
                    // Seed the first four entries, then fill each quartet
                    // without a branch between individual multiples.
                    mstore(add(t, 32), power)
                    power := xtime(power)
                    mstore(add(t, 64), power)
                    mstore(add(t, 96), xor(mload(add(t, 32)), power))
                    power := xtime(power)
                    for { let stride := 128 } lt(stride, 8192) { stride := shl(1, stride) } {
                        for { let src := t } lt(src, add(t, stride)) { src := add(src, 128) } {
                            let dest := add(src, stride)
                            mstore(dest, xor(mload(src), power))
                            mstore(add(dest, 32), xor(mload(add(src, 32)), power))
                            mstore(add(dest, 64), xor(mload(add(src, 64)), power))
                            mstore(add(dest, 96), xor(mload(add(src, 96)), power))
                        }
                        power := xtime(power)
                    }
                }
                for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                    let acc := add(sums, shl(8, i))
                    let a0 := mload(acc)
                    let a1 := mload(add(acc, 32))
                    let a2 := mload(add(acc, 64))
                    let a3 := mload(add(acc, 96))
                    let a4 := mload(add(acc, 128))
                    let a5 := mload(add(acc, 160))
                    let a6 := mload(add(acc, 192))
                    let a7 := mload(add(acc, 224))
                    let row := add(rows.offset, shl(3, add(mul(i, width), col)))
                    for { let j := 0 } lt(j, used) { j := add(j, 1) } {
                        let w := calldataload(add(row, shl(3, j)))
                        let t := add(tables, shl(13, j))
                        a0 := xor(a0, lookup(t, w, 0))
                        a1 := xor(a1, lookup(t, w, 1))
                        a2 := xor(a2, lookup(t, w, 2))
                        a3 := xor(a3, lookup(t, w, 3))
                        a4 := xor(a4, lookup(t, w, 4))
                        a5 := xor(a5, lookup(t, w, 5))
                        a6 := xor(a6, lookup(t, w, 6))
                        a7 := xor(a7, lookup(t, w, 7))
                    }
                    mstore(acc, a0)
                    mstore(add(acc, 32), a1)
                    mstore(add(acc, 64), a2)
                    mstore(add(acc, 96), a3)
                    mstore(add(acc, 128), a4)
                    mstore(add(acc, 160), a5)
                    mstore(add(acc, 192), a6)
                    mstore(add(acc, 224), a7)
                }
            }
            for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                let acc := add(sums, shl(8, i))
                let v := mload(add(acc, 224))
                for { let k := 224 } gt(k, 0) { k := sub(k, 32) } {
                    v := xor(shiftByte(v), mload(add(acc, sub(k, 32))))
                }
                mstore(add(add(values, 32), shl(5, i)), v)
            }
        }
    }

    /// The enclosing transcript supplies both caps, the distinct sorted query
    /// positions and the evaluation point. Every returned value derives from both authenticated rows.
    function verifyPaired(
        bytes32[2] memory caps,
        uint256 depth,
        uint256[] memory indices,
        uint192[] memory point,
        bytes calldata main,
        bytes calldata fixedRows,
        bytes32[] calldata mainPath,
        bytes32[] calldata fixedPath
    ) internal pure returns (uint192[] memory folded) {
        if (point.length != 6) revert InvalidFoldGeometry();
        NativeMerkle.verify(caps[0], depth, 32 * 8, indices, main, mainPath);
        NativeMerkle.verify(caps[1], depth, 16 * 8, indices, fixedRows, fixedPath);
        return foldPaired(point, main, fixedRows);
    }

    /// Both matrices must already be authenticated at the same sorted indices.
    function foldPaired(uint192[] memory point, bytes calldata main, bytes calldata fixedRows)
        internal
        pure
        returns (uint192[] memory folded)
    {
        if (point.length != 6 || main.length != 2 * fixedRows.length) revert InvalidFoldGeometry();
        uint192[] memory eq = weights(point);
        folded = baseRows(main, eq, 0, 32);
        uint192[] memory right = baseRows(fixedRows, eq, 32, 16);
        for (uint256 i; i < folded.length; ++i) {
            folded[i] ^= right[i];
        }
    }
}
