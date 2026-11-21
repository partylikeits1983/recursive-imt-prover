// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// Binary Keccak multiproof shared by the native aggregate and large-prime opening.
library KeccakFrontier {
    /// The caller supplies count sorted, distinct rows, authenticates the resulting
    /// frontier and checks the returned cursor against the available sibling bytes.
    function reduce(
        uint256[] memory indices,
        bytes32[] memory hashes,
        uint256 count,
        uint256 levels,
        bytes calldata siblings,
        uint256 cursor
    ) internal pure returns (uint256 remaining, uint256 consumed) {
        // Compact the frontier in place. Each level produces at most one parent
        // per consumed input, so writes cannot overwrite an unread entry.
        assembly ("memory-safe") {
            let ip := add(indices, 32)
            let hp := add(hashes, 32)
            let size := shl(5, count)
            let sibling := add(siblings.offset, cursor)
            // Until two paths are siblings, every level consumes exactly one
            // sibling per query. Traverse that prefix per path with a fixed
            // calldata stride and retain its intermediate hash on the stack.
            let minXor := not(0)
            for { let i := 32 } lt(i, size) { i := add(i, 32) } {
                let d := xor(mload(add(ip, i)), mload(add(ip, sub(i, 32))))
                if lt(d, minXor) { minXor := d }
            }
            let levelsApart := 0
            for {} and(lt(levelsApart, levels), gt(minXor, 1)) {} {
                levelsApart := add(levelsApart, 1)
                minXor := shr(1, minXor)
            }
            if levelsApart {
                let span := mul(levelsApart, size)
                for { let i := 0 } lt(i, size) { i := add(i, 32) } {
                    let index := mload(add(ip, i))
                    let digest := mload(add(hp, i))
                    let pos := add(sibling, i)
                    for { let end := add(pos, span) } lt(pos, end) { pos := add(pos, size) } {
                        let slot := shl(5, and(index, 1))
                        mstore(slot, digest)
                        mstore(xor(32, slot), calldataload(pos))
                        digest := keccak256(0, 64)
                        index := shr(1, index)
                    }
                    mstore(add(ip, i), index)
                    mstore(add(hp, i), digest)
                }
                sibling := add(sibling, span)
            }
            for { let level := levelsApart } lt(level, levels) { level := add(level, 1) } {
                let output := 0
                for { let input := 0 } lt(input, size) {} {
                    let index := mload(add(ip, input))
                    let a := mload(add(hp, input))
                    input := add(input, 32)
                    // Only read the next frontier element while it is within the allocated array.
                    let paired := 0
                    if lt(input, size) { paired := eq(mload(add(ip, input)), xor(index, 1)) }
                    switch paired
                    case 1 {
                        mstore(0, a)
                        mstore(32, mload(add(hp, input)))
                        input := add(input, 32)
                    }
                    default {
                        let slot := shl(5, and(index, 1))
                        mstore(slot, a)
                        mstore(xor(32, slot), calldataload(sibling))
                        sibling := add(sibling, 32)
                    }
                    mstore(add(ip, output), shr(1, index))
                    mstore(add(hp, output), keccak256(0, 64))
                    output := add(output, 32)
                }
                size := output
            }
            remaining := shr(5, size)
            consumed := sub(sibling, siblings.offset)
        }
    }
}
