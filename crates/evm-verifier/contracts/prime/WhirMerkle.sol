// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {KeccakFrontier} from "../KeccakFrontier.sol";

library WhirMerkle {
    error InvalidOpening();

    /// Authenticate rows in original transcript order against a binary Keccak tree.
    /// The reference sends one sibling per unmatched node in sorted order, bottom up.
    function verify(
        bytes32 root,
        uint256[] memory indices,
        bytes32[] memory hashes,
        uint256 depth,
        bytes calldata hints,
        uint256 cursor
    ) internal pure returns (uint256) {
        uint256 n = indices.length;
        // Queries arrive in random order. Move each index and its hash together.
        assembly ("memory-safe") {
            let ip := add(indices, 32)
            let hp := add(hashes, 32)
            let end := shl(5, n)
            for { let offset := 32 } lt(offset, end) { offset := add(offset, 32) } {
                let index := mload(add(ip, offset))
                let digest := mload(add(hp, offset))
                let dest := offset
                for {} dest {} {
                    let prev := sub(dest, 32)
                    let other := mload(add(ip, prev))
                    if iszero(gt(other, index)) { break }
                    mstore(add(ip, dest), other)
                    mstore(add(hp, dest), mload(add(hp, prev)))
                    dest := prev
                }
                mstore(add(ip, dest), index)
                mstore(add(hp, dest), digest)
            }
        }
        uint256 unique;
        for (uint256 i; i < n; ++i) {
            if (unique != 0 && indices[i] == indices[unique - 1]) {
                if (hashes[i] != hashes[unique - 1]) revert InvalidOpening();
            } else {
                indices[unique] = indices[i];
                hashes[unique++] = hashes[i];
            }
        }
        uint256 consumed;
        (n, consumed) = KeccakFrontier.reduce(indices, hashes, unique, depth, hints, cursor);
        if (consumed > hints.length || n != 1 || indices[0] != 0 || hashes[0] != root) revert InvalidOpening();
        return consumed;
    }
}
