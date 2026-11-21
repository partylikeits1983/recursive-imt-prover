// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {KeccakFrontier} from "../KeccakFrontier.sol";

/// Binary, singleton-cap commitments used by the native IMT root's two additive WHIR openings.
library NativeMerkle {
    error WrongOpeningShape();
    error InvalidMerkleOpening();

    /// The enclosing WHIR verifier supplies the authenticated cap, geometry, and its sorted
    /// distinct Fiat–Shamir indices. Each row is the native serialization of its field elements.
    function verify(
        bytes32 cap,
        uint256 depth,
        uint256 rowBytes,
        uint256[] memory indices,
        bytes calldata rows,
        bytes32[] calldata siblings
    ) internal pure {
        (, bytes32[] memory hashes, uint256 count) = frontier(depth, depth, rowBytes, indices, rows, siblings);
        if (count != 1 || hashes[0] != cap) revert InvalidMerkleOpening();
    }

    /// Consume exactly the supplied siblings through the requested number of
    /// levels. The caller authenticates every returned (index, digest) pair.
    function frontier(
        uint256 depth,
        uint256 levels,
        uint256 rowBytes,
        uint256[] memory indices,
        bytes calldata rows,
        bytes32[] calldata siblings
    ) internal pure returns (uint256[] memory nodes, bytes32[] memory hashes, uint256 count) {
        return reduceFrontier(depth, levels, rowBytes, indices, rows, siblings, false);
    }

    /// These are the Keccak digests of full native rows. Their preimages are
    /// bound to the WHIR folds by the enclosing joint proof.
    function digestFrontier(
        uint256 depth,
        uint256 levels,
        uint256[] memory indices,
        bytes calldata digests,
        bytes32[] calldata siblings
    ) internal pure returns (uint256[] memory nodes, bytes32[] memory hashes, uint256 count) {
        return reduceFrontier(depth, levels, 32, indices, digests, siblings, true);
    }

    function reduceFrontier(
        uint256 depth,
        uint256 levels,
        uint256 rowBytes,
        uint256[] memory indices,
        bytes calldata rows,
        bytes32[] calldata siblings,
        bool digests
    ) private pure returns (uint256[] memory nodes, bytes32[] memory hashes, uint256 count) {
        count = indices.length;
        if (
            depth > 32 || levels > depth || count == 0 || count > (1 << depth) || rowBytes == 0
                || rows.length != count * rowBytes
        ) {
            revert WrongOpeningShape();
        }

        // In-place frontier reduction. Keep the caller's original indices for the algebraic folds.
        nodes = new uint256[](count);
        hashes = new bytes32[](count);
        bool valid;
        bytes calldata siblingBytes;
        assembly ("memory-safe") {
            let ids := add(nodes, 32)
            let src := add(indices, 32)
            let vals := add(hashes, 32)
            let scratch := mload(0x40)
            let limit := shl(depth, 1)
            siblingBytes.offset := siblings.offset
            siblingBytes.length := shl(5, siblings.length)
            valid := 1
            let previous := 0
            for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                let offset := shl(5, i)
                let index := mload(add(src, offset))
                if or(iszero(lt(index, limit)), and(iszero(iszero(i)), iszero(lt(previous, index)))) {
                    valid := 0
                    break
                }
                previous := index
                mstore(add(ids, offset), index)
                switch digests
                case 1 { mstore(add(vals, offset), calldataload(add(rows.offset, offset))) }
                default {
                    calldatacopy(scratch, add(rows.offset, mul(i, rowBytes)), rowBytes)
                    mstore(add(vals, offset), keccak256(scratch, rowBytes))
                }
            }
        }
        if (!valid) revert InvalidMerkleOpening();
        uint256 consumed;
        (count, consumed) = KeccakFrontier.reduce(nodes, hashes, count, levels, siblingBytes, 0);
        if (consumed != siblingBytes.length) revert InvalidMerkleOpening();
    }
}
