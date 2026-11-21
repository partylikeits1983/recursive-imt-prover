// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {KeccakFrontier} from "../KeccakFrontier.sol";
import {BinaryTerminalTranscript as T} from "./BinaryTerminalTranscript.sol";

/// Opens one canonical pruned multiproof directly in LeanVM's serialized format.
library BinaryTerminalMerkle {
    error BadOpening();

    struct Rows {
        uint256[] queries;
        uint256[] offsets;
        uint256 zeroWords;
        uint256 end;
    }

    function open(
        bytes calldata proof,
        uint256 start,
        bytes32 cap,
        uint256 depth,
        uint256 count,
        uint256 width,
        bytes32[] memory challenges,
        uint256 firstHash
    ) internal pure returns (Rows memory r) {
        if (T.u32le(proof, start) != count) revert BadOpening();
        uint256 offset = start + 4;
        r.queries = new uint256[](count);
        uint256[] memory order = new uint256[](count);
        uint256 draws = 128 / depth;
        uint256 mask = (uint256(1) << depth) - 1;
        uint256 word;
        for (uint256 i; i < count; ++i) {
            if (i % draws == 0) word = T.little128(uint128(bytes16(challenges[firstHash + i / draws])));
            uint256 pos = word & mask;
            word >>= depth;
            if (T.u32le(proof, offset) != pos) revert BadOpening();
            offset += 4;
            r.queries[i] = pos;
            // Low byte retains the draw's ordinal for repeated and unsorted queries.
            uint256 key = (pos << 8) | i;
            uint256 j = i;
            while (j != 0 && order[j - 1] > key) {
                order[j] = order[j - 1];
                unchecked {
                    --j;
                }
            }
            order[j] = key;
        }
        if (T.u32le(proof, offset) != depth || T.u32le(proof, offset + 4) != width) revert BadOpening();
        uint256 rowWords = T.u32le(proof, offset + 8);
        if (rowWords > width) revert BadOpening();
        r.zeroWords = width - rowWords;
        offset += 12;
        uint256[] memory nodes = new uint256[](count);
        bytes32[] memory hashes = new bytes32[](count);
        r.offsets = new uint256[](count);
        uint256 unique;
        uint256 rowStart;
        uint256 anyFirst;
        bytes memory row = new bytes(width * 8);
        for (uint256 i; i < count; ++i) {
            uint256 pos = order[i] >> 8;
            if (unique == 0 || nodes[unique - 1] != pos) {
                rowStart = offset;
                offset += rowWords * 8;
                if (offset > proof.length) revert BadOpening();
                bytes32 digest;
                uint256 skip = r.zeroWords * 8;
                assembly ("memory-safe") {
                    let src := add(proof.offset, rowStart)
                    let dst := add(row, 32)
                    calldatacopy(add(dst, skip), src, mul(rowWords, 8))
                    digest := keccak256(dst, mload(row))
                    anyFirst := or(anyFirst, shr(192, calldataload(src)))
                }
                nodes[unique] = pos;
                hashes[unique++] = digest;
            }
            r.offsets[order[i] & 255] = rowStart;
        }
        if (rowWords > 0 && anyFirst == 0) revert BadOpening();
        (uint256 remaining, uint256 end) = KeccakFrontier.reduce(nodes, hashes, unique, depth, proof, offset);
        if (end > proof.length || remaining != 1 || nodes[0] != 0 || hashes[0] != cap) revert BadOpening();
        r.end = end;
    }
}
