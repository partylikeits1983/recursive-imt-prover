// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Ordered public statements for IMT proof trees.
library ImtBatchStatement {
    error WrongBatchLength(uint256 bytesReceived);
    error InvalidRootCount(uint256 count);

    /// The root-only client reserves the remaining 64 record bytes as zeros.
    function digestRoots(bytes32[] calldata roots) internal pure returns (bytes32) {
        uint256 count = roots.length;
        if (count == 0 || count > 64 || (count & (count - 1)) != 0) revert InvalidRootCount(count);
        bytes32[64] memory nodes;
        for (uint256 i; i < count; ++i) {
            nodes[i] = keccak256(abi.encodePacked("IMT-AGG-LEAF-V3", roots[i], bytes32(0), bytes32(0)));
        }
        return fold(nodes, count);
    }

    /// @dev Each 96-byte record is root || input tag || output commitment.
    /// A settlement contract can pass the result to its pinned proof verifier.
    function digest64(bytes calldata records) internal pure returns (bytes32) {
        if (records.length != 64 * 96) revert WrongBatchLength(records.length);

        bytes32[64] memory nodes;
        for (uint256 i; i < 64; ++i) {
            nodes[i] = keccak256(abi.encodePacked("IMT-AGG-LEAF-V3", records[96 * i:96 * (i + 1)]));
        }
        return fold(nodes, 64);
    }

    function fold(bytes32[64] memory nodes, uint256 count) private pure returns (bytes32) {
        for (uint256 width = count; width > 1; width /= 2) {
            uint8 childCount = uint8(count / width);
            for (uint256 i; i < width / 2; ++i) {
                nodes[i] = keccak256(
                    abi.encodePacked("IMT-AGG-NODE-V2", nodes[2 * i], childCount, nodes[2 * i + 1], childCount)
                );
            }
        }
        return nodes[0];
    }
}
