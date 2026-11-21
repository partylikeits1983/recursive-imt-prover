// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeMerkle} from "../contracts/imt/NativeMerkle.sol";

/// Local harness for the Merkle authentication phase. It exposes no root-proof acceptance entry point.
contract NativeMerkleTest {
    function checkOpening(
        bytes32 cap,
        uint256 depth,
        uint256 width,
        uint256[] memory indices,
        bytes calldata rows,
        bytes32[] calldata siblings
    ) external pure {
        NativeMerkle.verify(cap, depth, width, indices, rows, siblings);
    }

    function checkDigests(
        bytes32 cap,
        uint256 depth,
        uint256[] memory ids,
        bytes calldata digests,
        bytes32[] calldata siblings
    ) external pure {
        (, bytes32[] memory nodes, uint256 n) = NativeMerkle.digestFrontier(depth, depth, ids, digests, siblings);
        require(n == 1 && nodes[0] == cap);
    }

    function pair(bytes32 left, bytes32 right) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(left, right));
    }

    function testOffsetsAndSharedParents() external view {
        bytes32 a = keccak256(hex"01");
        bytes32 b = keccak256(hex"02");
        bytes32 c = keccak256(hex"03");
        bytes32 d = keccak256(hex"04");
        bytes32 root = pair(pair(a, b), pair(c, d));
        uint256[] memory ids = new uint256[](3);
        ids[0] = 0;
        ids[1] = 1;
        ids[2] = 3;
        bytes32[] memory siblings = new bytes32[](1);
        siblings[0] = c;
        this.checkOpening(root, 2, 1, ids, hex"010204", siblings);
        mustReject(root, ids, hex"010203", siblings);
        mustReject(bytes32(0), ids, hex"010204", siblings);
        mustReject(root, ids, hex"010204", new bytes32[](0));
        mustReject(root, ids, hex"010204", new bytes32[](2));
        ids[2] = 1;
        mustReject(root, ids, hex"010204", siblings);
        ids[2] = 4;
        mustReject(root, ids, hex"010204", siblings);
    }

    // Independent, level-by-level encoder over a full tree. Two distinct leaves
    // can meet at any of six heights, including at the first or last step.
    function testFuzzUnsharedPaths(uint8 x, uint8 y) external view {
        uint256 a = uint256(x) % 64;
        uint256 b = uint256(y) % 64;
        if (a == b) b ^= 1;
        if (a > b) (a, b) = (b, a);
        uint256[] memory ids = new uint256[](2);
        ids[0] = a;
        ids[1] = b;
        bytes memory rows = abi.encodePacked(uint8(a), uint8(b));
        bytes32[] memory tree = new bytes32[](128);
        for (uint256 i; i < 64; ++i) {
            tree[64 + i] = keccak256(abi.encodePacked(uint8(i)));
        }
        for (uint256 i = 63; i > 0; --i) {
            tree[i] = pair(tree[2 * i], tree[2 * i + 1]);
        }
        a += 64;
        b += 64;
        bytes32[] memory path = new bytes32[](10);
        uint256 n;
        while (a > 1) {
            if ((a ^ 1) != b) {
                path[n++] = tree[a ^ 1];
                if (a != b) path[n++] = tree[b ^ 1];
            }
            a >>= 1;
            b >>= 1;
        }
        assembly ("memory-safe") { mstore(path, n) }
        this.checkOpening(tree[1], 6, 1, ids, rows, path);
        bytes memory digests = abi.encodePacked(tree[64 + ids[0]], tree[64 + ids[1]]);
        this.checkDigests(tree[1], 6, ids, digests, path);
        digests[31] ^= 0x01;
        (bool ok,) = address(this).staticcall(abi.encodeCall(this.checkDigests, (tree[1], 6, ids, digests, path)));
        require(!ok);
    }

    function mustReject(bytes32 root, uint256[] memory ids, bytes memory rows, bytes32[] memory siblings) private view {
        (bool accepted,) =
            address(this).staticcall(abi.encodeCall(this.checkOpening, (root, 2, 1, ids, rows, siblings)));
        require(!accepted);
    }
}
