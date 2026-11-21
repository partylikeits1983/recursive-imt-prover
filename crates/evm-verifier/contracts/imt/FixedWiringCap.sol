// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeMidpointPolicy as Policy} from "./NativeMidpointPolicy.sol";

import {NativeMerkle} from "./NativeMerkle.sol";
import {NativeFold} from "./NativeFold.sol";
import {NativeWhirInitial} from "./NativeWhirInitial.sol";

/// Public verifier-key data. STOP makes the deployed code inert, including when
/// a digest contains an opcode such as SELFDESTRUCT.
contract WiringPage {
    error WrongPageSize();

    constructor(bytes memory hashes) {
        if (hashes.length != 512 * 32) revert WrongPageSize();
        bytes memory runtime = abi.encodePacked(hex"00", hashes);
        assembly ("memory-safe") {
            return(add(runtime, 32), mload(runtime))
        }
    }
}

/// Built once for a pinned terminal verifier. Authenticate all 4,096 subtree
/// roots against the original fixed cap before saving their page addresses.
contract FixedWiringCap {
    error InvalidWiringCap();

    bytes32 public immutable wiringRoot;
    address[8] private pages;

    constructor(bytes32 expectedRoot, address[8] memory sources) {
        bytes32[4096] memory hashes;
        for (uint256 i; i < 8; ++i) {
            address page = sources[i];
            if (page.code.length != 1 + 512 * 32) revert InvalidWiringCap();
            uint256 first;
            assembly ("memory-safe") {
                extcodecopy(page, 0, 0, 1)
                first := byte(0, mload(0))
                extcodecopy(page, add(hashes, shl(14, i)), 1, 16384)
            }
            if (first != 0) revert InvalidWiringCap();
        }
        for (uint256 n = 4096; n > 1; n >>= 1) {
            assembly ("memory-safe") {
                for { let i := 0 } lt(i, shr(1, n)) { i := add(i, 1) } {
                    mstore(add(hashes, shl(5, i)), keccak256(add(hashes, shl(6, i)), 64))
                }
            }
        }
        if (hashes[0] != expectedRoot) revert InvalidWiringCap();
        wiringRoot = expectedRoot;
        pages = sources;
    }

    function verifyRows(uint256[] memory indices, bytes calldata rows, bytes32[] calldata siblings) public view {
        (uint256[] memory nodes, bytes32[] memory hashes, uint256 n) =
            NativeMerkle.frontier(24, 12, 16 * 8, indices, rows, siblings);
        checkFrontier(nodes, hashes, n);
    }

    function checkFrontier(uint256[] memory nodes, bytes32[] memory hashes, uint256 n) internal view {
        for (uint256 i; i < n; ++i) {
            uint256 node = nodes[i];
            address page = pages[node >> 9];
            bytes32 expected;
            assembly ("memory-safe") {
                extcodecopy(page, 0, add(1, shl(5, and(node, 511))), 32)
                expected := mload(0)
            }
            if (hashes[i] != expected) revert NativeMerkle.InvalidMerkleOpening();
        }
    }

    /// Called with the two early transcript commitments and the WHIR-derived queries.
    function firstRows(
        bytes32[2] memory caps,
        NativeWhirInitial.Fold memory fold,
        NativeWhirInitial.Query memory query,
        NativeFold.Opening calldata opening
    ) internal view returns (uint192[71] memory values) {
        if (caps[1] != wiringRoot) revert InvalidWiringCap();
        (uint256[] memory indices, uint256[71] memory ranks) = NativeFold.queryOrder(query.indices, Policy.FIRST_COUNT);
        NativeMerkle.verify(caps[0], 24, 256, indices, opening.mainRows, opening.mainPath);
        verifyRows(indices, opening.fixedRows, opening.fixedPath);
        uint192[] memory point = new uint192[](6);
        for (uint256 i; i < 6; ++i) {
            point[5 - i] = fold.point[i];
        }
        uint192[] memory folded = NativeFold.foldPaired(point, opening.mainRows, opening.fixedRows);
        for (uint256 i; i < Policy.FIRST_COUNT; ++i) {
            values[i] = folded[ranks[i]];
        }
    }
}
