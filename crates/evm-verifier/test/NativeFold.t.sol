// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WhirFixtureProfile} from "./WhirFixtureProfile.sol";
import {NativeFold} from "../contracts/imt/NativeFold.sol";
import {NativeField} from "../contracts/imt/NativeField.sol";
import {NativeBitBatch} from "../contracts/imt/NativeBitBatch.sol";
import {NativeWhirInitial} from "../contracts/imt/NativeWhirInitial.sol";

contract NativeFoldTest is WhirFixtureProfile {
    /// Component receipt starts from the ring state checked by the bit-batch harness.
    function checkFirstRows(
        bytes32[2] memory caps,
        bytes32 ringBlock,
        uint192 ringSum,
        bytes calldata section,
        NativeFold.Opening calldata opening
    ) external pure returns (bytes32) {
        if (section.length != 472) revert NativeWhirInitial.InvalidProofLength();
        NativeBitBatch.RingState memory ring;
        ring.stream.blockHash = ringBlock;
        ring.claimedSum = ringSum;
        NativeWhirInitial.Fold memory fold = NativeWhirInitial.initialFold(ring, section[:384], fourVariableFolds());
        NativeWhirInitial.Query memory q = NativeWhirInitial.firstQuery(fold, section[384:]);
        return keccak256(abi.encode(NativeFold.firstRows(caps, fold, q, opening)));
    }

    function testFuzzQueryOrder(bytes32 seed) external pure {
        uint256[71] memory draws;
        for (uint256 i; i < 71; ++i) {
            draws[i] = uint256(keccak256(abi.encode(seed, i))) % 11;
        }
        (uint256[] memory ids, uint256[71] memory ranks) = NativeFold.queryOrder(draws);
        for (uint256 i; i < 71; ++i) {
            require(ids[ranks[i]] == draws[i]);
        }
        for (uint256 i = 1; i < ids.length; ++i) {
            require(ids[i - 1] < ids[i]);
        }
    }
    // Component harness. The enclosing PCS supplies both commitments, indices and point.

    function checkPaired(
        bytes32[2] memory caps,
        uint256 depth,
        uint256[] memory indices,
        uint192[] memory point,
        bytes calldata main,
        bytes calldata fixedRows,
        bytes32[] calldata mainPath,
        bytes32[] calldata fixedPath
    ) external pure returns (uint192[] memory folded) {
        return NativeFold.verifyPaired(caps, depth, indices, point, main, fixedRows, mainPath, fixedPath);
    }

    function testFuzzPairedFold(bytes32 seed) external view {
        bytes memory main = new bytes(256);
        bytes memory wiring = new bytes(128);
        uint192[64] memory cells;
        for (uint256 i; i < 48; ++i) {
            uint64 word = uint64(uint256(keccak256(abi.encode(seed, i))));
            cells[i] = word;
            for (uint256 j; j < 8; ++j) {
                if (i < 32) main[8 * i + j] = bytes1(uint8(word >> (8 * j)));
                else wiring[8 * (i - 32) + j] = bytes1(uint8(word >> (8 * j)));
            }
        }
        uint192[] memory point = new uint192[](6);
        for (uint256 d; d < 6; ++d) {
            uint192 r = uint192(uint256(keccak256(abi.encode(seed, 48 + d))));
            point[5 - d] = r;
            for (uint256 i; i < 32 >> d; ++i) {
                uint192 a = cells[2 * i];
                cells[i] = a ^ NativeField.mul(r, a ^ cells[2 * i + 1]);
            }
        }
        bytes32[2] memory caps = [keccak256(main), keccak256(wiring)];
        uint256[] memory indices = new uint256[](1);
        bytes32[] memory path = new bytes32[](0);
        uint192[] memory got = this.checkPaired(caps, 0, indices, point, main, wiring, path, path);
        require(got.length == 1 && got[0] == cells[0]);
    }
}

contract NativeFoldTestFour is NativeFoldTest {
    function fourVariableFolds() internal pure override returns (bool) {
        return true;
    }
}
