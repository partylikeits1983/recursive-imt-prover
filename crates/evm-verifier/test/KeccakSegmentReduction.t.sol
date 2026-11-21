// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {KeccakSegmentReduction} from "../contracts/prime/KeccakSegmentReduction.sol";
import {WHIR_PRIME} from "../contracts/prime/WhirTranscript.sol";

interface SegmentGkrFixture {
    function readFileBinary(string calldata path) external view returns (bytes memory);
}

contract KeccakSegmentReductionTest {
    SegmentGkrFixture private constant VM = SegmentGkrFixture(address(uint160(uint256(keccak256("hevm cheat code")))));
    KeccakSegmentReduction private verifier;

    function setUp() external {
        verifier = new KeccakSegmentReduction();
    }

    function testThreeRoundsAtAllEightSegmentPositions() external view {
        bytes memory data = VM.readFileBinary("test/fixtures/terminal-segment-gkr.bin");
        (bool ok, bytes memory result) = address(verifier).staticcall(data);
        require(ok && keccak256(result) == 0x8bc12e2a2728b1f013af147561785ebe4d5ddcc13e1398755b0d963178f7b495);
    }

    function testNoncanonicalSumcheckCoefficient() external view {
        bytes memory data = VM.readFileBinary("test/fixtures/terminal-segment-gkr.bin");
        assembly ("memory-safe") {
            let args := add(data, 36)
            let proof := add(args, mload(add(args, 864)))
            mstore(add(proof, 64), WHIR_PRIME)
        }
        (bool ok, bytes memory result) = address(verifier).staticcall(data);
        require(!ok && bytes4(result) == KeccakSegmentReduction.InvalidEncoding.selector);
    }
}
