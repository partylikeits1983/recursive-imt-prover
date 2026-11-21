// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TerminalSegmentOutputVerifier} from "../contracts/prime/TerminalSegmentOutputVerifier.sol";
import {SegmentFixture} from "./TerminalSegment.t.sol";

contract TerminalSegmentOutputTest {
    SegmentFixture private constant VM = SegmentFixture(address(uint160(uint256(keccak256("hevm cheat code")))));
    TerminalSegmentOutputVerifier private verifier;

    function setUp() external {
        verifier = new TerminalSegmentOutputVerifier();
    }

    function testPackedOutputReductionOnTheFullTable() external view {
        bytes memory data = VM.readFileBinary("test/fixtures/terminal-segments.bin");
        uint256[37] memory bridge =
            abi.decode(VM.readFileBinary("test/fixtures/terminal-output-bits.bin"), (uint256[37]));
        this.checkReduction(data, bridge);
    }

    function checkReduction(bytes calldata data, uint256[37] calldata bridge) external view {
        (
            bytes32 parent,
            bytes32 left,
            bytes32 right,
            bytes32 root,
            uint256[2] memory readings,
            bytes memory proof,
            bytes memory hints
        ) = abi.decode(data[4:], (bytes32, bytes32, bytes32, bytes32, uint256[2], bytes, bytes));
        (uint256[25] memory point, uint256[25] memory lanes) =
            verifier.reduceOutput(parent, left, right, root, readings, proof, hints, bridge);
        require(
            keccak256(abi.encode(point, lanes)) == 0xd805be6ea2de489c25ad97d4ecf2af8f7888a960bcff9da2f7d6a92be03bf5e5
        );
    }
}
