// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {RootFixtures} from "./NativeAggregateRoot.t.sol";

contract TerminalDigitTest {
    RootFixtures private constant VM = RootFixtures(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private verifier;

    function deploy(string memory artifact, bytes memory args) private returns (address instance) {
        bytes memory init = bytes.concat(VM.getCode(artifact), args);
        assembly ("memory-safe") { instance := create(0, add(init, 32), mload(init)) }
        require(instance.code.length != 0);
    }

    function setUp() external {
        address gkr = deploy("KeccakSegmentReduction.sol:KeccakSegmentReduction", "");
        address opening = deploy("TerminalDigitVerifier.sol:DigitOpeningVerifier", "");
        verifier = deploy("TerminalDigitVerifier.sol:TerminalDigitVerifier", abi.encode(gkr, opening));
    }

    function testBothEndpointsRangeAndPublicNodeOn512Rows() external view {
        bytes memory data = VM.readFileBinary("test/fixtures/terminal-closed-digits512.bin");
        (bool ok, bytes memory result) = verifier.staticcall(data);
        require(ok && abi.decode(result, (bool)));
    }

    function testChangedDigitEvaluationReverts() external view {
        bytes memory data = VM.readFileBinary("test/fixtures/terminal-closed-digits512.bin");
        // The WHIR proof follows the 110 digit-sumcheck evaluations and the opening value.
        uint256 start;
        assembly ("memory-safe") { start := mload(add(add(data, 36), mul(31, 32))) }
        data[4 + start - 1] ^= 0x01;
        (bool ok, bytes memory reason) = verifier.staticcall(data);
        require(!ok && reason.length >= 4);
    }
}
