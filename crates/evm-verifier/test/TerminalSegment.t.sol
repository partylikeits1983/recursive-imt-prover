// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TerminalSegmentVerifier} from "../contracts/prime/TerminalSegmentVerifier.sol";
import {PrimeWhirReduction} from "../contracts/prime/PrimeWhirOpeningVerifier.sol";
import {KeccakSegmentRow} from "../contracts/prime/KeccakSegmentRow.sol";
import {WHIR_PRIME, WhirField} from "../contracts/prime/WhirTranscript.sol";

interface SegmentFixture {
    function readFileBinary(string calldata path) external view returns (bytes memory);
}

contract TerminalSegmentTest {
    SegmentFixture private constant VM = SegmentFixture(address(uint160(uint256(keccak256("hevm cheat code")))));
    TerminalSegmentVerifier private verifier;

    function setUp() external {
        verifier = new TerminalSegmentVerifier();
    }

    function fixture() private view returns (bytes memory) {
        return VM.readFileBinary("test/fixtures/terminal-segments.bin");
    }

    function testBothSegmentEndpointReadings() external view {
        (bool ok, bytes memory result) = address(verifier).staticcall(fixture());
        require(ok && abi.decode(result, (bool)));
    }

    function testNoncanonicalSegmentReading() external view {
        bytes memory data = fixture();
        assembly ("memory-safe") { mstore(add(data, 164), WHIR_PRIME) }
        (bool ok, bytes memory result) = address(verifier).staticcall(data);
        require(!ok && bytes4(result) == PrimeWhirReduction.InvalidStatement.selector);
    }

    function testFuzzPackedFinalStateMatchesEvm(bytes32 first, bytes32 second, bytes32 third) external pure {
        bytes memory message = abi.encodePacked(first, second, third);
        bytes memory padded = abi.encodePacked(message, hex"01", new bytes(38), hex"80", new bytes(64));
        uint256[64] memory row = KeccakSegmentRow.row(padded);
        uint256 digestLE = row[7] | ((row[15] & 0xffff) << 240);
        require(bytes32(WhirField.reverse(digestLE)) == keccak256(message));
        require(row[63] == 0);
    }
}
