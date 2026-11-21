// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TerminalNodePortsVerifier} from "../contracts/prime/TerminalNodePortsVerifier.sol";
import {PrimeWhirReduction, PrimeWhirOpeningVerifier} from "../contracts/prime/PrimeWhirOpeningVerifier.sol";

interface NodePortFixture {
    function readFileBinary(string calldata path) external view returns (bytes memory);
}

contract TerminalNodePortsTest {
    NodePortFixture private constant VM = NodePortFixture(address(uint160(uint256(keccak256("hevm cheat code")))));
    TerminalNodePortsVerifier private verifier;

    function setUp() external {
        verifier = new TerminalNodePortsVerifier();
    }

    function testBothNativeInstances() external view {
        bytes memory data = VM.readFileBinary("test/fixtures/terminal-node-ports.bin");
        (bool ok, bytes memory result) = address(verifier).staticcall(data);
        require(ok && abi.decode(result, (bool)));
    }

    function testReorderedValidParentCannotReuseProof() external view {
        bytes memory data = VM.readFileBinary("test/fixtures/terminal-node-ports.bin");
        bytes32 left;
        bytes32 right;
        assembly ("memory-safe") {
            left := mload(add(data, 68))
            right := mload(add(data, 100))
        }
        bytes32 reordered = keccak256(abi.encodePacked("IMT-AGG-NODE-V2", right, uint8(32), left, uint8(32)));
        assembly ("memory-safe") {
            mstore(add(data, 36), reordered)
            mstore(add(data, 68), right)
            mstore(add(data, 100), left)
        }
        (bool ok, bytes memory result) = address(verifier).staticcall(data);
        require(!ok && bytes4(result) == PrimeWhirReduction.InvalidWork.selector);
    }
}
