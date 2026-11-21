// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {PrimeWhirReduction, PrimeWhirOpeningVerifier} from "../contracts/prime/PrimeWhirOpeningVerifier.sol";
import {WhirMerkle} from "../contracts/prime/WhirMerkle.sol";
import {WHIR_PRIME, WhirField} from "../contracts/prime/WhirTranscript.sol";

interface PrimeFixtureFiles {
    function readFileBinary(string calldata path) external view returns (bytes memory);
}

contract PrimeWhirOpeningTest {
    PrimeFixtureFiles private constant VM = PrimeFixtureFiles(address(uint160(uint256(keccak256("hevm cheat code")))));
    PrimeWhirOpeningVerifier private verifier;

    function setUp() external {
        verifier = new PrimeWhirOpeningVerifier();
    }

    function fixture() private view returns (bytes memory) {
        return VM.readFileBinary("test/fixtures/prime-whir-opening.bin");
    }

    function testReferenceOpening() external view {
        (bool ok, bytes memory result) = address(verifier).staticcall(fixture());
        require(ok && abi.decode(result, (bool)));
    }

    function assertError(bytes memory data, bytes4 expected) private view {
        (bool ok, bytes memory result) = address(verifier).staticcall(data);
        require(!ok && result.length >= 4 && bytes4(result) == expected);
    }

    function testNoncanonicalCoordinate() external view {
        bytes memory data = fixture();
        assembly ("memory-safe") { mstore(add(data, 100), WHIR_PRIME) }
        assertError(data, PrimeWhirReduction.InvalidStatement.selector);
    }

    function testNoncanonicalRow() external view {
        bytes memory data = fixture();
        uint256 encoded = WhirField.reverse(WHIR_PRIME);
        assembly ("memory-safe") {
            let args := add(data, 36)
            let hints := add(args, mload(add(args, 832)))
            mstore(add(hints, 40), encoded)
        }
        assertError(data, WhirField.NonCanonicalField.selector);
    }

    function testIncorrectFinalSumcheck() external view {
        bytes memory data = fixture();
        assembly ("memory-safe") {
            let args := add(data, 36)
            let proof := add(args, mload(add(args, 800)))
            let addr := add(proof, mload(proof))
            mstore8(addr, xor(byte(0, mload(addr)), 1))
        }
        assertError(data, PrimeWhirReduction.InvalidFinalSum.selector);
    }

    function testExtraAndMissingSiblingRejected() external view {
        bytes memory data = bytes.concat(fixture(), bytes32(0));
        uint256 hints;
        uint256 length;
        assembly ("memory-safe") {
            let args := add(data, 36)
            hints := add(args, mload(add(args, 832)))
            length := mload(hints)
            mstore(hints, add(length, 32))
        }
        assertError(data, PrimeWhirReduction.InvalidProof.selector);
        assembly ("memory-safe") { mstore(hints, sub(length, 1)) }
        assertError(data, WhirMerkle.InvalidOpening.selector);
    }

    // Index sampling is with replacement in this fixed profile.
    function duplicateOpening(bytes32 duplicate, bytes calldata hints) external pure returns (uint256) {
        uint256[] memory indices = new uint256[](3);
        indices[0] = 1;
        indices[2] = 1;
        bytes32[] memory hashes = new bytes32[](3);
        hashes[0] = bytes32(uint256(9));
        hashes[1] = bytes32(uint256(2));
        hashes[2] = duplicate;
        bytes32 root = keccak256(abi.encode(hashes[1], hashes[0]));
        return WhirMerkle.verify(root, indices, hashes, 1, hints, 0);
    }

    function testDuplicateAndUnsortedQueries() external view {
        require(this.duplicateOpening(bytes32(uint256(9)), "") == 0);
        (bool ok, bytes memory reason) =
            address(this).staticcall(abi.encodeCall(this.duplicateOpening, (bytes32(0), "")));
        require(!ok && bytes4(reason) == WhirMerkle.InvalidOpening.selector);
    }
}
