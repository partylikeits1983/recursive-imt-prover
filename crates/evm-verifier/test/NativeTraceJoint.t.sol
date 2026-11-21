// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {RootFixtures} from "./NativeAggregateRoot.t.sol";

contract NativeTraceJointTest {
    RootFixtures private constant VM = RootFixtures(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private checker;

    function deploy(string memory artifact, bytes memory args) private returns (address a) {
        bytes memory code = bytes.concat(VM.getCode(artifact), args);
        assembly ("memory-safe") { a := create(0, add(code, 32), mload(code)) }
        require(a.code.length != 0);
    }

    function setUp() external {
        address pcs = deploy("NibbleOpeningVerifier.sol:NativeTraceOpeningVerifier", "");
        address folds = deploy("NativeWhirFoldProof.sol:NativeTraceFoldProof", abi.encode(pcs));
        address gkr = deploy("KeccakSegmentReduction.sol:KeccakSegmentReduction192", "");
        address rounds = deploy("TerminalNibbleVerifier.sol:NativeTraceKeccakReduction", abi.encode(gkr, pcs));
        address pair = deploy("NibbleOpeningVerifier.sol:NativeTracePairOpeningVerifier", "");
        checker = deploy("NativeTraceJointProof.sol:NativeTraceJointProof", abi.encode(folds, rounds, pair));
    }

    function testBothIdentitiesAndChangedInputs() external view {
        bytes memory data = VM.readFileBinary("test/fixtures/native-trace-joint.bin");
        (bool ok, bytes memory result) = checker.staticcall(data);
        require(ok && abi.decode(result, (bool)));
        uint256 rows;
        uint256 hints;
        assembly ("memory-safe") {
            rows := mload(add(data, 100))
            hints := mload(add(data, 228))
        }
        // One native row, one Keccak message, and the common opening's first queried row.
        uint256[3] memory offsets = [4 + 32 + rows + 100, 4 + 32 + hints + 600, 4 + 32 + hints + 48336 + 8];
        for (uint256 i; i < offsets.length; ++i) {
            data[offsets[i]] ^= 0x01;
            (ok, result) = checker.staticcall(data);
            require(!ok && result.length >= 4);
            data[offsets[i]] ^= 0x01;
        }
    }
}
