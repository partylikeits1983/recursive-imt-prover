// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {RootFixtures} from "./NativeAggregateRoot.t.sol";
import {WhirMerkle} from "../contracts/prime/WhirMerkle.sol";

contract NibbleOpeningTest {
    RootFixtures private constant VM = RootFixtures(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant FULL_ROOT = 0x0831872856e3e362a1cd7aef4db53045c94a3b1bd914d08ab702d919430a61d9;

    function deploy(string memory artifact) private returns (address instance) {
        bytes memory code = VM.getCode(artifact);
        assembly ("memory-safe") { instance := create(0, add(code, 32), mload(code)) }
        require(instance.code.length != 0);
    }

    function testDenseDigitOpeningAndChangedLastPath() external {
        address v = deploy("NibbleOpeningVerifier.sol:SampleNibbleOpeningVerifier");
        bytes memory data = VM.readFileBinary("test/fixtures/whir-nibbles19-dense.bin");
        (bool ok, bytes memory result) = v.staticcall(data);
        require(ok && abi.decode(result, (bool)));
        uint256 offset;
        uint256 length;
        assembly ("memory-safe") {
            offset := mload(add(data, 196))
            length := mload(add(add(data, 36), offset))
        }
        data[4 + offset + 32 + length - 1] ^= 0x01;
        (ok, result) = v.staticcall(data);
        require(!ok && result.length >= 4);
    }

    function testFullProfileWithSingleNonzeroCoefficient() external {
        address v = deploy("NibbleOpeningVerifier.sol:NibbleOpeningVerifier");
        bytes memory data = VM.readFileBinary("test/fixtures/whir-nibbles28-profile.bin");
        (bool ok, bytes memory result) = v.staticcall(data);
        require(ok && abi.decode(result, (bool)));
        data[4 + 127] ^= 0x01;
        (ok, result) = v.staticcall(data);
        require(!ok && result.length >= 4);
    }

    function testFullKeccakReductionMatchesNativeCoordinatesAndLanes() external {
        address v = deploy("KeccakSegmentReduction.sol:KeccakSegmentReduction192");
        bytes memory data = VM.readFileBinary("test/fixtures/keccak-segments192-full.bin");
        (bool ok, bytes memory result) = v.staticcall(data);
        require(ok && keccak256(result) == 0x88971a819060849ae1a4ebb6bf57c41a468b0bdffde28a6f19aabed8cc503279);
    }

    function checkLinkedTransitions(
        string memory fixture,
        string memory pcsArtifact,
        string memory verifierArtifact,
        uint256 n
    ) private {
        address gkr = deploy("KeccakSegmentReduction.sol:KeccakSegmentReduction192");
        address pcs = deploy(pcsArtifact);
        bytes memory init = bytes.concat(VM.getCode(verifierArtifact), abi.encode(gkr, pcs));
        address verifier;
        assembly ("memory-safe") { verifier := create(0, add(init, 32), mload(init)) }
        require(verifier.code.length != 0);
        bytes memory data = VM.readFileBinary(fixture);
        (bool ok, bytes memory result) = verifier.staticcall(data);
        require(ok && abi.decode(result, (bool)));
        // Both reduction layers bind all three moments of the same committed digits.
        uint256 off;
        assembly ("memory-safe") { off := mload(add(add(data, 36), mul(30, 32))) }
        data[4 + off + 32 + 120 * n + 47] ^= 0x01;
        (ok, result) = verifier.staticcall(data);
        require(!ok && result.length >= 4);
    }

    function testLinkedSampleChecksRoundsDigitsAndOpening() external {
        checkLinkedTransitions(
            "test/fixtures/keccak-nibble-transitions128.bin",
            "NibbleOpeningVerifier.sol:SampleNibbleOpeningVerifier",
            "TerminalNibbleVerifier.sol:SampleTerminalNibbleVerifier",
            19
        );
    }

    function testFullLinkedRoundsDigitsAndOpening() external {
        checkLinkedTransitions(
            "test/fixtures/keccak-nibble-transitions-full.bin",
            "NibbleOpeningVerifier.sol:NibbleOpeningVerifier",
            "TerminalNibbleVerifier.sol:TerminalNibbleVerifier",
            28
        );
    }

    // The fixed read set exercises two cosets, one duplicate and adjacent leaves.
    // WHIR's full query schedule is tested separately above.
    function checkInitialPaths(bytes calldata hints) external pure {
        bytes32 seed = keccak256(abi.encodePacked("recursive-imt/cap-opening-control/v1", FULL_ROOT));
        uint256 first = uint32(bytes4(seed)) % (1 << 29);
        uint256 second = uint32(bytes4(seed << 32)) % (1 << 29);
        uint256[] memory indices = new uint256[](5);
        indices[0] = first;
        indices[1] = first ^ 1;
        indices[2] = second;
        indices[3] = first;
        indices[4] = second | ((1 << 24) - 1);
        require(bytes8(hints[:8]) == hex"5000000000000000");
        uint256 pos = 8;
        bytes32[] memory hashes = new bytes32[](5);
        for (uint256 i; i < 5; ++i) {
            hashes[i] = keccak256(hints[pos:pos + 384]);
            pos += 384;
        }
        require(WhirMerkle.verify(FULL_ROOT, indices, hashes, 29, hints, pos) == hints.length);
    }

    function testInitialOpeningOnFullActualTable() external view {
        bytes memory data = VM.readFileBinary("test/fixtures/nibbles-full-initial-paths.bin");
        this.checkInitialPaths(data);
        data[data.length - 1] ^= 0x01;
        (bool ok,) = address(this).staticcall(abi.encodeCall(this.checkInitialPaths, (data)));
        require(!ok);
    }
}
