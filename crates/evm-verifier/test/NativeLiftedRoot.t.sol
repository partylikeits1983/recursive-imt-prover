// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WiringPage} from "../contracts/imt/FixedWiringCap.sol";
import {NativeMidpointAggregateRootTest} from "./NativeAggregateRoot.t.sol";

/// The complete native 64-client statement with its WHIR row evaluations certified in Field192.
contract NativeLiftedRootTest is NativeMidpointAggregateRootTest {
    function openingVerifier(bytes32 authority) internal override returns (address) {
        bytes memory cap = VM.readFileBinary("test/fixtures/terminal-fixed-cap.bin");
        require(cap.length == 8 * 16384);
        address[8] memory pages;
        for (uint256 i; i < pages.length; ++i) {
            bytes memory chunk = new bytes(16384);
            assembly ("memory-safe") { mcopy(add(chunk, 32), add(add(cap, 32), shl(14, i)), 16384) }
            pages[i] = address(new WiringPage(chunk));
        }
        address pcs = deploy("NibbleOpeningVerifier.sol:SampleNibbleOpeningVerifier", "");
        address folds = deploy("NativeWhirFoldProof.sol:NativeWhirFoldProof", abi.encode(pcs));
        return deploy("NativeLiftedOpening.sol:NativeLiftedOpening", abi.encode(authority, FIXED, pages, folds));
    }

    function setUp() public override {
        super.setUp();
        fixture = "test/fixtures/terminal-midpoint-lifted.bin";
    }

    function testAlteredFoldEvaluationReverts() external view {
        bytes memory proof = VM.readFileBinary(fixture);
        uint256 batch;
        assembly ("memory-safe") { batch := mload(add(add(proof, 36), 128)) }
        // Skip the ABI length, native batching and ring proof, then the new table commitment.
        uint256 values = 4 + batch + 32 + (65 + 1 + 8 * 28 + 192) * 24 + 32;
        proof[values + 71 * 24] ^= 0x01;
        (bool ok, bytes memory reason) = verifier.staticcall(proof);
        require(!ok && reason.length >= 4);
    }
}
