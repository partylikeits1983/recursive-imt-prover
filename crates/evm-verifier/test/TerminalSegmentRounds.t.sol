// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TerminalSegmentRoundsVerifier} from "../contracts/prime/TerminalSegmentRoundsVerifier.sol";
import {RootFixtures} from "./NativeAggregateRoot.t.sol";

contract TerminalSegmentRoundsTest {
    RootFixtures private constant VM = RootFixtures(address(uint160(uint256(keccak256("hevm cheat code")))));
    TerminalSegmentRoundsVerifier private verifier;
    address private roundsModule;

    function deploy(string memory name, bytes memory args) private returns (address instance) {
        bytes memory init = bytes.concat(VM.getCode(string.concat(name, ".sol:", name)), args);
        assembly ("memory-safe") {
            instance := create(0, add(init, 32), mload(init))
        }
        require(instance.code.length != 0);
    }

    function setUp() external {
        address table = deploy("TerminalSegmentOutputVerifier", "");
        roundsModule = deploy("KeccakSegmentReduction", "");
        verifier =
            TerminalSegmentRoundsVerifier(deploy("TerminalSegmentRoundsVerifier", abi.encode(table, roundsModule)));
    }

    function reduce(bytes calldata table, bytes calldata rounds) external view returns (bytes32) {
        (
            bytes32 parent,
            bytes32 left,
            bytes32 right,
            bytes32 root,
            uint256[2] memory readings,
            bytes memory proof,
            bytes memory hints
        ) = abi.decode(table[4:], (bytes32, bytes32, bytes32, bytes32, uint256[2], bytes, bytes));
        uint256[37] memory bridge =
            abi.decode(VM.readFileBinary("test/fixtures/terminal-output-bits.bin"), (uint256[37]));
        (uint256[] memory point, uint256[25] memory lanes) =
            verifier.reduceTransitions(parent, left, right, root, readings, proof, hints, bridge, rounds);
        return keccak256(abi.encode(point, lanes));
    }

    function testFullTableReturnsNativeInputClaims() external view {
        bytes memory table = VM.readFileBinary("test/fixtures/terminal-segments.bin");
        bytes memory rounds = VM.readFileBinary("test/fixtures/terminal-linked-rounds.bin");
        require(this.reduce(table, rounds) == 0xe2a00f03e1d14deddc500205cad3772036d78a64c3ecce94fe6cb7f91b04418e);
    }

    function testChangedLastRoundReverts() external view {
        bytes memory table = VM.readFileBinary("test/fixtures/terminal-segments.bin");
        bytes memory rounds = VM.readFileBinary("test/fixtures/terminal-linked-rounds.bin");
        rounds[rounds.length - 1] ^= 0x01;
        (bool ok, bytes memory reason) = address(this).staticcall(abi.encodeCall(this.reduce, (table, rounds)));
        require(!ok && reason.length >= 4);
    }

    function testRate32UsesItsPinnedDomainAndReturnsNativeInputClaims() external {
        address table = deploy("TerminalSegmentOutputVerifierRate32", "");
        address verifier32 = deploy("TerminalSegmentRoundsVerifier", abi.encode(table, roundsModule));
        bytes memory data = VM.readFileBinary("test/fixtures/terminal-segment-rounds-rate32.bin");
        (bool ok, bytes memory result) = verifier32.staticcall(data);
        require(ok && keccak256(result) == 0x93e783ab04fe4c7c7d076e0b4f7cc27051833b3ca2da2f7843570a17320d4834);
        (ok, result) = address(verifier).staticcall(data);
        require(!ok && result.length >= 4);
    }
}
