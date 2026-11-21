// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WiringPage} from "../contracts/imt/FixedWiringCap.sol";

interface RootFixtures {
    function getCode(string calldata artifact) external view returns (bytes memory);
    function readFileBinary(string calldata path) external view returns (bytes memory);
}

abstract contract RootFixtureTest {
    RootFixtures internal constant VM = RootFixtures(address(uint160(uint256(keccak256("hevm cheat code")))));
    function profile()
        internal
        pure
        virtual
        returns (bytes32 authority, string memory contractPrefix, string memory fixturePrefix);
    bytes32 internal constant FIXED = 0xb6de4fa6b94cdd6d7ee0255ae4bf97f1a10cbb2a783b847f77cd8083b3a2e30b;
    address internal verifier;
    string internal fixture;

    function deploy(string memory artifact, bytes memory args) internal returns (address instance) {
        bytes memory init = bytes.concat(VM.getCode(artifact), args);
        assembly ("memory-safe") { instance := create(0, add(init, 32), mload(init)) }
        require(instance.code.length != 0);
    }

    function pages(string memory file) private returns (address[4] memory deployed) {
        bytes memory data = VM.readFileBinary(file);
        require(data.length > 0 && data.length <= 65536);
        for (uint256 start; start < data.length; start += 16384) {
            bytes memory chunk = new bytes(16384);
            uint256 n = data.length - start;
            if (n > 16384) n = 16384;
            assembly ("memory-safe") { mcopy(add(chunk, 32), add(add(data, 32), start), n) }
            deployed[start / 16384] = address(new WiringPage(chunk));
        }
    }

    function openingVerifier(bytes32 authority) internal virtual returns (address) {
        return deploy("NativeBitOpeningVerifier.sol:NativeBitOpeningVerifierFour", abi.encode(authority, FIXED));
    }

    function setUp() public virtual {
        (bytes32 authority, string memory prefix, string memory filePrefix) = profile();
        fixture = string.concat("test/fixtures/", filePrefix, "-root-call.bin");
        address[4] memory bus = pages("test/fixtures/terminal-bus-domain.bin");
        address[4] memory air = pages("test/fixtures/terminal-air-program.bin");
        address arithmetic =
            deploy("NativeAirClosingVerifier.sol:NativeAirClosingVerifier", abi.encode(authority, FIXED, bus, air));
        address relation =
            deploy(string.concat("NativeRootRelation.sol:", prefix, "RootRelation"), abi.encode(authority, arithmetic));
        address[4] memory layout = pages(string.concat("test/fixtures/", filePrefix, "-column-geometry.bin"));
        address columns =
            deploy(string.concat("NativeColumnVerifier.sol:", prefix, "ColumnVerifier"), abi.encode(layout[0]));
        address opening = openingVerifier(authority);
        verifier = deploy(
            string.concat("NativeAggregateRootVerifier.sol:", prefix, "AggregateRootVerifier"),
            abi.encode(relation, columns, opening)
        );
    }

    function testVerified64ClientRoot() external view {
        bytes memory proof = VM.readFileBinary(fixture);
        (bool ok, bytes memory accepted) = verifier.staticcall(proof);
        require(ok && abi.decode(accepted, (bool)));
    }

    function testDifferentExpectedDigestAndFinalOpeningRevert() external view {
        bytes memory proof = VM.readFileBinary(fixture);
        proof[4] ^= 0x01;
        (bool ok, bytes memory reason) = verifier.staticcall(proof);
        require(!ok && reason.length >= 4);
        proof[4] ^= 0x01;
        // Follow the native closing-wire offset inside the last dynamic tuple.
        uint256 pcs;
        uint256 closing;
        assembly ("memory-safe") {
            let payload := add(proof, 36)
            pcs := mload(add(payload, 160))
            closing := mload(add(add(payload, pcs), 128))
        }
        proof[4 + pcs + closing + 32] ^= 0x01;
        (ok, reason) = verifier.staticcall(proof);
        require(!ok && reason.length >= 4);
    }
}

contract NativeAggregateRootTest is RootFixtureTest {
    function profile() internal pure override returns (bytes32, string memory, string memory) {
        return (0x6d999ec770660eb927350bedaa1d877b45defe1e46c48c6aed6cd12b07d81624, "Native", "terminal");
    }
}

contract NativeMidpointAggregateRootTest is RootFixtureTest {
    function profile() internal pure override returns (bytes32, string memory, string memory) {
        return
            (0xca78c9d60b8987ef35bc0e9453708c76994c4a60c844dd9f1673c6a4bd0130f1, "NativeMidpoint", "terminal-midpoint");
    }

    function testRejectsComparisonProofOfSameStatement() external view {
        bytes memory comparison = VM.readFileBinary("test/fixtures/terminal-midpoint-comparison-root-call.bin");
        (bool ok, bytes memory reason) = verifier.staticcall(comparison);
        require(!ok && reason.length >= 4);
    }

    function testChangedMidpointOpeningReverts() external view {
        bytes memory proof = VM.readFileBinary(fixture);
        uint256 relation;
        uint256 evaluations;
        assembly ("memory-safe") {
            let head := add(proof, 36)
            relation := mload(add(head, 96))
            evaluations := mload(add(add(head, relation), 64))
        }
        proof[4 + relation + evaluations + 32 + 617 * 24] ^= 0x01;
        (bool ok, bytes memory reason) = verifier.staticcall(proof);
        require(!ok && reason.length >= 4);
    }
}
