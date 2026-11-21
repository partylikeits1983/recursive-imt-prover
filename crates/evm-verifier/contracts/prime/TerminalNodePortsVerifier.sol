// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {PrimeWhirOpeningVerifier} from "./PrimeWhirOpeningVerifier.sol";
import {WHIR_PRIME as P, WhirField} from "./WhirTranscript.sol";

/// Constrains the final ordered node's hash ports in both copies of the pinned terminal circuit.
/// A complete relation verifier must also check the remaining gates and derive checkpointRoot.
contract TerminalNodePortsVerifier {
    PrimeWhirOpeningVerifier private immutable opening = new PrimeWhirOpeningVerifier();
    bytes32 private constant KEY = 0x494900e0fa468212ed93087501b2ca91a608331d9a12070b6cc05133943e7405;
    uint256 private constant FINAL_ROW = 21670;
    error WrongParent();

    function verifyPorts(
        bytes32 parent,
        bytes32 left,
        bytes32 right,
        bytes32 checkpointRoot,
        bytes calldata proof,
        bytes calldata hints
    ) external view returns (bool) {
        bytes memory message = abi.encodePacked("IMT-AGG-NODE-V2", left, uint8(32), right, uint8(32));
        if (keccak256(message) != parent) revert WrongParent();
        bytes32 context =
            keccak256(abi.encodePacked("recursive-imt/terminal-node-ports/v1", KEY, parent, uint8(64), left, right));
        uint256[22] memory point;
        // MSB selects the child verifier. The other 15 row bits select its final node permutation.
        point[0] = challenge(context, checkpointRoot, 0);
        for (uint256 i = 1; i < 16; ++i) {
            point[i] = (FINAL_ROW >> (15 - i)) & 1;
        }
        for (uint8 i = 1; i <= 4; ++i) {
            point[17 + i] = challenge(context, checkpointRoot, i);
        }
        uint256 value = portsValue(message, parent, point);
        return opening.verify(checkpointRoot, context, point, value, proof, hints);
    }

    function challenge(bytes32 context, bytes32 root, uint8 i) private pure returns (uint256) {
        bytes memory prefix = abi.encodePacked("recursive-imt/terminal-node-query/v1", context, root, i);
        uint256 hi = uint256(keccak256(abi.encodePacked(prefix, bytes1(0))));
        uint256 lo = uint256(keccak256(abi.encodePacked(prefix, bytes1(uint8(1)))));
        return addmod(mulmod(hi, addmod(type(uint256).max, 1, P), P), lo, P);
    }

    function portsValue(bytes memory message, bytes32 parent, uint256[22] memory point) private pure returns (uint256) {
        // One 136-byte Keccak rate block with Ethereum padding, followed by the zero capacity lanes.
        bytes memory padded = abi.encodePacked(message, bytes1(uint8(1)), new bytes(53), hex"80", new bytes(72));
        uint256[16] memory words;
        for (uint256 i; i < 13; ++i) {
            uint256 x;
            assembly ("memory-safe") { x := mload(add(add(padded, 32), shl(4, i))) }
            words[i] = uint128(WhirField.reverse(x));
        }
        uint256 digest = WhirField.reverse(uint256(parent));
        words[13] = uint128(digest);
        words[14] = digest >> 128;
        // Both roles carry the same input and digest, so their expected interpolation is identical.
        for (uint256 bit; bit < 4; ++bit) {
            for (uint256 i; i < (8 >> bit); ++i) {
                uint256 a = words[2 * i];
                words[i] = addmod(a, mulmod(point[21 - bit], addmod(words[2 * i + 1], P - a, P), P), P);
            }
        }
        return words[0];
    }
}
