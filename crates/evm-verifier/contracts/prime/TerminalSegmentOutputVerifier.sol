// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TerminalSegmentTable} from "./TerminalSegmentVerifier.sol";
import {WHIR_PRIME as P} from "./WhirTranscript.sol";

/// Reduces a WHIR-authenticated packed-output evaluation to 25 bit-lane claims.
/// A permutation argument must discharge these claims at the returned point.
contract TerminalSegmentOutputVerifier is TerminalSegmentTable {
    function reduceOutput(
        bytes32 parent,
        bytes32 left,
        bytes32 right,
        bytes32 root,
        uint256[2] calldata readings,
        bytes calldata proof,
        bytes calldata hints,
        uint256[37] calldata bridge
    ) external view returns (uint256[25] memory point, uint256[25] memory lanes) {
        (uint256[22] memory outputPoint, bytes32 context, uint256 value) =
            checkTable(parent, left, right, root, readings, proof, hints);
        bytes32 cv = keccak256(abi.encodePacked("recursive-imt/packed-output-bits/v1", context, root, readings, value));
        for (uint256 i; i < 19; ++i) {
            point[i] = outputPoint[i];
        }
        uint256 sum = readings[1];
        for (uint8 k; k < 6; ++k) {
            uint256 c0 = bridge[2 * k];
            uint256 c2 = bridge[2 * k + 1];
            if (c0 >= P || c2 >= P) revert InvalidStatement();
            cv = keccak256(abi.encodePacked(cv, k, c0, c2));
            uint256 r = challenge(cv, 4, k);
            point[19 + k] = r;
            uint256 c1 = addmod(sum, P - addmod(addmod(c0, c0, P), c2, P), P);
            sum = addmod(c0, mulmod(r, addmod(c1, mulmod(r, c2, P), P), P), P);
        }
        uint256[8] memory chunks = eq3(outputPoint, 19);
        uint256[4] memory high;
        for (uint256 i; i < 4; ++i) {
            uint256 first = (i & 2) != 0 ? point[19] : P + 1 - point[19];
            uint256 second = (i & 1) != 0 ? point[20] : P + 1 - point[20];
            high[i] = mulmod(first, second, P);
        }
        uint256 low = 1;
        for (uint256 i; i < 4; ++i) {
            low = mulmod(low, addmod(1, mulmod((1 << (1 << i)) - 1, point[24 - i], P), P), P);
        }
        // Each 16-bit block is entirely inside one 240-bit chunk. The low four
        // bit coordinates have the same weighted sum for every block.
        uint256 check;
        for (uint256 lane; lane < 25; ++lane) {
            uint256 weight;
            for (uint256 h; h < 4; ++h) {
                uint256 bit = 64 * lane + 16 * h;
                uint256 scale = mulmod(chunks[bit / 240], 1 << (bit % 240), P);
                weight = addmod(weight, mulmod(high[h], scale, P), P);
            }
            lanes[lane] = bridge[12 + lane];
            if (lanes[lane] >= P) revert InvalidStatement();
            check = addmod(check, mulmod(weight, lanes[lane], P), P);
        }
        if (sum != mulmod(low, check, P)) revert InvalidFinalSum();
    }
}
