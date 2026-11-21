// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BinaryExtension as E} from "./BinaryExtension.sol";
import {BinaryTerminalProfile as P} from "./BinaryTerminalProfile.sol";
import {BinaryTerminalTranscript} from "./BinaryTerminalTranscript.sol";
import {BinaryWhir} from "./BinaryWhir.sol";

/// Weights the VM's column claims at the terminal WHIR evaluation point.
/// All operand indices and selectors come from the fixed program's layout.
contract BinaryStackBasis {
    function u16(bytes memory program, uint256 cursor) private pure returns (uint256 n) {
        assembly ("memory-safe") { n := shr(240, mload(add(add(program, 32), cursor))) }
    }

    function operand(bytes32[] calldata hashes, bytes memory program, uint256 cursor) private pure returns (uint256) {
        uint256 index = u16(program, cursor);
        if (index < 2) return index;
        return sample(hashes, index - 2);
    }

    function sample(bytes32[] calldata hashes, uint256 index) private pure returns (uint256) {
        return BinaryTerminalTranscript.little128(uint128(bytes16(hashes[index])));
    }

    function selectors(uint256[24] memory x) private pure returns (uint256[] memory tree) {
        tree = new uint256[](P.SELECTORS);
        tree[1] = 1;
        bytes memory plan = P.BASIS_PARENTS;
        for (uint256 i; i < plan.length; i += 5) {
            uint256 variable = x[uint8(plan[i])];
            uint256 end = u16(plan, i + 3);
            for (uint256 n = u16(plan, i + 1); n < end; ++n) {
                uint256 right = E.mul(tree[n], variable);
                tree[2 * n] = tree[n] ^ right;
                tree[2 * n + 1] = right;
            }
        }
    }

    function ringWeight(bytes32[] calldata hashes, uint256[24] memory x) private pure returns (uint256 weight) {
        bytes memory coords = P.RING_POINT;
        uint256 width = coords.length / 2;
        uint256[24] memory point;
        for (uint256 i; i < width; ++i) {
            point[i] = operand(hashes, coords, 2 * i);
        }
        uint256[8] memory g;
        for (uint256 b; b < 8; ++b) {
            g[b] = sample(hashes, P.RING_CHALLENGES + 8 + b);
        }
        for (uint256 p; p < 8; ++p) {
            uint256 blockWeight;
            for (uint256 b; b < 8; ++b) {
                uint256 term = g[b];
                for (uint256 i; i < width; ++i) {
                    term = E.mul(term, 1 ^ point[i] ^ x[i]);
                    point[i] = E.square(point[i]);
                }
                blockWeight ^= term;
                if (p < 7) {
                    uint256 v = g[b];
                    for (uint256 j; j < 8; ++j) {
                        v = E.square(v);
                    }
                    g[b] = v;
                }
            }
            weight ^= E.mul(blockWeight, sample(hashes, P.RING_CHALLENGES + p));
        }
    }

    function derive(bytes32[] calldata hashes) external pure returns (uint256) {
        uint256[24] memory folds = BinaryWhir.pointOf(hashes);
        uint256[24] memory x;
        for (uint256 i; i < 24; ++i) {
            x[i] = folds[(i + P.FIRST_FOLD) % 24];
        }
        uint256[] memory tree = selectors(x);
        uint256 r = sample(hashes, P.RING_CHALLENGES + 16);
        bytes memory plan = P.BASIS_GROUPS;
        uint256 acc;
        uint256 cursor;
        while (cursor < plan.length) {
            uint256 width = uint8(plan[cursor++]);
            uint256 count = uint8(plan[cursor++]);
            uint256 prefix = 1;
            for (uint256 i; i < width; ++i) {
                prefix = E.mul(prefix, 1 ^ operand(hashes, plan, cursor) ^ x[i]);
                cursor += 2;
            }
            for (uint256 i; i < count; ++i) {
                acc = E.mul(r, acc) ^ E.mul(prefix, tree[u16(plan, cursor)]);
                cursor += 2;
            }
        }
        return E.mul(r, acc) ^ E.mul(tree[P.RING_SELECTOR], ringWeight(hashes, x));
    }
}
