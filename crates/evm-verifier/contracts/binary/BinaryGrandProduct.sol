// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BinaryExtension as E} from "./BinaryExtension.sol";
import {BinaryTerminalProfile as P} from "./BinaryTerminalProfile.sol";
import {BinaryTerminalTranscript as T} from "./BinaryTerminalTranscript.sol";

/// The three grand products certify the VM's push, pull and count buses.
library BinaryGrandProduct {
    error InvalidBusProduct();

    function word(bytes memory p, uint256 i) internal pure returns (uint256 n) {
        assembly ("memory-safe") { n := shr(240, mload(add(add(p, 32), i))) }
    }

    function sample(bytes32[] calldata hashes, uint256 i) internal pure returns (uint256) {
        return T.little128(uint128(bytes16(hashes[i])));
    }

    function mix(uint256 a, uint256 b, uint256 r) internal pure returns (uint256) {
        return a ^ E.mul(r, a ^ b);
    }

    function poly3(uint256[3] memory v, uint256 x) private pure returns (uint256) {
        return v[0] ^ E.mul(x, v[1] ^ E.mul(x, v[2]));
    }

    function verify(bytes calldata stream, bytes32[] calldata hashes)
        internal pure returns (uint256[32] memory point, uint256[3] memory values)
    {
        values[0] = T.scalar(stream, P.BUS_GRAND);
        values[1] = values[0];
        values[2] = T.scalar(stream, P.BUS_GRAND + 1);
        if (values[2] == 0) revert InvalidBusProduct();
        uint256 cursor = P.BUS_GRAND + 2;
        uint256 width;
        bytes memory plan = P.BUS_LAYERS;
        for (uint256 pos; pos < plan.length; pos += 5) {
            uint256 step = uint8(plan[pos]);
            uint256 degree = 1 << step;
            uint256 first = word(plan, pos + 1);
            uint256 combiner = sample(hashes, first);
            uint256 claim = poly3(values, combiner);
            uint256[32] memory next;
            for (uint256 i; i < width; ++i) {
                uint256 r = sample(hashes, first + 1 + i);
                uint256 total;
                uint256 tail;
                for (uint256 j = degree; j != 0; --j) {
                    uint256 c = T.scalar(stream, cursor + j - 1);
                    total ^= c;
                    tail = c ^ E.mul(r, tail);
                }
                claim ^= E.mul(point[i], total) ^ E.mul(r, tail);
                cursor += degree;
                next[step + i] = r;
            }
            uint256 y = word(plan, pos + 3);
            for (uint256 i; i < step; ++i) next[i] = sample(hashes, y + i);
            uint256[3] memory products;
            for (uint256 side; side < 3; ++side) {
                uint256 a = T.scalar(stream, cursor);
                uint256 b = T.scalar(stream, cursor + 1);
                uint256 product = E.mul(a, b);
                uint256 value = mix(a, b, next[0]);
                if (step == 2) {
                    uint256 c = T.scalar(stream, cursor + 2);
                    uint256 d = T.scalar(stream, cursor + 3);
                    product = E.mul(product, E.mul(c, d));
                    value = mix(value, mix(c, d, next[0]), next[1]);
                }
                values[side] = value;
                products[side] = product;
                cursor += degree;
            }
            if (claim != poly3(products, combiner)) revert InvalidBusProduct();
            width += step;
            point = next;
        }
        assert(cursor == P.BUS_MEMORY && width == P.BUS_DEPTH);
    }
}
