// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeField} from "./NativeField.sol";
import {NativeKeccak} from "./NativeKeccak.sol";

/// First nonlinear layer of the native root's packed Keccak argument.
library NativeChiLayer {
    error InvalidChiSum();
    error InvalidChiEndpoint();

    // GenericDegreeShape::new(23, 3, 0) seeded over Poly64/Poly192.
    bytes internal constant CUBIC_DOMAIN =
        hex"65000000000000000170332d73756d636865636b2d67656e657269632d6465677265650000000000000000000000000000000000000000000000000000000000000000000000001a5ea850b71985b768cf939b9d82fb8857c5cfc4cc3654a0155c2d95ca63ce11bb0000000080000000";

    // GenericDegreeShape::new(24, 3, 0), for the additional segment coordinate.
    bytes internal constant MIDPOINT_DOMAIN =
        hex"65000000000000000170332d73756d636865636b2d67656e657269632d6465677265650000000000000000000000000000000000000000000000000000000000000000000000001a34f7737a5c8142209fa442af923fc03240cff09496fa0373a1bbfd928f6028900000000080000000";

    function check(
        NativeKeccak.Stream memory s,
        uint192[27] memory outputPoint,
        uint192 t,
        uint192 projectedSum,
        bytes calldata wire
    ) internal pure returns (uint192[23] memory point, uint192[3] memory values) {
        uint192 running;
        (point, values, running,) = rounds(s, projectedSum, wire, false);
        uint192 weight = positionWeight(outputPoint, point);
        for (uint256 i; i < 12; ++i) {
            weight = NativeField.mul(weight, 1 ^ outputPoint[i] ^ point[i]);
        }
        if (NativeField.mul(weight, chi(t, values)) != running) revert InvalidChiEndpoint();
    }

    function rounds(NativeKeccak.Stream memory s, uint192 projectedSum, bytes calldata wire, bool midpoint)
        internal
        pure
        returns (uint192[23] memory point, uint192[3] memory values, uint192 running, uint192 segment)
    {
        uint256 n = midpoint ? 24 : 23;
        if (wire.length != (1 + n * 3 + 3) * 24) revert NativeKeccak.InvalidKeccakShape();
        if (NativeKeccak.read192(wire, 0) != projectedSum) revert InvalidChiSum();
        running = projectedSum;
        for (uint256 i; i < n; ++i) {
            uint256 offset = 24 + i * 72;
            bytes calldata poly = wire[offset:offset + 72];
            // The first round absorbs the shape, claimed sum and coefficients before sampling.
            s.blockHash = i == 0
                ? keccak256(abi.encodePacked(s.blockHash, midpoint ? MIDPOINT_DOMAIN : CUBIC_DOMAIN, wire[:96]))
                : keccak256(abi.encodePacked(s.blockHash, poly));
            s.consumedWords = 0;
            uint192 x = NativeKeccak.sample192(s);
            if (midpoint && i == 0) segment = x;
            else point[midpoint ? i - 1 : i] = x;
            running = NativeField.cubic(
                running,
                NativeKeccak.read192(poly, 0),
                NativeKeccak.read192(poly, 24),
                NativeKeccak.read192(poly, 48),
                x
            );
        }
        for (uint256 i; i < 3; ++i) {
            values[i] = NativeKeccak.read192(wire, (1 + n * 3 + i) * 24);
        }
    }

    function chi(uint192 t, uint192[3] memory values) internal pure returns (uint192) {
        return NativeField.mul(embeddingSum(t), values[0] ^ values[2]) ^ NativeField.mul(values[1], values[2]);
    }

    // Bit j of 0xb1b9b1 is the coefficient of t^j. Its repeated nibbles give
    // (1 + (1+t+t³)t⁴)(1+t⁸+t¹⁶) + t¹¹ in characteristic two.
    function embeddingSum(uint192 t) internal pure returns (uint192) {
        uint192 t2 = NativeField.square(t);
        uint192 t3 = NativeField.mul(t, t2);
        uint192 t4 = NativeField.square(t2);
        uint192 t8 = NativeField.square(t4);
        uint192 t16 = NativeField.square(t8);
        return NativeField.mul(1 ^ NativeField.mul(1 ^ t ^ t3, t4), 1 ^ t8 ^ t16) ^ NativeField.mul(t3, t8);
    }

    function positionWeight(uint192[27] memory original, uint192[23] memory point) internal pure returns (uint192) {
        // Sum eq(original,j)*eq(point,j) for j<1600. All six bit coordinates are
        // free. The five lane coordinates cover the disjoint sets 0..15, 16..23, 24.
        uint192[5] memory all;
        uint192[5] memory high;
        for (uint256 i; i < 5; ++i) {
            all[i] = 1 ^ original[16 + i] ^ point[12 + i];
            high[i] = NativeField.mul(original[16 + i], point[12 + i]);
        }
        uint192 first = NativeField.mul(all[0] ^ high[0], all[1]) ^ NativeField.mul(high[0], all[1] ^ high[1]);
        uint192 last = NativeField.mul(high[0], high[1]);
        for (uint256 i = 2; i < 5; ++i) {
            first = NativeField.mul(first, all[i]);
            last = NativeField.mul(last, all[i] ^ high[i]);
        }
        uint192 weight = first ^ last;
        for (uint256 i = 5; i < 11; ++i) {
            weight = NativeField.mul(weight, 1 ^ original[16 + i] ^ point[12 + i]);
        }
        return weight;
    }
}
