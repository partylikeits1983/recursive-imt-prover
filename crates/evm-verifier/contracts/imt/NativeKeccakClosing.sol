// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeField as F} from "./NativeField.sol";
import {NativeKeccak as K} from "./NativeKeccak.sol";
import {NativeKeccakRounds as R} from "./NativeKeccakRounds.sol";

/// Close the packed Keccak input and arithmetic port functionals. The caller
/// authenticates the four returned boundary points and their values in the
/// arithmetic argument. This component verifies both sumchecks against them.
library NativeKeccakClosing {
    error InvalidBridge();
    error InvalidClosing();

    bytes private constant INPUT_DOMAIN =
        hex"65000000000000000170332d73756d636865636b2d67656e657269632d6465677265650000000000000000000000000000000000000000000000000000000000000000000000001a156a648991433015131cd9675811e26aea2bf71fd5eea80964e958207e4c88c70000000080000000";
    bytes private constant PORT_DOMAIN =
        hex"65000000000000000170332d73756d636865636b2d67656e657269632d6465677265650000000000000000000000000000000000000000000000000000000000000000000000001acb93ab20d67241344eb75a5f15691b3af8f5eae3bc906fb9d95665d7f881c4b20000000080000000";
    // Same 16 binary embedding polynomials used by the packed Keccak prover.
    bytes private constant EMBED =
        hex"40c50b7f79f24b4e0a72740c5357da1d1c9e04be6e785246097cdc109e7e1f1454213cfc4cfcc8775770187386818a16";

    function checkBridge(bytes calldata arithmeticPoint, bytes calldata row, bytes calldata bridge) internal pure {
        if (arithmeticPoint.length != 19 * 24 || row.length != 232 * 24 || bridge.length != 133 * 24) {
            revert InvalidBridge();
        }
        bytes calldata coords = arithmeticPoint[arithmeticPoint.length - 17 * 24:];
        if (keccak256(coords) != keccak256(bridge[:17 * 24])) revert InvalidBridge();
        uint192 template = K.read192(coords, 0);
        for (uint256 i; i < 116; ++i) {
            uint192 a = K.read192(row, 24 * i);
            uint192 b = K.read192(row, 24 * (116 + i));
            if ((a ^ F.mul(template, a ^ b)) != K.read192(bridge, 24 * (17 + i))) revert InvalidBridge();
        }
    }

    function quadratic(K.Stream memory stream, uint192 sum, bytes calldata wire, bool input)
        private
        pure
        returns (uint192[15] memory point, uint192 product)
    {
        uint256 rounds = input ? 15 : 12;
        if (wire.length != (1 + 2 * rounds) * 24 || K.read192(wire, 0) != sum) revert InvalidClosing();
        product = sum;
        for (uint256 i; i < rounds; ++i) {
            bytes calldata poly = wire[24 + 48 * i:72 + 48 * i];
            stream.blockHash = i == 0
                ? keccak256(abi.encodePacked(stream.blockHash, input ? INPUT_DOMAIN : PORT_DOMAIN, wire[:72]))
                : keccak256(abi.encodePacked(stream.blockHash, poly));
            stream.consumedWords = 0;
            uint192 r = K.sample192(stream);
            point[i] = r;
            uint192 h0 = K.read192(poly, 0);
            uint192 h2 = K.read192(poly, 24);
            uint192 k = F.divideBySix(h0 ^ h2 ^ F.timesX(product));
            product = h0 ^ F.mul(r, product ^ F.mul(r ^ 1, k));
        }
    }

    function embeddedAt(uint192 t, uint192[15] memory p) private pure returns (uint192) {
        uint192[24] memory powers;
        powers[0] = 1;
        for (uint256 i = 1; i < 24; ++i) {
            powers[i] = F.mul(powers[i - 1], t);
        }
        uint192[16] memory lanes;
        for (uint256 i; i < 16; ++i) {
            uint256 mask = (uint256(uint8(EMBED[3 * i])) << 16) | (uint256(uint8(EMBED[3 * i + 1])) << 8)
                | uint8(EMBED[3 * i + 2]);
            for (uint256 b; mask != 0; ++b) {
                if (mask & 1 != 0) lanes[i] ^= powers[b];
                mask >>= 1;
            }
        }
        for (uint256 d; d < 4; ++d) {
            for (uint256 i; i < 8 >> d; ++i) {
                uint192 a = lanes[2 * i];
                lanes[i] = a ^ F.mul(p[3 - d], a ^ lanes[2 * i + 1]);
            }
        }
        return lanes[0];
    }

    function weights(uint192[7] memory point) private pure returns (uint192[128] memory w) {
        w[0] = 1;
        for (uint256 d; d < 7; ++d) {
            uint192 rest = point[d];
            for (uint256 j = 1 << d; j > 1; --j) {
                uint256 i = j - 1;
                uint192 a = w[i];
                uint192 hi = F.mul(a, point[d]);
                w[2 * i] = a ^ hi;
                w[2 * i + 1] = hi;
                rest ^= hi;
            }
            w[1] = rest;
            w[0] ^= rest;
        }
    }

    function portWeight(uint192 direction, uint192[128] memory mix, uint192[15] memory p)
        private
        pure
        returns (uint192)
    {
        uint192[7] memory limbPoint;
        for (uint256 i; i < 7; ++i) {
            limbPoint[i] = p[1 + i];
        }
        uint192[128] memory limbs = weights(limbPoint);
        uint192 normal;
        uint192 swapped;
        for (uint256 i; i < 100; ++i) {
            normal ^= F.mul(mix[i], limbs[i]);
        }
        for (uint256 i; i < 16; ++i) {
            swapped ^= F.mul(mix[100 + i], limbs[i]);
        }
        // The low four bit coordinates weight a 16-bit Poly64 word. Swapping
        // bytes flips the most significant of these four selector bits.
        uint192 low = 1;
        for (uint256 k; k < 3; ++k) {
            low = F.mul(low, 1 ^ F.scale(p[11 - k], uint64(1 ^ (1 << (1 << k)))));
        }
        uint192 high = 1 ^ F.scale(p[8], 257);
        uint192 bits = F.mul(normal, high) ^ F.mul(swapped, high ^ 257);
        return F.mul(F.mul(low, bits), 1 ^ p[0] ^ direction);
    }

    function verify(
        R.Progress memory state,
        bytes calldata bridge,
        uint192[27] memory outputPoint,
        uint192 outputValue,
        bytes calldata wire,
        uint192[4] memory evals
    ) internal pure returns (uint192[27][4] memory points) {
        if (
            state.remaining != 0 || bridge.length != 133 * 24 || wire.length != (31 + 25) * 24
                || evals[2] != outputValue
        ) {
            revert InvalidClosing();
        }
        K.Stream memory stream = K.Stream(state.blockHash, 3);
        (uint192[15] memory input, uint192 product) = quadratic(stream, state.value, wire[:31 * 24], true);
        uint192 inputWeight = F.mul(embeddedAt(state.embeddingPoint, input), R.closingPositionWeight(state, input));
        if (product != F.mul(inputWeight, evals[0])) revert InvalidClosing();
        for (uint256 i; i < 12; ++i) {
            points[0][i] = state.point[i];
        }
        for (uint256 i; i < 15; ++i) {
            points[0][12 + i] = input[i];
        }
        uint192[7] memory portPoint;
        for (uint256 i; i < 7; ++i) {
            portPoint[i] = K.sample192(stream);
        }
        uint192[128] memory mix = weights(portPoint);
        uint192 portSum;
        for (uint256 i; i < 116; ++i) {
            portSum ^= F.mul(mix[i], K.read192(bridge, 24 * (17 + i)));
        }
        (uint192[15] memory link, uint192 linkProduct) = quadratic(stream, portSum, wire[31 * 24:], false);
        uint192 weight = portWeight(K.read192(bridge, 16 * 24), mix, link);
        if (linkProduct != F.mul(weight, evals[1] ^ F.mul(link[0], evals[1] ^ evals[3]))) revert InvalidClosing();
        for (uint256 i; i < 16; ++i) {
            points[1][i] = K.read192(bridge, 24 * i);
        }
        for (uint256 i; i < 11; ++i) {
            points[1][16 + i] = link[i + 1];
        }
        points[2] = outputPoint;
        points[3] = points[1];
    }
}
