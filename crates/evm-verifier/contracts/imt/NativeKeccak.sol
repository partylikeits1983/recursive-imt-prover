// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeChiMap} from "./NativeChiMap.sol";
import {NativeField} from "./NativeField.sol";

/// Initial packed chi claim of the 2^16-state native IMT Keccak argument.
library NativeKeccak {
    error InvalidKeccakShape();
    error InvalidKeccakProjection();

    // Poly64 little-endian serialization of the pinned stacked-commitment domain separator.
    bytes internal constant COMMITMENT_DOMAIN =
        hex"65000000000000000170332d73756d636865636b2d6c61796f75742d636f6d6d69746d656e740000000000000000000000000000000000000000000000000000000000000000001dde2644dafc9d326c94bcd3346ad8cdb2ce615d4d185a524fd7d11e4be51e82560000000080000000";

    struct Stream {
        bytes32 blockHash;
        uint256 consumedWords;
    }

    function sample64(Stream memory s) internal pure returns (uint64 word) {
        if (s.consumedWords == 4) {
            s.blockHash = keccak256(abi.encodePacked(s.blockHash));
            s.consumedWords = 0;
        }
        // The native byte challenger pops from the end. Poly64 accumulates little endian.
        word = uint64(uint256(s.blockHash) >> (s.consumedWords * 64));
        ++s.consumedWords;
    }

    function sample192(Stream memory s) internal pure returns (uint192) {
        uint192 lo = sample64(s);
        uint192 mid = sample64(s);
        return lo | (mid << 64) | (uint192(sample64(s)) << 128);
    }

    // Each caller has checked the exact length of its packed slice.
    function read192(bytes calldata data, uint256 offset) internal pure returns (uint192 value) {
        uint256 raw;
        assembly ("memory-safe") {
            raw := calldataload(add(data.offset, offset))
        }
        return decode192(raw);
    }

    function read192Memory(bytes memory data, uint256 offset) internal pure returns (uint192) {
        uint256 raw;
        assembly ("memory-safe") {
            raw := mload(add(add(data, 32), offset))
        }
        return decode192(raw);
    }

    /// Write exactly 24 little-endian bytes in a caller-sized buffer.
    function write192(bytes memory data, uint256 offset, uint192 value) internal pure {
        uint192 reversed = decode192(uint256(value) << 64);
        assembly ("memory-safe") {
            mstore(0, shl(64, reversed))
            mcopy(add(add(data, 32), offset), 0, 24)
        }
    }

    function decode192(uint256 x) private pure returns (uint192 value) {
        assembly ("memory-safe") {
            let m := 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff
            x := or(shl(8, and(x, m)), and(shr(8, x), m))
            m := 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff
            x := or(shl(16, and(x, m)), and(shr(16, x), m))
            m := 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
            x := or(shl(32, and(x, m)), and(shr(32, x), m))
            value := or(
                shr(192, x),
                or(shl(64, and(shr(128, x), 0xffffffffffffffff)), shl(128, and(shr(64, x), 0xffffffffffffffff)))
            )
        }
    }

    /// Bind the trusted verifier identity, joint witness root, 17 bridge coordinates and 116 limb values.
    /// The enclosing arithmetic opening must authenticate the same cap and bridge.
    function outputPoint(bytes32 authority, bytes32 cap, bytes calldata bridge)
        internal
        pure
        returns (Stream memory s, uint192[27] memory point)
    {
        if (bridge.length != (17 + 116) * 24) revert InvalidKeccakShape();
        bytes32 seed =
            keccak256(abi.encodePacked("imt-checkpoint-keccak-bridge-rows-v1", hex"1000000000000000", authority));
        s.blockHash = keccak256(abi.encodePacked(seed, COMMITMENT_DOMAIN, cap, bridge));
        for (uint256 i; i < point.length; ++i) {
            point[i] = sample192(s);
        }
    }

    /// Check the projected chi output and derive the initial claim for round 23's cubic sumcheck.
    function firstChi(Stream memory s, uint192[27] memory point, bytes calldata output, bytes calldata coefficients)
        internal
        pure
        returns (uint192 t, uint192 sum)
    {
        if (output.length != 24 || coefficients.length != 47 * 24) revert InvalidKeccakShape();
        uint192[47] memory c;
        for (uint256 i; i < 47; ++i) {
            c[i] = read192(coefficients, 24 * i);
        }
        if ((projected(c, point) ^ iota23(point)) != read192(output, 0)) revert InvalidKeccakProjection();
        s.blockHash = keccak256(abi.encodePacked(s.blockHash, output, hex"1700000000000000", coefficients));
        s.consumedWords = 0;
        t = sample192(s);
        sum = c[46];
        for (uint256 i = 46; i != 0; --i) {
            sum = c[i - 1] ^ NativeField.mul(sum, t);
        }
    }

    function midpointChi(
        Stream memory s,
        uint192[27] memory point,
        bytes calldata boundaries,
        bytes calldata coefficients
    ) internal pure returns (uint192 segment, uint192 t, uint192 sum) {
        if (boundaries.length != 48 || coefficients.length != 47 * 24) {
            revert InvalidKeccakShape();
        }
        s.blockHash = keccak256(abi.encodePacked(s.blockHash, boundaries));
        s.consumedWords = 0;
        segment = sample192(s);
        uint192 middle = read192(boundaries, 24);
        uint192 expected = middle ^ NativeField.mul(segment, middle ^ read192(boundaries, 0));
        uint192[47] memory c;
        for (uint256 i; i < 47; ++i) {
            c[i] = read192(coefficients, 24 * i);
        }
        uint192 before = iota11(point);
        if ((projected(c, point) ^ before ^ NativeField.mul(segment, before ^ iota23(point))) != expected) {
            revert InvalidKeccakProjection();
        }
        s.blockHash = keccak256(abi.encodePacked(s.blockHash, hex"0b00000000000000", coefficients));
        s.consumedWords = 0;
        t = sample192(s);
        sum = c[46];
        for (uint256 i = 46; i != 0; --i) {
            sum = c[i - 1] ^ NativeField.mul(sum, t);
        }
    }

    function iota11(uint192[27] memory point) private pure returns (uint192) {
        // Round 11 toggles lane-zero bits 1, 3 and 31.
        uint192 lane = 1;
        for (uint256 i = 16; i < 21; ++i) {
            lane = NativeField.mul(lane, 1 ^ point[i]);
        }
        uint192 bits;
        uint256[3] memory positions = [uint256(1), 3, 31];
        for (uint256 j; j < 3; ++j) {
            uint192 w = 1;
            for (uint256 k; k < 6; ++k) {
                w = NativeField.mul(w, point[21 + k] ^ uint192(1 ^ ((positions[j] >> (5 - k)) & 1)));
            }
            bits ^= w;
        }
        return NativeField.mul(lane, bits);
    }

    function projected(uint192[47] memory c, uint192[27] memory point) private pure returns (uint192) {
        uint192[16] memory lanes = NativeChiMap.project(c);
        // The last four instance coordinates select the packed lanes in MSB-first order.
        for (uint256 depth; depth < 4; ++depth) {
            uint192 r = point[15 - depth];
            for (uint256 j; j < 8 >> depth; ++j) {
                uint192 lo = lanes[2 * j];
                lanes[j] = lo ^ NativeField.mul(r, lo ^ lanes[2 * j + 1]);
            }
        }
        return lanes[0];
    }

    function iota23(uint192[27] memory point) private pure returns (uint192) {
        // Round 23 sets lane-zero bits 3, 15, 31 and 63. Factor their equality weights.
        uint192 a = point[21];
        uint192 b = point[22];
        uint192 c = point[23];
        uint192 d = point[24];
        uint192 zero = NativeField.mul(NativeField.mul(1 ^ a, 1 ^ b), NativeField.mul(1 ^ c, 1 ^ d));
        uint192 pair = NativeField.mul(NativeField.mul(c, d), 1 ^ NativeField.mul(a, 1 ^ b));
        uint192 weight = NativeField.mul(point[25], point[26]);
        for (uint256 i = 16; i < 21; ++i) {
            weight = NativeField.mul(weight, 1 ^ point[i]);
        }
        return NativeField.mul(weight, zero ^ pair);
    }
}
