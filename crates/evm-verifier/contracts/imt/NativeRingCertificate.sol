// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeField as F} from "./NativeField.sol";

/// Optional hash-only sumcheck certificate for the shared terminal ring weight.
/// All inputs are supplied by the enclosing checked WHIR opening.
contract NativeRingCertificate {
    error InvalidRingCertificate();
    uint256 private constant ROUND_BYTES = 28 * 24;
    uint256 private constant MAP_OFFSET = 24 + 8 * ROUND_BYTES;
    bytes32 private constant DOMAIN = keccak256("imt-terminal-ring-product-sumcheck-v1");

    function scalar(bytes calldata data, uint256 offset) private pure returns (uint192 v) {
        assembly ("memory-safe") { v := shr(64, calldataload(add(data.offset, offset))) }
    }

    /// h(0)+h(1) is the sum of all nonconstant monomial coefficients in characteristic two.
    function round(uint192 sum, uint192 r, bytes calldata message) private pure returns (uint192) {
        uint192 high;
        uint192 linear = sum;
        for (uint256 i = 28; i > 1; --i) {
            uint192 c = scalar(message, (i - 1) * 24);
            linear ^= c;
            high = c ^ F.mul(r, high);
        }
        return scalar(message, 0) ^ F.mul(r, linear ^ F.mul(r, high));
    }

    /// Expand in the trace-dual basis: coefficient i is Tr(a*x^i).
    /// Tr(b) is the leading coefficient of b*f'(x) modulo f(x).
    /// The cubic trace pairing exchanges the two nonconstant limbs.
    function dualCoordinates(uint192 a) private pure returns (uint192 bits) {
        uint192 b = a ^ F.timesX(F.timesX(a));
        uint192 ones = 0x100000000000000010000000000000001;
        for (uint256 i; i < 64; ++i) {
            bits |= uint192(uint256((b >> 63) & ones) << i);
            b = F.timesX(b);
        }
        return uint192(uint64(bits)) | (uint192(uint64(bits >> 128)) << 64) | (uint192(uint64(bits >> 64)) << 128);
    }

    /// Apply the map to each reading by selecting and XORing images of its dual-basis digits.
    function productAt(uint192[32] memory reading, uint192[26] calldata draw, uint192[192] memory map)
        private
        pure
        returns (uint192 value)
    {
        uint192[26] memory images;
        for (uint256 d; d < 26; ++d) {
            reading[d] = dualCoordinates(reading[d]);
        }
        uint192[16] memory sums;
        for (uint256 n; n < 48; ++n) {
            for (uint256 i; i < 4; ++i) {
                uint192 b = map[4 * n + i];
                for (uint256 j; j < (1 << i); ++j) {
                    sums[(1 << i) + j] = sums[j] ^ b;
                }
            }
            for (uint256 d; d < 26; ++d) {
                images[d] ^= sums[uint256(reading[d] >> (4 * n)) & 15];
            }
        }
        value = 1;
        for (uint256 d; d < 26; ++d) {
            value = F.mul(value, 1 ^ draw[25 - d] ^ images[d]);
        }
    }

    function batchImages(uint192[192] memory map, uint192[8] calldata batching) private pure returns (uint192) {
        uint256 n = 192;
        for (uint256 d = 8; d != 0; --d) {
            uint192 r = batching[d - 1];
            for (uint256 i; i < n / 2; ++i) {
                uint192 a = map[2 * i];
                map[i] = a ^ F.mul(r, a ^ map[2 * i + 1]);
            }
            if (n & 1 != 0) map[n / 2] = map[n - 1] ^ F.mul(r, map[n - 1]);
            n = (n + 1) / 2;
        }
        return map[0];
    }

    /// Sum_i tau^i d_i^(2^j) for the 64 Poly64 dual basis elements.
    /// The leading term of the divided difference is (tau+x)^63 since all
    /// binomial coefficients of degree 63 are odd.
    function baseProjection(uint192 tau, uint64 x, uint64 invDerivative) private pure returns (uint192) {
        uint192 v = tau ^ x;
        uint192 v2 = F.square(v);
        uint192 v3 = F.mul(v, v2);
        uint192 v7 = F.mul(v3, F.square(v2));
        uint192 v63 = F.mul(v7, F.square(F.square(F.square(v7))));
        return F.scale(v63 ^ v3 ^ v2 ^ F.scale(tau, x) ^ 1, invDerivative);
    }

    /// Evaluate the known polynomial projection of the Frobenius map at tau.
    /// The low six j bits select the base-field conjugate, the two high bits
    /// only change the index of the cubic conjugate modulo three.
    function expectedProjection(uint192 tau, uint192[8] memory q) private pure returns (uint192 total) {
        uint192 t64 = tau;
        for (uint256 i; i < 6; ++i) {
            t64 = F.square(t64);
        }
        uint192 t128 = F.square(t64);
        uint192[3] memory cubic;
        uint192 y = uint192(1) << 64;
        for (uint256 i; i < 3; ++i) {
            uint192 next = F.square(y);
            cubic[i] = 1 ^ F.mul(t64, next) ^ F.mul(t128, y);
            y = next;
        }
        uint192[3] memory upper;
        for (uint256 i; i < 3; ++i) {
            uint192 a = cubic[i];
            uint192 b = cubic[(i + 1) % 3];
            uint192 c = cubic[(i + 2) % 3];
            uint192 lo = a ^ F.mul(q[6], a ^ b);
            uint192 hi = c ^ F.mul(q[6], c ^ a);
            upper[i] = lo ^ F.mul(q[7], lo ^ hi);
        }
        uint192[64] memory eq;
        eq[0] = 1;
        for (uint256 d; d < 6; ++d) {
            uint256 size = 1 << d;
            uint192 rest = q[d];
            for (uint256 i; i < size - 1; ++i) {
                eq[i + size] = F.mul(q[d], eq[i]);
                eq[i] ^= eq[i + size];
                rest ^= eq[i + size];
            }
            eq[2 * size - 1] = rest;
            eq[size - 1] ^= rest;
        }
        uint192[3] memory sums;
        uint64 x = 2;
        uint64 inv = 0x5555555555555552;
        for (uint256 i; i < 64; ++i) {
            sums[i % 3] ^= F.mul(eq[i], baseProjection(tau, x, inv));
            x = F.square64(x);
            inv = F.square64(inv);
        }
        for (uint256 i; i < 3; ++i) {
            total ^= F.mul(sums[i], upper[i]);
        }
    }

    function verify(
        uint192[32] calldata reading,
        uint192[26] calldata draw,
        uint192[8] calldata batching,
        bytes calldata proof
    ) external pure returns (uint192 weight) {
        if (proof.length != MAP_OFFSET + 192 * 24) revert InvalidRingCertificate();
        weight = scalar(proof, 0);
        bytes32 state = keccak256(abi.encode(DOMAIN, reading, draw, batching, weight));
        uint192 sum = weight;
        uint192[8] memory q;
        for (uint256 d; d < 8; ++d) {
            uint256 start = 24 + d * ROUND_BYTES;
            bytes calldata message = proof[start:start + ROUND_BYTES];
            state = keccak256(abi.encodePacked(state, message));
            q[d] = uint192(uint256(state));
            sum = round(sum, q[d], message);
        }
        bytes calldata table = proof[MAP_OFFSET:];
        uint192 tau = uint192(uint256(keccak256(abi.encodePacked(state, table))));
        uint192[192] memory map;
        uint192 projection;
        uint192[] memory multiplier = F.multiplierTable(tau);
        for (uint256 i = 192; i != 0; --i) {
            map[i - 1] = scalar(table, (i - 1) * 24);
            projection = map[i - 1] ^ F.multiplyFixed(multiplier, projection);
        }
        if (projection != expectedProjection(tau, q)) revert InvalidRingCertificate();
        uint192 product = productAt(reading, draw, map);
        uint192 dual = batchImages(map, batching);
        // j=192..255 are padding in the sum over the 192 conjugates.
        if (sum != F.mul(F.mul(product, dual), 1 ^ F.mul(q[6], q[7]))) revert InvalidRingCertificate();
    }
}
