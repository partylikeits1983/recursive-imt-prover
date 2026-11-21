// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeChiLayer} from "./NativeChiLayer.sol";
import {NativeChiMap} from "./NativeChiMap.sol";
import {NativeField as F} from "./NativeField.sol";
import {NativeKeccak as K} from "./NativeKeccak.sol";

/// Reduces all 24 native packed Keccak rounds to the input closing claim.
/// The enclosing verifier must bind the bridge and authenticate the final bit opening.
library NativeKeccakRounds {
    uint256 internal constant COEFFICIENT_BYTES = 47 * 24;
    uint256 internal constant LAYER_BYTES = COEFFICIENT_BYTES + 73 * 24;

    bytes internal constant ROTATIONS = hex"00013e1c1b242c063714030a2b1927292d0f150812023d380e";
    bytes internal constant RC =
        hex"00000000000000010000000000008082800000000000808a8000000080008000000000000000808b000000008000000180000000800080818000000000008009000000000000008a00000000000000880000000080008009000000008000000a000000008000808b800000000000008b8000000000008089800000000000800380000000000080028000000000000080000000000000800a800000008000000a8000000080008081800000000000808000000000800000018000000080008008";

    struct Progress {
        bytes32 blockHash;
        uint192 embeddingPoint;
        uint192 beta;
        uint192 value;
        uint192[23] point;
        uint8 remaining;
        uint192 segment;
    }

    function first(bytes calldata prefix, bytes calldata cubic) internal pure returns (Progress memory state) {
        if (prefix.length != 4408) revert K.InvalidKeccakShape();
        (K.Stream memory stream, uint192[27] memory output) =
            K.outputPoint(bytes32(prefix[:32]), bytes32(prefix[32:64]), prefix[64:3256]);
        (uint192 t, uint192 sum) = K.firstChi(stream, output, prefix[3256:3280], prefix[3280:]);
        (uint192[23] memory point, uint192[3] memory values) = NativeChiLayer.check(stream, output, t, sum, cubic);
        return bind(stream, t, point, values, cubic[1680:], 23);
    }

    function firstMidpoint(bytes calldata prefix, bytes calldata cubic) private pure returns (Progress memory state) {
        if (prefix.length != 4432) revert K.InvalidKeccakShape();
        (K.Stream memory stream, uint192[27] memory output) =
            K.outputPoint(bytes32(prefix[:32]), bytes32(prefix[32:64]), prefix[64:3256]);
        (uint192 prev, uint192 t, uint192 sum) = K.midpointChi(stream, output, prefix[3256:3304], prefix[3304:]);
        (uint192[23] memory p, uint192[3] memory values, uint192 end, uint192 segment) =
            NativeChiLayer.rounds(stream, sum, cubic, true);
        uint192 w = F.mul(1 ^ prev ^ segment, NativeChiLayer.positionWeight(output, p));
        for (uint256 i; i < 12; ++i) {
            w = F.mul(w, 1 ^ output[i] ^ p[i]);
        }
        if (F.mul(w, NativeChiLayer.chi(t, values)) != end) revert NativeChiLayer.InvalidChiEndpoint();
        state = bind(stream, t, p, values, cubic[cubic.length - 72:], 11);
        state.segment = segment;
    }

    function bind(
        K.Stream memory stream,
        uint192 t,
        uint192[23] memory point,
        uint192[3] memory values,
        bytes calldata encoded,
        uint8 remaining
    ) private pure returns (Progress memory state) {
        stream.blockHash = keccak256(abi.encodePacked(stream.blockHash, encoded));
        stream.consumedWords = 0;
        uint192 beta = K.sample192(stream);
        return Progress(
            stream.blockHash, t, beta, values[0] ^ F.mul(beta, values[1] ^ F.mul(beta, values[2])), point, remaining, 0
        );
    }

    function eqWeights(uint192[23] memory p, uint256 firstCoord, uint256 count)
        private
        pure
        returns (uint192[64] memory w)
    {
        w[0] = 1;
        for (uint256 i; i < count; ++i) {
            // The basis weights sum to one. The high children sum to this coordinate.
            uint192 rest = p[firstCoord + i];
            for (uint256 j = 1 << i; j > 1; --j) {
                uint256 src = j - 1;
                uint192 old = w[src];
                uint192 hi = F.mul(old, p[firstCoord + i]);
                w[2 * src + 1] = hi;
                w[2 * src] = old ^ hi;
                rest ^= hi;
            }
            w[1] = rest;
            w[0] ^= rest;
        }
    }

    function laneWeights(Progress memory state) private pure returns (uint192[25] memory lanes) {
        uint192[64] memory eq = eqWeights(state.point, 12, 5);
        uint192 square = F.square(state.beta);
        for (uint256 j; j < 25; ++j) {
            uint256 start = j - j % 5;
            lanes[j] = eq[j] ^ F.mul(state.beta, eq[start + (j + 4) % 5]) ^ F.mul(square, eq[start + (j + 3) % 5]);
        }
    }

    function pi(uint256 j) private pure returns (uint256) {
        return j / 5 + 5 * ((2 * (j % 5) + 3 * (j / 5)) % 5);
    }

    function iota(uint192[64] memory bits, uint192[25] memory lanes, uint256 round)
        private
        pure
        returns (uint192 total)
    {
        uint64 constantBits;
        for (uint256 i; i < 8; ++i) {
            constantBits = (constantBits << 8) | uint8(RC[8 * round + i]);
        }
        // The Keccak-f[1600] round constants use only positions 2^j - 1.
        uint256[7] memory positions;
        uint256 count;
        for (uint256 j; j < 7; ++j) {
            uint256 pos = (uint256(1) << j) - 1;
            if ((constantBits >> pos) & 1 != 0) positions[count++] = pos;
        }
        for (uint256 i; i < 11; ++i) {
            uint256 source = i == 0 ? 0 : (i <= 5 ? 1 + (i - 1) * 5 : 4 + (i - 6) * 5);
            uint256 rotation = uint8(ROTATIONS[source]) + uint256(i > 5 ? 1 : 0);
            uint192 selected;
            for (uint256 k; k < count; ++k) {
                selected ^= bits[(positions[k] + rotation) & 63];
            }
            total ^= F.mul(lanes[pi(source)], selected);
        }
    }

    // Dot the 16 projected coefficients with EMBED(t). Combine each power's
    // coefficients first, then evaluate the degree-23 polynomial by Horner.
    function project(uint192[47] memory c, uint192 t) private pure returns (uint192 value) {
        uint192[24] memory coeff = NativeChiMap.embedded(c);
        value = coeff[23];
        for (uint256 i = 23; i != 0; --i) {
            value = coeff[i - 1] ^ F.mul(t, value);
        }
    }

    // All cyclic correlations of the two six-coordinate equality tables.
    function correlations(uint192[23] memory newPoint, uint192[23] memory oldPoint)
        private
        pure
        returns (uint192[64] memory table)
    {
        table[0] = 1;
        for (uint256 bit; bit < 6; ++bit) {
            uint192 a = newPoint[17 + bit];
            uint192 b = oldPoint[17 + bit];
            uint192 cross = F.mul(a, b);
            uint192 up = b ^ cross;
            uint192 down = a ^ cross;
            uint256 n = 1 << bit;
            uint192[32] memory above;
            uint192[32] memory below;
            // Summing a cyclic correlation over all shifts gives the product of
            // the two basis sums, which is one at every level.
            uint192 lastUp = up;
            uint192 lastDown = down;
            for (uint256 j; j < n - 1; ++j) {
                above[j] = F.mul(table[j], up);
                below[j] = F.mul(table[j], down);
                lastUp ^= above[j];
                lastDown ^= below[j];
            }
            above[n - 1] = lastUp;
            below[n - 1] = lastDown;
            for (uint256 k = n; k != 0; --k) {
                uint256 j = k - 1;
                table[2 * j] = table[j] ^ above[j] ^ below[j];
                table[2 * j + 1] = above[j] ^ below[(j + 1) % n];
            }
        }
    }

    function positionWeight(uint192[25] memory lanes, uint192[23] memory oldPoint, uint192[23] memory newPoint)
        private
        pure
        returns (uint192 total)
    {
        uint192[64] memory targets = eqWeights(newPoint, 12, 5);
        uint192[5] memory columns;
        for (uint256 i; i < 25; ++i) {
            columns[i % 5] ^= targets[i];
        }
        uint192[64] memory corr = correlations(newPoint, oldPoint);
        for (uint256 i; i < 25; ++i) {
            uint256 r = uint8(ROTATIONS[i]);
            uint192 term =
                F.mul(targets[i] ^ columns[(i + 4) % 5], corr[r]) ^ F.mul(columns[(i + 1) % 5], corr[(r + 1) & 63]);
            total ^= F.mul(lanes[pi(i)], term);
        }
    }

    function next(Progress memory state, bytes calldata wire) internal pure returns (Progress memory) {
        return nextLayer(state, wire, false);
    }

    function nextLayer(Progress memory state, bytes calldata wire, bool midpoint)
        private
        pure
        returns (Progress memory)
    {
        if (state.remaining == 0 || state.remaining > 23 || wire.length != LAYER_BYTES + (midpoint ? 72 : 0)) revert K.InvalidKeccakShape();
        uint8 round = state.remaining - 1;
        uint192[25] memory lanes = laneWeights(state);
        uint192[47] memory c;
        for (uint256 i; i < 47; ++i) {
            c[i] = K.read192(wire, 24 * i);
        }
        // Both midpoint segments use the same bit coordinate and lane weights.
        uint192[64] memory bits = eqWeights(state.point, 17, 6);
        uint192 constantValue = iota(bits, lanes, round);
        if (midpoint) constantValue ^= F.mul(state.segment, constantValue ^ iota(bits, lanes, round + 12));
        constantValue = F.mul(constantValue, NativeChiLayer.embeddingSum(state.embeddingPoint));
        if ((project(c, state.embeddingPoint) ^ constantValue) != state.value) {
            revert K.InvalidKeccakProjection();
        }
        K.Stream memory stream;
        stream.blockHash =
            keccak256(abi.encodePacked(state.blockHash, bytes8(uint64(round) << 56), wire[:COEFFICIENT_BYTES]));
        uint192 t = K.sample192(stream);
        uint192 sum = c[46];
        for (uint256 i = 46; i != 0; --i) {
            sum = c[i - 1] ^ F.mul(sum, t);
        }
        bytes calldata cubic = wire[COEFFICIENT_BYTES:];
        (uint192[23] memory p, uint192[3] memory values, uint192 endpoint, uint192 segment) =
            NativeChiLayer.rounds(stream, sum, cubic, midpoint);
        uint192 weight = positionWeight(lanes, state.point, p);
        for (uint256 i; i < 12; ++i) {
            weight = F.mul(weight, 1 ^ state.point[i] ^ p[i]);
        }
        if (midpoint) weight = F.mul(weight, 1 ^ state.segment ^ segment);
        if (F.mul(weight, NativeChiLayer.chi(t, values)) != endpoint) revert NativeChiLayer.InvalidChiEndpoint();
        state = bind(stream, t, p, values, cubic[cubic.length - 72:], round);
        state.segment = segment;
        return state;
    }

    /// Evaluate the final input bit functional at the position selected by the closing sumcheck.
    function closingPositionWeight(Progress memory state, uint192[15] memory position) internal pure returns (uint192) {
        uint192[23] memory nextPoint;
        for (uint256 i; i < 11; ++i) {
            nextPoint[12 + i] = position[4 + i];
        }
        return positionWeight(laneWeights(state), state.point, nextPoint);
    }

    function verifyMidpointRounds(bytes calldata prefix, bytes calldata layers)
        internal
        pure
        returns (Progress memory state)
    {
        uint256 size = LAYER_BYTES + 72;
        if (layers.length != 12 * size - COEFFICIENT_BYTES) revert K.InvalidKeccakShape();
        uint256 start = size - COEFFICIENT_BYTES;
        state = firstMidpoint(prefix, layers[:start]);
        for (; start < layers.length; start += size) {
            state = nextLayer(state, layers[start:start + size], true);
        }
    }

    function verifyRounds(bytes calldata prefix, bytes calldata layers) internal pure returns (Progress memory state) {
        if (layers.length != 24 * LAYER_BYTES - COEFFICIENT_BYTES) revert K.InvalidKeccakShape();
        uint256 start = LAYER_BYTES - COEFFICIENT_BYTES;
        state = first(prefix, layers[:start]);
        for (; start < layers.length; start += LAYER_BYTES) {
            state = next(state, layers[start:start + LAYER_BYTES]);
        }
    }
}
