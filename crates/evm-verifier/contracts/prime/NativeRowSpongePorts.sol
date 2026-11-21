// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NibbleSumcheck} from "./NibbleSumcheck.sol";
import {NativeRowSpongeOpeningVerifier} from "./NibbleOpeningVerifier.sol";

/// Bind row digits to Keccak sponge inputs and finished digest bytes for the strong midpoint schedule.
/// Permutation transitions and fold arithmetic are separate relations on the same commitment.
contract NativeRowSpongePorts is NibbleSumcheck {
    constructor(NativeRowSpongeOpeningVerifier pcs) NibbleSumcheck(pcs) {}

    struct Mix {
        uint256 row;
        uint256 slot;
        uint256 nibble;
        uint256 bit;
        uint256 digest;
        uint256 byteWeight;
        uint256 digestMix;
        uint256 rangeMix;
    }

    function power(uint256 a, uint256 n) private pure returns (uint256 v) {
        v = 1;
        for (; n != 0; n >>= 1) {
            if (n & 1 != 0) v = mulmod(v, a, P);
            a = mulmod(a, a, P);
        }
    }

    function weighted(uint256[] memory basisWeights, uint256 start, uint256 count, uint256 ratio)
        private
        pure
        returns (uint256 value)
    {
        for (uint256 i = count; i != 0; --i) {
            value = addmod(basisWeights[start + i - 1], mulmod(value, ratio, P), P);
        }
    }

    function publicClaim(Mix memory m, bytes calldata digests) private pure returns (uint256 value) {
        // The 240 final little-endian byte polynomials are independent of the private table.
        uint256 byteWeight = m.byteWeight;
        uint256 digestWeight = m.digest;
        assembly ("memory-safe") {
            for { let i := add(digests.offset, digests.length) } gt(i, digests.offset) {} {
                i := sub(i, 32)
                let raw := calldataload(i)
                let part := 0
                for { let j := 0 } lt(j, 32) { j := add(j, 1) } {
                    part := addmod(and(raw, 255), mulmod(part, byteWeight, P), P)
                    raw := shr(8, raw)
                }
                value := addmod(part, mulmod(value, digestWeight, P), P)
            }
        }
        value = mulmod(value, m.digestMix, P);
        uint256 high = mulmod(power(m.bit, 3), power(m.nibble, 271), P);
        uint256 slot2 = mulmod(m.slot, m.slot, P);
        uint256 paired = addmod(
            mulmod(m.slot, addmod(power(m.nibble, 240), high, P), P),
            mulmod(slot2, addmod(power(m.nibble, 256), high, P), P),
            P
        );
        uint256 single = mulmod(slot2, addmod(power(m.nibble, 224), high, P), P);
        uint256 padding;
        for (uint256 i = 169; i != 0; --i) {
            padding = addmod(i <= 71 ? paired : single, mulmod(m.row, padding, P), P);
        }
        return addmod(value, padding, P);
    }

    function rowWeights(Mix memory m, uint256[] memory point) private pure returns (uint256[5] memory v) {
        uint256[] memory w = weights(point, 0, 10);
        uint256 row = 1;
        uint256 digest = 1;
        uint256 slot2 = mulmod(m.slot, m.slot, P);
        for (uint256 i; i < 169; ++i) {
            uint256 a = w[3 * i];
            uint256 b = w[3 * i + 1];
            uint256 c = w[3 * i + 2];
            uint256 middle = mulmod(m.slot, b, P);
            v[0] = addmod(v[0], mulmod(row, addmod(a, addmod(middle, mulmod(slot2, c, P), P), P), P), P);
            uint256 previous = mulmod(m.slot, a, P);
            if (i < 71) {
                v[2] = addmod(v[2], mulmod(digest, b, P), P);
                digest = mulmod(digest, m.digest, P);
            } else {
                previous = addmod(previous, mulmod(slot2, b, P), P);
            }
            v[1] = addmod(v[1], mulmod(row, previous, P), P);
            v[2] = addmod(v[2], mulmod(digest, c, P), P);
            digest = mulmod(digest, m.digest, P);
            uint256 group = i < 71 ? 3 : 4;
            v[group] = addmod(v[group], mulmod(row, w[512 + 2 * i], P), P);
            row = mulmod(row, m.row, P);
        }
        v[1] = P - v[1];
        v[2] = mulmod(v[2], m.digestMix, P);
    }

    // One lane holds 16 four-bit digits. All message and carry starts are lane-aligned.
    function messageWeight(uint256[] memory lanes, uint256 radix, uint256 slot, bool paired)
        private
        pure
        returns (uint256 weight)
    {
        uint256 cut = paired ? 32 : 34;
        weight = weighted(lanes, 72, 17, radix);
        weight = addmod(weight, mulmod(slot, weighted(lanes, 89, cut - 17, radix), P), P);
        uint256 slot2 = mulmod(slot, slot, P);
        weight = addmod(weight, mulmod(slot2, weighted(lanes, 72 + cut, 48 - cut, radix), P), P);
        uint256 carry = mulmod(slot, weighted(lanes, 128, 17, radix), P);
        if (!paired) carry = addmod(carry, mulmod(slot2, weighted(lanes, 160, 17, radix), P), P);
        return addmod(P - weight, addmod(carry, carry, P), P);
    }

    function columnWeights(Mix memory m, uint256[] memory p) private pure returns (uint256[5] memory v) {
        uint256[] memory lane = weights(p, 10, 8);
        uint256[] memory digit = weights(p, 18, 4);
        uint256 radix = power(m.nibble, 16);
        uint256 tail = weighted(digit, 0, 16, m.nibble);
        v[0] = mulmod(weighted(lane, 0, 25, radix), tail, P);
        for (uint256 l = 25; l != 0; --l) {
            uint256 i = l - 1;
            v[1] = addmod(lane[(i / 7) * 32 + 25 + i % 7], mulmod(radix, v[1], P), P);
        }
        v[1] = mulmod(v[1], tail, P);
        uint256 bytesTail;
        for (uint256 i = 8; i != 0; --i) {
            uint256 d = 2 * i - 2;
            bytesTail = addmod(addmod(digit[d], mulmod(16, digit[d + 1], P), P), mulmod(m.byteWeight, bytesTail, P), P);
        }
        v[2] = mulmod(weighted(lane, 25, 4, power(m.byteWeight, 8)), bytesTail, P);
        v[3] = mulmod(messageWeight(lane, radix, m.slot, true), tail, P);
        v[4] = mulmod(messageWeight(lane, radix, m.slot, false), tail, P);
    }

    function reducePorts(bytes32 root, bytes calldata digests, bytes calldata digits)
        public
        pure
        returns (Reading memory)
    {
        if (digests.length != 240 * 32) revert InvalidDigits();
        bytes32 seed = keccak256(abi.encodePacked("recursive-imt/native-row-sponge-ports/v1", root, keccak256(digests)));
        Mix memory m = Mix(
            coin(seed, 0, 0),
            coin(seed, 0, 1),
            coin(seed, 0, 2),
            coin(seed, 0, 3),
            coin(seed, 0, 4),
            coin(seed, 0, 5),
            coin(seed, 0, 6),
            coin(seed, 0, 7)
        );
        (Claim memory upper, uint256[3] memory moments) = upperClaim(seed, publicClaim(m, digests), digits, 22);
        uint256[5] memory rows = rowWeights(m, upper.point);
        uint256[5] memory cols = columnWeights(m, upper.point);
        uint256 bitWeight;
        for (uint256 i; i < 5; ++i) {
            if (i != 2) bitWeight = addmod(bitWeight, mulmod(rows[i], cols[i], P), P);
        }
        uint256[] memory bw = new uint256[](4);
        bw[0] = 1;
        for (uint256 i = 1; i < 4; ++i) {
            bw[i] = mulmod(bw[i - 1], m.bit, P);
        }
        (uint256 bits,, uint256 range) = bitPolynomials(moments, bw, new uint256[](4));
        uint256 sum = addmod(mulmod(bits, bitWeight, P), mulmod(moments[0], mulmod(rows[2], cols[2], P), P), P);
        sum = addmod(
            sum, mulmod(range, mulmod(m.rangeMix, equality(coins(seed, 1, 22), 0, upper.point, 0, 22), P), P), P
        );
        if (sum != upper.sum) revert InvalidDigits();
        return reduceMoments(upper, moments, digits);
    }

    function verifyPorts(
        bytes32 root,
        bytes calldata digests,
        bytes calldata digits,
        bytes calldata proof,
        bytes calldata hints
    ) external view returns (bool) {
        verifyReading(reducePorts(root, digests, digits), root, proof, hints);
        return true;
    }
}
