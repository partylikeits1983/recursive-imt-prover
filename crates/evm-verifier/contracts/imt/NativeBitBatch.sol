// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeField} from "./NativeField.sol";
import {NativeKeccak} from "./NativeKeccak.sol";

/// Reduce current bit openings to one PCS reading. The enclosing proof derives
/// the packed (point, value) records, transcript prefix and commitment.
library NativeBitBatch {
    error InvalidBatch();
    error WrongEndpoint();
    error WrongTensor();

    struct Endpoint {
        uint192[32] point;
        uint192 value;
        // The challenger has sampled the final round from this block and then
        // absorbed value in little endian. The next phase continues from both.
        bytes32 blockHash;
    }

    function le64(uint256 n) private pure returns (bytes8) {
        // The terminal profile bounds both counts below 2^16.
        return bytes8(uint64(((n & 255) << 56) | ((n >> 8) << 48)));
    }

    // Plonky3 commitment_domain_separator::<Poly64>() at the pinned revision.
    bytes internal constant COMMITMENT_DOMAIN =
        hex"65000000000000000170332d73756d636865636b2d6c61796f75742d636f6d6d69746d656e740000000000000000000000000000000000000000000000000000000000000000001dde2644dafc9d326c94bcd3346ad8cdb2ce615d4d185a524fd7d11e4be51e82560000000080000000";

    /// The application pins the authority and fixed cap. The arithmetic
    /// verifier must derive the main cap and the 134 ordered bit claims.
    function reduceTerminal(
        bytes32 authority,
        bytes32 mainCap,
        bytes32 fixedCap,
        bytes memory claims,
        bytes calldata proof
    ) internal pure returns (Endpoint memory) {
        if (claims.length != 134 * 33 * 24) revert InvalidBatch();
        return reduce(
            abi.encodePacked("imt-terminal-shared-bit-opening-v1", authority, COMMITMENT_DOMAIN, mainCap, fixedCap),
            claims,
            proof
        );
    }

    /// The terminal profile fixes the arity at 32. The 32 two-coefficient
    /// round messages and final value occupy exactly 1,560 bytes.
    function reduce(bytes memory prefix, bytes memory claims, bytes calldata proof)
        internal
        pure
        returns (Endpoint memory end)
    {
        uint256 stride = 33 * 24;
        uint256 count = claims.length / stride;
        if (count == 0 || count > 65535 || claims.length != count * stride || proof.length != 65 * 24) {
            revert InvalidBatch();
        }
        NativeKeccak.Stream memory s;
        s.blockHash =
            keccak256(abi.encodePacked(prefix, "imt-boolean-reading-sumcheck-v01", le64(32), le64(count), claims));
        uint192 alpha = NativeKeccak.sample192(s);
        uint192 sum;
        for (uint256 i = count; i != 0; --i) {
            sum = NativeKeccak.read192Memory(claims, i * stride - 24) ^ NativeField.mul(sum, alpha);
        }
        for (uint256 i; i < 32; ++i) {
            bytes calldata message = proof[48 * i:48 * (i + 1)];
            s.blockHash = keccak256(abi.encodePacked(s.blockHash, message));
            s.consumedWords = 0;
            uint192 r = NativeKeccak.sample192(s);
            end.point[i < 6 ? 26 + i : i - 6] = r;
            sum = NativeField.sumcheckRound(sum, NativeKeccak.read192(message, 0), NativeKeccak.read192(message, 24), r);
        }
        end.value = NativeKeccak.read192(proof, 64 * 24);
        end.blockHash = s.blockHash;
        if (sum != NativeField.mul(end.value, totalWeight(claims, end.point, alpha, count))) revert WrongEndpoint();
    }

    /// Check the deferred ring switch's incoming evaluation. The opening carries
    /// 192 little-endian Poly64 rows. WHIR must still authenticate the same tensor.
    function checkTensor(Endpoint memory end, bytes calldata rows) internal pure {
        if (rows.length != 192 * 8) revert InvalidBatch();
        uint192[64] memory columns;
        for (uint256 i; i < 64; ++i) {
            uint192 a = uint64(NativeKeccak.read192(rows, 8 * i));
            uint192 b = uint64(NativeKeccak.read192(rows, 8 * (64 + i)));
            uint192 c = uint64(NativeKeccak.read192(rows, 8 * (128 + i)));
            columns[i] = a | (b << 64) | (c << 128);
        }
        // Transpose three 64-by-64 binary matrices in parallel. Each step
        // exchanges off-diagonal submatrices of size s within each 64-bit limb.
        uint192 mask = 0x00000000ffffffff00000000ffffffff00000000ffffffff;
        for (uint256 s = 32; s != 0; s >>= 1) {
            for (uint256 blockStart; blockStart < 64; blockStart += 2 * s) {
                for (uint256 j = blockStart; j < blockStart + s; ++j) {
                    uint192 swap = ((columns[j] >> s) ^ columns[j + s]) & mask;
                    columns[j] ^= uint192(uint256(swap) << s);
                    columns[j + s] ^= swap;
                }
            }
            mask ^= uint192(uint256(mask) << (s >> 1));
        }
        // Fold adjacent columns first, using the least significant bit coordinate.
        for (uint256 d; d < 6; ++d) {
            uint192 r = end.point[31 - d];
            for (uint256 i; i < 32 >> d; ++i) {
                uint192 a = columns[2 * i];
                columns[i] = a ^ NativeField.mul(r, a ^ columns[2 * i + 1]);
            }
        }
        if (columns[0] != end.value) revert WrongTensor();
    }

    struct RingState {
        NativeKeccak.Stream stream;
        uint192[8] batchingPoint;
        uint192 claimedSum;
    }

    function littleEndian(uint192 a) private pure returns (bytes24) {
        uint256 x = a;
        assembly ("memory-safe") {
            let m := 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff
            x := or(shl(8, and(x, m)), and(shr(8, x), m))
            m := 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff
            x := or(shl(16, and(x, m)), and(shr(16, x), m))
            m := 0x00000000ffffffff00000000ffffffff00000000ffffffff
            x := or(shl(32, and(x, m)), and(shr(32, x), m))
            x := or(shr(128, x), or(and(x, 0xffffffffffffffff0000000000000000), shl(128, x)))
        }
        return bytes24(uint192(x));
    }

    // Pinned Plonky3 batch shape with one current reading at a point of arity 32.
    bytes internal constant RING_DOMAIN =
        hex"81000000000000000170332d73756d636865636b2d6269742d72696e672d7377697463682d636c61696d7300000000000000000000000000000000000000000000000000000000229957a8e3a6fcdc7e9e23a12fb338e1cd6b129185d4d01e85ecff7870930f10730000001c000000080000000000000001000000086465666572726564000000008000000000000000";

    /// Bind the same tensor used for the incoming evaluation. Derive the
    /// starting sum and Fiat-Shamir state for WHIR's deferred initial weight.
    function ringSwitch(Endpoint memory end, bytes calldata rows) internal pure returns (RingState memory ring) {
        checkTensor(end, rows);
        // Reserve the trailing eight bytes touched by the last packed mstore.
        bytes memory encoded = new bytes(32 * 24 + 8);
        assembly ("memory-safe") {
            mstore(encoded, 768)
        }
        for (uint256 i; i < 32; ++i) {
            bytes24 coordinate = littleEndian(end.point[i]);
            assembly ("memory-safe") {
                mstore(add(add(encoded, 32), mul(24, i)), coordinate)
            }
        }
        ring.stream.blockHash =
            keccak256(abi.encodePacked(end.blockHash, littleEndian(end.value), RING_DOMAIN, encoded, rows));
        for (uint256 i; i < 8; ++i) {
            ring.batchingPoint[i] = NativeKeccak.sample192(ring.stream);
        }
        // The single claim has weight lambda^0. Consume lambda to advance the transcript.
        NativeKeccak.sample192(ring.stream);
        uint192[96] memory folds;
        for (uint256 i; i < 96; ++i) {
            uint192 packed = NativeKeccak.read192(rows, 16 * i);
            uint64 lo = uint64(packed);
            uint64 hi = uint64(packed >> 64);
            folds[i] = uint192(lo) ^ NativeField.scale(ring.batchingPoint[7], lo ^ hi);
        }
        uint256 count = 96;
        for (uint256 d = 7; d != 0; --d) {
            uint192 r = ring.batchingPoint[d - 1];
            for (uint256 i; i < count / 2; ++i) {
                uint192 a = folds[2 * i];
                folds[i] = a ^ NativeField.mul(r, a ^ folds[2 * i + 1]);
            }
            if (count % 2 != 0) {
                uint192 a = folds[count - 1];
                folds[count / 2] = a ^ NativeField.mul(r, a);
            }
            count = (count + 1) / 2;
        }
        ring.claimedSum = folds[0];
    }

    // Each node covers a fixed coordinate range of the common random point.
    // Equal serialized inputs at that node have the same equality weight.
    struct WeightCache {
        uint256[1024] inputs;
        uint192[1024] values;
    }

    function subtree(
        bytes memory claims,
        uint256 start,
        uint192[32] memory point,
        uint256 first,
        uint256 width,
        uint256 node,
        WeightCache memory cache
    ) private pure returns (uint192 product) {
        uint256 input;
        uint256 slot;
        assembly ("memory-safe") {
            input := add(add(claims, 32), add(start, mul(first, 24)))
            slot := add(shl(5, node), and(keccak256(input, mul(width, 24)), 31))
        }
        // Hashing selects a bucket. Compare the actual input bytes on every hit.
        uint256 previous = cache.inputs[slot];
        if (previous != 0) {
            bool same;
            assembly ("memory-safe") {
                let last := sub(mul(width, 24), 32)
                same := eq(mload(add(input, last)), mload(add(previous, last)))
                for { let i := 0 } and(same, lt(i, last)) { i := add(i, 32) } {
                    same := eq(mload(add(input, i)), mload(add(previous, i)))
                }
            }
            if (same) return cache.values[slot];
        }
        if (width == 2) {
            uint256 offset = start + 24 * first;
            product = NativeField.mul(
                1 ^ point[first] ^ NativeKeccak.read192Memory(claims, offset),
                1 ^ point[first + 1] ^ NativeKeccak.read192Memory(claims, offset + 24)
            );
        } else {
            uint256 half = width >> 1;
            product = NativeField.mul(
                subtree(claims, start, point, first, half, node * 2, cache),
                subtree(claims, start, point, first + half, half, node * 2 + 1, cache)
            );
        }
        cache.inputs[slot] = input;
        cache.values[slot] = product;
    }

    function totalWeight(bytes memory claims, uint192[32] memory point, uint192 alpha, uint256 count)
        private
        pure
        returns (uint192 sum)
    {
        WeightCache memory cache;
        for (uint256 i = count; i != 0; --i) {
            uint256 start = (i - 1) * 33 * 24;
            uint192 left = subtree(claims, start, point, 0, 16, 2, cache);
            uint192 right = subtree(claims, start, point, 16, 16, 3, cache);
            sum = NativeField.mul(left, right) ^ NativeField.mul(alpha, sum);
        }
    }
}
