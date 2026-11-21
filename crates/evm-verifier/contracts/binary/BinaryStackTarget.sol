// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BinaryExtension as E} from "./BinaryExtension.sol";
import {BinaryTerminalProfile as P} from "./BinaryTerminalProfile.sol";
import {BinaryTerminalTranscript as T} from "./BinaryTerminalTranscript.sol";

/// The batched claimed value on the VM's stacked polynomial. The native ring switch
/// maps 64 input slices to its leading claim. All other claims follow in verifier order.
library BinaryStackTarget {
    function challenge(bytes32[] memory hashes, uint256 i) private pure returns (uint256) {
        return T.little128(uint128(bytes16(hashes[i])));
    }

    function frobenius8(uint256 x) private pure returns (uint256) {
        for (uint256 i; i < 8; ++i) {
            x = E.square(x);
        }
        return x;
    }

    function ringTarget(bytes calldata stream, bytes32[] memory hashes) private pure returns (uint256 target) {
        uint256[8] memory g;
        for (uint256 i; i < 8; ++i) {
            g[i] = challenge(hashes, P.RING_CHALLENGES + 8 + i);
        }
        uint256[64] memory images;
        for (uint256 i; i < 64; ++i) {
            uint256 v = T.scalar(stream, P.SLICES + i);
            uint256 psi = E.mul(g[0], v);
            for (uint256 j = 1; j < 8; ++j) {
                v = E.square(v);
                psi ^= E.mul(g[j], v);
            }
            images[i] = psi;
        }
        uint256 z = 2;
        for (uint256 p = 8; p != 0;) {
            unchecked {
                --p;
            }
            z = frobenius8(z);
            uint256 acc = images[63];
            for (uint256 i = 63; i != 0;) {
                unchecked {
                    --i;
                }
                acc = images[i] ^ E.mulBase(acc, uint64(z));
            }
            for (uint256 j; j < p; ++j) {
                acc = frobenius8(acc);
            }
            target ^= E.mul(acc, challenge(hashes, P.RING_CHALLENGES + p));
        }
    }

    function derive(bytes32 publicInput, bytes calldata stream, bytes32[] memory hashes)
        internal
        pure
        returns (uint256)
    {
        uint256 r = challenge(hashes, P.RING_CHALLENGES + 16);
        uint256 acc = T.scalar(stream, P.OUTPUT_VALUE) ^ E.mul(r, T.scalar(stream, P.OOD_VALUE));
        uint256 x = challenge(hashes, P.PUBLIC_CHALLENGE);
        uint256 low = T.little128(uint128(bytes16(publicInput)));
        uint256 high = T.little128(uint128(uint256(publicInput)));
        for (uint256 i = 2; i != 0;) {
            unchecked {
                --i;
            }
            uint64 a = uint64(low >> (64 * i));
            uint64 b = uint64(high >> (64 * i));
            acc = E.mul(acc, r) ^ a ^ E.mulBase(x, a ^ b);
        }
        // The range list excludes the uncommitted table columns. Each range packs
        // its first scalar and count as two big-endian u16s in the pinned profile.
        bytes memory ranges = P.TARGET_RANGES;
        for (uint256 end = ranges.length; end != 0; end -= 4) {
            uint256 span;
            assembly ("memory-safe") { span := shr(224, mload(add(add(ranges, 28), end))) }
            uint256 start = span >> 16;
            for (uint256 i = start + uint16(span); i > start;) {
                unchecked {
                    --i;
                }
                acc = T.scalar(stream, i) ^ E.mul(acc, r);
            }
        }
        return ringTarget(stream, hashes) ^ E.mul(acc, r);
    }
}
