// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeMidpointPolicy as Policy} from "./NativeMidpointPolicy.sol";

import {NativeBitBatch} from "./NativeBitBatch.sol";
import {NativeKeccak} from "./NativeKeccak.sol";
import {NativeField} from "./NativeField.sol";

/// Initial WHIR fold of the shared native terminal opening with 26 packed variables.
library NativeWhirInitial {
    error InvalidProofLength();
    error InvalidProofOfWork();

    // Serialized Poly64 transcript domains from the pinned Plonky3 layout.
    bytes internal constant VIRTUAL_DOMAIN =
        hex"9f000000000000000170332d73756d636865636b2d6c61796f75742d6f6f640000000000000000000000000000000000000000000000000000000000000000000000000000000016569d6ec81944896727d06922bf1fa0e10072e5bc5129a66890329b5c95eea3440000003a00000008000000000000001a0000000100000000010100000008000000000000000100000008000000000000001a0000000800000000000000018000";
    bytes internal constant WHIR_DOMAIN =
        hex"06020000000000000370332d776869720000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007eb82e6a2369b90cb907eb679636c654419dc75579e7e4a125bee2498c9aa9887000001a100000008000000000000001a0000000800000000000000020000000800000000000000000000000800000000000000400000000800000000000000980000000800000000000000100000000800000000000000040000000800000000000000010000002470332d776869722d646f6d61696e3a63616e746f722d6e6f76656c2d62617369732d7631000000010100000008000000000000000100000008000000000000000600000008000000000000000300000008000000000000000600000008000000000000000800000008000000000000000500000008000000000000000000000008000000000000000500000008000000000000000900000008000000000000000300000008000000000000000c00000008000000000000000b00000008000000000000000300000008000000000000000d00000008000000000000000d00000008000000000000000300000008000000000000000e00000008000000000000000f00000008000000000000000300000008000000000000000f000000080000000000000011000000080000000000000003000000080000000000000010800000";

    struct Fold {
        uint192[2] oodPoints;
        uint192 alpha;
        uint192[6] point;
        uint192 sum;
        NativeKeccak.Stream stream;
    }

    struct Query {
        bytes32 nextCap;
        uint192[2] oodPoints;
        uint192[2] answers;
        uint256[71] indices;
        NativeKeccak.Stream stream;
    }

    /// Derive the row positions for both original commitments. The folded
    /// oracle cap must be authenticated in the following WHIR query phase.
    function firstQuery(Fold memory fold, bytes calldata proof) internal pure returns (Query memory q) {
        if (proof.length != 40 + 24 * Policy.INITIAL_OODS) revert InvalidProofLength();
        q.nextCap = bytes32(proof[:32]);
        q.stream = fold.stream;
        q.stream.blockHash = keccak256(abi.encodePacked(q.stream.blockHash, q.nextCap));
        q.stream.consumedWords = 0;
        for (uint256 i; i < Policy.INITIAL_OODS; ++i) {
            uint256 at = 32 + 24 * i;
            q.oodPoints[i] = NativeKeccak.sample192(q.stream);
            q.answers[i] = NativeKeccak.read192(proof, at);
            uint256 end = i + 1 == Policy.INITIAL_OODS ? proof.length : at + 24;
            q.stream.blockHash = keccak256(abi.encodePacked(q.stream.blockHash, proof[at:end]));
            q.stream.consumedWords = 0;
        }
        if (NativeKeccak.sample64(q.stream) & ((1 << Policy.FIRST_QUERY_BITS) - 1) != 0) revert InvalidProofOfWork();

        // Plonky3 partitions the 24-bit address space for each power-of-two
        // summand in the query budget. Preserve draw order, including repeats.
        uint256 cursor;
        for (uint256 bins = 64; bins != 0; bins >>= 1) {
            if (Policy.FIRST_COUNT & bins == 0) continue;
            uint256 width = (1 << 24) / bins;
            for (uint256 j; j < bins; ++j) {
                q.indices[cursor++] = j * width + (NativeKeccak.sample64(q.stream) & (width - 1));
            }
        }
    }

    uint256 internal constant FOLD_WIDTH = Policy.INITIAL_FOLD_BITS == 0 ? 48 : 56;
    uint256 internal constant INITIAL_BYTES = 24 * Policy.INITIAL_OODS + 6 * FOLD_WIDTH;

    /// OOD answers followed by six quadratic fold messages and any required grinding witnesses.
    /// Keep the challenges for the final WHIR constraint evaluation.
    function initialFold(NativeBitBatch.RingState memory ring, bytes calldata proof, bool fourVariableFolds)
        internal
        pure
        returns (Fold memory fold)
    {
        if (proof.length != INITIAL_BYTES || (!fourVariableFolds && Policy.FIRST_COUNT != 71)) {
            revert InvalidProofLength();
        }
        fold.stream = ring.stream;
        bytes memory prefix;
        for (uint256 i; i < Policy.INITIAL_OODS; ++i) {
            fold.stream.blockHash = keccak256(abi.encodePacked(fold.stream.blockHash, prefix, VIRTUAL_DOMAIN));
            fold.stream.consumedWords = 0;
            fold.oodPoints[i] = NativeKeccak.sample192(fold.stream);
            prefix = proof[i * 24:(i + 1) * 24];
        }
        fold.stream.blockHash = keccak256(
            abi.encodePacked(
                fold.stream.blockHash,
                prefix,
                fourVariableFolds ? Policy.WHIR_DOMAIN : WHIR_DOMAIN,
                Policy.BATCHING_DOMAIN
            )
        );
        fold.stream.consumedWords = 0;
        fold.alpha = NativeKeccak.sample192(fold.stream);
        fold.sum = ring.claimedSum;
        for (uint256 i = Policy.INITIAL_OODS; i != 0; --i) {
            fold.sum = NativeKeccak.read192(proof, (i - 1) * 24) ^ NativeField.mul(fold.alpha, fold.sum);
        }
        for (uint256 i; i < 6; ++i) {
            uint256 start = 24 * Policy.INITIAL_OODS + FOLD_WIDTH * i;
            bytes calldata message = proof[start:start + FOLD_WIDTH];
            fold.stream.blockHash = i == 0
                ? keccak256(abi.encodePacked(fold.stream.blockHash, Policy.INITIAL_DOMAIN, message))
                : keccak256(abi.encodePacked(fold.stream.blockHash, message));
            fold.stream.consumedWords = 0;
            if (
                Policy.INITIAL_FOLD_BITS != 0
                    && NativeKeccak.sample64(fold.stream) & ((1 << Policy.INITIAL_FOLD_BITS) - 1) != 0
            ) {
                revert InvalidProofOfWork();
            }
            uint192 r = NativeKeccak.sample192(fold.stream);
            fold.point[i] = r;
            fold.sum = NativeField.sumcheckRound(
                fold.sum, NativeKeccak.read192(message, 0), NativeKeccak.read192(message, 24), r
            );
        }
    }
}
