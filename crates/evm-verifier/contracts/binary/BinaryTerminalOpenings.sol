// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BinaryTerminalProfile as P} from "./BinaryTerminalProfile.sol";
import {BinaryTerminalTranscript as T} from "./BinaryTerminalTranscript.sol";
import {BinaryTerminalMerkle as M} from "./BinaryTerminalMerkle.sol";

import {BinaryWhir} from "./BinaryWhir.sol";
import {BinaryStackTarget} from "./BinaryStackTarget.sol";
import {BinaryStackBasis} from "./BinaryStackBasis.sol";
import {ImtBatchStatement} from "../ImtBatchStatement.sol";

/// Transcript and opening authentication for one pinned recursive terminal profile.
/// The enclosing verifier must discharge the deferred bytecode evaluation and the algebraic identities.
contract BinaryTerminalOpenings {
    BinaryStackBasis private immutable STACK_BASIS = new BinaryStackBasis();

    function frame(bytes32 digest, uint8 count, bytes16 deferredValue, bytes calldata proof)
        private
        pure
        returns (bytes calldata stream, bytes32[] memory challenges, uint256 offset, bytes32 publicInput)
    {
        if (count != P.COUNT || bytes8(proof[:8]) != bytes8(uint64(P.POINT_LOG) << 56)) revert T.WrongShape();
        uint256 streamStart = 8 + uint256(P.POINT_LOG) * 16 + 4;
        if (T.u32le(proof, streamStart - 4) != P.SCALARS) revert T.WrongShape();
        publicInput = keccak256(
            abi.encodePacked(P.PROGRAM, digest, bytes1(count), new bytes(63), proof[8:streamStart - 4], deferredValue)
        );
        uint256 end = streamStart + P.SCALARS * 16;
        stream = proof[streamStart:end];
        challenges = T.challenges(publicInput, stream);
        if (T.u32le(proof, end) != 5) revert T.WrongShape();
        offset = end + 4;
    }

    /// The caller derives target and basis from the execution, bus, Keccak and ring-switch reductions.
    function checkWhir(
        bytes32 digest,
        uint8 count,
        bytes16 deferredValue,
        uint128 target,
        uint128 basis,
        bytes calldata proof
    ) public pure returns (bool) {
        (bytes calldata stream, bytes32[] memory challenges, uint256 offset,) =
            frame(digest, count, deferredValue, proof);
        if (BinaryWhir.verify(proof, stream, challenges, offset, target, basis) != proof.length) revert T.WrongShape();
        return true;
    }

    /// Opening check with the public IMT roots supplied in client order.
    /// The three reduction inputs still require independent execution verification.
    function checkRootListOpening(
        bytes32[] calldata roots,
        bytes16 deferredValue,
        uint128 target,
        uint128 basis,
        bytes calldata proof
    ) external pure returns (bool) {
        if (roots.length != P.COUNT) revert T.WrongShape();
        return checkWhir(ImtBatchStatement.digestRoots(roots), uint8(roots.length), deferredValue, target, basis, proof);
    }

    /// Derives the stacked opening target from the root-bound transcript. The basis,
    /// deferred bytecode value and VM execution identities still need verification.
    function checkRootListStackTarget(
        bytes32[] calldata roots,
        bytes16 deferredValue,
        uint128 basis,
        bytes calldata proof
    ) external pure returns (bool) {
        if (roots.length != P.COUNT) revert T.WrongShape();
        (bytes calldata stream, bytes32[] memory hashes, uint256 offset, bytes32 publicInput) =
            frame(ImtBatchStatement.digestRoots(roots), P.COUNT, deferredValue, proof);
        uint256 target = BinaryStackTarget.derive(publicInput, stream, hashes);
        if (BinaryWhir.verify(proof, stream, hashes, offset, target, basis) != proof.length) revert T.WrongShape();
        return true;
    }

    /// Verifies the stack opening with both reductions derived from the transcript.
    /// Execution identities and the deferred bytecode evaluation are separate obligations.
    function checkRootListStackOpening(bytes32[] calldata roots, bytes16 deferredValue, bytes calldata proof)
        external
        view
        returns (bool)
    {
        if (roots.length != P.COUNT) revert T.WrongShape();
        (bytes calldata stream, bytes32[] memory hashes, uint256 offset, bytes32 publicInput) =
            frame(ImtBatchStatement.digestRoots(roots), P.COUNT, deferredValue, proof);
        uint256 target = BinaryStackTarget.derive(publicInput, stream, hashes);
        if (BinaryWhir.verify(proof, stream, hashes, offset, target, STACK_BASIS.derive(hashes)) != proof.length) {
            revert T.WrongShape();
        }
        return true;
    }

    function checkOpenings(bytes32 digest, uint8 count, bytes16 deferredValue, bytes calldata proof)
        external
        pure
        returns (bool)
    {
        (bytes calldata stream, bytes32[] memory challenges, uint256 offset,) =
            frame(digest, count, deferredValue, proof);
        for (uint256 i; i < 5; ++i) {
            (uint256 capPos, uint256 firstHash, uint256 depth, uint256 draws) = P.phase(i);
            bytes32 cap = bytes32(stream[capPos * 16:capPos * 16 + 32]);
            M.Rows memory rows =
                M.open(proof, offset, cap, depth, draws, i == 0 ? 1 << P.FIRST_FOLD : 32, challenges, firstHash);
            offset = rows.end;
        }
        if (offset != proof.length) revert T.WrongShape();
        return true;
    }
}
