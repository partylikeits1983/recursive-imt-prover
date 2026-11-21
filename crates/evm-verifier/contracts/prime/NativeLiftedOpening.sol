// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeBitClaimReduction} from "../imt/NativeBitOpeningVerifier.sol";
import {NativeBitBatch} from "../imt/NativeBitBatch.sol";
import {NativeFold} from "../imt/NativeFold.sol";
import {NativeMerkle} from "../imt/NativeMerkle.sol";
import {NativeKeccak as K} from "../imt/NativeKeccak.sol";
import {NativeWhirOpening} from "../imt/NativeWhirOpening.sol";
import {NativeWhirInitial as Initial} from "../imt/NativeWhirInitial.sol";
import {NativeWhirRounds as Rounds} from "../imt/NativeWhirRounds.sol";
import {NativeWhirClosing as Closing} from "../imt/NativeWhirClosing.sol";
import {NativeRingCertificate} from "../imt/NativeRingCertificate.sol";
import {FixedWiringCap} from "../imt/FixedWiringCap.sol";

interface NativeRowCertificate {
    function openingProofBytes() external pure returns (uint256);
    function verifyFolds(
        bytes32 root,
        bytes calldata draws,
        bytes calldata rows,
        bytes calldata values,
        bytes calldata digits,
        bytes calldata proof,
        bytes calldata hints
    ) external view returns (bool);
}

/// Alternate opening module for the full midpoint root. Every deferred row evaluation
/// used in the native transcript is checked by the single prime-field certificate.
contract NativeLiftedOpening is FixedWiringCap {
    bytes32 private immutable authority;
    NativeBitClaimReduction private immutable reduction = new NativeBitClaimReduction();
    NativeRingCertificate private immutable ringVerifier = new NativeRingCertificate();
    NativeRowCertificate private immutable folds;
    uint256 private immutable proofEnd;
    uint256 private constant RING_END = (65 + 1 + 8 * 28 + 192) * 24;

    constructor(bytes32 identity, bytes32 fixedRoot, address[8] memory pages, NativeRowCertificate verifier)
        FixedWiringCap(fixedRoot, pages)
    {
        require(address(verifier).code.length != 0);
        authority = identity;
        folds = verifier;
        proofEnd = 8744 + verifier.openingProofBytes();
    }

    function digestRows() internal pure virtual returns (bool) {
        return false;
    }

    function authenticate(
        bytes32 cap,
        uint256 depth,
        uint256 width,
        uint256[] memory ids,
        bytes calldata rows,
        bytes32[] calldata path
    ) private pure {
        if (!digestRows()) {
            NativeMerkle.verify(cap, depth, width, ids, rows, path);
            return;
        }
        (, bytes32[] memory hashes, uint256 n) = NativeMerkle.digestFrontier(depth, depth, ids, rows, path);
        if (n != 1 || hashes[0] != cap) revert NativeMerkle.InvalidMerkleOpening();
    }

    function copyRow(bytes memory ordered, uint256 cursor, bytes calldata src, uint256 offset, uint256 length)
        private
        pure
    {
        bytes calldata row = src[offset:offset + length];
        if (cursor + length > ordered.length) revert Rounds.WrongShape();
        assembly ("memory-safe") { calldatacopy(add(add(ordered, 32), cursor), row.offset, length) }
    }

    function collectFirst(
        bytes32 cap,
        Initial.Query memory q,
        NativeFold.Opening calldata opening,
        bytes memory ordered,
        bytes calldata values
    ) private view returns (uint192[71] memory v) {
        (uint256[] memory ids, uint256[71] memory ranks) = NativeFold.queryOrder(q.indices);
        authenticate(cap, 24, 256, ids, opening.mainRows, opening.mainPath);
        if (digestRows()) {
            (uint256[] memory nodes, bytes32[] memory hashes, uint256 n) =
                NativeMerkle.digestFrontier(24, 12, ids, opening.fixedRows, opening.fixedPath);
            checkFrontier(nodes, hashes, n);
        } else {
            verifyRows(ids, opening.fixedRows, opening.fixedPath);
        }
        uint256 mainWidth = digestRows() ? 32 : 256;
        uint256 fixedWidth = digestRows() ? 32 : 128;
        uint256 stride = mainWidth + fixedWidth;
        for (uint256 i; i < 71; ++i) {
            copyRow(ordered, i * stride, opening.mainRows, ranks[i] * mainWidth, mainWidth);
            copyRow(ordered, i * stride + mainWidth, opening.fixedRows, ranks[i] * fixedWidth, fixedWidth);
            v[i] = K.read192(values, i * 24);
        }
    }

    function collectLater(
        bytes32 cap,
        Rounds.Challenges memory c,
        uint256 stage,
        Rounds.Witness calldata w,
        bytes memory ordered,
        uint256 start,
        bytes calldata values
    ) private pure returns (uint192[] memory v) {
        uint256 count = Rounds.queryCount(stage, true);
        (uint256[] memory ids, uint256[71] memory ranks) = NativeFold.queryOrder(c.indices, count);
        authenticate(cap, 24 - stage, 384, ids, w.rows, w.siblings);
        uint256 width = digestRows() ? 32 : 384;
        uint256 base = (start + (digestRows() ? 71 : 0)) * width;
        v = new uint192[](count);
        for (uint256 i; i < count; ++i) {
            copyRow(ordered, base + i * width, w.rows, ranks[i] * width, width);
            v[i] = K.read192(values, (start + i) * 24);
        }
    }

    function reduceFolds(
        bytes32 cap,
        NativeBitBatch.RingState memory ring,
        NativeWhirOpening.Proof calldata p,
        bytes calldata cert
    ) private view returns (Closing.Check memory) {
        if (p.initial.length != 472 || p.steps.length != 4 || cert.length < proofEnd) revert Rounds.WrongShape();
        bytes calldata values = cert[32:4088];
        Initial.Fold memory first = Initial.initialFold(ring, p.initial[:384], true);
        Initial.Query memory q = Initial.firstQuery(first, p.initial[384:]);
        bytes memory draws = new bytes(22 * 24);
        bytes memory rows = new bytes(digestRows() ? 240 * 32 : 169 * 384);
        for (uint256 i; i < 6; ++i) {
            K.write192(draws, 24 * i, first.point[i]);
        }
        Rounds.State memory state = Rounds.start(first, q, collectFirst(cap, q, p.firstRows, rows, values));
        Rounds.Challenges[] memory steps = new Rounds.Challenges[](4);
        uint256 index = 71;
        for (uint256 stage; stage < 4; ++stage) {
            bytes32 previous = state.cap;
            Rounds.Witness calldata w = p.steps[stage];
            Rounds.Challenges memory c = Rounds.challenges(state, stage, w, true);
            state.values = collectLater(previous, c, stage, w, rows, index, values);
            index += state.values.length;
            for (uint256 j; j < 4; ++j) {
                K.write192(draws, 24 * (6 + 4 * stage + j), c.point[j]);
            }
            if (stage == 3) Rounds.checkFinalRows(w.wire[224:w.wire.length - 8], c.indices, state.values);
            steps[stage] = c;
        }
        if (
            index != 169
                || !folds.verifyFolds(
                    bytes32(cert[:32]), draws, rows, values, cert[4088:8744], cert[8744:proofEnd], cert[proofEnd:]
                )
        ) {
            revert Rounds.WrongShape();
        }
        uint192[] memory last = Rounds.finalFold(state, p.closing, true);
        bytes calldata wire = p.steps[3].wire;
        return Closing.reduce(first, q, steps, last, wire[224:wire.length - 8], state.sum, true);
    }

    function verifyOpening(bytes32 cap, bytes calldata claims, bytes calldata batch, NativeWhirOpening.Proof calldata p)
        external
        view
        returns (Closing.Identity memory)
    {
        if (batch.length <= RING_END) revert Rounds.WrongShape();
        (uint192[32] memory reading, NativeBitBatch.RingState memory ring) =
            reduction.reduce([authority, cap, wiringRoot], claims, batch[:65 * 24], p.tensor);
        Closing.Check memory end = reduceFolds(cap, ring, p, batch[RING_END:]);
        return Closing.finish(end, ringVerifier.verify(reading, end.draw, ring.batchingPoint, batch[65 * 24:RING_END]));
    }
}

contract NativeDigestOpening is NativeLiftedOpening {
    constructor(bytes32 identity, bytes32 fixedRoot, address[8] memory pages, NativeRowCertificate verifier)
        NativeLiftedOpening(identity, fixedRoot, pages, verifier)
    {}

    function digestRows() internal pure override returns (bool) {
        return true;
    }
}
