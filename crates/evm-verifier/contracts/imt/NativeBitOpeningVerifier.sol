// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeBitBatch} from "./NativeBitBatch.sol";
import {NativeWhirOpening} from "./NativeWhirOpening.sol";
import {NativeWhirClosing} from "./NativeWhirClosing.sol";
import {NativeWhirInitial as Initial} from "./NativeWhirInitial.sol";
import {NativeFold} from "./NativeFold.sol";
import {FixedWiringCap} from "./FixedWiringCap.sol";

import {NativeRingWeight} from "./NativeRingWeight.sol";
import {NativeRingCertificate} from "./NativeRingCertificate.sol";

contract NativeBitClaimReduction {
    function reduce(bytes32[3] memory keys, bytes memory claims, bytes calldata batch, bytes calldata tensor)
        external
        pure
        returns (uint192[32] memory, NativeBitBatch.RingState memory)
    {
        NativeBitBatch.Endpoint memory end = NativeBitBatch.reduceTerminal(keys[0], keys[1], keys[2], claims, batch);
        return (end.point, NativeBitBatch.ringSwitch(end, tensor));
    }
}

/// Polynomial-opening component of the shared 64-client terminal protocol.
/// The calling root verifier derives mainCap and the 134 ordered claim records
/// from its authenticated arithmetic and Keccak arguments.
abstract contract NativeBitOpeningBase {
    NativeBitClaimReduction private immutable reduction = new NativeBitClaimReduction();
    bytes32 private immutable authority;
    bytes32 private immutable fixedCommitment;

    constructor(bytes32 expectedAuthority, bytes32 expectedWiringRoot) {
        authority = expectedAuthority;
        fixedCommitment = expectedWiringRoot;
    }

    function fourVariableFolds() internal pure virtual returns (bool) {
        return false;
    }

    function authenticatedFirstRows(
        bytes32[2] memory caps,
        Initial.Fold memory fold,
        Initial.Query memory query,
        NativeFold.Opening calldata rows
    ) internal view virtual returns (uint192[71] memory) {
        return NativeFold.firstRows(caps, fold, query, rows);
    }

    function reduceOpening(
        bytes32 mainCap,
        bytes calldata claims,
        bytes calldata batch,
        NativeWhirOpening.Proof calldata p
    )
        internal
        view
        returns (uint192[32] memory reading, uint192[8] memory batching, NativeWhirClosing.Check memory check)
    {
        NativeBitBatch.RingState memory ring;
        (reading, ring) = reduction.reduce([authority, mainCap, fixedCommitment], claims, batch, p.tensor);
        batching = ring.batchingPoint;
        check =
            NativeWhirOpening.reduce([mainCap, fixedCommitment], ring, p, fourVariableFolds(), authenticatedFirstRows);
    }
}

contract NativeBitOpeningVerifier is NativeBitOpeningBase {
    constructor(bytes32 authority, bytes32 fixedCap) NativeBitOpeningBase(authority, fixedCap) {}

    function verifyOpening(
        bytes32 mainCap,
        bytes calldata claims,
        bytes calldata batch,
        NativeWhirOpening.Proof calldata p
    ) external view virtual returns (NativeWhirClosing.Identity memory) {
        (uint192[32] memory reading, uint192[8] memory batching, NativeWhirClosing.Check memory check) =
            reduceOpening(mainCap, claims, batch, p);
        return NativeWhirClosing.finish(check, NativeRingWeight.evaluate(reading, check.draw, batching));
    }
}

contract NativeBitOpeningVerifierFour is NativeBitOpeningVerifier {
    constructor(bytes32 expectedAuthority, bytes32 expectedWiringRoot)
        NativeBitOpeningVerifier(expectedAuthority, expectedWiringRoot)
    {}

    function fourVariableFolds() internal pure override returns (bool) {
        return true;
    }
}

/// The public fixed-tree cap is authenticated once at deployment and reused
/// across every root proved with this key. The witness tree remains per proof.
contract NativeCappedBitOpeningVerifier is NativeBitOpeningVerifier, FixedWiringCap {
    constructor(bytes32 authority, bytes32 fixedRoot, address[8] memory pages)
        NativeBitOpeningVerifier(authority, fixedRoot)
        FixedWiringCap(fixedRoot, pages)
    {}

    function authenticatedFirstRows(
        bytes32[2] memory caps,
        Initial.Fold memory fold,
        Initial.Query memory query,
        NativeFold.Opening calldata rows
    ) internal view override returns (uint192[71] memory) {
        return firstRows(caps, fold, query, rows);
    }
}

contract NativeCappedBitOpeningVerifierFour is NativeCappedBitOpeningVerifier {
    constructor(bytes32 authority, bytes32 fixedRoot, address[8] memory pages)
        NativeCappedBitOpeningVerifier(authority, fixedRoot, pages)
    {}

    function fourVariableFolds() internal pure override returns (bool) {
        return true;
    }
}

/// The certificate only computes the ring weight. Both verification modes
/// derive every input to that calculation from the same authenticated opening.
contract NativeCertifiedBitOpeningVerifier is NativeBitOpeningBase {
    NativeRingCertificate private immutable ringVerifier = new NativeRingCertificate();
    constructor(bytes32 authority, bytes32 fixedCap) NativeBitOpeningBase(authority, fixedCap) {}

    function verifyOpening(
        bytes32 mainCap,
        bytes calldata claims,
        bytes calldata batch,
        NativeWhirOpening.Proof calldata p,
        bytes calldata certificate
    ) external view returns (NativeWhirClosing.Identity memory) {
        (uint192[32] memory reading, uint192[8] memory batching, NativeWhirClosing.Check memory check) =
            reduceOpening(mainCap, claims, batch, p);
        return NativeWhirClosing.finish(check, ringVerifier.verify(reading, check.draw, batching, certificate));
    }
}

contract NativeCertifiedBitOpeningVerifierFour is NativeCertifiedBitOpeningVerifier {
    constructor(bytes32 authority, bytes32 fixedCap) NativeCertifiedBitOpeningVerifier(authority, fixedCap) {}

    function fourVariableFolds() internal pure override returns (bool) {
        return true;
    }
}

/// Full root opening with an authenticated fixed-tree cap and the public
/// sumcheck certificate for the ring weight. The first 65 field elements
/// encode the ordinary bit-claim batch, followed by the ring certificate.
contract NativeCappedCertifiedBitOpeningVerifierFour is NativeCappedBitOpeningVerifierFour {
    NativeRingCertificate private immutable ringVerifier = new NativeRingCertificate();

    constructor(bytes32 authority, bytes32 fixedRoot, address[8] memory pages)
        NativeCappedBitOpeningVerifierFour(authority, fixedRoot, pages)
    {}

    function verifyOpening(
        bytes32 mainCap,
        bytes calldata claims,
        bytes calldata wire,
        NativeWhirOpening.Proof calldata p
    ) external view override returns (NativeWhirClosing.Identity memory) {
        uint256 batch = 65 * 24;
        if (wire.length < batch) revert NativeBitBatch.InvalidBatch();
        (uint192[32] memory reading, uint192[8] memory batching, NativeWhirClosing.Check memory check) =
            reduceOpening(mainCap, claims, wire[:batch], p);
        return NativeWhirClosing.finish(check, ringVerifier.verify(reading, check.draw, batching, wire[batch:]));
    }
}
