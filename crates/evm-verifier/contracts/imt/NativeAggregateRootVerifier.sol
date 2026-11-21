// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeRootRelation, NativeMidpointRootRelation} from "./NativeRootRelation.sol";
import {NativeColumnVerifier, NativeMidpointColumnVerifier} from "./NativeColumnVerifier.sol";
import {NativeBitOpeningVerifier} from "./NativeBitOpeningVerifier.sol";
import {NativeWhirOpening} from "./NativeWhirOpening.sol";
import {NativeKeccak as K} from "./NativeKeccak.sol";

/// Direct verification of the 64-client shared-opening IMT root. Deployments
/// pin the three verifier instances belonging to the same trusted root key.
contract NativeAggregateRootVerifier {
    NativeRootRelation private immutable relation;
    NativeColumnVerifier private immutable columns;
    NativeBitOpeningVerifier private immutable opening;

    constructor(
        NativeRootRelation relationVerifier,
        NativeColumnVerifier columnVerifier,
        NativeBitOpeningVerifier openingVerifier
    ) {
        require(
            address(relationVerifier).code.length != 0 && address(columnVerifier).code.length != 0
                && address(openingVerifier).code.length != 0
        );
        relation = relationVerifier;
        columns = columnVerifier;
        opening = openingVerifier;
    }

    function verifyRoot(
        bytes32 expectedDigest,
        uint8 expectedCount,
        bytes32 mainCap,
        NativeRootRelation.Proof calldata p,
        bytes calldata batch,
        NativeWhirOpening.Proof calldata pcs
    ) external view returns (bool) {
        (uint192[19] memory point, K.Stream memory transcript, uint192[27][4] memory auxiliary) =
            relation.reduceRelation(expectedDigest, expectedCount, mainCap, p);
        bytes memory claims = columns.derive(point, transcript.blockHash, auxiliary, p.columns);
        opening.verifyOpening(mainCap, claims, batch, pcs);
        return true;
    }
}

contract NativeMidpointAggregateRootVerifier {
    NativeMidpointRootRelation private immutable relation;
    NativeMidpointColumnVerifier private immutable columns;
    NativeBitOpeningVerifier private immutable opening;

    constructor(
        NativeMidpointRootRelation relationVerifier,
        NativeMidpointColumnVerifier columnVerifier,
        NativeBitOpeningVerifier openingVerifier
    ) {
        require(
            address(relationVerifier).code.length != 0 && address(columnVerifier).code.length != 0
                && address(openingVerifier).code.length != 0
        );
        relation = relationVerifier;
        columns = columnVerifier;
        opening = openingVerifier;
    }

    function verifyRoot(
        bytes32 expectedDigest,
        uint8 expectedCount,
        bytes32 mainCap,
        NativeRootRelation.Proof calldata p,
        bytes calldata batch,
        NativeWhirOpening.Proof calldata pcs
    ) external view returns (bool) {
        (uint192[19] memory point, K.Stream memory transcript, uint192[28][5] memory auxiliary) =
            relation.reduceRelation(expectedDigest, expectedCount, mainCap, p);
        bytes memory claims = columns.derive(point, transcript.blockHash, auxiliary, p.columns);
        opening.verifyOpening(mainCap, claims, batch, pcs);
        return true;
    }
}
