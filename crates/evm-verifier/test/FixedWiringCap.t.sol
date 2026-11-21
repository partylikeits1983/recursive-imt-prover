// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeWhirRoundsHarness} from "./NativeWhirRounds.t.sol";
import {FixedWiringCap} from "../contracts/imt/FixedWiringCap.sol";
import {NativeFold} from "../contracts/imt/NativeFold.sol";
import {NativeWhirInitial} from "../contracts/imt/NativeWhirInitial.sol";
import {NativeBitBatch} from "../contracts/imt/NativeBitBatch.sol";

/// Differential harness for the real root. The ring state is independently
/// reproduced by the bit-batch component before this call.
contract CappedFoldHarness is FixedWiringCap, NativeWhirRoundsHarness {
    constructor(bytes32 root, address[8] memory sources) FixedWiringCap(root, sources) {}

    function authenticatedFirst(
        bytes32[2] memory caps,
        NativeWhirInitial.Fold memory first,
        NativeWhirInitial.Query memory q,
        NativeFold.Opening calldata opening
    ) internal view override returns (uint192[71] memory) {
        return firstRows(caps, first, q, opening);
    }

    function checkFirstRows(
        bytes32[2] memory caps,
        bytes32 ringBlock,
        uint192 ringSum,
        bytes calldata section,
        NativeFold.Opening calldata opening
    ) external view returns (bytes32) {
        if (section.length != 472) revert NativeWhirInitial.InvalidProofLength();
        NativeBitBatch.RingState memory ring;
        ring.stream.blockHash = ringBlock;
        ring.claimedSum = ringSum;
        NativeWhirInitial.Fold memory fold = NativeWhirInitial.initialFold(ring, section[:384], fourVariableFolds());
        NativeWhirInitial.Query memory query = NativeWhirInitial.firstQuery(fold, section[384:]);
        return keccak256(abi.encode(firstRows(caps, fold, query, opening)));
    }
}

contract CappedFoldHarnessFour is CappedFoldHarness {
    constructor(bytes32 root, address[8] memory sources) CappedFoldHarness(root, sources) {}

    function fourVariableFolds() internal pure override returns (bool) {
        return true;
    }
}
