// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeMidpointPolicy as Policy} from "./NativeMidpointPolicy.sol";

import {NativeBitBatch} from "./NativeBitBatch.sol";
import {NativeFold} from "./NativeFold.sol";
import {NativeWhirInitial as Initial} from "./NativeWhirInitial.sol";
import {NativeWhirRounds as Rounds} from "./NativeWhirRounds.sol";
import {NativeWhirClosing as Closing} from "./NativeWhirClosing.sol";

/// Open the shared bit commitment at the endpoint derived by the bit-claim verifier.
library NativeWhirOpening {
    struct Proof {
        bytes tensor;
        bytes initial;
        NativeFold.Opening firstRows;
        Rounds.Witness[] steps;
        bytes closing;
    }

    /// The enclosing verifier obtains both reading and ring from the same checked bit reduction.
    function reduce(
        bytes32[2] memory caps,
        NativeBitBatch.RingState memory ring,
        Proof calldata p,
        bool four,
        function(bytes32[2] memory, Initial.Fold memory, Initial.Query memory, NativeFold.Opening calldata)
            internal
            view returns (uint192[71] memory) firstRows
    ) internal view returns (Closing.Check memory) {
        if (
            p.initial.length != Initial.INITIAL_BYTES + 40 + 24 * Policy.INITIAL_OODS
                || p.steps.length != (four ? 4 : 5)
        ) revert Rounds.WrongShape();
        Initial.Fold memory first = Initial.initialFold(ring, p.initial[:Initial.INITIAL_BYTES], four);
        Initial.Query memory q = Initial.firstQuery(first, p.initial[Initial.INITIAL_BYTES:]);
        Rounds.State memory state = Rounds.start(first, q, firstRows(caps, first, q, p.firstRows));
        Rounds.Challenges[] memory steps = new Rounds.Challenges[](p.steps.length);
        for (uint256 s; s < steps.length; ++s) {
            steps[s] = Rounds.step(state, s, p.steps[s], four);
        }
        uint192[] memory last = Rounds.finalFold(state, p.closing, four);
        bytes calldata wire = p.steps[steps.length - 1].wire;
        return Closing.reduce(
            first, q, steps, last, wire[Rounds.foldBytes(steps.length - 1, four):wire.length - 8], state.sum, four
        );
    }
}
