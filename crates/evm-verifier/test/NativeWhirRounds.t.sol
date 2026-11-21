// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WhirFixtureProfile} from "./WhirFixtureProfile.sol";
import {NativeBitBatch} from "../contracts/imt/NativeBitBatch.sol";
import {NativeWhirInitial as Initial} from "../contracts/imt/NativeWhirInitial.sol";
import {NativeWhirRounds as Rounds} from "../contracts/imt/NativeWhirRounds.sol";
import {NativeFold} from "../contracts/imt/NativeFold.sol";

/// The diagnostic caller passes the exact state returned by the previous call.
/// A settlement verifier runs these internal functions with its own state.
contract NativeWhirRoundsHarness is WhirFixtureProfile {
    function fromRing(
        bytes32[2] memory caps,
        bytes32 blockHash,
        uint192 sum,
        bytes calldata section,
        NativeFold.Opening calldata opening
    ) external view returns (bytes memory) {
        return abi.encode(start(caps, blockHash, sum, section, opening));
    }

    function start(
        bytes32[2] memory caps,
        bytes32 blockHash,
        uint192 sum,
        bytes calldata section,
        NativeFold.Opening calldata opening
    ) private view returns (Rounds.State memory) {
        if (section.length != 472) revert Initial.InvalidProofLength();
        NativeBitBatch.RingState memory ring;
        ring.stream.blockHash = blockHash;
        ring.claimedSum = sum;
        Initial.Fold memory first = Initial.initialFold(ring, section[:384], fourVariableFolds());
        Initial.Query memory q = Initial.firstQuery(first, section[384:]);
        return Rounds.start(first, q, authenticatedFirst(caps, first, q, opening));
    }

    function authenticatedFirst(
        bytes32[2] memory caps,
        Initial.Fold memory first,
        Initial.Query memory q,
        NativeFold.Opening calldata opening
    ) internal view virtual returns (uint192[71] memory) {
        return NativeFold.firstRows(caps, first, q, opening);
    }

    /// Meter one call from the ring state to the closing sumcheck.
    function allFolds(
        bytes32[2] memory caps,
        bytes32 blockHash,
        uint192 sum,
        bytes calldata section,
        NativeFold.Opening calldata opening,
        Rounds.Witness[] calldata witnesses,
        bytes calldata closing
    ) external view returns (uint192, bytes32) {
        if (witnesses.length != (fourVariableFolds() ? 4 : 5)) {
            revert Rounds.WrongShape();
        }
        Rounds.State memory s = start(caps, blockHash, sum, section, opening);
        for (uint256 i; i < witnesses.length; ++i) {
            Rounds.step(s, i, witnesses[i], fourVariableFolds());
        }
        uint192[] memory point = Rounds.finalFold(s, closing, fourVariableFolds());
        return (s.sum, keccak256(abi.encodePacked(point)));
    }

    function advance(uint256 stage, bytes calldata carry, Rounds.Witness calldata witness)
        external
        pure
        returns (bytes memory, uint192, uint192, bytes32, bytes32, bytes32)
    {
        Rounds.State memory s = abi.decode(carry, (Rounds.State));
        Rounds.Challenges memory c = Rounds.step(s, stage, witness, fourVariableFolds());
        return (
            abi.encode(s),
            c.alpha,
            s.sum,
            keccak256(abi.encodePacked(c.point)),
            keccak256(abi.encode(c.indices)),
            keccak256(abi.encodePacked(s.values))
        );
    }

    function finish(bytes calldata carry, bytes calldata wire) external pure returns (uint192, bytes32) {
        Rounds.State memory s = abi.decode(carry, (Rounds.State));
        uint192[] memory point = Rounds.finalFold(s, wire, fourVariableFolds());
        return (s.sum, keccak256(abi.encodePacked(point)));
    }
}

contract NativeWhirRoundsHarnessFour is NativeWhirRoundsHarness {
    function fourVariableFolds() internal pure override returns (bool) {
        return true;
    }
}
