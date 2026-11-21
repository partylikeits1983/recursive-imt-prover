// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TerminalSegmentOutputVerifier} from "./TerminalSegmentOutputVerifier.sol";
import {KeccakSegmentReduction} from "./KeccakSegmentReduction.sol";

/// Checks the checkpoint opening and all three rounds at all eight segment
/// positions. The enclosing argument must authenticate the returned input bits.
contract TerminalSegmentRoundsVerifier {
    TerminalSegmentOutputVerifier private immutable table;
    KeccakSegmentReduction private immutable rounds;

    constructor(TerminalSegmentOutputVerifier tableVerifier, KeccakSegmentReduction roundVerifier) {
        require(address(tableVerifier).code.length != 0 && address(roundVerifier).code.length != 0);
        table = tableVerifier;
        rounds = roundVerifier;
    }

    function reduceTransitions(
        bytes32 parent,
        bytes32 left,
        bytes32 right,
        bytes32 root,
        uint256[2] calldata readings,
        bytes calldata proof,
        bytes calldata hints,
        uint256[37] calldata bridge,
        bytes calldata gkr
    ) external view returns (uint256[] memory, uint256[25] memory) {
        (uint256[25] memory outputPoint, uint256[25] memory lanes) =
            table.reduceOutput(parent, left, right, root, readings, proof, hints, bridge);
        bytes32 instance =
            keccak256(abi.encodePacked("recursive-imt/segment-rounds/v1", parent, left, right, root, readings));
        uint256[] memory point = new uint256[](25);
        for (uint256 i; i < 25; ++i) {
            point[i] = outputPoint[i];
        }
        return rounds.reduceFromBits(instance, point, lanes, gkr);
    }
}
