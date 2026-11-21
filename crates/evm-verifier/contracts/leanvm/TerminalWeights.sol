// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { LeanVmWhir as W } from "./LeanVmWhir.sol";

library TerminalWeights {
    function evaluate(
        W.Statement[][3] memory groups,
        uint256 gamma,
        uint256 theta,
        uint256 thetaPower,
        uint256[] memory point
    ) public pure returns (uint256) {
        return W.evaluateThreeGroupWeights(groups, gamma, theta, thetaPower, point);
    }
}
