// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {PrimeWhirReduction} from "./PrimeWhirOpeningVerifier.sol";

/// Fixed 22-variable, rate-1/32 WHIR schedule.
library WhirRate32 {
    function schedule() internal pure returns (PrimeWhirReduction.Schedule memory cfg) {
        cfg.domain =
            hex"a0ec7bd36696a78832e33f46e748e87f9ac618b2611f6ecf3cce65ba4360f2ff9edde5a35ff0f88bebd117c76c1deece48818c6170d00cee28cb8e056f385490fc8c823d960630bb11967f14bd08db1a57abb3fb0bee14ec3c291d2d9e2f8a42";
        cfg.generator = 5709868443893258075976348696661355716898495876243883251619397131511003808859;
        cfg.depth = 24;
        cfg.maxHints = 146_648;
        cfg.queries = [49, 35, 27, 22, 19, 17, 15];
        cfg.thresholds = [
            uint64(291587647640057),
            577323597568755,
            426484946027922,
            384888738010590,
            2520450020812150,
            44460738367125888,
            49017964049756784
        ];
    }
}
