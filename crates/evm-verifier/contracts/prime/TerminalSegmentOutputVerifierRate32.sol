// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TerminalSegmentOutputVerifier} from "./TerminalSegmentOutputVerifier.sol";

import {WhirRate32} from "./WhirRate32.sol";

/// Rate-1/32 checkpoint opening at the same 135-bit local Johnson target.
/// The initial RS domain is twice as large, reducing the number of queried rows.
contract TerminalSegmentOutputVerifierRate32 is TerminalSegmentOutputVerifier {
    function schedule() internal pure override returns (Schedule memory) {
        return WhirRate32.schedule();
    }
}
