// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// Each benchmark deploys a separate contract with its native proof profile fixed in bytecode.
abstract contract WhirFixtureProfile {
    function fourVariableFolds() internal pure virtual returns (bool) {
        return false;
    }
}
