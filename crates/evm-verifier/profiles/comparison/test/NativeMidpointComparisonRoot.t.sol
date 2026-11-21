// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {RootFixtureTest} from "../../../test/NativeAggregateRoot.t.sol";

contract NativeMidpointComparisonRootTest is RootFixtureTest {
    function profile() internal pure override returns (bytes32, string memory, string memory) {
        // Both circuits have the same column geometry and fixed wiring.
        return
            (0x282c3def9df3dc42b9b396bc9613c5e501fe9e66102800cc3b40a6bd250b9c55, "NativeMidpoint", "terminal-midpoint");
    }

    function setUp() public override {
        super.setUp();
        fixture = "test/fixtures/terminal-midpoint-comparison-root-call.bin";
    }

    function testRejectsStrongProofOfSameStatement() external view {
        bytes memory strong = VM.readFileBinary("test/fixtures/terminal-midpoint-root-call.bin");
        (bool ok, bytes memory reason) = verifier.staticcall(strong);
        require(!ok && reason.length >= 4);
    }
}
