// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BinaryTerminalTest} from "../../../test/BinaryTerminal.t.sol";

contract BinaryCompactTest is BinaryTerminalTest {
    function opening() internal pure override returns (string memory, bytes16, uint128, uint128) {
        return (
            "test/fixtures/binary-terminal-compact-64.imt",
            0x44a194183108c8747f7476ad29d07665,
            0x1a10cbc64c186a36b9cdcdd360296ce0,
            0xb35473bd6c994891e7a21d86c4ed7b3f
        );
    }
}
