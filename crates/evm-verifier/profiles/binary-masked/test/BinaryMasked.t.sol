// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BinaryTerminalTest} from "../../../test/BinaryTerminal.t.sol";

contract BinaryMaskedTest is BinaryTerminalTest {
    function publicStatement() internal pure override returns (bytes32, uint8, string memory) {
        return (
            0xe53194aaa11bf06e943ad2139ad621891cb25d21d6c7347e3864cb10e82e290f,
            2,
            "test/fixtures/leanvm-masked-imt-roots-2.bin"
        );
    }

    function opening() internal pure override returns (string memory, bytes16, uint128, uint128) {
        return (
            "test/fixtures/binary-terminal-masked-2.imt",
            0x737545a7eb8d3c39f6a1a5d8733b7d92,
            0xbb90b1db5c59c9e0a16496f39e7b9258,
            0xcc764b132e4cd357ef02d6984a10512a
        );
    }
}
