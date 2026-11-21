// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ImtBatchStatement} from "../contracts/ImtBatchStatement.sol";

contract ImtBatchStatementTest {
    function digest64(bytes calldata records) external pure returns (bytes32) {
        return ImtBatchStatement.digest64(records);
    }

    function testMatchesNativeDigestAndBindsOrder() external view {
        // Same ordered records as ordered_statement_binds_input_tag_root_and_count in Rust.
        bytes memory records = new bytes(64 * 96);
        for (uint256 i; i < 64; ++i) {
            for (uint256 j; j < 32; ++j) {
                records[96 * i + j] = bytes1(uint8(i));
                records[96 * i + 32 + j] = bytes1(uint8(255 - i));
                records[96 * i + 64 + j] = bytes1(uint8(42));
            }
        }
        bytes32 expected = 0x7293b4bcf5ed3ad8ad655d255c6c63ac7a99632fced837e931290728a21a5025;
        require(this.digest64(records) == expected);
        for (uint256 i; i < 96; ++i) {
            (records[i], records[i + 96]) = (records[i + 96], records[i]);
        }
        require(this.digest64(records) != expected);
    }

    function testRejectsWrongRecordLengths() external view {
        assertWrongLength(0);
        assertWrongLength(63 * 96);
        assertWrongLength(64 * 96 - 1);
        assertWrongLength(64 * 96 + 1);
    }

    function assertWrongLength(uint256 length) private view {
        try this.digest64(new bytes(length)) returns (bytes32) {
            revert("accepted wrong batch length");
        } catch (bytes memory reason) {
            require(
                keccak256(reason)
                    == keccak256(abi.encodeWithSelector(ImtBatchStatement.WrongBatchLength.selector, length))
            );
        }
    }
}
