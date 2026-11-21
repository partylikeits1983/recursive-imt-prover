// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BinaryTerminalProfile as Profile} from "./BinaryTerminalProfile.sol";

/// All field elements travel as 16 little-endian bytes (constant coefficient first).
library BinaryTerminalTranscript {
    error WrongShape();
    error InvalidGrindingNonce();

    function little128(uint256 x) internal pure returns (uint256) {
        uint256 m = 0x00ff00ff00ff00ff00ff00ff00ff00ff;
        x = ((x >> 8) & m) | ((x & m) << 8);
        m = 0x0000ffff0000ffff0000ffff0000ffff;
        x = ((x >> 16) & m) | ((x & m) << 16);
        m = 0x00000000ffffffff00000000ffffffff;
        x = ((x >> 32) & m) | ((x & m) << 32);
        return uint64(x >> 64) | (uint256(uint64(x)) << 64);
    }

    function scalar(bytes calldata wire, uint256 i) internal pure returns (uint256) {
        return little128(uint128(bytes16(wire[16 * i:16 * i + 16])));
    }

    function u32le(bytes calldata wire, uint256 offset) internal pure returns (uint256 value) {
        if (offset + 4 > wire.length) revert WrongShape();
        assembly ("memory-safe") {
            let w := calldataload(add(wire.offset, offset))
            value := or(or(byte(0, w), shl(8, byte(1, w))), or(shl(16, byte(2, w)), shl(24, byte(3, w))))
        }
    }

    function challenges(bytes32 publicInput, bytes calldata stream) internal pure returns (bytes32[] memory hashes) {
        if (stream.length != 16 * Profile.SCALARS || scalar(stream, 0) != 20 || scalar(stream, 7) != Profile.RATE_LOG) {
            revert WrongShape();
        }
        // The memory log, table log heights and rate determine the reduction's schedule.
        for (uint256 i; i < Profile.TABLE_HEIGHTS.length; ++i) {
            uint256 n = scalar(stream, i + 1);
            uint256 maxRows = uint256(1) << uint8(Profile.TABLE_HEIGHTS[i]);
            if (n <= (maxRows >> 1) || n > maxRows) revert WrongShape();
        }
        bytes32 initial = keccak256(abi.encodePacked("IMT/LeanVM/terminal-transcript/v1", Profile.PROGRAM, publicInput));
        bytes memory steps = Profile.HASH_STEPS;
        hashes = new bytes32[](steps.length);
        bool valid;
        // Each 128-byte preimage is the previous digest, then four 24-byte slots.
        // Each occupied slot has a scalar and a little-endian u64 observation/nonce tag.
        assembly ("memory-safe") {
            let tmp := mload(0x40)
            let cursor := stream.offset
            let digest := initial
            let mask := not(sub(shl(128, 1), 1))
            let dest := add(hashes, 32)
            valid := 1
            for { let pos := add(steps, 32) } lt(pos, add(add(steps, 32), mload(steps))) { pos := add(pos, 1) } {
                let op := byte(0, mload(pos))
                let count := and(op, 7)
                let bits := shr(3, op)
                mstore(tmp, digest)
                mstore(add(tmp, 32), 0)
                mstore(add(tmp, 64), 0)
                mstore(add(tmp, 96), 0)
                for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                    let nonce := and(iszero(iszero(bits)), eq(add(i, 1), count))
                    let tag := add(1, mul(nonce, 3))
                    mstore(add(add(tmp, 32), mul(i, 24)), or(and(calldataload(cursor), mask), shl(120, tag)))
                    cursor := add(cursor, 16)
                }
                digest := keccak256(tmp, 128)
                if bits {
                    let pow :=
                        or(
                            or(byte(16, digest), shl(8, byte(17, digest))),
                            or(shl(16, byte(18, digest)), shl(24, byte(19, digest)))
                        )
                    if and(pow, sub(shl(bits, 1), 1)) {
                        valid := 0
                        break
                    }
                }
                mstore(dest, digest)
                dest := add(dest, 32)
            }
            valid := and(valid, eq(cursor, add(stream.offset, stream.length)))
        }
        if (!valid) revert InvalidGrindingNonce();
    }
}
