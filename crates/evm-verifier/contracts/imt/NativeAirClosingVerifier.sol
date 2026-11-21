// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeArithmeticVerifier} from "./NativeArithmeticVerifier.sol";
import {NativeField as F} from "./NativeField.sol";
import {NativeKeccak as K} from "./NativeKeccak.sol";

/// Evaluate the trusted AIR and bus relations on the column readings. The
/// enclosing verifier must open these same readings in the shared polynomial commitment.
contract NativeAirClosingVerifier is NativeArithmeticVerifier {
    error InvalidClosingKey();
    error InvalidArithmeticColumns();

    address[4] private closingPages;

    constructor(bytes32 authority, bytes32 fixedRoot, address[4] memory busPages, address[4] memory airPages)
        NativeArithmeticVerifier(authority, fixedRoot, busPages)
    {
        bytes32[4] memory hashes = [
            bytes32(0xa598e6916167cc6b99ca98cb1a105bcddec27a5a989e88c30b360a465bed19c3),
            bytes32(0x48b85bbc7753bf012730172bad7a37b81c9f862f28a860d3ec521fcaad102981),
            bytes32(0x0a71cb48e1823cedc67365722bad0996a4aa7c363c4533a94e2f2dd30a04eb52),
            bytes32(0xebb2df8f88d1d2db6fb2e37229e6daea1bd5353554ff369a161e5e7858d23daf)
        ];
        for (uint256 i; i < 4; ++i) {
            if (airPages[i].codehash != hashes[i]) revert InvalidClosingKey();
        }
        closingPages = airPages;
    }

    function program() private view returns (bytes memory code) {
        code = new bytes(57475);
        for (uint256 i; i < 4; ++i) {
            address page = closingPages[i];
            uint256 take = i == 3 ? 57475 - 3 * 16384 : 16384;
            assembly ("memory-safe") {
                extcodecopy(page, add(add(code, 32), shl(14, i)), 1, take)
            }
        }
    }

    // The key compiler emits 100 big-endian Poly64 constants, then five-byte
    // instructions in topological order: opcode, left u16, right u16.
    // For the two packed constant scalings the right operand is an exponent.
    function evaluate(uint192[] memory registers, bytes memory code) private pure returns (uint192) {
        // The AIR's Horner evaluation multiplies by alpha 997 times.
        uint192[] memory alphaTable = F.multiplierTable(registers[2]);
        uint256 pos;
        uint256 write;
        uint256 end;
        assembly ("memory-safe") {
            pos := add(code, 32)
            write := add(add(registers, 32), mul(2175, 32))
            end := add(pos, 800)
            for {} lt(pos, end) { pos := add(pos, 8) } {
                mstore(write, shr(192, mload(pos)))
                write := add(write, 32)
            }
            end := add(add(code, 32), mload(code))
        }
        while (pos < end) {
            uint256 tag;
            uint256 right;
            uint192 a;
            uint192 b;
            assembly ("memory-safe") {
                let instruction := mload(pos)
                tag := byte(0, instruction)
                let base := add(registers, 32)
                a := mload(add(base, shl(5, and(shr(232, instruction), 65535))))
                right := and(shr(216, instruction), 65535)
                b := mload(add(base, shl(5, right)))
                pos := add(pos, 5)
            }
            uint192 result;
            if (tag == 1) result = a ^ b;
            else if (tag == 2) result = F.mul(a, b);
            else if (tag == 5) result = F.multiplyFixed(alphaTable, b);
            else if (tag == 6) result = F.scaleMonomial(a, right);
            else if (tag == 7) result = F.scaleOnes(a, right);
            else if (tag == 3) result = F.square(a);
            else result = F.scale(a, uint64(b));
            assembly ("memory-safe") {
                mstore(write, result)
                write := add(write, 32)
            }
        }
        return registers[13609];
    }

    function verifyArithmetic(
        bytes32 digest,
        uint8 count,
        bytes32 cap,
        bytes calldata busWire,
        bytes calldata sumcheck,
        bytes calldata columns
    ) external view returns (AirClaim memory air) {
        bool midpoint = columns.length == (620 + 1451) * 24;
        if (!midpoint && columns.length != (619 + 1451) * 24) revert InvalidArithmeticColumns();
        Claims memory bus;
        (bus, air) = reduceArithmetic(digest, count, cap, busWire, sumcheck);
        uint192[] memory registers = new uint192[](13610);
        registers[1] = 1;
        registers[2] = air.alpha;
        registers[3] = air.beta;
        registers[4] = air.lambda;
        registers[5] = bus.offset;
        for (uint256 i; i < 3; ++i) {
            registers[6 + i] = bus.fingerprint[i];
        }
        for (uint256 i; i < 19; ++i) {
            registers[9 + i] = air.tau[i];
            registers[28 + i] = air.point[i];
        }
        for (uint256 i; i < 26; ++i) {
            registers[47 + i] = bus.point[i];
        }
        for (uint256 i; i < 32; ++i) {
            registers[73 + i] = uint8(digest[i]);
        }
        for (uint256 i; i < 615; ++i) {
            registers[105 + i] = K.read192(columns, 24 * i);
        }
        // The AIR references only application and fixed columns. Boundary readings
        // between them are constrained by the Keccak verifier and the opening.
        uint256 fixedStart = midpoint ? 620 : 619;
        for (uint256 i; i < 1451; ++i) {
            registers[105 + 619 + i] = K.read192(columns, 24 * (fixedStart + i));
        }
        if (evaluate(registers, program()) != air.sum) revert InvalidArithmeticColumns();
    }
}
