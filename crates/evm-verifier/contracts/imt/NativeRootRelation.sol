// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeAirClosingVerifier} from "./NativeAirClosingVerifier.sol";
import {NativeArithmeticVerifier} from "./NativeArithmeticVerifier.sol";
import {NativeKeccakBoundaryVerifier, NativeMidpointBoundaryVerifier} from "./NativeKeccakBoundaryVerifier.sol";
import {NativeKeccak as K} from "./NativeKeccak.sol";
import {NativeField as F} from "./NativeField.sol";

/// Native 64-client root argument up to its shared polynomial opening.
abstract contract NativeRootRelationBase {
    bytes32 internal immutable authority;
    NativeAirClosingVerifier private immutable arithmetic;

    constructor(bytes32 expectedAuthority, NativeAirClosingVerifier arithmeticVerifier) {
        authority = expectedAuthority;
        arithmetic = arithmeticVerifier;
    }

    struct Proof {
        bytes bus;
        bytes sumcheck;
        bytes columns;
        bytes outputAndCoefficients;
        bytes layers;
        bytes closing;
    }

    function arithmeticBridge(bytes32 digest, uint8 count, bytes32 mainCap, Proof calldata p)
        internal
        view
        returns (NativeArithmeticVerifier.AirClaim memory air, bytes memory bridge)
    {
        air = arithmetic.verifyArithmetic(digest, count, mainCap, p.bus, p.sumcheck, p.columns);
        bridge = new bytes((17 + 116) * 24);
        for (uint256 i; i < 17; ++i) {
            K.write192(bridge, i * 24, air.point[i + 2]);
        }
        // The hash table starts at main column 383. Each of its 232 opened
        // sixteen-bit limbs uses one committed reading scaled by 2^16 - 1.
        for (uint256 i; i < 116; ++i) {
            uint192 a = K.read192(p.columns, (383 + i) * 24);
            uint192 b = K.read192(p.columns, (383 + 116 + i) * 24);
            K.write192(bridge, (17 + i) * 24, F.scaleOnes(a ^ F.mul(air.point[2], a ^ b), 4));
        }
    }
}

contract NativeRootRelation is NativeRootRelationBase {
    NativeKeccakBoundaryVerifier private immutable boundary;

    constructor(bytes32 expectedAuthority, NativeAirClosingVerifier arithmeticVerifier)
        NativeRootRelationBase(expectedAuthority, arithmeticVerifier)
    {
        boundary = new NativeKeccakBoundaryVerifier(expectedAuthority);
    }

    function reduceRelation(bytes32 digest, uint8 count, bytes32 mainCap, Proof calldata p)
        external
        view
        returns (uint192[19] memory point, K.Stream memory stream, uint192[27][4] memory extra)
    {
        if (p.columns.length != 2070 * 24) revert NativeAirClosingVerifier.InvalidArithmeticColumns();
        (NativeArithmeticVerifier.AirClaim memory air, bytes memory bridge) =
            arithmeticBridge(digest, count, mainCap, p);
        uint192[4] memory values;
        for (uint256 i; i < 4; ++i) {
            values[i] = K.read192(p.columns, (615 + i) * 24);
        }
        bytes memory prefix = abi.encodePacked(authority, mainCap, bridge, p.outputAndCoefficients);
        extra = boundary.reduceBoundary(mainCap, prefix, p.layers, p.closing, values);
        return (air.point, air.transcript, extra);
    }
}

contract NativeMidpointRootRelation is NativeRootRelationBase {
    NativeMidpointBoundaryVerifier private immutable boundary;

    constructor(bytes32 expectedAuthority, NativeAirClosingVerifier arithmeticVerifier)
        NativeRootRelationBase(expectedAuthority, arithmeticVerifier)
    {
        boundary = new NativeMidpointBoundaryVerifier(expectedAuthority);
    }

    function reduceRelation(bytes32 digest, uint8 count, bytes32 mainCap, Proof calldata p)
        external
        view
        returns (uint192[19] memory, K.Stream memory, uint192[28][5] memory)
    {
        if (p.columns.length != 2071 * 24) revert NativeAirClosingVerifier.InvalidArithmeticColumns();
        (NativeArithmeticVerifier.AirClaim memory air, bytes memory bridge) =
            arithmeticBridge(digest, count, mainCap, p);
        uint192[5] memory values;
        for (uint256 i; i < 5; ++i) {
            values[i] = K.read192(p.columns, (615 + i) * 24);
        }
        bytes memory prefix = abi.encodePacked(authority, mainCap, bridge, p.outputAndCoefficients);
        return (air.point, air.transcript, boundary.reduceBoundary(mainCap, prefix, p.layers, p.closing, values));
    }
}
