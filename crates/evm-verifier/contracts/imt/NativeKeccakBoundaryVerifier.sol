// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeKeccak as K} from "./NativeKeccak.sol";
import {NativeKeccakRounds as R} from "./NativeKeccakRounds.sol";
import {NativeKeccakClosing as Closing} from "./NativeKeccakClosing.sol";

contract NativeKeccakLayers {
    function reduce(bytes calldata prefix, bytes calldata layers) external pure returns (R.Progress memory) {
        return R.verifyRounds(prefix, layers);
    }
}

/// Verify the terminal's linked Keccak argument against the specified arithmetic
/// row and four boundary evaluations. A root verifier authenticates the row at
/// arithmeticPoint and those evaluations at precisely the four returned points.
contract NativeKeccakBoundaryVerifier {
    bytes32 private immutable authority;
    NativeKeccakLayers private immutable permutation = new NativeKeccakLayers();

    constructor(bytes32 expectedAuthority) {
        authority = expectedAuthority;
    }

    function verifyBoundary(
        bytes32 mainCap,
        bytes calldata arithmeticPoint,
        bytes calldata row,
        bytes calldata prefix,
        bytes calldata layers,
        bytes calldata closing,
        uint192[4] calldata evaluations
    ) external view returns (uint192[27][4] memory) {
        if (prefix.length != 4408) revert Closing.InvalidBridge();
        Closing.checkBridge(arithmeticPoint, row, prefix[64:3256]);
        return reduceBoundary(mainCap, prefix, layers, closing, evaluations);
    }

    /// The enclosing relation derives the bridge in prefix from its opened columns.
    function reduceBoundary(
        bytes32 mainCap,
        bytes calldata prefix,
        bytes calldata layers,
        bytes calldata closing,
        uint192[4] calldata evaluations
    ) public view returns (uint192[27][4] memory) {
        if (prefix.length != 4408 || bytes32(prefix[:32]) != authority || bytes32(prefix[32:64]) != mainCap) {
            revert Closing.InvalidBridge();
        }
        bytes calldata bridge = prefix[64:3256];
        R.Progress memory state = permutation.reduce(prefix, layers);
        (, uint192[27] memory outputPoint) = K.outputPoint(authority, mainCap, bridge);
        return Closing.verify(state, bridge, outputPoint, K.read192(prefix, 3256), closing, evaluations);
    }
}

/// Both halves share the permutation circuit. The segment coordinate selects
/// input or midpoint from one committed table, and the output has its own table.
contract NativeMidpointLayers {
    function reduce(bytes calldata prefix, bytes calldata layers) external pure returns (R.Progress memory) {
        return R.verifyMidpointRounds(prefix, layers);
    }
}

contract NativeMidpointBoundaryVerifier {
    bytes32 private immutable authority;
    NativeMidpointLayers private immutable permutation = new NativeMidpointLayers();

    constructor(bytes32 expectedAuthority) {
        authority = expectedAuthority;
    }

    function reduceBoundary(
        bytes32 mainCap,
        bytes calldata prefix,
        bytes calldata layers,
        bytes calldata closing,
        uint192[5] calldata values
    ) external view returns (uint192[28][5] memory points) {
        if (
            prefix.length != 4432 || bytes32(prefix[:32]) != authority || bytes32(prefix[32:64]) != mainCap
                || K.read192(prefix, 3280) != values[2]
        ) revert Closing.InvalidBridge();
        bytes calldata bridge = prefix[64:3256];
        R.Progress memory state = permutation.reduce(prefix, layers);
        (, uint192[27] memory output) = K.outputPoint(authority, mainCap, bridge);
        uint192[4] memory boundary = [values[0], values[1], values[3], values[4]];
        uint192[27][4] memory base = Closing.verify(state, bridge, output, K.read192(prefix, 3256), closing, boundary);
        points[0][0] = state.segment;
        points[2][0] = 1;
        for (uint256 i; i < 27; ++i) {
            points[0][i + 1] = base[0][i];
            points[1][i + 1] = base[1][i];
            points[2][i + 1] = base[2][i];
            points[3][i] = base[2][i];
            points[4][i] = base[3][i];
        }
    }
}
