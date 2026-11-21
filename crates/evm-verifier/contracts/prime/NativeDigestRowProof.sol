// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NibbleSumcheck} from "./NibbleSumcheck.sol";
import {NativeSpongeFoldReduction} from "./NativeWhirFoldProof.sol";
import {NativeSpongeKeccakReduction} from "./TerminalNibbleVerifier.sol";
import {NativeRowSpongePorts} from "./NativeRowSpongePorts.sol";
import {NativeRowTripleOpeningVerifier} from "./NibbleOpeningVerifier.sol";

/// Bind all 169 native fold results to the 240 Merkle-authenticated leaf digests.
contract NativeDigestRowProof {
    error WrongShape();
    NativeSpongeFoldReduction private immutable folds;
    NativeSpongeKeccakReduction private immutable rounds;
    NativeRowSpongePorts private immutable ports;
    NativeRowTripleOpeningVerifier private immutable opening;

    constructor(
        NativeSpongeFoldReduction f,
        NativeSpongeKeccakReduction k,
        NativeRowSpongePorts p,
        NativeRowTripleOpeningVerifier w
    ) {
        require(
            address(f).code.length != 0 && address(k).code.length != 0 && address(p).code.length != 0
                && address(w).code.length != 0
        );
        folds = f;
        rounds = k;
        ports = p;
        opening = w;
    }

    function openingProofBytes() external pure returns (uint256) {
        return 1544;
    }

    function verifyFolds(
        bytes32 root,
        bytes calldata draws,
        bytes calldata digests,
        bytes calldata values,
        bytes calldata digits,
        bytes calldata proof,
        bytes calldata hints
    ) external view returns (bool) {
        uint256 gkrEnd = 600 + 1455 * 24;
        uint256 roundDigitsEnd = gkrEnd + 5136;
        uint256 portEnd = roundDigitsEnd + 5376;
        if (hints.length < portEnd) revert WrongShape();
        uint256[25] memory output;
        for (uint256 i; i < 25; ++i) {
            output[i] = uint192(bytes24(hints[i * 24:i * 24 + 24]));
        }
        NibbleSumcheck.Reading memory a = folds.reduceFolds(root, draws, digests, values, digits);
        NibbleSumcheck.Reading memory b =
            rounds.reduceTrace(root, output, hints[600:gkrEnd], hints[gkrEnd:roundDigitsEnd]);
        NibbleSumcheck.Reading memory c = ports.reducePorts(root, digests, hints[roundDigitsEnd:portEnd]);
        uint256[] memory points = new uint256[](68);
        for (uint256 i; i < 22; ++i) {
            points[i] = a.point[i];
            points[i + 23] = b.point[i];
            points[i + 46] = c.point[i];
        }
        points[22] = a.value;
        points[45] = b.value;
        bytes32 context =
            keccak256(abi.encodePacked("recursive-imt/native-row-openings/v1", a.context, b.context, c.context));
        return opening.verify(root, context, points, c.value, proof, hints[portEnd:]);
    }
}
