// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {NibbleSumcheck} from "./NibbleSumcheck.sol";
import {NativeTraceFoldProof} from "./NativeWhirFoldProof.sol";
import {NativeTraceKeccakReduction} from "./TerminalNibbleVerifier.sol";
import {NativeTracePairOpeningVerifier} from "./NibbleOpeningVerifier.sol";

/// Check all native row folds and all Keccak-f transitions under one WHIR commitment.
/// The enclosing root still authenticates row preimages and native Merkle paths in Solidity.
contract NativeTraceJointProof {
    error WrongShape();
    NativeTraceFoldProof private immutable folds;
    NativeTraceKeccakReduction private immutable hashRounds;
    NativeTracePairOpeningVerifier private immutable opening;

    constructor(NativeTraceFoldProof f, NativeTraceKeccakReduction k, NativeTracePairOpeningVerifier w) {
        require(address(f).code.length != 0 && address(k).code.length != 0 && address(w).code.length != 0);
        folds = f;
        hashRounds = k;
        opening = w;
    }

    function openingProofBytes() external pure returns (uint256) {
        return 1784;
    }

    function verifyFolds(
        bytes32 root,
        bytes calldata draws,
        bytes calldata rows,
        bytes calldata values,
        bytes calldata digits,
        bytes calldata proof,
        bytes calldata hints
    ) external view returns (bool) {
        uint256 gkrEnd = 25 * 24 + 1725 * 24;
        uint256 digitsEnd = gkrEnd + 2 * 26 * 120 + 96;
        if (hints.length < digitsEnd) revert WrongShape();
        uint256[25] memory output;
        for (uint256 i; i < 25; ++i) {
            output[i] = uint192(bytes24(hints[i * 24:i * 24 + 24]));
        }
        NibbleSumcheck.Reading memory a = folds.reduceFolds(root, draws, rows, values, digits);
        NibbleSumcheck.Reading memory b =
            hashRounds.reduceTrace(root, output, hints[600:gkrEnd], hints[gkrEnd:digitsEnd]);
        uint256[] memory points = new uint256[](53);
        for (uint256 i; i < 26; ++i) {
            points[i] = a.point[i];
            points[i + 27] = b.point[i];
        }
        points[26] = a.value;
        bytes32 context = keccak256(abi.encodePacked("recursive-imt/native-trace-openings/v1", a.context, b.context));
        return opening.verify(root, context, points, b.value, proof, hints[digitsEnd:]);
    }
}
