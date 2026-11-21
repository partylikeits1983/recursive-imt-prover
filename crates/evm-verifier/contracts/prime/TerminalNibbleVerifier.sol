// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NibbleSumcheck} from "./NibbleSumcheck.sol";
import {KeccakSegmentReduction192} from "./KeccakSegmentReduction.sol";
import {NibbleOpeningVerifier} from "./NibbleOpeningVerifier.sol";

/// Binds the 24 Keccak rounds, the public node inputs and all four-bit digits to one root.
/// The enclosing IMT relation must also enforce each child's recursive verification.
abstract contract CheckpointNibbleRelation is NibbleSumcheck {
    bytes32 internal constant KEY = 0x494900e0fa468212ed93087501b2ca91a608331d9a12070b6cc05133943e7405;
    KeccakSegmentReduction192 private immutable rounds;
    error InvalidStatement();

    constructor(KeccakSegmentReduction192 g, NibbleOpeningVerifier w) NibbleSumcheck(w) {
        require(address(g).code.length != 0);
        rounds = g;
    }

    function rowBits() internal pure virtual returns (uint256) {
        return 16;
    }

    function hasPublicNode() internal pure virtual returns (bool) {
        return true;
    }

    function lastRow() private pure returns (uint256) {
        return uint256(21670) >> (16 - rowBits());
    }

    struct Terms {
        uint256[] input;
        uint256[] output;
        uint256[25] bi;
        uint256[25] bo;
        uint256[] range;
        uint256[] known;
        uint256 rangeMix;
        uint256 knownMix;
    }

    function knownSum(Terms memory t, bytes memory message) private pure returns (uint256 v) {
        uint256[] memory lanes = weights(t.known, rowBits() + 3, 5);
        uint256[] memory pair = weights(t.known, rowBits() + 8, 4);
        bytes memory data = abi.encodePacked(message, hex"01", new bytes(53), hex"80");
        for (uint256 i; i < data.length; ++i) {
            uint256 d = uint8(data[i]);
            if (d == 0) continue;
            uint256 sum;
            for (uint256 j; j < 2; ++j) {
                sum = addmod(sum, mulmod((d >> (4 * j)) & 15, pair[2 * (i % 8) + j], P), P);
            }
            v = addmod(v, mulmod(lanes[i / 8], sum, P), P);
        }
        return mulmod(v, mulmod(t.knownMix, basis(t.known, 1, rowBits() - 1, lastRow()), P), P);
    }

    // Sum eq(known,x) eq(closing,x) over the final node and padding rows of both child roles.
    function rowMask(uint256[] memory a, uint256[] memory b) private pure returns (uint256) {
        uint256 equal = 1;
        uint256 above;
        for (uint256 k = 1; k < rowBits(); ++k) {
            uint256 one = mulmod(a[k], b[k], P);
            uint256 zero = mulmod(P + 1 - a[k], P + 1 - b[k], P);
            above = mulmod(above, addmod(one, zero, P), P);
            if (((lastRow() >> (rowBits() - 1 - k)) & 1) == 0) {
                above = addmod(above, mulmod(equal, one, P), P);
                equal = mulmod(equal, zero, P);
            } else {
                equal = mulmod(equal, one, P);
            }
        }
        return mulmod(equality(a, 0, b, 0, 1), addmod(equal, above, P), P);
    }

    // The last output occupies spare lane slots (segment = lane / 7, lane slot = 25 + lane % 7).
    function endpointWeights(Terms memory t, uint256[] memory x) private pure returns (uint256 wi, uint256 wo) {
        uint256[] memory lane = weights(x, rowBits() + 3, 5);
        uint256[] memory sx = weights(x, rowBits(), 3);
        uint256[] memory so = weights(t.output, rowBits(), 3);
        uint256 tail;
        uint256 shifted;
        uint256 direct;
        for (uint256 s; s < 7; ++s) {
            shifted = addmod(shifted, mulmod(so[s], sx[s + 1], P), P);
        }
        for (uint256 l; l < 25; ++l) {
            wi = addmod(wi, mulmod(t.bi[l], lane[l], P), P);
            direct = addmod(direct, mulmod(t.bo[l], lane[l], P), P);
            tail = addmod(tail, mulmod(t.bo[l], mulmod(sx[l / 7], lane[25 + l % 7], P), P), P);
        }
        wi = mulmod(
            wi,
            mulmod(equality(t.input, 0, x, 0, rowBits() + 3), equality(t.input, rowBits() + 3, x, rowBits() + 8, 4), P),
            P
        );
        wo = addmod(mulmod(shifted, direct, P), mulmod(so[7], tail, P), P);
        wo = mulmod(
            wo,
            mulmod(equality(t.output, 0, x, 0, rowBits()), equality(t.output, rowBits() + 3, x, rowBits() + 8, 4), P),
            P
        );
    }

    function closing(Terms memory t, uint256[] memory x, uint256[3] memory m) private pure returns (uint256 v) {
        (uint256 wi, uint256 wo) = endpointWeights(t, x);
        (uint256 hi, uint256 ho, uint256 range) =
            bitPolynomials(m, weights(t.input, t.input.length - 2, 2), weights(t.output, t.output.length - 2, 2));
        v = addmod(mulmod(wi, hi, P), mulmod(wo, ho, P), P);
        v = addmod(v, mulmod(t.rangeMix, mulmod(range, equality(t.range, 0, x, 0, x.length), P), P), P);
        if (!hasPublicNode()) return v;
        uint256 r = rowBits();
        uint256[] memory kl = weights(t.known, r + 3, 5);
        uint256[] memory xl = weights(x, r + 3, 5);
        uint256 allowed;
        for (uint256 i; i < 25; ++i) {
            allowed = addmod(allowed, mulmod(kl[i], xl[i], P), P);
        }
        uint256 w = mulmod(rowMask(t.known, x), basis(x, r, 3, 0), P);
        w = mulmod(w, mulmod(allowed, equality(t.known, r + 8, x, r + 8, 4), P), P);
        return addmod(v, mulmod(t.knownMix, mulmod(w, m[0], P), P), P);
    }

    function transitionIdentity(
        bytes32 instance,
        bytes memory message,
        uint256[25] calldata outputLanes,
        bytes calldata gkr,
        bytes calldata digits
    ) internal view returns (Claim memory upper, uint256[3] memory m) {
        Terms memory t;
        t.output = coins(instance, 0, rowBits() + 9);
        uint256[25] memory lanes;
        (t.input, lanes) = rounds.reduceFromBits(instance, t.output, outputLanes, gkr);
        bytes32 seed = keccak256(abi.encodePacked(instance, outputLanes, t.input, lanes));
        t.range = coins(seed, 3, rowBits() + 12);

        t.rangeMix = coin(seed, 5, 0);
        uint256 sum;
        if (hasPublicNode()) {
            t.known = coins(seed, 4, rowBits() + 12);
            t.knownMix = coin(seed, 5, 1);
            sum = knownSum(t, message);
        }
        for (uint8 l; l < 25; ++l) {
            t.bi[l] = coin(seed, 1, l);
            t.bo[l] = coin(seed, 2, l);
            sum = addmod(sum, addmod(mulmod(t.bi[l], lanes[l], P), mulmod(t.bo[l], outputLanes[l], P), P), P);
        }
        (upper, m) = upperClaim(seed, sum, digits, rowBits() + 12);
        if (upper.sum != closing(t, upper.point, m)) revert InvalidDigits();
    }
}

contract TerminalNibbleVerifier is CheckpointNibbleRelation {
    constructor(KeccakSegmentReduction192 g, NibbleOpeningVerifier w) CheckpointNibbleRelation(g, w) {}

    function verifyTransitions(
        bytes32 parent,
        bytes32 left,
        bytes32 right,
        bytes32 root,
        uint256[25] calldata outputLanes,
        bytes calldata gkr,
        bytes calldata digits,
        bytes calldata proof,
        bytes calldata hints
    ) external view returns (bool) {
        bytes memory message = abi.encodePacked("IMT-AGG-NODE-V2", left, uint8(32), right, uint8(32));
        if (keccak256(message) != parent) revert InvalidStatement();
        bytes32 instance = keccak256(
            abi.encodePacked("recursive-imt/keccak-nibbles192/v1", KEY, parent, left, right, uint8(rowBits()), root)
        );
        (Claim memory upper, uint256[3] memory m) = transitionIdentity(instance, message, outputLanes, gkr, digits);
        openMoments(upper, m, root, digits, proof, hints);
        return true;
    }
}

contract SampleTerminalNibbleVerifier is TerminalNibbleVerifier {
    constructor(KeccakSegmentReduction192 g, NibbleOpeningVerifier w) TerminalNibbleVerifier(g, w) {}

    function rowBits() internal pure override returns (uint256) {
        return 7;
    }
}

/// Reduce the 16,384 rows of a native verifier's Keccak trace to one public WHIR reading.
contract NativeTraceKeccakReduction is CheckpointNibbleRelation {
    constructor(KeccakSegmentReduction192 g, NibbleOpeningVerifier w) CheckpointNibbleRelation(g, w) {}

    function rowBits() internal pure virtual override returns (uint256) {
        return 14;
    }

    function hasPublicNode() internal pure override returns (bool) {
        return false;
    }

    function domain() internal pure virtual returns (string memory) {
        return "recursive-imt/native-trace-keccak/v1";
    }

    function reduceTrace(bytes32 root, uint256[25] calldata outputLanes, bytes calldata gkr, bytes calldata digits)
        external
        view
        returns (Reading memory)
    {
        bytes32 instance = keccak256(abi.encodePacked(domain(), root));
        (Claim memory upper, uint256[3] memory m) = transitionIdentity(instance, "", outputLanes, gkr, digits);
        return reduceMoments(upper, m, digits);
    }
}

/// The 512 allocated Keccak rows occupy the low half of the row sponge table.
contract NativeSpongeKeccakReduction is NativeTraceKeccakReduction {
    constructor(KeccakSegmentReduction192 g, NibbleOpeningVerifier pcs) NativeTraceKeccakReduction(g, pcs) {}

    function rowBits() internal pure override returns (uint256) {
        return 9;
    }

    function domain() internal pure override returns (string memory) {
        return "recursive-imt/native-row-keccak/v1";
    }

    function openingPoint(uint256[] memory point) internal pure override returns (uint256[] memory z) {
        z = new uint256[](22);
        for (uint256 i; i < 21; ++i) {
            z[i + 1] = point[i];
        }
    }
}
