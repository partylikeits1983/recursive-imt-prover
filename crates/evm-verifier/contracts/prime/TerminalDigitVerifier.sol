// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WHIR_PRIME as P} from "./WhirTranscript.sol";
import {PrimeWhirOpeningVerifier} from "./PrimeWhirOpeningVerifier.sol";
import {WhirRate32} from "./WhirRate32.sol";
import {KeccakSegmentReduction} from "./KeccakSegmentReduction.sol";

contract DigitOpeningVerifier is PrimeWhirOpeningVerifier {
    function schedule() internal pure override returns (Schedule memory) {
        return WhirRate32.schedule();
    }
}

/// Checks all Keccak transitions on the 512-row terminal checkpoint sample.
/// The table includes both final node rows. Child proof verification is a separate relation.
contract TerminalDigitVerifier {
    uint256 private constant R = 9;
    uint256 private constant N = R + 13;
    uint256 private constant B = R + 9;
    uint256 private constant LAST = 21670 >> (16 - R);
    uint256 private constant HALF = (P + 1) / 2;
    uint256 private constant THIRD = (2 * P + 1) / 3;
    bytes32 private constant KEY = 0x494900e0fa468212ed93087501b2ca91a608331d9a12070b6cc05133943e7405;

    error InvalidStatement();
    error InvalidDigits();
    KeccakSegmentReduction private immutable rounds;
    DigitOpeningVerifier private immutable opening;

    constructor(KeccakSegmentReduction roundVerifier, DigitOpeningVerifier openingVerifier) {
        require(address(roundVerifier).code.length != 0 && address(openingVerifier).code.length != 0);
        rounds = roundVerifier;
        opening = openingVerifier;
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

    function coin(bytes32 seed, uint8 family, uint8 index) private pure returns (uint256) {
        bytes memory buf = abi.encodePacked("recursive-imt/digit-coin/v1", seed, family, index, uint8(0));
        uint256 hi = uint256(keccak256(buf));
        buf[buf.length - 1] = 0x01;
        return addmod(mulmod(hi, addmod(type(uint256).max, 1, P), P), uint256(keccak256(buf)), P);
    }

    function coins(bytes32 seed, uint8 family, uint256 n) private pure returns (uint256[] memory a) {
        a = new uint256[](n);
        for (uint8 i; i < n; ++i) {
            a[i] = coin(seed, family, i);
        }
    }

    function equality(uint256[] memory a, uint256 ai, uint256[] memory b, uint256 bi, uint256 count)
        private
        pure
        returns (uint256 v)
    {
        v = 1;
        for (uint256 i; i < count; ++i) {
            uint256 x = a[ai + i];
            uint256 y = b[bi + i];
            v = mulmod(v, addmod(mulmod(x, y, P), mulmod(P + 1 - x, P + 1 - y, P), P), P);
        }
    }

    function weights(uint256[] memory a, uint256 start, uint256 bits) private pure returns (uint256[] memory w) {
        w = new uint256[](1 << bits);
        w[0] = 1;
        for (uint256 k; k < bits; ++k) {
            uint256 stride = 1 << k;
            uint256 r = a[start + bits - 1 - k];
            for (uint256 j; j < stride; ++j) {
                uint256 h = mulmod(w[j], r, P);
                w[j + stride] = h;
                w[j] = addmod(w[j], P - h, P);
            }
        }
    }

    function basis(uint256[] memory a, uint256 start, uint256 bits, uint256 index) private pure returns (uint256 v) {
        v = 1;
        for (uint256 k; k < bits; ++k) {
            uint256 r = a[start + bits - 1 - k];
            v = mulmod(v, ((index >> k) & 1) == 1 ? r : P + 1 - r, P);
        }
    }

    function knownSum(Terms memory t, bytes memory message) private pure returns (uint256 v) {
        uint256[] memory lanes = weights(t.known, R + 3, 5);
        uint256[] memory pair = weights(t.known, R + 8, 5);
        bytes memory data = abi.encodePacked(message, hex"01", new bytes(53), hex"80");
        for (uint256 i; i < data.length; ++i) {
            uint256 d = uint8(data[i]);
            if (d == 0) continue;
            uint256 sum;
            for (uint256 j; j < 4; ++j) {
                sum = addmod(sum, mulmod((d >> (2 * j)) & 3, pair[4 * (i % 8) + j], P), P);
            }
            v = addmod(v, mulmod(lanes[i / 8], sum, P), P);
        }
        return mulmod(v, mulmod(t.knownMix, basis(t.known, 1, R - 1, LAST), P), P);
    }

    // Sum eq(known,x) eq(closing,x) over the final node and padding rows of both child roles.
    function rowMask(uint256[] memory a, uint256[] memory b) private pure returns (uint256) {
        uint256 equal = 1;
        uint256 above;
        for (uint256 k = 1; k < R; ++k) {
            uint256 one = mulmod(a[k], b[k], P);
            uint256 zero = mulmod(P + 1 - a[k], P + 1 - b[k], P);
            above = mulmod(above, addmod(one, zero, P), P);
            if (((LAST >> (R - 1 - k)) & 1) == 0) {
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
        uint256[] memory lane = weights(x, R + 3, 5);
        uint256[] memory sx = weights(x, R, 3);
        uint256[] memory so = weights(t.output, R, 3);
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
        wi = mulmod(wi, mulmod(equality(t.input, 0, x, 0, R + 3), equality(t.input, R + 3, x, R + 8, 5), P), P);
        wo = addmod(mulmod(shifted, direct, P), mulmod(so[7], tail, P), P);
        wo = mulmod(wo, mulmod(equality(t.output, 0, x, 0, R), equality(t.output, R + 3, x, R + 8, 5), P), P);
    }

    function closing(Terms memory t, uint256[] memory x, uint256 d) private pure returns (uint256 v) {
        (uint256 wi, uint256 wo) = endpointWeights(t, x);
        uint256 product = mulmod(d, addmod(d, P - 1, P), P);
        uint256 cube = mulmod(product, addmod(d, P - 2, P), P);
        uint256 low = addmod(addmod(d, P - product, P), mulmod(2 * THIRD, cube, P), P);
        uint256 high = mulmod(HALF, addmod(d, P - low, P), P);
        uint256 delta = addmod(high, P - low, P);
        v = addmod(
            mulmod(wi, addmod(low, mulmod(delta, t.input[B - 1], P), P), P),
            mulmod(wo, addmod(low, mulmod(delta, t.output[B - 1], P), P), P),
            P
        );
        uint256 range = mulmod(cube, addmod(d, P - 3, P), P);
        v = addmod(v, mulmod(t.rangeMix, mulmod(range, equality(t.range, 0, x, 0, N), P), P), P);
        uint256[] memory kl = weights(t.known, R + 3, 5);
        uint256[] memory xl = weights(x, R + 3, 5);
        uint256 allowed;
        for (uint256 i; i < 25; ++i) {
            allowed = addmod(allowed, mulmod(kl[i], xl[i], P), P);
        }
        uint256 w = mulmod(rowMask(t.known, x), basis(x, R, 3, 0), P);
        w = mulmod(w, mulmod(allowed, equality(t.known, R + 8, x, R + 8, 5), P), P);
        return addmod(v, mulmod(t.knownMix, mulmod(w, d, P), P), P);
    }

    function interpolate(uint256[6] memory y, uint256 r) private pure returns (uint256 sum) {
        // The denominators of the Lagrange basis at 0..5 are 120 / [-1,5,-10,10,-5,1].
        uint256[6] memory c = [P - 1, 5, P - 10, 10, P - 5, 1];
        uint256[6] memory prefix;
        uint256 run = 1;
        for (uint256 i; i < 6; ++i) {
            prefix[i] = run;
            run = mulmod(run, addmod(r, P - i, P), P);
        }
        run = 1;
        for (uint256 i = 6; i != 0;) {
            --i;
            sum = addmod(sum, mulmod(mulmod(prefix[i], run, P), mulmod(c[i], y[i], P), P), P);
            run = mulmod(run, addmod(r, P - i, P), P);
        }
        return mulmod(sum, 8572895124803716128713175583559099409681442723496280117948463306408858327450, P);
    }

    function checkDigits(
        bytes32 seed,
        Terms memory t,
        uint256 sum,
        bytes calldata digits,
        bytes32 root,
        bytes calldata proof,
        bytes calldata hints
    ) private view {
        if (digits.length != 32 * (5 * N + 1)) revert InvalidDigits();
        uint256[] memory x = new uint256[](N);
        uint256[22] memory point;
        for (uint8 k; k < N; ++k) {
            uint256 offset = uint256(k) * 160;
            uint256[6] memory y;
            for (uint256 j; j < 5; ++j) {
                uint256 a = uint256(bytes32(digits[offset + 32 * j:offset + 32 * j + 32]));
                if (a >= P) revert InvalidDigits();
                y[j == 0 ? 0 : j + 1] = a;
            }
            y[1] = addmod(sum, P - y[0], P);
            seed = keccak256(abi.encodePacked(seed, k, digits[offset:offset + 160]));
            x[k] = coin(seed, 6, k);
            point[k] = x[k];
            sum = interpolate(y, x[k]);
        }
        uint256 d = uint256(bytes32(digits[160 * N:]));
        if (d >= P || sum != closing(t, x, d)) revert InvalidDigits();
        bytes32 context = keccak256(abi.encodePacked("recursive-imt/keccak-digit-opening/v1", seed));
        if (!opening.verify(root, context, point, d, proof, hints)) revert InvalidDigits();
    }

    function verifySample(
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
        bytes32 instance =
            keccak256(abi.encodePacked("recursive-imt/keccak-digits/v1", KEY, parent, left, right, uint8(R), root));
        Terms memory t;
        t.output = coins(instance, 0, B);
        uint256[25] memory lanes;
        (t.input, lanes) = rounds.reduceFromBits(instance, t.output, outputLanes, gkr);
        bytes32 seed = keccak256(abi.encodePacked(instance, outputLanes, t.input, lanes));
        t.range = coins(seed, 3, N);
        t.known = coins(seed, 4, N);
        t.rangeMix = coin(seed, 5, 0);
        t.knownMix = coin(seed, 5, 1);
        uint256 sum = knownSum(t, message);
        for (uint8 l; l < 25; ++l) {
            t.bi[l] = coin(seed, 1, l);
            t.bo[l] = coin(seed, 2, l);
            sum = addmod(sum, addmod(mulmod(t.bi[l], lanes[l], P), mulmod(t.bo[l], outputLanes[l], P), P), P);
        }
        checkDigits(seed, t, sum, digits, root, proof, hints);
        return true;
    }
}
