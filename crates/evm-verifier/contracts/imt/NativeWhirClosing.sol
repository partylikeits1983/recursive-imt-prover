// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeMidpointPolicy as Policy} from "./NativeMidpointPolicy.sol";

import {NativeKeccak as K} from "./NativeKeccak.sol";
import {NativeField as F} from "./NativeField.sol";
import {NativeWhirInitial as Initial} from "./NativeWhirInitial.sol";
import {NativeWhirRounds as Rounds} from "./NativeWhirRounds.sol";

/// Close the weighted WHIR sumcheck using the challenges of the authenticated rounds.
library NativeWhirClosing {
    error WrongIdentity();

    struct Identity {
        uint192 ordinary;
        uint192 ring;
        uint192 value;
    }

    struct Check {
        uint192[26] draw;
        uint192 ordinary;
        uint192 value;
        uint192 scale;
        uint192 sum;
    }

    /// Draw order is least-significant coordinate first for suffix folding.
    function equality(uint192[26] memory draw, uint256 start, uint192 x) private pure returns (uint192 w) {
        w = 1;
        for (uint256 i = start; i < 26; ++i) {
            w = F.mul(w, 1 ^ draw[i] ^ x);
            x = F.square(x);
        }
    }

    function selection(uint192[26] memory draw, uint256 start, uint256 index) private pure returns (uint192 w) {
        uint64 x = Rounds.domainPoint(index);
        w = 1;
        for (uint256 i = start; i < 26; ++i) {
            w = F.mul(w, 1 ^ F.scale(draw[i], x ^ 1));
            x ^= F.square64(x);
        }
    }

    function groupWeight(
        uint192[26] memory draw,
        uint256 start,
        uint192 alpha,
        uint192[2] memory oods,
        uint256[71] memory indices,
        uint256 count
    ) private pure returns (uint192) {
        uint192 w;
        for (uint256 i = count; i != 0; --i) {
            w = selection(draw, start, indices[i - 1]) ^ F.mul(alpha, w);
        }
        for (uint256 i = Policy.INITIAL_OODS; i != 0; --i) {
            w = equality(draw, start, oods[i - 1]) ^ F.mul(alpha, w);
        }
        return F.mul(alpha, w);
    }

    function finalValue(bytes calldata poly, uint192[] memory last) internal pure returns (uint192) {
        if (last.length != 4 && last.length != 5) revert Rounds.WrongShape();
        uint256 width = 1 << last.length;
        if (poly.length != 24 * width) revert Rounds.WrongShape();
        uint192[32] memory values;
        for (uint256 i; i < width; ++i) {
            values[i] = K.read192(poly, i * 24);
        }
        for (uint256 d; d < last.length; ++d) {
            width >>= 1;
            for (uint256 i; i < width; ++i) {
                uint192 a = values[2 * i];
                values[i] = a ^ F.mul(last[d], a ^ values[2 * i + 1]);
            }
        }
        return values[0];
    }

    function reduce(
        Initial.Fold memory first,
        Initial.Query memory q,
        Rounds.Challenges[] memory steps,
        uint192[] memory last,
        bytes calldata poly,
        uint192 sum,
        bool four
    ) internal pure returns (Check memory check) {
        if (steps.length != (four ? 4 : 5) || last.length != (four ? 4 : 5)) {
            revert Rounds.WrongShape();
        }
        uint192[26] memory draw;
        for (uint256 i; i < 6; ++i) {
            draw[i] = first.point[i];
        }
        uint256 cursor = 6;
        for (uint256 s; s < steps.length; ++s) {
            if (steps[s].point.length != (four ? 4 : 3)) revert Rounds.WrongShape();
            for (uint256 i; i < steps[s].point.length; ++i) {
                draw[cursor++] = steps[s].point[i];
            }
        }
        for (uint256 i; i < last.length; ++i) {
            draw[cursor++] = last[i];
        }
        check.ordinary = equality(draw, 0, first.oodPoints[0]);
        if (Policy.INITIAL_OODS == 2) check.ordinary ^= F.mul(first.alpha, equality(draw, 0, first.oodPoints[1]));
        cursor = 6;
        uint192[2] memory oods = q.oodPoints;
        uint256[71] memory indices = q.indices;
        for (uint256 s; s < steps.length; ++s) {
            uint256 count = s == 0 ? Policy.FIRST_COUNT : Rounds.queryCount(s - 1, four);
            check.ordinary ^= groupWeight(draw, cursor, steps[s].alpha, oods, indices, count);
            cursor += steps[s].point.length;
            oods = steps[s].oods;
            indices = steps[s].indices;
        }
        check.draw = draw;
        check.value = finalValue(poly, last);
        check.scale = Policy.INITIAL_OODS == 2 ? F.square(first.alpha) : first.alpha;
        check.sum = sum;
    }

    function finish(Check memory check, uint192 ring) internal pure returns (Identity memory) {
        uint192 combined = check.ordinary ^ F.mul(check.scale, ring);
        if (F.mul(combined, check.value) != check.sum) revert WrongIdentity();
        return Identity(check.ordinary, ring, check.value);
    }
}
