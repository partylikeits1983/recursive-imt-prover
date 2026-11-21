// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BinaryTerminalProfile as P} from "./BinaryTerminalProfile.sol";
import {BinaryTerminalTranscript as T} from "./BinaryTerminalTranscript.sol";
import {BinaryTerminalMerkle as M} from "./BinaryTerminalMerkle.sol";
import {BinaryExtension as E} from "./BinaryExtension.sol";
import {BinaryLaneFold} from "./BinaryLaneFold.sol";
import {BinaryNovel} from "./BinaryNovel.sol";

/// Five-level additive WHIR on the 24-variable stacked witness of the compact terminal.
library BinaryWhir {
    error InvalidFold();

    struct Phase {
        bool first;
        uint256 rounds;
        uint256 mu;
        uint256 end;
        uint256 factor;
        uint256 lambda;
        uint256[6] alpha;
        uint256[6] beta;
        uint256[20] high;
    }

    struct Check {
        uint256 claim;
        uint256 weight;
        uint256[24] point;
        uint256[24] shifts;
        uint256[] tables;
    }

    function sample(bytes32[] memory hashes, uint256 i) internal pure returns (uint256) {
        return T.little128(uint128(bytes16(hashes[i])));
    }

    function pointOf(bytes32[] memory hashes) internal pure returns (uint256[24] memory point) {
        uint256 k;
        for (uint256 i; i < 5; ++i) {
            (uint256 first,) = P.foldPosition(i);
            for (uint256 j; j < (i == 0 ? P.FIRST_FOLD : 4); ++j) {
                point[k++] = sample(hashes, first + 3 * j);
            }
        }
        for (uint256 i; i < P.TAIL; ++i) {
            point[k++] = sample(hashes, hashes.length - P.TAIL + i);
        }
    }

    function phase(uint256 level, bytes calldata stream, bytes32[] memory hashes, Check memory c)
        private
        pure
        returns (Phase memory p)
    {
        p.first = level == 0;
        p.rounds = p.first ? P.FIRST_FOLD : 4;
        p.mu = 24 - P.FIRST_FOLD - 4 * level;
        (uint256 first, uint256 end) = P.foldPosition(level);
        p.end = end;
        uint256 pos = end - 5 * p.rounds;
        for (uint256 j; j < p.rounds; ++j) {
            uint256 a = sample(hashes, first + 3 * j);
            uint256 b = sample(hashes, first + 3 * j + 1);
            p.alpha[j] = a;
            p.beta[j] = b;
            uint256 u = T.scalar(stream, pos);
            uint256 w = T.scalar(stream, pos + 1);
            uint256 c0 = T.scalar(stream, pos + 2);
            uint256 c1 = T.scalar(stream, pos + 3);
            c.claim = u ^ E.mul(b, c0) ^ E.mul(a, u ^ c.claim ^ E.mul(a, w) ^ E.mul(b, c0 ^ c1));
            pos += 5;
        }
        (, uint256 q, uint256 depth, uint256 n) = P.phase(level);

        if (level == 4) {
            for (uint256 i; i < (1 << P.TAIL) + 4; ++i) {
                p.high[i] = T.scalar(stream, end + i);
            }
        } else {
            p.lambda = sample(hashes, q + (n + (128 / depth) - 1) / (128 / depth));
            for (uint256 i; i < p.rounds; ++i) {
                p.high[i] = T.scalar(stream, end + 2 + i);
            }
            p.factor = 1;
            for (uint256 i; i < p.mu; ++i) {
                uint256 t = c.point[24 - p.mu + i];
                if (t != 0) p.factor = E.mul(p.factor, t);
            }
            uint256 eq = 1;
            for (uint256 i; i < p.mu; ++i) {
                eq = E.mul(eq, 1 ^ c.point[24 - p.mu + i] ^ sample(hashes, q - p.mu + i));
            }
            c.weight ^= E.mul(p.lambda, eq);
            // Next cap, high coefficients, OOD nonce, then its evaluation.
            c.claim ^= E.mul(p.lambda, T.scalar(stream, end + 3 + p.rounds));
        }
    }

    function foldRow(bytes calldata proof, M.Rows memory rows, uint256 idx, Phase memory p, uint256[64] memory lanes)
        private
        pure
        returns (uint256)
    {
        uint256 base = rows.offsets[idx];
        uint256 width = uint256(1) << p.rounds;
        uint256 zeros = rows.zeroWords;
        uint256 firstLevel = p.first ? 1 : 0;
        // Authenticate first, then expand the compressed zero prefix in a scratch
        // row. Read limbs directly in either lane order without slicing Solidity bytes.
        assembly ("memory-safe") {
            function little64(w) -> v {
                let m := 0x00ff00ff00ff00ff
                w := or(and(shr(8, w), m), shl(8, and(w, m)))
                m := 0x0000ffff0000ffff
                w := or(and(shr(16, w), m), shl(16, and(w, m)))
                v := or(shr(32, w), shl(32, and(w, 0xffffffff)))
            }
            let source := add(proof.offset, base)
            let bytes_ := shl(3, zeros)
            let tmp := mload(0x40)
            // Clear scratch even when it was used for the preceding authenticated row.
            calldatacopy(tmp, calldatasize(), bytes_)
            let full := shl(sub(4, firstLevel), width)
            calldatacopy(add(tmp, bytes_), source, sub(full, bytes_))
            switch firstLevel
            case 1 {
                let dst := add(lanes, shl(5, sub(width, 1)))
                for { let ptr := tmp } lt(ptr, add(tmp, full)) { ptr := add(ptr, 8) } {
                    mstore(dst, little64(shr(192, mload(ptr))))
                    dst := sub(dst, 32)
                }
            }
            default {
                let dst := lanes
                for { let ptr := tmp } lt(ptr, add(tmp, full)) { ptr := add(ptr, 16) } {
                    let w := mload(ptr)
                    let a := little64(shr(192, w))
                    let b := little64(and(shr(128, w), 0xffffffffffffffff))
                    mstore(dst, or(a, shl(64, b)))
                    dst := add(dst, 32)
                }
            }
        }
        for (uint256 j; j < p.rounds; ++j) {
            uint256 scale = p.alpha[j] ^ E.mulBase(p.beta[j], uint64(rows.queries[idx]));
            width >>= 1;
            BinaryLaneFold.fold(lanes, width, scale, p.first && j == 0);
        }
        return lanes[0];
    }

    function verify(
        bytes calldata proof,
        bytes calldata stream,
        bytes32[] memory hashes,
        uint256 offset,
        uint256 target,
        uint256 basis
    ) internal pure returns (uint256 end) {
        Check memory c;
        c.claim = target;
        c.weight = basis;
        c.point = pointOf(hashes);
        // Factor each 1 + t*(1+W) as t*((1+1/t)+W). The same t applies to every query.
        // A zero coordinate contributes one to the original product.
        uint256 product = 1;
        for (uint256 i = P.FIRST_FOLD; i < 24; ++i) {
            c.shifts[i] = product;
            if (c.point[i] != 0) product = E.mul(product, c.point[i]);
        }
        uint256 inv = E.inverse(product);
        for (uint256 i = 24; i > P.FIRST_FOLD;) {
            unchecked {
                --i;
            }
            if (c.point[i] != 0) {
                c.shifts[i] = 1 ^ E.mul(inv, c.shifts[i]);
                inv = E.mul(inv, c.point[i]);
            }
        }
        c.tables = BinaryNovel.tables();
        uint256[64] memory lanes;
        uint256[24] memory what;
        for (uint256 level; level < 5; ++level) {
            Phase memory p = phase(level, stream, hashes, c);
            (uint256 cap, uint256 q, uint256 depth, uint256 n) = P.phase(level);
            M.Rows memory rows = M.open(
                proof,
                offset,
                bytes32(stream[16 * cap:16 * cap + 32]),
                depth,
                n,
                level == 0 ? 1 << P.FIRST_FOLD : 32,
                hashes,
                q
            );
            offset = rows.end;
            uint256 values;
            uint256 weights;
            // Horner gives the powers 1, lambda, ... in the original draw order.
            for (uint256 idx = n; idx != 0;) {
                unchecked {
                    --idx;
                }
                uint256 v = foldRow(proof, rows, idx, p, lanes);
                BinaryNovel.evaluate(c.tables, rows.queries[idx], p.mu, what);
                uint256 polynomial = BinaryNovel.polynomial(p.high, what, level == 4 ? (1 << P.TAIL) + 4 : p.rounds);
                if (level == 4) {
                    if (v != polynomial) revert InvalidFold();
                } else {
                    v ^= E.mulBase(polynomial, uint64(what[p.mu]));
                    uint256 w = 1;
                    for (uint256 i; i < p.mu; ++i) {
                        uint256 k = 24 - p.mu + i;
                        if (c.point[k] != 0) w = E.mul(w, c.shifts[k] ^ what[i]);
                    }
                    values = E.mul(values, p.lambda) ^ v;
                    weights = E.mul(weights, p.lambda) ^ w;
                }
            }
            if (level < 4) {
                uint256 l2 = E.mul(p.lambda, p.lambda);
                c.claim ^= E.mul(l2, values);
                c.weight ^= E.mul(E.mul(l2, p.factor), weights);
            } else {
                uint256 tail = P.SCALARS - 2 * P.TAIL;
                for (uint256 k; k < P.TAIL; ++k) {
                    uint256 c0 = T.scalar(stream, tail + 2 * k);
                    uint256 c2 = T.scalar(stream, tail + 2 * k + 1);
                    uint256 r = c.point[24 - P.TAIL + k];
                    c.claim = c0 ^ E.mul(r, c.claim ^ c2 ^ E.mul(r, c2));
                }
                for (uint256 k; k < P.TAIL; ++k) {
                    uint256 width = 1 << (P.TAIL - k - 1);
                    uint256 r = c.point[24 - P.TAIL + k];
                    for (uint256 j; j < width; ++j) {
                        uint256 a = p.high[2 * j];
                        p.high[j] = a ^ E.mul(r, a ^ p.high[2 * j + 1]);
                    }
                }
                uint256 folded = p.high[0];
                if (E.mul(c.weight, folded) != c.claim) revert InvalidFold();
            }
        }
        return offset;
    }
}
