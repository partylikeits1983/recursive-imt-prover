// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WHIR_PRIME} from "./WhirTranscript.sol";

/// Three-round GKR reduction over eight successive segments of Keccak-f[1600].
/// The enclosing protocol authenticates outputWords at the initial point and
/// the 25 returned input-bit evaluations at bitPoint. This call performs the reduction only.
contract KeccakSegmentReduction {
    function modulus() internal pure virtual returns (uint256) {
        return WHIR_PRIME;
    }

    function scalarBytes() internal pure virtual returns (uint256) {
        return 32;
    }
    bytes32 private constant IV = keccak256("recursive-imt/three-round-gkr-control/v1");
    bytes private constant ROT = hex"00013e1c1b242c063714030a2b1927292d0f150812023d380e";
    bytes private constant RC =
        hex"00000000000000010000000000008082800000000000808a8000000080008000000000000000808b000000008000000180000000800080818000000000008009000000000000008a00000000000000880000000080008009000000008000000a000000008000808b800000000000008b8000000000008089800000000000800380000000000080028000000000000080000000000000800a800000008000000a8000000080008081800000000000808000000000800000018000000080008008";

    error InvalidEncoding();
    error InvalidEquation();

    struct Stream {
        bytes32 state;
        uint256 offset;
        bool projected;
    }

    function absorb(Stream memory s, uint256 value) private pure {
        uint256 size = scalarBytes();
        uint256 pad = (32 - size) * 8;
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, mload(s))
            mstore8(add(p, 32), 0)
            mstore(add(p, 33), shl(pad, value))
            mstore(s, keccak256(p, add(33, size)))
        }
    }

    function draw(Stream memory s) private pure returns (uint256 r) {
        uint256 prime = modulus();
        uint256 radix = addmod(type(uint256).max, 1, prime);
        assembly ("memory-safe") {
            mstore(0, mload(s))
            mstore8(32, 1)
            let hi := keccak256(0, 33)
            mstore(s, hi)
            mstore(0, hi)
            mstore8(32, 2)
            r := addmod(mulmod(hi, radix, prime), keccak256(0, 33), prime)
        }
    }

    function read(Stream memory s, bytes calldata proof) private pure returns (uint256 v) {
        uint256 prime = modulus();
        uint256 size = scalarBytes();
        v = uint256(bytes32(proof[s.offset:s.offset + size])) >> ((32 - size) * 8);
        if (v >= prime) revert InvalidEncoding();
        s.offset += size;
        absorb(s, v);
    }

    function sumcheck(Stream memory s, bytes calldata p, uint256 n, uint256 degree, uint256 sum)
        private
        pure
        returns (uint256 value, uint256[] memory point)
    {
        uint256 prime = modulus();
        point = new uint256[](n);
        uint256 size = scalarBytes();
        uint256 pad = (32 - size) * 8;
        if (s.offset + size * degree * n > p.length) revert InvalidEncoding();
        uint256 radix = addmod(type(uint256).max, 1, prime);
        uint256 half = ((prime + 1) / 2);
        uint256 bad = uint32(InvalidEncoding.selector);
        assembly ("memory-safe") {
            let pos := add(p.offset, mload(add(s, 32)))
            let cv := mload(s)
            let scratch := mload(0x40)
            let width := mul(size, degree)
            let dest := add(point, 32)
            for { let end := add(dest, shl(5, n)) } lt(dest, end) { dest := add(dest, 32) } {
                let first := pos
                let total := 0
                for { let limit := add(pos, width) } lt(pos, limit) { pos := add(pos, size) } {
                    let coeff := shr(pad, calldataload(pos))
                    if iszero(lt(coeff, prime)) {
                        mstore(0, bad)
                        revert(28, 4)
                    }
                    total := addmod(total, coeff, prime)
                    mstore(scratch, cv)
                    mstore8(add(scratch, 32), 0)
                    mstore(add(scratch, 33), shl(pad, coeff))
                    cv := keccak256(scratch, add(33, size))
                }
                mstore(scratch, cv)
                mstore8(add(scratch, 32), 1)
                cv := keccak256(scratch, 33)
                mstore(scratch, cv)
                mstore8(add(scratch, 32), 2)
                let r := addmod(mulmod(cv, radix, prime), keccak256(scratch, 33), prime)
                mstore(dest, r)
                // p(0) + p(1) fixes the missing constant coefficient.
                let v := 0
                for { let q := pos } gt(q, first) {} {
                    q := sub(q, size)
                    v := addmod(shr(pad, calldataload(q)), mulmod(r, v, prime), prime)
                }
                sum := addmod(mulmod(half, addmod(sum, sub(prime, total), prime), prime), mulmod(v, r, prime), prime)
            }
            mstore(s, cv)
            mstore(add(s, 32), sub(pos, p.offset))
            value := sum
        }
    }

    function eq(uint256[] memory a, uint256[] memory b, uint256 n) private pure returns (uint256 e) {
        uint256 prime = modulus();
        assembly ("memory-safe") {
            e := 1
            for { let end := add(a, shl(5, n)) } lt(a, end) {} {
                a := add(a, 32)
                b := add(b, 32)
                let x := mload(a)
                let y := mload(b)
                e := mulmod(
                    e,
                    addmod(mulmod(x, y, prime), mulmod(sub(add(prime, 1), x), sub(add(prime, 1), y), prime), prime),
                    prime
                )
            }
        }
    }

    function xorBit(uint256 a, uint256 b) private pure returns (uint256) {
        uint256 prime = modulus();
        return addmod(a, mulmod(b, prime + 1 - addmod(a, a, prime), prime), prime);
    }

    function read25(Stream memory s, bytes calldata p) private pure returns (uint256[25] memory v) {
        for (uint256 i; i < 25; ++i) {
            v[i] = read(s, p);
        }
    }

    function equalityTable(uint256[] memory r, uint256 start, uint256 bits) private pure returns (uint256[] memory e) {
        uint256 prime = modulus();
        e = new uint256[](1 << bits);
        e[0] = 1;
        for (uint256 i; i < bits; ++i) {
            uint256 stride = 1 << i;
            for (uint256 j; j < stride; ++j) {
                uint256 high = mulmod(e[j], r[start + bits - 1 - i], prime);
                e[j + stride] = high;
                e[j] = addmod(e[j], prime - high, prime);
            }
        }
    }

    function iotaConstant(uint256[] memory r, uint256 step) private pure returns (uint256 v) {
        uint256 prime = modulus();
        uint256[] memory bits = equalityTable(r, r.length - 6, 6);
        uint256[] memory seg = equalityTable(r, r.length - 9, 3);
        bytes memory rc = RC;
        for (uint256 i; i < 8; ++i) {
            uint256 word;
            assembly ("memory-safe") { word := shr(192, mload(add(add(rc, 32), shl(3, add(mul(3, i), step))))) }
            uint256 lane;
            for (uint256 k; k < 7; ++k) {
                uint256 pos = (1 << k) - 1;
                if ((word >> pos) & 1 != 0) lane = addmod(lane, bits[pos], prime);
            }
            v = addmod(v, mulmod(seg[i], lane, prime), prime);
        }
    }

    // Sum the equality weights for a bit at position j+shift and b at j (mod 64).
    // Two states track carry through the six bits of the position.
    function rotationWeights(uint256[] memory a, uint256[] memory b) private pure returns (uint256[18] memory weights) {
        uint256 prime = modulus();
        for (uint256 k; k < 6; ++k) {
            uint256 j = a.length - 1 - k;
            uint256 up = mulmod(a[j], prime + 1 - b[j], prime);
            uint256 down = mulmod(prime + 1 - a[j], b[j], prime);
            weights[3 * k] = up;
            weights[3 * k + 1] = down;
            weights[3 * k + 2] = prime + 1 - addmod(up, down, prime);
        }
    }

    function rotated(uint256[18] memory weights, uint256 shift) private pure returns (uint256 result) {
        uint256 prime = modulus();
        assembly ("memory-safe") {
            let clear := 1
            let carry := 0
            for { let end := add(weights, 576) } lt(weights, end) { weights := add(weights, 96) } {
                let up := mload(weights)
                let down := mload(add(weights, 32))
                let same := mload(add(weights, 64))
                switch and(shift, 1)
                case 0 {
                    clear := addmod(mulmod(same, clear, prime), mulmod(up, carry, prime), prime)
                    carry := mulmod(down, carry, prime)
                }
                default {
                    carry := addmod(mulmod(same, carry, prime), mulmod(down, clear, prime), prime)
                    clear := mulmod(up, clear, prime)
                }
                shift := shr(1, shift)
            }
            result := addmod(clear, carry, prime)
        }
    }

    // A gate whose coefficients depend only on the suffix commutes with
    // evaluating its other coordinates when it is linear in the witness.
    function linearSumcheck(
        Stream memory s,
        bytes calldata p,
        uint256[] memory alpha,
        uint256 tail,
        uint256 degree,
        uint256 sum
    ) private pure returns (uint256 v, uint256[] memory point, uint256 equality) {
        uint256 prime = modulus();
        if (!s.projected) {
            (v, point) = sumcheck(s, p, alpha.length, degree, sum);
            equality = eq(alpha, point, alpha.length);
            return (v, point, equality);
        }
        uint256[] memory suffix;
        (v, suffix) = sumcheck(s, p, tail, degree, sum);
        point = new uint256[](alpha.length);
        uint256 prefix = alpha.length - tail;
        for (uint256 i; i < prefix; ++i) {
            point[i] = alpha[i];
        }
        equality = 1;
        for (uint256 i; i < tail; ++i) {
            uint256 a = alpha[prefix + i];
            uint256 b = suffix[i];
            point[prefix + i] = b;
            equality = mulmod(
                equality, addmod(mulmod(a, b, prime), mulmod(prime + 1 - a, prime + 1 - b, prime), prime), prime
            );
        }
    }

    function iota(
        Stream memory s,
        bytes calldata p,
        uint256[] memory alpha,
        uint256[25] memory beta,
        uint256 sum,
        uint256 step
    ) private pure returns (uint256[] memory point, uint256 next) {
        uint256 prime = modulus();
        uint256 v;
        uint256 e;
        (v, point, e) = linearSumcheck(s, p, alpha, 9, 3, sum);
        uint256 first = read(s, p);
        uint256 rest = read(s, p);
        uint256 w = addmod(mulmod(beta[0], xorBit(first, iotaConstant(point, step)), prime), rest, prime);
        if (v != mulmod(e, w, prime)) revert InvalidEquation();
        beta[0] = mulmod(beta[0], draw(s), prime);
        uint256 y = draw(s);
        for (uint256 i = 1; i < 25; ++i) {
            beta[i] = mulmod(beta[i], y, prime);
        }
        next = addmod(mulmod(first, beta[0], prime), mulmod(rest, y, prime), prime);
    }

    function iotaChi(
        Stream memory s,
        bytes calldata p,
        uint256[] memory alpha,
        uint256[25] memory beta,
        uint256 sum,
        uint256 step
    ) private pure returns (uint256[] memory chiPoint, uint256[25] memory pi) {
        uint256 prime = modulus();
        uint256 n = alpha.length;
        (uint256[] memory iotaPoint, uint256 next) = iota(s, p, alpha, beta, sum, step);
        uint256 v;
        (v, chiPoint) = sumcheck(s, p, n, 4, next);
        pi = read25(s, p);
        uint256 w;
        for (uint256 i; i < 25; ++i) {
            uint256 base = i - i % 5;
            uint256 b = pi[base + ((i + 1) % 5)];
            uint256 c = pi[base + ((i + 2) % 5)];
            w = addmod(w, mulmod(beta[i], xorBit(pi[i], mulmod(prime + 1 - b, c, prime)), prime), prime);
        }
        if (v != mulmod(eq(iotaPoint, chiPoint, n), w, prime)) revert InvalidEquation();
    }

    function rho(
        Stream memory s,
        bytes calldata p,
        uint256[] memory chiPoint,
        uint256[25] memory beta,
        uint256[25] memory pi
    ) private pure returns (uint256[] memory rhoPoint, uint256 thetaSum) {
        uint256 prime = modulus();
        uint256 n = chiPoint.length;
        uint256 sum;
        for (uint256 i; i < 25; ++i) {
            beta[i] = draw(s);
            uint256 x = i % 5;
            uint256 y = i / 5;
            sum = addmod(sum, mulmod(beta[i], pi[y + 5 * ((2 * x + 3 * y) % 5)], prime), prime);
        }
        uint256 v;
        uint256 rowWeight = 1;
        if (s.projected) {
            (v, rhoPoint,) = linearSumcheck(s, p, chiPoint, 6, 2, sum);
        } else {
            (v, rhoPoint) = sumcheck(s, p, n, 2, sum);
            rowWeight = eq(chiPoint, rhoPoint, n - 6);
        }
        uint256[25] memory theta = read25(s, p);
        bytes memory shifts = ROT;
        uint256[18] memory weights = rotationWeights(chiPoint, rhoPoint);
        sum = 0;
        for (uint256 i; i < 25; ++i) {
            uint256 rotation = rotated(weights, uint8(shifts[i]));
            sum = addmod(sum, mulmod(mulmod(beta[i], theta[i], prime), rotation, prime), prime);
            beta[i] = draw(s);
            thetaSum = addmod(thetaSum, mulmod(beta[i], prime + 1 - addmod(theta[i], theta[i], prime), prime), prime);
        }
        if (v != mulmod(sum, rowWeight, prime)) revert InvalidEquation();
    }

    struct Theta {
        uint256[] point;
        uint256[5] ai;
        uint256[] cPoint;
        uint256[25] a;
    }

    function thetaCD(Stream memory s, bytes calldata p, uint256[] memory rhoPoint, uint256 sum)
        private
        pure
        returns (Theta memory t)
    {
        uint256 prime = modulus();
        uint256 n = rhoPoint.length;
        uint256 v;
        (v, t.point) = sumcheck(s, p, n, 3, sum);
        uint256[5] memory d;
        uint256 check;
        for (uint256 i; i < 5; ++i) {
            t.ai[i] = read(s, p);
        }
        for (uint256 i; i < 5; ++i) {
            d[i] = read(s, p);
            check = addmod(check, mulmod(t.ai[i], d[i], prime), prime);
        }
        if (v != mulmod(check, eq(rhoPoint, t.point, n), prime)) revert InvalidEquation();
        uint256[5] memory betaD;
        sum = 0;
        for (uint256 i; i < 5; ++i) {
            betaD[i] = draw(s);
            sum = addmod(sum, mulmod(betaD[i], d[i], prime), prime);
        }
        uint256[] memory dPoint;
        (v, dPoint) = sumcheck(s, p, n, 3, sum);
        uint256[5] memory c;
        uint256[5] memory rotC;
        for (uint256 i; i < 5; ++i) {
            c[i] = read(s, p);
        }
        for (uint256 i; i < 5; ++i) {
            rotC[i] = read(s, p);
        }
        check = 0;
        for (uint256 i; i < 5; ++i) {
            check = addmod(check, mulmod(betaD[i], mulmod(c[(i + 4) % 5], rotC[(i + 1) % 5], prime), prime), prime);
        }
        if (v != mulmod(check, eq(t.point, dPoint, n), prime)) revert InvalidEquation();
        uint256[5] memory betaC;
        uint256[5] memory betaRot;
        sum = 0;
        for (uint256 i; i < 5; ++i) {
            betaC[i] = draw(s);
            sum = addmod(sum, mulmod(betaC[i], c[i], prime), prime);
        }
        for (uint256 i; i < 5; ++i) {
            betaRot[i] = draw(s);
            sum = addmod(sum, mulmod(betaRot[i], rotC[i], prime), prime);
        }
        (v, t.cPoint) = sumcheck(s, p, n, 6, sum);
        t.a = read25(s, p);
        uint256 e = eq(dPoint, t.cPoint, n);
        uint256 rot = mulmod(eq(dPoint, t.cPoint, n - 6), rotated(rotationWeights(dPoint, t.cPoint), 1), prime);
        check = 0;
        for (uint256 j; j < 5; ++j) {
            uint256 product = 1;
            for (uint256 i; i < 5; ++i) {
                product = mulmod(product, t.a[5 * i + j], prime);
            }
            uint256 w = addmod(mulmod(e, betaC[j], prime), mulmod(rot, betaRot[j], prime), prime);
            check = addmod(check, mulmod(w, product, prime), prime);
        }
        if (v != check) revert InvalidEquation();
    }

    function round(
        Stream memory s,
        bytes calldata p,
        uint256[] memory alpha,
        uint256[25] memory beta,
        uint256 sum,
        uint256 step
    ) private pure returns (uint256[] memory result, uint256[25] memory bits) {
        uint256 prime = modulus();
        (uint256[] memory chiPoint, uint256[25] memory pi) = iotaChi(s, p, alpha, beta, sum, step);
        (uint256[] memory rhoPoint, uint256 thetaSum) = rho(s, p, chiPoint, beta, pi);
        Theta memory t = thetaCD(s, p, rhoPoint, thetaSum);
        sum = 0;
        for (uint256 i; i < 5; ++i) {
            uint256 b = draw(s);
            sum = addmod(sum, mulmod(b, t.ai[i], prime), prime);
            for (uint256 j; j < 25; j += 5) {
                beta[j + i] = mulmod(beta[j + i], b, prime);
            }
        }
        uint256[25] memory betaA;
        for (uint256 i; i < 25; ++i) {
            betaA[i] = draw(s);
            sum = addmod(sum, mulmod(betaA[i], t.a[i], prime), prime);
        }
        uint256 v;
        (v, result) = sumcheck(s, p, alpha.length, 2, sum);
        bits = read25(s, p);
        uint256 eTheta = eq(t.point, result, alpha.length);
        uint256 eC = eq(t.cPoint, result, alpha.length);
        uint256 check;
        for (uint256 i; i < 25; ++i) {
            uint256 w = addmod(mulmod(beta[i], eTheta, prime), mulmod(betaA[i], eC, prime), prime);
            check = addmod(check, mulmod(w, bits[i], prime), prime);
            bits[i] = mulmod(((prime + 1) / 2), prime + 1 - bits[i], prime);
        }
        if (v != check) revert InvalidEquation();
    }

    function reduce(bytes32 context, uint8 logSegments, uint256[25] calldata outputWords, bytes calldata proof)
        external
        pure
        returns (uint256[] memory bitPoint, uint256[25] memory inputBits)
    {
        uint256 prime = modulus();
        uint256 n = logSegments;
        if (n < 3 || n > 19 || proof.length != scalarBytes() * (3 * (23 * (n + 6) + 122) + 2 * (n + 6) + 3)) {
            revert InvalidEncoding();
        }
        Stream memory s = Stream(IV, 0, false);
        absorb(s, uint256(context) >> 128);
        absorb(s, uint128(uint256(context)));
        uint256[] memory start = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            start[i] = draw(s);
        }
        s.state = IV;
        for (uint256 i; i < n; ++i) {
            absorb(s, start[i]);
        }
        uint256[25] memory beta;
        uint256 sum;
        for (uint256 i; i < 25; ++i) {
            if (outputWords[i] >= prime) revert InvalidEncoding();
            beta[i] = draw(s);
            sum = addmod(sum, mulmod(beta[i], outputWords[i], prime), prime);
        }
        if (sum != read(s, proof)) revert InvalidEquation();
        (uint256 v, uint256[] memory x) = sumcheck(s, proof, n, 2, sum);
        uint256 words = read(s, proof);
        if (v != mulmod(words, eq(start, x, n), prime)) revert InvalidEquation();
        uint256[] memory y;
        (v, y) = sumcheck(s, proof, 6, 2, words);
        sum = read(s, proof);
        uint256 powers = 1;
        bitPoint = new uint256[](n + 6);
        for (uint256 i; i < n; ++i) {
            bitPoint[i] = x[i];
        }
        for (uint256 i; i < 6; ++i) {
            bitPoint[n + i] = y[i];
            uint256 power = 1 << (1 << (5 - i));
            powers = mulmod(powers, addmod(1, mulmod(power - 1, y[i], prime), prime), prime);
        }
        if (v != mulmod(powers, sum, prime)) revert InvalidEquation();
        return layers(s, proof, bitPoint, beta, sum);
    }

    function layers(
        Stream memory s,
        bytes calldata proof,
        uint256[] memory bitPoint,
        uint256[25] memory beta,
        uint256 sum
    ) private pure returns (uint256[] memory, uint256[25] memory inputBits) {
        uint256 prime = modulus();
        for (uint256 t = 3; t != 0; --t) {
            (bitPoint, inputBits) = round(s, proof, bitPoint, beta, sum, t - 1);
            if (t > 1) {
                sum = 0;
                for (uint256 i; i < 25; ++i) {
                    beta[i] = draw(s);
                    sum = addmod(sum, mulmod(beta[i], inputBits[i], prime), prime);
                }
            }
        }
        if (s.offset != proof.length) revert InvalidEncoding();
        return (bitPoint, inputBits);
    }

    function startBits(bytes32 instance, uint256[] calldata point, uint256[25] calldata lanes)
        private
        pure
        returns (Stream memory s, uint256[25] memory beta, uint256 sum)
    {
        uint256 prime = modulus();
        if (point.length < 9 || point.length > 25) revert InvalidEncoding();
        s = Stream(keccak256("recursive-imt/segment-gkr-bits/v1"), 0, true);
        absorb(s, uint256(instance) >> 128);
        absorb(s, uint128(uint256(instance)));
        absorb(s, point.length);
        for (uint256 i; i < point.length; ++i) {
            if (point[i] >= prime) revert InvalidEncoding();
            absorb(s, point[i]);
        }
        for (uint256 i; i < 25; ++i) {
            if (lanes[i] >= prime) revert InvalidEncoding();
            absorb(s, lanes[i]);
        }
        for (uint256 i; i < 25; ++i) {
            beta[i] = draw(s);
            sum = addmod(sum, mulmod(beta[i], lanes[i], prime), prime);
        }
    }

    /// Continue the GKR argument from the exact bit point and lane claims
    /// of the preceding packed-output reduction.
    function reduceFromBits(
        bytes32 instance,
        uint256[] calldata point,
        uint256[25] calldata lanes,
        bytes calldata proof
    ) external pure returns (uint256[] memory, uint256[25] memory) {
        (Stream memory s, uint256[25] memory beta, uint256 sum) = startBits(instance, point, lanes);
        // Iota uses nine coordinates, Rho six, and the five other gates use all coordinates.
        if (proof.length != scalarBytes() * 3 * (18 * point.length + 161)) revert InvalidEncoding();
        return layers(s, proof, point, beta, sum);
    }
}

/// Compact 24-byte field messages for the WHIR reference's 192-bit prime.
contract KeccakSegmentReduction192 is KeccakSegmentReduction {
    function modulus() internal pure override returns (uint256) {
        return 3801539170989320091464968600173246866371124347557388484609;
    }

    function scalarBytes() internal pure override returns (uint256) {
        return 24;
    }
}
