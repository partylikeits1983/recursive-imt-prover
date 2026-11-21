// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NibbleOpeningVerifier} from "./NibbleOpeningVerifier.sol";

/// Verify two degree-five sumchecks ending at one authenticated evaluation of four-bit digits.
abstract contract NibbleSumcheck {
    uint256 internal constant P = 3801539170989320091464968600173246866371124347557388484609;
    uint256 private constant INV15FACT = 3063593248034336008151019227636051598981549154170283083820;
    // Four degree-15 bit interpolation polynomials scaled by 15!, followed by
    // the monic product of (d-i) for i=0..15. Coefficients are signed big-endian int64s.
    bytes private constant COEFFICIENTS =
        hex"0000000000000000000b088545400000ffdd3442d7980000002e623d34f40000ffdcc09f66a0800000114433bd460000fffa2e3c68b64000000166b27ad24000ffffc0fb512e88000000082762550000ffffff39551620000000000dbbc38000ffffffff5460100000000000059b0000ffffffffffe3e0000000000000004000000000000000000000000000000000000000086925654000ffffe1746e49980000002d3c265eb400ffffdac9d92a5080000013db06a9f200fffff89ec4f467c0000001f78d4d4a40ffffff9eb6074a000000000da88b1040fffffffe9cc38a800000000019c8f740fffffffffeb2bf8000000000000b1bc0ffffffffffffc7c00000000000000080000000000000000000000000000000000001750037e4f400fffb476e5d11e78000067bc3a6f47b40fffaec7e0a78810000028ea3905af4f0ffff1dca8c84a5f8000037a4ca453ec8fffff60c81262ae00000014e5bbb5558ffffffdfd2c49e90000000023e183b88ffffffffe3d118600000000000ec7598fffffffffffb5bb80000000000000a9000000000000000000000000000000000fffde27b00fb21000006bd635af1a640fff6ea877c4f95600006fafa97a51b60fffc8b30fe7f490800012d2b7b69cb14ffffb6d9682fc60c00000cf2a7c54710fffffe507bb4f1440000002944ca0a18fffffffd2309346c0000000023dec1f0fffffffffed39e44000000000005e434fffffffffffff29800000000000000000000000000000000fffffecf8888a800000003f24a44f300fffffa6468a19e80000004996c6ebc10fffffd89c55a20c0000000eb1525b448ffffffc07ba95a480000000cb844e1d1fffffffe16c989200000000037519dfcfffffffffb514af000000000004ac326fffffffffffcaae000000000000019b4ffffffffffffff880000000000000001";
    NibbleOpeningVerifier private immutable opening;
    error InvalidDigits();

    constructor(NibbleOpeningVerifier pcs) {
        require(address(pcs).code.length != 0);
        opening = pcs;
    }

    function coin(bytes32 seed, uint8 family, uint8 index) internal pure returns (uint256) {
        uint256 high;
        uint256 low;
        assembly ("memory-safe") {
            let scratch := mload(0x40)
            mstore(scratch, 0x7265637572736976652d696d742f64696769742d636f696e2f76310000000000)
            mstore(add(scratch, 27), seed)
            mstore8(add(scratch, 59), family)
            mstore8(add(scratch, 60), index)
            mstore8(add(scratch, 61), 0)
            high := keccak256(scratch, 62)
            mstore8(add(scratch, 61), 1)
            low := keccak256(scratch, 62)
        }
        return addmod(mulmod(high, addmod(type(uint256).max, 1, P), P), low, P);
    }

    function coins(bytes32 seed, uint8 family, uint256 n) internal pure returns (uint256[] memory a) {
        a = new uint256[](n);
        for (uint8 i; i < n; ++i) {
            a[i] = coin(seed, family, i);
        }
    }

    function equality(uint256[] memory a, uint256 ai, uint256[] memory b, uint256 bi, uint256 count)
        internal
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

    function weights(uint256[] memory a, uint256 start, uint256 bits) internal pure returns (uint256[] memory w) {
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

    function basis(uint256[] memory a, uint256 start, uint256 bits, uint256 index) internal pure returns (uint256 v) {
        v = 1;
        for (uint256 k; k < bits; ++k) {
            uint256 r = a[start + bits - 1 - k];
            v = mulmod(v, ((index >> k) & 1) == 1 ? r : P + 1 - r, P);
        }
    }

    function bitPolynomials(uint256[3] memory m, uint256[] memory wi, uint256[] memory wo)
        internal
        pure
        returns (uint256 hi, uint256 ho, uint256 range)
    {
        uint256[17] memory power;
        (uint256 a, uint256 b, uint256 c) = (m[0], m[1], m[2]);
        power[0] = 1;
        power[1] = a;
        power[2] = mulmod(a, a, P);
        power[3] = b;
        power[4] = c;
        power[5] = mulmod(a, c, P);
        power[6] = mulmod(b, b, P);
        power[7] = mulmod(b, c, P);
        power[8] = mulmod(c, c, P);
        power[9] = mulmod(a, power[8], P);
        power[10] = mulmod(c, power[6], P);
        power[11] = mulmod(b, power[8], P);
        power[12] = mulmod(c, power[8], P);
        power[13] = mulmod(a, power[12], P);
        power[14] = mulmod(power[6], power[8], P);
        power[15] = mulmod(b, power[12], P);
        power[16] = mulmod(power[8], power[8], P);
        bytes memory coeffs = COEFFICIENTS;
        for (uint256 k; k < 5; ++k) {
            uint256 v;
            for (uint256 j; j < 17; ++j) {
                uint256 f;
                assembly ("memory-safe") {
                    f := signextend(7, shr(192, mload(add(add(coeffs, 32), shl(3, add(mul(17, k), j))))))
                    if slt(f, 0) { f := add(f, P) }
                }
                v = addmod(v, mulmod(f, power[j], P), P);
            }
            if (k == 4) {
                range = v;
            } else {
                hi = addmod(hi, mulmod(v, wi[k], P), P);
                ho = addmod(ho, mulmod(v, wo[k], P), P);
            }
        }
        hi = mulmod(hi, INV15FACT, P);
        ho = mulmod(ho, INV15FACT, P);
    }

    function interpolate(uint256[6] memory y, uint256 r) private pure returns (uint256 sum) {
        // Newton interpolation at 0..5. Each pass computes one order of forward differences.
        assembly ("memory-safe") {
            function difference(x, z) -> d { d := addmod(x, sub(P, z), P) }
            let y0 := mload(add(y, 0))
            let y1 := mload(add(y, 32))
            let y2 := mload(add(y, 64))
            let y3 := mload(add(y, 96))
            let y4 := mload(add(y, 128))
            let y5 := mload(add(y, 160))
            y5 := difference(y5, y4)
            y4 := difference(y4, y3)
            y3 := difference(y3, y2)
            y2 := difference(y2, y1)
            y1 := difference(y1, y0)
            y5 := difference(y5, y4)
            y4 := difference(y4, y3)
            y3 := difference(y3, y2)
            y2 := difference(y2, y1)
            y5 := difference(y5, y4)
            y4 := difference(y4, y3)
            y3 := difference(y3, y2)
            y5 := difference(y5, y4)
            y4 := difference(y4, y3)
            y5 := difference(y5, y4)
            sum := mulmod(y5, 982064285838907690295116888378088773812540456452325358524, P)
            sum := addmod(
                mulmod(y4, 1108782258205218360010615841717197002691577934704238308011, P),
                mulmod(addmod(r, sub(P, 4), P), sum, P),
                P
            )
            sum := addmod(
                mulmod(y3, 633589861831553348577494766695541144395187391259564747435, P),
                mulmod(addmod(r, sub(P, 3), P), sum, P),
                P
            )
            sum := addmod(
                mulmod(y2, 1900769585494660045732484300086623433185562173778694242305, P),
                mulmod(addmod(r, sub(P, 2), P), sum, P),
                P
            )
            sum := addmod(y1, mulmod(addmod(r, sub(P, 1), P), sum, P), P)
            sum := addmod(y0, mulmod(r, sum, P), P)
        }
    }

    function read(bytes calldata data, uint256 off) private pure returns (uint256 v) {
        v = uint192(bytes24(data[off:off + 24]));
        if (v >= P) revert InvalidDigits();
    }

    struct Claim {
        bytes32 seed;
        uint256 sum;
        uint256[] point;
    }

    function reduceDigits(bytes32 seed, uint256 sum, uint8 stage, bytes calldata proof, uint256 n)
        private
        pure
        returns (Claim memory c)
    {
        c.point = new uint256[](n);
        for (uint8 k; k < n; ++k) {
            uint256 off = uint256(k) * 120;
            uint256[6] memory y;
            for (uint256 j; j < 5; ++j) {
                y[j == 0 ? 0 : j + 1] = read(proof, off + 24 * j);
            }
            y[1] = addmod(sum, P - y[0], P);
            seed = keccak256(abi.encodePacked(seed, stage, k, proof[off:off + 120]));
            c.point[k] = coin(seed, 6, k);
            sum = interpolate(y, c.point[k]);
        }
        c.seed = seed;
        c.sum = sum;
    }

    function upperClaim(bytes32 seed, uint256 sum, bytes calldata digits, uint256 n)
        internal
        pure
        returns (Claim memory upper, uint256[3] memory m)
    {
        uint256 part = 120 * n;
        if (digits.length != 2 * part + 96) revert InvalidDigits();
        upper = reduceDigits(seed, sum, 0, digits[:part], n);
        for (uint256 j; j < 3; ++j) {
            m[j] = read(digits, part + j * 24);
        }
    }

    function openingPoint(uint256[] memory point) internal pure virtual returns (uint256[] memory) {
        return point;
    }

    struct Reading {
        bytes32 context;
        uint256[] point;
        uint256 value;
    }

    function reduceMoments(Claim memory upper, uint256[3] memory m, bytes calldata digits)
        internal
        pure
        returns (Reading memory reading)
    {
        uint256 n = upper.point.length;
        uint256 part = 120 * n;
        bytes32 seed;
        uint256 sum;
        seed = keccak256(abi.encodePacked(upper.seed, digits[part:part + 72]));
        uint256[3] memory beta;
        for (uint8 j; j < 3; ++j) {
            beta[j] = coin(seed, 7, j);
            sum = addmod(sum, mulmod(beta[j], m[j], P), P);
        }
        Claim memory lower = reduceDigits(seed, sum, 1, digits[part + 72:2 * part + 72], n);
        uint256 d = read(digits, 2 * part + 72);
        uint256 d2 = mulmod(d, d, P);
        uint256 powers = addmod(mulmod(beta[0], d, P), mulmod(beta[1], mulmod(d, d2, P), P), P);
        powers = addmod(powers, mulmod(beta[2], mulmod(d2, d2, P), P), P);
        if (lower.sum != mulmod(equality(upper.point, 0, lower.point, 0, n), powers, P)) revert InvalidDigits();
        reading = Reading(
            keccak256(abi.encodePacked("recursive-imt/nibble-mle/v1", lower.seed)), openingPoint(lower.point), d
        );
    }

    function openMoments(
        Claim memory upper,
        uint256[3] memory m,
        bytes32 root,
        bytes calldata digits,
        bytes calldata proof,
        bytes calldata hints
    ) internal view {
        verifyReading(reduceMoments(upper, m, digits), root, proof, hints);
    }

    function verifyReading(Reading memory reading, bytes32 root, bytes calldata proof, bytes calldata hints)
        internal
        view
    {
        if (!opening.verify(root, reading.context, reading.point, reading.value, proof, hints)) {
            revert InvalidDigits();
        }
    }
}
