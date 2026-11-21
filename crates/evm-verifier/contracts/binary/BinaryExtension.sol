// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeField as K} from "../imt/NativeField.sol";

/// LeanVM's quadratic extension y² = x y + 1 over the IMT polynomial-basis GF(2^64).
library BinaryExtension {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        uint64 al = uint64(a);
        uint64 ah = uint64(a >> 64);
        uint64 bl = uint64(b);
        uint64 bh = uint64(b >> 64);
        uint256 lo = K.wideMul64(al, bl);
        uint256 hi = K.wideMul64(ah, bh);
        uint256 middle = K.wideMul64(al ^ ah, bl ^ bh) ^ lo ^ hi;
        return K.reduceWide(lo ^ hi) | (uint256(K.reduceWide(middle ^ (hi << 1))) << 64);
    }

    function mulBase(uint256 a, uint64 b) internal pure returns (uint256) {
        return K.mul64(uint64(a), b) | (uint256(K.mul64(uint64(a >> 64), b)) << 64);
    }

    function square(uint256 a) internal pure returns (uint256) {
        uint64 h = K.square64(uint64(a >> 64));
        uint64 twice = (h << 1) ^ ((h >> 63) * 0x1b);
        return (K.square64(uint64(a)) ^ h) | (uint256(twice) << 64);
    }

    /// One inversion serves a whole point by Montgomery's batch-inversion trick.
    function inverse(uint256 a) internal pure returns (uint256) {
        uint64 hi = uint64(a >> 64);
        uint256 conjugate = a ^ K.mul64(hi, 2);
        uint64 norm = uint64(mul(a, conjugate));
        // x^(2^64-2). The caller has removed zero factors.
        uint64 v = norm;
        for (uint256 i = 1; i < 63; ++i) {
            v = K.mul64(K.square64(v), norm);
        }
        return mulBase(conjugate, K.square64(v));
    }
}
