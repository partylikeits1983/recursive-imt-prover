// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeField} from "../contracts/imt/NativeField.sol";
import {NativeChiLayer} from "../contracts/imt/NativeChiLayer.sol";
import {NativeKeccak} from "../contracts/imt/NativeKeccak.sol";

contract NativeFieldTest {
    function testFuzzExtensionConvolution(uint192 a, uint192 b) external pure {
        uint64[5] memory coefficients;
        for (uint256 i; i < 3; ++i) {
            for (uint256 j; j < 3; ++j) {
                coefficients[i + j] ^= NativeField.mul64(uint64(a >> (64 * i)), uint64(b >> (64 * j)));
            }
        }
        uint192 expected = uint192(coefficients[0] ^ coefficients[3])
            | (uint192(coefficients[1] ^ coefficients[3] ^ coefficients[4]) << 64)
            | (uint192(coefficients[2] ^ coefficients[4]) << 128);
        require(NativeField.mul(a, b) == expected);
    }

    /// Meter the arithmetic with Rust-derived Fiat-Shamir challenges. The
    /// full verifier derives them itself and checks the Keccak endpoints.
    function profileCubicRounds(bytes calldata data) external view returns (uint256) {
        require(data.length == (2 + 23 * 4) * 24);
        uint192 sum = NativeKeccak.read192(data, 0);
        uint256 start = gasleft();
        for (uint256 offset = 24; offset < data.length - 24; offset += 96) {
            sum = NativeField.cubic(
                sum,
                NativeKeccak.read192(data, offset),
                NativeKeccak.read192(data, offset + 24),
                NativeKeccak.read192(data, offset + 48),
                NativeKeccak.read192(data, offset + 72)
            );
        }
        require(sum == NativeKeccak.read192(data, data.length - 24));
        return start - gasleft();
    }

    function testFuzzFixedMultiplier(uint192 a, uint192 b) external pure {
        require(NativeField.multiplyFixed(NativeField.multiplierTable(a), b) == NativeField.mul(a, b));
    }

    function testFuzzCubicScalings(uint192 a) external pure {
        require(NativeField.timesX(a) == NativeField.scale(a, 2));
        require(NativeField.scale(NativeField.divideBySix(a), 6) == a);
    }

    function testFuzzPackedConstantScalings(uint192 a, uint8 seed) external pure {
        uint256 shift = 1 + seed % 60;
        require(NativeField.scaleMonomial(a, shift) == NativeField.scale(a, uint64(1) << uint64(shift)));
        uint256 levels = 1 + seed % 6;
        uint64 ones = uint64((uint256(1) << (1 << levels)) - 1);
        require(NativeField.scaleOnes(a, levels) == NativeField.scale(a, ones));
    }

    function testFuzzEmbeddingSum(uint192 t) external pure {
        require(NativeField.square(t) == NativeField.mul(t, t));
        uint192 referenceValue = 1;
        for (uint256 i = 23; i != 0; --i) {
            referenceValue = NativeField.mul(referenceValue, t) ^ uint192((uint256(0xb1b9b1) >> (i - 1)) & 1);
        }
        require(NativeChiLayer.embeddingSum(t) == referenceValue);
    }

    function testFuzzBaseMultiplication(uint64 a, uint64 b) external pure {
        require(NativeField.mul64(a, b) == referenceProduct(a, b));
    }

    function testSaturatedResidueClasses() external pure {
        for (uint64 a; a < 16; ++a) {
            for (uint64 b; b < 16; ++b) {
                uint64 left = 0x1111111111111111 * a;
                uint64 right = 0x1111111111111111 * b;
                require(NativeField.mul64(left, right) == referenceProduct(left, right));
                left ^= uint64(1) << ((a + 4 * b) % 64);
                require(NativeField.mul64(left, right) == referenceProduct(left, right));
            }
        }
    }

    // Independent polynomial long multiplication interleaved with reduction.
    function referenceProduct(uint64 a, uint64 b) private pure returns (uint64 answer) {
        uint64 x = a;
        for (uint256 i = 0; i < 64; ++i) {
            if (((b >> i) & 1) != 0) answer ^= x;
            uint64 top = x >> 63;
            x = (x << 1) ^ (top * 0x1b);
        }
    }

    function testFullCoefficientOverlapAndReduction() external pure {
        uint64 ones = type(uint64).max;
        // Values computed by the independent long multiplication below.
        uint64 expected;
        uint64 x = ones;
        for (uint256 i; i < 64; ++i) {
            expected ^= x;
            x = (x << 1) ^ ((x >> 63) * 0x1b);
        }
        require(NativeField.mul64(ones, ones) == expected);
        require(NativeField.mul64(1 << 63, 2) == 0x1b);
        uint192 y = uint192(1) << 64;
        require(NativeField.mul(uint192(1) << 128, y) == (y ^ 1));
    }

    // Captured by the native verifier of the saved 64-leaf root. Each limb is a Poly64.
    // Source: crates/flock-backend/tests/fixtures/native-root-whir-rounds.txt.
    function testFourNativeSumcheckRounds() external pure {
        uint192 claim = 0xb7fd901dd99b244e6dbdbdffe5149a56a12f2fd7a5cc1e63;
        claim = NativeField.sumcheckRound(
            claim,
            0x98b90dd3f18bdf5b11583c57dbb7ab4e4617e413d0af5ff8,
            0xab0f046f67cc473c9907ef0649efd811b477cfca65e1eaec,
            0x7364c48f3fc2e250cd63e0aad10e433e6a572770e596fe95
        );
        require(claim == 0x48189dd6a701cc117f384b8f2a0c8fc4b5539bbb83e3b976);
        claim = NativeField.sumcheckRound(
            claim,
            0x36e2c27e1fd6be5d7ed36a7658f7417d2c3fa0eef06b6024,
            0x6600edb4dedd51fb274bfaadef95db7b72e0e688c513a157,
            0x1073d93ccb2970a5f95f383c7b82aa3876fd6a57f809e9e1
        );
        require(claim == 0x418b580d8a03f6ac36211a15309bdd49e32a7686886b6b4a);
        claim = NativeField.sumcheckRound(
            claim,
            0x9f7453f8fa09335244ce596882b27febf558aff9efcb388a,
            0x080ec02f22d26e08922653b88ec6284d92a7562eaa36964b,
            0x7eb052cc7f61f9265f1193ceee40152810954278de3d0ce6
        );
        require(claim == 0x8416a8cf2a041bfed95f167b2f4f6e9f05066864e1972835);
        claim = NativeField.sumcheckRound(
            claim,
            0x4789cdf31836a5a20686810aafeb8a4ff6bedf6550fa4d4d,
            0x882ea70924b82f321e9d66efca9855cbaa6a95aba90b24a8,
            0xa1e19a9280a96c190521cbe9d94f594c73388c7322ab73c4
        );
        require(claim == 0x49b1fd3a8dfb90c4303c56998f06422ab5b32b5626c7c34c);
    }
}
