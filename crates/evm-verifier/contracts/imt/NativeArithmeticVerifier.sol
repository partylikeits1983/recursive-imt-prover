// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeBusVerifier} from "./NativeBusVerifier.sol";
import {NativeField as F} from "./NativeField.sol";
import {NativeKeccak as K} from "./NativeKeccak.sol";

/// Derive the terminal AIR opening point and reduced claim from the expected
/// public statement, checked bus product, and degree-four arithmetic sumcheck.
contract NativeArithmeticVerifier is NativeBusVerifier {
    error InvalidArithmeticSum();

    bytes private constant AIR_DOMAIN =
        hex"69020000000000000170332d6d756c74692d737461726b2d7a65726f636865636b0000000000000000000000000000000000000000000000000000000000000000000000000000185f0f37279aee0545c5479b2fb42482ec0d8831c127b0102002731a072ee00327000002040000000800000000000000130000000800000000000000000000000800000000000000000000000800000000000000130000000800000000000000020000000800000000000000000000000800000000000000020000000800000000000000000000000800000000000000020000000800000000000000000000000800000000000000020000000800000000000000000000000800000000000000020000000800000000000000000000000800000000000000020000000800000000000000000000000800000000000000020000000800000000000000000000000800000000000000020000000800000000000000000000000800000000000000030000000800000000000000000000000800000000000000030000000800000000000000000000000800000000000000030000000800000000000000000000000800000000000000030000000800000000000000000000000800000000000000030000000800000000000000000000000800000000000000030000000800000000000000000000000800000000000000020000000800000000000000000000000800000000000000020000000800000000000000000000000800000000000000020000000800000000000000000000000800000000000000010000000800000000000000000000000800000000000000020000000800000000000000000000000800000000000000038000000000000000";
    bytes private constant SUM_DOMAIN =
        hex"65000000000000000170332d73756d636865636b2d67656e657269632d6465677265650000000000000000000000000000000000000000000000000000000000000000000000001a997fc974efcb850c77242eaa87887c9ec155a8f5abebde10725a5aeea13e5ccd0000000080000000";

    constructor(bytes32 authority, bytes32 fixedRoot, address[4] memory pages)
        NativeBusVerifier(authority, fixedRoot, pages)
    {}

    struct AirClaim {
        uint192 alpha;
        uint192 beta;
        uint192 lambda;
        uint192[19] tau;
        uint192[19] point;
        uint192 sum;
        K.Stream transcript;
    }

    function reduceArithmetic(bytes32 digest, uint8 count, bytes32 cap, bytes calldata busWire, bytes calldata wire)
        public
        view
        returns (Claims memory bus, AirClaim memory air)
    {
        if (wire.length != 24 + 19 * 96) revert InvalidArithmeticSum();
        bus = verifyBus(digest, count, cap, busWire);
        K.Stream memory s = K.Stream(keccak256(abi.encodePacked(bus.transcript.blockHash, AIR_DOMAIN)), 0);
        air.alpha = K.sample192(s);
        air.beta = K.sample192(s);
        uint192 lambda = K.sample192(s);
        air.lambda = lambda;
        for (uint256 i; i < 19; ++i) {
            uint192 v;
            do {
                v = K.sample192(s);
            } while (v == 0);
            air.tau[i] = v;
        }
        uint192 sum = F.mul(lambda, (bus.values[0] ^ 1) ^ F.mul(lambda, bus.values[1] ^ 1));
        if (K.read192(wire, 0) != sum) revert InvalidArithmeticSum();
        for (uint256 i; i < 19; ++i) {
            bytes calldata values = wire[24 + i * 96:120 + i * 96];
            s.blockHash = i == 0
                ? keccak256(abi.encodePacked(s.blockHash, SUM_DOMAIN, wire[:120]))
                : keccak256(abi.encodePacked(s.blockHash, values));
            s.consumedWords = 0;
            uint192 r = K.sample192(s);
            air.point[i] = r;
            sum = interpolation(values, sum, r);
        }
        air.sum = sum;
        air.transcript = s;
    }
}
