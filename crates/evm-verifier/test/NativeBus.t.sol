// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeBusVerifier} from "../contracts/imt/NativeBusVerifier.sol";
import {NativeArithmeticVerifier} from "../contracts/imt/NativeArithmeticVerifier.sol";
import {NativeKeccak as K} from "../contracts/imt/NativeKeccak.sol";
import {WiringPage} from "../contracts/imt/FixedWiringCap.sol";
import {FixtureReader} from "./NativeKeccak.t.sol";

contract NativeBusTest {
    FixtureReader private constant VM = FixtureReader(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant AUTHORITY = 0x6d999ec770660eb927350bedaa1d877b45defe1e46c48c6aed6cd12b07d81624;
    bytes32 private constant FIXED = 0xb6de4fa6b94cdd6d7ee0255ae4bf97f1a10cbb2a783b847f77cd8083b3a2e30b;
    bytes32 private constant MAIN = 0x7aa1b81ff51e742a677e0c046f3f7e853a8c6f3ba0b20b7ccb12c48fca77a54a;
    bytes32 private constant DIGEST = 0x6511d0c8c106fecb40fe7050968e08d9a2b2281488404c50e1fe1edca2d7c696;

    function setUp() public {
        bytes memory domain = VM.readFileBinary("test/fixtures/terminal-bus-domain.bin");
        require(domain.length == 51656);
        address[4] memory pages;
        for (uint256 i; i < 4; ++i) {
            bytes memory code = new bytes(16384);
            uint256 take = i == 3 ? domain.length - i * 16384 : 16384;
            assembly ("memory-safe") {
                mcopy(add(code, 32), add(add(domain, 32), mul(i, 16384)), take)
            }
            pages[i] = address(new WiringPage(code));
        }
        verifier = new NativeArithmeticVerifier(AUTHORITY, FIXED, pages);
    }

    NativeArithmeticVerifier private verifier;

    function testStatementThroughBusOn64Clients() external view {
        bytes memory wire = VM.readFileBinary("test/fixtures/terminal-bus-proof.bin");
        NativeBusVerifier.Claims memory c = verifier.verifyBus(DIGEST, 64, MAIN, wire);
        uint192 next = K.sample192(c.transcript);
        require(
            keccak256(abi.encode(c.fingerprint, c.offset, c.point, c.values, next))
                == 0x0d1ea3e8e81a61b6ef378b5c89f90238f5fea7c3ee404ce94a97bde2c0da4359
        );
    }

    function testBusAndArithmeticReduction() external view {
        bytes memory bus = VM.readFileBinary("test/fixtures/terminal-bus-proof.bin");
        bytes memory wire = VM.readFileBinary("test/fixtures/terminal-air-sumcheck.bin");
        (, NativeArithmeticVerifier.AirClaim memory air) = verifier.reduceArithmetic(DIGEST, 64, MAIN, bus, wire);
        require(
            keccak256(
                abi.encode(air.alpha, air.beta, air.lambda, air.tau, air.point, air.sum, K.sample192(air.transcript))
            ) == 0xf2ad3092208090bcf4e4340cd2f6c82d617a96c45ba75fde262dd0c8463664e8
        );
        wire[0] ^= 0x01;
        (bool accepted,) =
            address(verifier).staticcall(abi.encodeCall(verifier.reduceArithmetic, (DIGEST, 64, MAIN, bus, wire)));
        require(!accepted);
    }

    function testRejectChangedStatementAndProductLayer() external view {
        bytes memory wire = VM.readFileBinary("test/fixtures/terminal-bus-proof.bin");
        (bool ok,) = address(verifier)
            .staticcall(abi.encodeCall(verifier.verifyBus, (DIGEST ^ bytes32(uint256(1)), 64, MAIN, wire)));
        require(!ok);
        wire[wire.length - 1] ^= 0x80;
        (ok,) = address(verifier).staticcall(abi.encodeCall(verifier.verifyBus, (DIGEST, 64, MAIN, wire)));
        require(!ok);
    }
}
