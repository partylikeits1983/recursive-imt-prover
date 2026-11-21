// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FixtureReader} from "./NativeKeccak.t.sol";
import {BinaryTerminalOpenings} from "../contracts/binary/BinaryTerminalOpenings.sol";
import {BinaryLaneFold} from "../contracts/binary/BinaryLaneFold.sol";
import {BinaryExtension as E} from "../contracts/binary/BinaryExtension.sol";

contract BinaryTerminalTest {
    FixtureReader private constant VM = FixtureReader(address(uint160(uint256(keccak256("hevm cheat code")))));
    BinaryTerminalOpenings private immutable openings = new BinaryTerminalOpenings();

    function publicStatement() internal pure virtual returns (bytes32, uint8, string memory) {
        return (
            0xdc2c73b09aa834e78f5d05f326e751caffa47c50b7c427e4638cf388e43787f3,
            64,
            "test/fixtures/leanvm-imt-roots-64.bin"
        );
    }

    function opening() internal pure virtual returns (string memory, bytes16, uint128, uint128) {
        return (
            "test/fixtures/binary-terminal-64.imt",
            0x44a194183108c8747f7476ad29d07665,
            0x596d8213de755814703dd3c435bae06e,
            0xdb8002f98824f48e9946605f2fc00a6e
        );
    }

    function fixture(string memory path) private view returns (bytes memory) {
        bytes memory bundle = VM.readFileBinary(path);
        (bytes32 digest, uint8 count,) = publicStatement();
        require(bytes32(bundle) == digest && bundle[32] == bytes1(count));
        bytes memory proof = new bytes(bundle.length - 33);
        assembly ("memory-safe") { mcopy(add(proof, 32), add(bundle, 65), mload(proof)) }
        return proof;
    }

    function testCheckedNativeOpening() external view {
        (string memory path, bytes16 deferred, uint128 target, uint128 basis) = opening();
        (bytes32 digest, uint8 count,) = publicStatement();
        bytes memory proof = fixture(path);
        require(openings.checkWhir(digest, count, deferred, target, basis, proof));
        (bool accepted,) = address(openings)
            .staticcall(abi.encodeCall(openings.checkWhir, (digest, count, deferred, target ^ 1, basis, proof)));
        require(!accepted);
    }

    function testCheckedOpeningBindsTheCLIListOfRoots() external view {
        (string memory path, bytes16 deferred, uint128 target, uint128 basis) = opening();
        bytes memory proof = fixture(path);
        (, uint8 count, string memory rootsPath) = publicStatement();
        bytes memory packed = VM.readFileBinary(rootsPath);
        require(packed.length == uint256(count) * 32);
        bytes32[] memory roots = new bytes32[](count);
        assembly ("memory-safe") { mcopy(add(roots, 32), add(packed, 32), mload(packed)) }
        require(openings.checkRootListOpening(roots, deferred, target, basis, proof));
        require(openings.checkRootListStackTarget(roots, deferred, basis, proof));
        require(openings.checkRootListStackOpening(roots, deferred, proof));
        (roots[0], roots[1]) = (roots[1], roots[0]);
        (bool accepted,) = address(openings)
            .staticcall(abi.encodeCall(openings.checkRootListOpening, (roots, deferred, target, basis, proof)));
        require(!accepted);
        (accepted,) =
            address(openings).staticcall(abi.encodeCall(openings.checkRootListStackOpening, (roots, deferred, proof)));
        require(!accepted);
    }

    function testRejectsChangedBasisAndStatement() external view {
        (string memory path, bytes16 deferred, uint128 target, uint128 basis) = opening();
        (bytes32 digest, uint8 count,) = publicStatement();
        bytes memory proof = fixture(path);
        (bool accepted,) = address(openings)
            .staticcall(abi.encodeCall(openings.checkWhir, (digest, count, deferred, target, basis ^ 1, proof)));
        require(!accepted);
        (bool app,) = address(openings)
            .staticcall(abi.encodeCall(openings.checkOpenings, (bytes32(uint256(digest) ^ 1), count, deferred, proof)));
        require(!app);
    }

    function checkLane(uint128 a, uint128 b, uint128 hi, bool base) private pure {
        uint256[64] memory lanes;
        lanes[0] = base ? uint64(a) : a;
        lanes[1] = hi;
        lanes[2] = lanes[0] ^ 1;
        uint256 first = E.mul(lanes[0], b) ^ hi;
        uint256 second = E.mul(lanes[2], b);
        BinaryLaneFold.fold(lanes, 2, b, base);
        require(lanes[0] == first && lanes[1] == second);
    }

    function testFuzzFixedLanes(uint128 a, uint128 b, uint128 hi, bool base) external pure {
        checkLane(a, b, hi, base);
    }

    function testFullResidueCarry() external pure {
        checkLane(type(uint128).max, type(uint128).max, 1, false);
        checkLane(type(uint128).max, type(uint128).max, 1, true);
        checkLane(0x11111111111111114444444444444444, 0x88888888888888882222222222222222, 0, false);
    }

    function testFuzzInverse(uint128 a) external pure {
        if (a != 0) require(E.mul(a, E.inverse(a)) == 1);
    }
}
