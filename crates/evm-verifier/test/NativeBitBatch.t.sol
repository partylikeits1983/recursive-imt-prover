// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WhirFixtureProfile} from "./WhirFixtureProfile.sol";
import {NativeKeccak} from "../contracts/imt/NativeKeccak.sol";
import {NativeBitBatch} from "../contracts/imt/NativeBitBatch.sol";
import {NativeWhirInitial} from "../contracts/imt/NativeWhirInitial.sol";

contract NativeBitBatchTest is WhirFixtureProfile {
    /// Benchmark harness. The full verifier will construct prefix and claims in memory.
    function check(bytes memory prefix, bytes memory claims, bytes calldata proof)
        external
        pure
        returns (bytes32 pointHash, uint192 value)
    {
        NativeBitBatch.Endpoint memory end = NativeBitBatch.reduce(prefix, claims, proof);
        return (keccak256(abi.encode(end.point)), end.value);
    }

    function checkTerminal(
        bytes32 authority,
        bytes32 mainCap,
        bytes32 fixedCap,
        bytes memory claims,
        bytes calldata proof
    ) external pure returns (bytes32, uint192) {
        NativeBitBatch.Endpoint memory end = NativeBitBatch.reduceTerminal(authority, mainCap, fixedCap, claims, proof);
        return (keccak256(abi.encode(end.point)), end.value);
    }

    function checkTerminalTensor(
        bytes32 authority,
        bytes32 mainCap,
        bytes32 fixedCap,
        bytes memory claims,
        bytes calldata proof,
        bytes calldata rows
    ) external pure returns (bytes32, uint192, uint192, uint192) {
        NativeBitBatch.Endpoint memory end = NativeBitBatch.reduceTerminal(authority, mainCap, fixedCap, claims, proof);
        NativeBitBatch.RingState memory ring = NativeBitBatch.ringSwitch(end, rows);
        return (keccak256(abi.encode(end.point)), end.value, ring.claimedSum, NativeKeccak.sample192(ring.stream));
    }

    function checkTensorAt(uint192[32] memory point, uint192 value, bytes calldata rows) external pure {
        NativeBitBatch.checkTensor(NativeBitBatch.Endpoint(point, value, 0), rows);
    }

    function checkInitialFold(
        bytes32[3] memory binding,
        bytes memory claims,
        bytes calldata batch,
        bytes calldata rows,
        bytes calldata first
    ) external pure returns (bytes32, uint192, uint192) {
        NativeBitBatch.Endpoint memory end =
            NativeBitBatch.reduceTerminal(binding[0], binding[1], binding[2], claims, batch);
        NativeWhirInitial.Fold memory fold =
            NativeWhirInitial.initialFold(NativeBitBatch.ringSwitch(end, rows), first, fourVariableFolds());
        return (keccak256(abi.encode(fold.point)), fold.sum, NativeKeccak.sample192(fold.stream));
    }

    function checkInitialQuery(
        bytes32[3] memory binding,
        bytes memory claims,
        bytes calldata batch,
        bytes calldata rows,
        bytes calldata section
    ) external pure returns (bytes32, uint192, bytes32, bytes32, bytes32) {
        if (section.length != 472) revert NativeWhirInitial.InvalidProofLength();
        NativeBitBatch.Endpoint memory end =
            NativeBitBatch.reduceTerminal(binding[0], binding[1], binding[2], claims, batch);
        NativeBitBatch.RingState memory ring = NativeBitBatch.ringSwitch(end, rows);
        bytes32 ringBlock = ring.stream.blockHash;
        NativeWhirInitial.Fold memory fold = NativeWhirInitial.initialFold(ring, section[:384], fourVariableFolds());
        NativeWhirInitial.Query memory q = NativeWhirInitial.firstQuery(fold, section[384:]);
        return (keccak256(abi.encode(fold.point)), fold.sum, q.nextCap, keccak256(abi.encode(q.indices)), ringBlock);
    }

    function testFuzzTensorAtBooleanColumn(uint8 column, uint192 value) external view {
        uint256 pos = uint256(column) % 64;
        uint192[32] memory point;
        for (uint256 i; i < 6; ++i) {
            point[31 - i] = uint192((pos >> i) & 1);
        }
        bytes memory rows = new bytes(1536);
        for (uint256 j; j < 192; ++j) {
            rows[8 * j + pos / 8] = bytes1(uint8(((uint256(value) >> j) & 1) << (pos % 8)));
        }
        this.checkTensorAt(point, value, rows);
        rows[8 * 191 + pos / 8] ^= bytes1(uint8(1 << (pos % 8)));
        (bool ok, bytes memory err) = address(this).staticcall(abi.encodeCall(this.checkTensorAt, (point, value, rows)));
        require(!ok && bytes4(err) == NativeBitBatch.WrongTensor.selector);
    }

    // A zero witness at a public point has an all-zero sumcheck and opened value.
    function testZeroWitnessAndFalseEvaluation() external view {
        bytes memory claims = new bytes(33 * 24);
        bytes memory proof = new bytes(65 * 24);
        (, uint192 v) = this.check("test", claims, proof);
        require(v == 0);
        claims[32 * 24] = 0x01;
        (bool ok, bytes memory err) =
            address(this).staticcall(abi.encodeCall(this.check, (bytes("test"), claims, proof)));
        require(!ok && bytes4(err) == NativeBitBatch.WrongEndpoint.selector);
    }
}

contract NativeBitBatchTestFour is NativeBitBatchTest {
    function fourVariableFolds() internal pure override returns (bool) {
        return true;
    }
}
