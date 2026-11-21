// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeKeccakRounds as R} from "../contracts/imt/NativeKeccakRounds.sol";
import {NativeChiLayer} from "../contracts/imt/NativeChiLayer.sol";
import {FixtureReader} from "./NativeKeccak.t.sol";

/// Differential harness. Only reduceAll establishes the whole 24-round chain
/// in a single call. It returns the claim the enclosing opening must check.
contract NativeKeccakRoundsTest {
    FixtureReader private constant VM = FixtureReader(address(uint160(uint256(keccak256("hevm cheat code")))));
    event log_named_uint(string key, uint256 value);

    function reduceFirst(bytes calldata prefix, bytes calldata cubic) external pure returns (R.Progress memory) {
        return R.first(prefix, cubic);
    }

    function reduceNext(R.Progress memory state, bytes calldata layer) external pure returns (R.Progress memory) {
        return R.next(state, layer);
    }

    function reduceAll(bytes calldata prefix, bytes calldata layers) external pure returns (R.Progress memory) {
        return R.verifyRounds(prefix, layers);
    }

    function testRejectWrongLength() external view {
        (bool ok,) = address(this).staticcall(abi.encodeCall(this.reduceAll, (bytes(""), bytes(""))));
        require(!ok);
    }

    function testAllLayersOfTerminalRoot() external {
        bytes memory prefix = VM.readFileBinary("test/fixtures/terminal-first-chi.bin");
        bytes memory wire = VM.readFileBinary("test/fixtures/terminal-chi-rounds.bin");
        uint256 start = gasleft();
        R.Progress memory state = this.reduceAll(prefix, wire);
        uint256 used = start - gasleft();
        require(state.remaining == 0);
        require(state.beta == 0xcc1f2b9bdc861910eeb23bb9615f1b35e9b04eb1fe820bc3);
        require(state.value == 0xb57d14f16f20ec6c5374b2911fc8573884e55aa35692900d);
        emit log_named_uint("24 linked layers, single call including ABI and return, execution gas", used);
    }

    function testRejectsChangedLastRoundInFullChain() external view {
        bytes memory prefix = VM.readFileBinary("test/fixtures/terminal-first-chi.bin");
        bytes memory wire = VM.readFileBinary("test/fixtures/terminal-chi-rounds.bin");
        wire[wire.length - 1] ^= 0x01;
        (bool ok, bytes memory err) = address(this).staticcall(abi.encodeCall(this.reduceAll, (prefix, wire)));
        require(!ok && bytes4(err) == NativeChiLayer.InvalidChiEndpoint.selector);
    }
}
