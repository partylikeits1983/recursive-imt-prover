// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeKeccak} from "../contracts/imt/NativeKeccak.sol";
import {NativeChiLayer} from "../contracts/imt/NativeChiLayer.sol";

interface FixtureReader {
    function readFileBinary(string calldata path) external view returns (bytes memory);
}

contract NativeKeccakTest {
    FixtureReader private constant VM = FixtureReader(address(uint160(uint256(keccak256("hevm cheat code")))));

    // Test harness for the linked Keccak prefix of the real terminal proof.
    function checkPrefix(bytes calldata prefix) external pure returns (bytes32 pointHash, uint192 firstSum) {
        require(prefix.length == 4408);
        (NativeKeccak.Stream memory s, uint192[27] memory point) =
            NativeKeccak.outputPoint(bytes32(prefix[:32]), bytes32(prefix[32:64]), prefix[64:3256]);
        (, firstSum) = NativeKeccak.firstChi(s, point, prefix[3256:3280], prefix[3280:]);
        pointHash = keccak256(abi.encode(point));
    }

    // Rust-verified terminal64 proof SHA-256 c9278530d663c4cb863ff92f50873fc31dc99b4815cdee3098ea409d688c43d4.
    function testFirstChiOfTerminalRoot() external view {
        bytes memory data = VM.readFileBinary("test/fixtures/terminal-first-chi.bin");
        (bytes32 point, uint192 sum) = this.checkPrefix(data);
        require(point == 0xb21d621b89cd32b60475382c36cb4de674d64dcb0417425a681a45e29b7dfb61);
        require(sum == 0x532f634e733d7ff288551531c385e9727fb0dff58f14b6b0);
    }

    function checkLayer(bytes calldata prefix, bytes calldata cubic) external pure {
        require(prefix.length == 4408);
        (NativeKeccak.Stream memory s, uint192[27] memory point) =
            NativeKeccak.outputPoint(bytes32(prefix[:32]), bytes32(prefix[32:64]), prefix[64:3256]);
        (uint192 t, uint192 sum) = NativeKeccak.firstChi(s, point, prefix[3256:3280], prefix[3280:]);
        NativeChiLayer.check(s, point, t, sum, cubic);
    }

    function testFirstCubicLayerOfTerminalRoot() external view {
        bytes memory prefix = VM.readFileBinary("test/fixtures/terminal-first-chi.bin");
        bytes memory cubic = VM.readFileBinary("test/fixtures/terminal-first-chi-cubic.bin");
        this.checkLayer(prefix, cubic);
    }

    function testCubicMessagesAndEndpointAreBound() external view {
        bytes memory prefix = VM.readFileBinary("test/fixtures/terminal-first-chi.bin");
        bytes memory cubic = VM.readFileBinary("test/fixtures/terminal-first-chi-cubic.bin");
        uint256[4] memory offsets = [uint256(0), 24, 1608, 1680];
        for (uint256 i; i < offsets.length; ++i) {
            cubic[offsets[i]] ^= 0x01;
            (bool ok, bytes memory err) = address(this).staticcall(abi.encodeCall(this.checkLayer, (prefix, cubic)));
            require(
                !ok
                    && bytes4(err)
                        == (i == 0 ? NativeChiLayer.InvalidChiSum.selector : NativeChiLayer.InvalidChiEndpoint.selector)
            );
            cubic[offsets[i]] ^= 0x01;
        }
    }

    function testRejectsChangedProjectedClaimAndTranscriptInputs() external view {
        bytes memory data = VM.readFileBinary("test/fixtures/terminal-first-chi.bin");
        uint256[5] memory offsets = [uint256(0), 32, 64, 3256, 3280];
        for (uint256 i; i < offsets.length; ++i) {
            data[offsets[i]] ^= 0x01;
            (bool ok, bytes memory err) = address(this).staticcall(abi.encodeCall(this.checkPrefix, data));
            require(!ok && bytes4(err) == NativeKeccak.InvalidKeccakProjection.selector);
            data[offsets[i]] ^= 0x01;
        }
    }
}
