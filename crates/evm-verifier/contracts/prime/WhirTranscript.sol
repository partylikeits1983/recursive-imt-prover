// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

uint256 constant WHIR_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

/// Fixed byte codec for the Field256 identity embedding.
library WhirField {
    error NonCanonicalField();

    function reverse(uint256 x) internal pure returns (uint256) {
        uint256 m = type(uint256).max / 0x101;
        x = ((x & m) << 8) | ((x >> 8) & m);
        m = type(uint256).max / 0x10001;
        x = ((x & m) << 16) | ((x >> 16) & m);
        m = type(uint256).max / 0x100000001;
        x = ((x & m) << 32) | ((x >> 32) & m);
        m = type(uint256).max / 0x10000000000000001;
        x = ((x & m) << 64) | ((x >> 64) & m);
        return (x << 128) | (x >> 128);
    }

    function read(bytes calldata data, uint256 offset) internal pure returns (uint256 value) {
        value = reverse(uint256(bytes32(data[offset:offset + 32])));
        if (value >= WHIR_PRIME) revert NonCanonicalField();
    }
}

/// Byte-compatible with Spongefish Hash<Keccak256> on a 64-bit reference host.
/// begin() groups a complete absorb run. Consecutive draw() calls share one squeeze stream.
library WhirTranscript {
    struct State {
        bytes32 cv;
        uint256 drawn;
    }

    /// Spongefish frames begin with 128 zero bytes, then an eight-byte big-endian domain
    /// and the chaining value. The suffix is either an absorbed message or a block counter.
    function begin(State memory self, bytes memory messages) internal pure {
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, 0)
            mstore(add(p, 32), 0)
            mstore(add(p, 64), 0)
            mstore(add(p, 96), 0)
            let cv := mload(self)
            let count := mload(add(self, 32))
            if count {
                mstore(add(p, 128), shl(192, 2))
                mstore(add(p, 136), cv)
                mstore(add(p, 168), shl(192, count))
                cv := keccak256(p, 176)
            }
            mstore(add(p, 128), 0)
            mstore(add(p, 136), cv)
            mcopy(add(p, 168), add(messages, 32), mload(messages))
            mstore(0, keccak256(p, add(168, mload(messages))))
            mstore(self, keccak256(0, 32))
            mstore(add(self, 32), 0)
        }
    }

    function draw(State memory self, uint256 count) internal pure returns (bytes memory result) {
        uint256 offset = self.drawn % 32;
        result = new bytes(offset + count);
        assembly ("memory-safe") {
            let scratch := mload(0x40)
            mstore(scratch, 0)
            mstore(add(scratch, 32), 0)
            mstore(add(scratch, 64), 0)
            mstore(add(scratch, 96), 0)
            mstore(add(scratch, 128), shl(192, 1))
            mstore(add(scratch, 136), mload(self))
            let consumed := mload(add(self, 32))
            let blockIndex := shr(5, consumed)
            let dest := add(result, 32)
            for { let pos := dest } lt(pos, add(dest, mload(result))) { pos := add(pos, 32) } {
                mstore(add(scratch, 168), shl(192, blockIndex))
                mstore(pos, keccak256(scratch, 176))
                blockIndex := add(blockIndex, 1)
            }
            mcopy(dest, add(dest, offset), count)
            mstore(result, count)
            mstore(add(self, 32), add(consumed, count))
        }
    }

    function field(State memory self) internal pure returns (uint256) {
        bytes memory data = draw(self, 64);
        uint256 lo;
        uint256 hi;
        assembly ("memory-safe") {
            lo := mload(add(data, 32))
            hi := mload(add(data, 64))
        }
        uint256 p = WHIR_PRIME;
        return addmod(WhirField.reverse(lo), mulmod(WhirField.reverse(hi), addmod(type(uint256).max, 1, p), p), p);
    }
}
