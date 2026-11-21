// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeField as F} from "./NativeField.sol";
import {NativeKeccak as K} from "./NativeKeccak.sol";

/// Arithmetic statement and product-tree reduction for the 64-client shared terminal.
/// The enclosing AIR verifies the two returned bus values against the committed tables.
contract NativeBusVerifier {
    error InvalidBusShape();
    error InvalidBusDomain();
    error InvalidBusLayer(uint256 layer);

    bytes32 private immutable authority;
    bytes32 private immutable fixedRoot;
    address[4] private pages;

    // Native transcript domain encodings derived from the trusted 19 arithmetic tables.
    bytes private constant STATEMENT_DOMAIN =
        hex"5d050000000000000270332d6d756c74692d737461726b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ed77241a3fcafd5cbbaa1d35820adf675b1e4dca17300de8c1b1dad449fd06cc9000004f800000008000000000000001300000008000000000000000000000008000000000000000a00000008000000000000000200000008000000000000000600000008000000000000000000000008000000000000000000000008000000000000001100000008000000000000000400000008000000000000001200000008000000000000000000000008000000000000000000000020696d742d737563636573736f722d616464726573732d7631110000000000000000000008000000000000000d00000008000000000000000200000008000000000000000600000008000000000000000000000008000000000000000000000008000000000000000b00000008000000000000000200000008000000000000000a00000008000000000000000000000008000000000000000000000008000000000000000d00000008000000000000000400000008000000000000001200000008000000000000000000000008000000000000000000000020696d742d737563636573736f722d616464726573732d76310d0000000000000000000008000000000000001300000008000000000000000200000008000000000000000600000008000000000000000000000008000000000000000000000008000000000000001200000008000000000000000200000008000000000000000a00000008000000000000000000000008000000000000000000000008000000000000001100000008000000000000000400000008000000000000001200000008000000000000000000000008000000000000000000000020696d742d737563636573736f722d616464726573732d7631110000000000000000000008000000000000001200000008000000000000000800000008000000000000001200000008000000000000000000000008000000000000000000000008000000000000001300000008000000000000000800000008000000000000001100000008000000000000000000000008000000000000000000000008000000000000001200000008000000000000000600000008000000000000000800000008000000000000000000000008000000000000000000000008000000000000001300000008000000000000000600000008000000000000000d00000008000000000000000000000008000000000000000000000008000000000000001300000008000000000000000600000008000000000000000d00000008000000000000000000000008000000000000000000000008000000000000001200000008000000000000000a00000008000000000000000f00000008000000000000000000000008000000000000000000000008000000000000001200000008000000000000002400000008000000000000004900000008000000000000000000000008000000000000000000000008000000000000001100000008000000000000001200000008000000000000001000000008000000000000000000000008000000000000000000000008000000000000001200000008000000000000000a0000000800000000000000060000000800000000000000000000000800000000000000000000000800000000000000040000000800000000000000010000000800000000000000000000000800000000000000000000000800000000000000000000000800000000000000100000000800000000000000e800000008000000000000010d00000008000000000000000000000008000000000000000080000000";
    bytes private constant PRODUCT_DOMAIN =
        hex"82000000000000000170332d6275732d70726f647563742d676b72000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012c3a95629e4767360a7f22d4bc534eb331f6cee4261ca844462e6b3d844e127100000001d000000081a00000000000000000000080200000000000000000000010180000000000000";

    constructor(bytes32 expectedAuthority, bytes32 expectedFixedRoot, address[4] memory sources) {
        bytes32[4] memory hashes = [
            bytes32(0xec5d41031c0a478d0247666374d4007e0caf892800b8c8279e05a0143bb8dddc),
            bytes32(0xb764fbfc6795001337dd3835a63315b469156c345d35c7eb03eb63df7d00419e),
            bytes32(0x2502956a47459eaa4e95ce3041bfe06a28f3799f6f0f7db987dceb3824259c18),
            bytes32(0x5416abcf40f3d0547470bb23cfe24a7641ab25873fbd98a9ff577aaf3c2281e2)
        ];
        for (uint256 i; i < 4; ++i) {
            if (sources[i].codehash != hashes[i]) revert InvalidBusDomain();
        }
        pages = sources;
        authority = expectedAuthority;
        fixedRoot = expectedFixedRoot;
    }

    struct Claims {
        uint192[3] fingerprint;
        uint192 offset;
        uint192[26] point;
        uint192[2] values;
        K.Stream transcript;
    }

    function start(bytes32 digest, bytes32 mainCap) private view returns (K.Stream memory s) {
        // One AIR reads two copies of the 32 digest bytes in Poly64, each followed by its role.
        bytes memory fields = new bytes(66 * 8);
        for (uint256 i; i < 32; ++i) {
            fields[8 * i] = digest[i];
            fields[8 * (i + 33)] = digest[i];
        }
        fields[65 * 8] = 0x01;
        bytes memory prefix =
            abi.encodePacked(authority, STATEMENT_DOMAIN, fixedRoot, K.COMMITMENT_DOMAIN, mainCap, fields);
        bytes memory message = bytes.concat(prefix, new bytes(51656));
        // Four inert code pages hold the native bus layout with its ordered declaration blocks.
        uint256 written = prefix.length;
        for (uint256 i; i < 4; ++i) {
            address page = pages[i];
            uint256 take = i == 3 ? 51656 - 3 * 16384 : 16384;
            assembly ("memory-safe") {
                extcodecopy(page, add(add(message, 32), written), 1, take)
            }
            written += take;
        }
        s.blockHash = keccak256(message);
    }

    function timesFour(uint192 v) private pure returns (uint192) {
        return F.timesX(F.timesX(v));
    }

    function timesTwenty(uint192 v) private pure returns (uint192) {
        uint192 four = timesFour(v);
        return four ^ timesFour(four);
    }

    /// Start with the cubic interpolant through 0..3. The correction through
    /// 4 and 5 is divisible by S4 = (x²+x)(x²+x+6), with S4(4)=S4(5)=0x168.
    function interpolation(bytes calldata msg_, uint192 claim, uint192 r) internal pure returns (uint192) {
        uint192 h0 = K.read192(msg_, 0);
        uint192 h2 = K.read192(msg_, 24);
        uint192 h3 = K.read192(msg_, 48);
        uint192 h4 = K.read192(msg_, 72);
        uint192 diff = h2 ^ h3 ^ claim;
        uint192 u = F.divideBySix(diff);
        uint192 v = F.divideBySix(h2 ^ h0 ^ F.timesX(claim ^ diff));
        uint192 p4 = h0 ^ timesFour(claim) ^ timesTwenty(timesFour(u) ^ v);
        uint64 inv = 0xe5e85e85e85e85e0;
        uint192 at4 = F.scale(h4 ^ p4, inv);
        if (msg_.length == 120) {
            uint192 slope = F.scale(h4 ^ K.read192(msg_, 96) ^ claim ^ timesTwenty(u), inv);
            at4 ^= F.mul(r ^ 4, slope);
        }
        uint192 s2 = F.square(r) ^ r;
        uint192 correction = F.mul(s2 ^ 6, at4);
        return h0 ^ F.mul(r, claim) ^ F.mul(s2, v ^ F.mul(r, u) ^ correction);
    }

    function blend(uint192 a, uint192 b, uint192 r) private pure returns (uint192) {
        return a ^ F.mul(r, a ^ b);
    }

    function children(bytes calldata four, uint192 b0, uint192 b1)
        private
        pure
        returns (uint192 product, uint192 value)
    {
        uint192 a = K.read192(four, 0);
        uint192 b = K.read192(four, 24);
        uint192 c = K.read192(four, 48);
        uint192 d = K.read192(four, 72);
        product = F.mul(F.mul(a, b), F.mul(c, d));
        value = blend(blend(a, b, b0), blend(c, d, b0), b1);
    }

    function absorb(K.Stream memory s, bytes calldata message) private pure {
        s.blockHash = keccak256(abi.encodePacked(s.blockHash, message));
        s.consumedWords = 0;
    }

    function verifyBus(bytes32 digest, uint8 count, bytes32 mainCap, bytes calldata wire)
        public
        view
        returns (Claims memory c)
    {
        if (count != 64 || wire.length != 21240) revert InvalidBusShape();
        K.Stream memory s = start(digest, mainCap);
        for (uint256 i; i < 3; ++i) {
            c.fingerprint[i] = K.sample192(s);
        }
        c.offset = K.sample192(s);
        s.blockHash = keccak256(abi.encodePacked(s.blockHash, PRODUCT_DOMAIN, wire[:24]));
        s.consumedWords = 0;
        uint192 root = K.read192(wire, 0);
        c.values = [root, root];
        uint256 pos = 24;
        uint192[26] memory point;
        for (uint256 n; n < 26; n += 2) {
            uint192 batching = K.sample192(s);
            uint192 running = c.values[0] ^ F.mul(batching, c.values[1]);
            uint192 eq = 1;
            uint192[26] memory next;
            for (uint256 j; j < n; ++j) {
                bytes calldata polynomial = wire[pos:pos + 120];
                pos += 120;
                absorb(s, polynomial);
                uint192 q = K.sample192(s);
                next[j + 2] = q;
                running = interpolation(polynomial, running, q);
                eq = F.mul(eq, 1 ^ point[j] ^ q);
            }
            bytes calldata row = wire[pos:pos + 192];
            pos += 192;
            absorb(s, row);
            uint192 b0 = K.sample192(s);
            uint192 b1 = K.sample192(s);
            next[0] = b0;
            next[1] = b1;
            (uint192 push, uint192 v0) = children(row[:96], b0, b1);
            (uint192 pull, uint192 v1) = children(row[96:], b0, b1);
            if (running != F.mul(eq, push ^ F.mul(batching, pull))) revert InvalidBusLayer(n / 2);
            c.values = [v0, v1];
            point = next;
        }
        for (uint256 i; i < 26; ++i) {
            c.point[i] = point[25 - i];
        }
        c.transcript = s;
    }
}
