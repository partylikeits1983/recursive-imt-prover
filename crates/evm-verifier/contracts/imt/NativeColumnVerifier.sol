// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeField as F} from "./NativeField.sol";
import {NativeKeccak as K} from "./NativeKeccak.sol";

/// Derive the native polynomial-opening claims from the checked root relation.
/// The immutable page describes the table geometry of the 64-client verifier key.
abstract contract NativeColumnBase {
    error InvalidGeometry();
    address private immutable page;

    constructor(address geometry, bytes32 expectedHash) {
        if (geometry.codehash != expectedHash) {
            revert InvalidGeometry();
        }
        page = geometry;
    }

    struct Run {
        uint256 face;
        uint256 source;
        uint256 height;
        uint256 suffix;
        uint256 variables;
        uint256 blocks;
        uint256 width;
        uint256 domainSize;
    }

    struct Cursor {
        uint256 geometry;
        uint256 column;
        uint256 record;
        bytes pending;
    }

    function header(bytes memory key, uint256 pos) private pure returns (Run memory r) {
        uint256 w;
        assembly ("memory-safe") {
            w := mload(add(add(key, 32), pos))
        }
        r.face = uint8(w >> 248);
        r.source = uint8(w >> 240);
        r.height = uint8(w >> 232);
        r.suffix = uint8(w >> 224);
        r.variables = uint8(w >> 216);
        r.blocks = uint8(w >> 208);
        r.width = uint16(w >> 192);
        r.domainSize = uint16(w >> 176);
    }

    function slice(bytes memory data, uint256 pos, uint256 length) private pure returns (bytes memory out) {
        out = new bytes(length);
        assembly ("memory-safe") {
            mcopy(add(out, 32), add(add(data, 32), pos), length)
        }
    }

    function rowPoint(
        Run memory r,
        uint192[19] calldata point,
        uint256 auxOffset,
        uint256 auxStride,
        bytes memory key,
        uint256 suffixStart
    ) private pure returns (bytes memory row) {
        row = new bytes((r.height + r.suffix) * 24);
        for (uint256 i; i < r.height; ++i) {
            uint192 v;
            if (r.source == 0) {
                v = point[19 - r.height + i];
            } else {
                uint256 at = auxOffset + 32 * ((r.source - 1) * auxStride + i);
                assembly ("memory-safe") { v := calldataload(at) }
            }
            K.write192(row, 24 * i, v);
        }
        for (uint256 i; i < r.suffix; ++i) {
            uint256 src = suffixStart + 8 * i;
            uint256 dest = 24 * (r.height + i);
            assembly ("memory-safe") { mcopy(add(add(row, 32), dest), add(add(key, 32), src), 8) }
        }
    }

    function put(bytes memory records, uint256 start, uint256 pos, uint256 face, uint192 v) private pure {
        // The joint word polynomial inserts its one- or two-bit face selector after
        // the first 20 stacked coordinates. Unwritten slots are initialized to zero.
        K.write192(records, start + 24 * (pos < 20 ? pos : pos + face + 1), v);
    }

    function blockRecord(
        bytes memory records,
        uint256 start,
        uint256 face,
        uint64 descriptor,
        uint192[9] memory coins,
        bytes memory row,
        bytes calldata values,
        uint192[512] memory scratch
    ) private pure {
        uint256 prefixBits = uint8(descriptor >> 56);
        uint256 variables = uint8(descriptor >> 48);
        uint256 prefix = uint32(descriptor);
        if (face == 1) K.write192(records, start + 20 * 24, 1);
        for (uint256 i; i < prefixBits; ++i) {
            if ((prefix >> (prefixBits - 1 - i)) & 1 != 0) put(records, start, i, face, 1);
        }
        for (uint256 i; i < variables; ++i) {
            put(records, start, prefixBits + i, face, coins[i]);
        }
        // The row is already in native byte order. Copy the contiguous pieces
        // on either side of the inserted face selector.
        uint256 rowAt = prefixBits + variables;
        uint256 before = rowAt < 20 ? 24 * (20 - rowAt) : 0;
        uint256 rowDest = start + 24 * rowAt;
        assembly ("memory-safe") {
            let src := add(row, 32)
            let dst := add(add(records, 32), rowDest)
            mcopy(dst, src, before)
            mcopy(add(add(dst, before), mul(24, add(face, 1))), add(src, before), sub(mload(row), before))
        }
        K.write192(records, start + 32 * 24, blockValue(uint16(descriptor >> 32), variables, coins, values, scratch));
    }

    function blockValue(
        uint256 first,
        uint256 variables,
        uint192[9] memory coins,
        bytes calldata values,
        uint192[512] memory scratch
    ) private pure returns (uint192) {
        uint256 n = 1 << variables;
        for (uint256 i; i < n; ++i) {
            scratch[i] = 24 * (first + i) < values.length ? K.read192(values, 24 * (first + i)) : 0;
        }
        while (n > 1) {
            n >>= 1;
            uint192 r = coins[--variables];
            for (uint256 i; i < n; ++i) {
                uint192 a = scratch[2 * i];
                scratch[i] = a ^ F.mul(r, a ^ scratch[2 * i + 1]);
            }
        }
        return scratch[0];
    }

    function deriveClaims(
        uint192[19] calldata point,
        bytes32 postAirBlock,
        uint256 auxOffset,
        uint256 auxStride,
        bytes calldata columns
    ) internal view returns (bytes memory records) {
        address geometry = page;
        bytes memory key = new bytes(auxStride == 28 ? 8268 : 8258);
        assembly ("memory-safe") { extcodecopy(geometry, add(key, 32), 1, mload(key)) }
        records = new bytes(134 * 33 * 24);
        K.Stream memory stream = K.Stream(postAirBlock, 0);
        Cursor memory c;
        uint192[512] memory scratch;
        while (c.geometry < key.length) {
            Run memory r = header(key, c.geometry);
            c.geometry += 10;
            bytes memory domain = slice(key, c.geometry, r.domainSize);
            c.geometry += r.domainSize;
            bytes memory row = rowPoint(r, point, auxOffset, auxStride, key, c.geometry);
            c.geometry += 8 * r.suffix;
            bytes calldata values = columns[c.column:c.column + r.width * 24];
            c.column += r.width * 24;
            c.pending = bytes.concat(c.pending, domain, row, values);
            uint192[9] memory coins;
            if (r.variables != 0) {
                stream.blockHash = keccak256(abi.encodePacked(stream.blockHash, c.pending));
                stream.consumedWords = 0;
                c.pending = "";
                for (uint256 i; i < r.variables; ++i) {
                    coins[i] = K.sample192(stream);
                }
            }
            for (uint256 b; b < r.blocks; ++b) {
                uint256 offset = c.geometry;
                uint64 descriptor;
                assembly ("memory-safe") { descriptor := shr(192, mload(add(add(key, 32), offset))) }
                c.geometry += 8;
                blockRecord(records, c.record, r.face, descriptor, coins, row, values, scratch);
                c.record += 33 * 24;
            }
        }
        if (c.record != records.length || c.column != columns.length || c.geometry != key.length) {
            revert InvalidGeometry();
        }
    }
}

contract NativeColumnVerifier is NativeColumnBase {
    constructor(address geometry)
        NativeColumnBase(geometry, 0xa8d4d18ecda1a6649367213b64fe42c9785379cabdf1649e33690088340537f2)
    {}

    function derive(
        uint192[19] calldata point,
        bytes32 postAirBlock,
        uint192[27][4] calldata aux,
        bytes calldata columns
    ) external view returns (bytes memory) {
        if (columns.length != 2070 * 24) revert InvalidGeometry();
        uint256 offset;
        assembly ("memory-safe") { offset := aux }
        return deriveClaims(point, postAirBlock, offset, 27, columns);
    }
}

contract NativeMidpointColumnVerifier is NativeColumnBase {
    constructor(address geometry)
        NativeColumnBase(geometry, 0x25a4ed979b690e7f03410591d75df214664f342fe0cd52806cd3c24fe9ac1205)
    {}

    function derive(
        uint192[19] calldata point,
        bytes32 postAirBlock,
        uint192[28][5] calldata aux,
        bytes calldata columns
    ) external view returns (bytes memory) {
        if (columns.length != 2071 * 24) revert InvalidGeometry();
        uint256 offset;
        assembly ("memory-safe") { offset := aux }
        return deriveClaims(point, postAirBlock, offset, 28, columns);
    }
}
