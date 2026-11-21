// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WhirField, WhirTranscript} from "./WhirTranscript.sol";
import {WhirMerkle} from "./WhirMerkle.sol";

/// WHIR over the 192-bit prime, using the finite-Johnson 135-bit local schedule,
/// full Keccak commitments, initial interleaving 16 and subsequent interleaving 32.
contract NibbleOpeningVerifier {
    using WhirTranscript for WhirTranscript.State;
    uint256 private constant P = 3801539170989320091464968600173246866371124347557388484609;
    bytes32 private constant SESSION = 0xfc8c823d960630bb11967f14bd08db1a57abb3fb0bee14ec3c291d2d9e2f8a42;
    error InvalidOpening();
    error InvalidWork();

    struct Profile {
        uint256 arity;
        uint256 stages;
        uint256 depth;
        uint256 generator;
        bytes domain;
        uint64[5] foldWork;
    }

    struct State {
        WhirTranscript.State sponge;
        uint256 pos;
        uint256 hint;
        uint256 sum;
        uint256 cursor;
        bytes32 root;
        Profile cfg;
        uint256[128] table;
        uint256[] rs;
        uint256[5] ood;
        uint256[5] mix;
        uint256[][5] points;
    }

    function readings() internal pure virtual returns (uint256) {
        return 1;
    }

    function wireSizes() internal pure virtual returns (uint256, uint256) {
        return (2168, 171720);
    }

    function profile() internal pure virtual returns (Profile memory p) {
        p.arity = 28;
        p.stages = 5;
        p.depth = 29;
        p.generator = 319592216488861777027453761503267660357846665680517156756;
        p.domain =
            hex"878b0cf75e288fde6806e90daf1b89070a45914f710ed24566972ee17b33ce2694881f3b065282cf13bb9814487ebb000f3776f209fb2665f7e4d06110a39ea1";
        p.foldWork = [type(uint64).max, type(uint64).max, 1075609754631835392, 33612804832244856, 1050400151007652];
    }

    function scalar(bytes calldata buf, uint256 i) private pure returns (uint256 v) {
        // Check the slice bounds even on the last packed element.
        v = WhirField.reverse(uint256(bytes32(buf[i:i + 24])));
        if (v >= P) revert WhirField.NonCanonicalField();
    }

    function challenge(WhirTranscript.State memory tr) private pure returns (uint256) {
        bytes memory b = tr.draw(56);
        uint256 lo;
        uint256 hi;
        assembly ("memory-safe") {
            lo := mload(add(b, 32))
            hi := mload(add(b, 64))
        }
        return
            addmod(WhirField.reverse(lo), mulmod(uint192(WhirField.reverse(hi)), addmod(type(uint256).max, 1, P), P), P);
    }

    function grind(State memory s, bytes calldata proof, uint64 threshold) private pure {
        if (threshold == type(uint64).max) return;
        bytes memory seed = s.sponge.draw(32);
        bytes calldata nonce = proof[s.pos:s.pos + 8];
        bytes32 digest = keccak256(abi.encodePacked(seed, nonce, bytes24(0)));
        if (uint64(WhirField.reverse(uint256(digest))) > threshold) revert InvalidWork();
        s.sponge.begin(nonce);
        s.pos += 8;
    }

    function fold(State memory s, bytes calldata proof, uint256 count, uint64 threshold) private pure {
        for (uint256 i; i < count; ++i) {
            uint256 c0 = scalar(proof, s.pos);
            uint256 c2 = scalar(proof, s.pos + 24);
            s.sponge.begin(proof[s.pos:s.pos + 48]);
            s.pos += 48;
            grind(s, proof, threshold);
            uint256 r = challenge(s.sponge);
            s.rs[s.cursor++] = r;
            uint256 c1 = addmod(s.sum, P - addmod(addmod(c0, c0, P), c2, P), P);
            s.sum = addmod(c0, mulmod(r, addmod(c1, mulmod(c2, r, P), P), P), P);
        }
    }

    function sample(State memory s, bytes calldata proof, uint256 stage) private pure returns (uint256 v) {
        s.ood[stage] = challenge(s.sponge);
        v = scalar(proof, s.pos);
        s.sponge.begin(proof[s.pos:s.pos + 24]);
        s.pos += 24;
    }

    function weights(State memory s, uint256 bits) private pure returns (uint256[] memory w) {
        w = new uint256[](1 << bits);
        w[0] = 1;
        for (uint256 k; k < bits; ++k) {
            uint256 b = s.rs[s.cursor - 1 - k];
            uint256 stride = 1 << k;
            for (uint256 j; j < stride; ++j) {
                uint256 high = mulmod(w[j], b, P);
                w[j + stride] = high;
                w[j] = addmod(w[j], P - high, P);
            }
        }
    }

    function powers(uint256 g) private pure returns (uint256[128] memory table) {
        assembly ("memory-safe") {
            for { let p := table } lt(p, add(table, 4096)) { p := add(p, 512) } {
                let v := 1
                for { let q := p } lt(q, add(p, 512)) { q := add(q, 32) } {
                    mstore(q, v)
                    v := mulmod(v, g, P)
                }
                g := v
            }
        }
    }

    function openRows(State memory s, bytes calldata proof, bytes calldata hints, uint256 stage)
        private
        pure
        returns (uint256[] memory values)
    {
        uint8[5] memory draws = [49, 31, 21, 16, 12];
        uint64[5] memory queryWork =
            [uint64(291587647640057), 1984821698187546, 12932261597155760, 66020828151507144, 313471598626301];
        grind(s, proof, queryWork[stage]);
        uint256 drop = stage == 0 ? 0 : stage + 1;
        uint256 depth = s.cfg.depth - drop;
        uint256 coset = s.cfg.arity - s.cursor;
        uint256 mask = (1 << depth) - 1;
        uint256 indexBytes = (depth + 7) / 8;
        uint256 count = draws[stage];
        bytes memory random = s.sponge.draw(count * indexBytes);
        uint256[] memory indices = new uint256[](count);
        bytes32[] memory hashes = new bytes32[](count);
        uint256[] memory zs = new uint256[](count);
        values = new uint256[](count);
        uint256[] memory w = weights(s, stage == 0 ? 4 : 5);
        if (WhirField.reverse(uint256(bytes32(bytes8(hints[s.hint:s.hint + 8])))) != count * w.length) {
            revert InvalidOpening();
        }
        s.hint += 8;
        uint256 rowSize = 24 * w.length;
        uint256[128] memory table = s.table;
        for (uint256 i; i < count; ++i) {
            uint256 idx;
            assembly ("memory-safe") {
                idx := and(mask, shr(sub(256, mul(indexBytes, 8)), mload(add(add(random, 32), mul(i, indexBytes)))))
            }
            indices[i] = idx;
            uint256 exponent = (((idx << (depth - coset)) & mask) | (idx >> coset)) << drop;
            uint256 z = 1;
            assembly ("memory-safe") {
                for { let pos := table } exponent { pos := add(pos, 512) } {
                    z := mulmod(z, mload(add(pos, shl(5, and(exponent, 15)))), P)
                    exponent := shr(4, exponent)
                }
            }
            zs[i] = z;
            bytes calldata row = hints[s.hint:s.hint + rowSize];
            s.hint += rowSize;
            (hashes[i], values[i]) = foldRow(row, w);
        }
        s.points[stage] = zs;
        s.hint = WhirMerkle.verify(s.root, indices, hashes, depth, hints, s.hint);
    }

    // The caller has sliced exactly 24 bytes per weight. The final load may
    // read eight additional bytes, which the 192-bit little-endian codec discards.
    function foldRow(bytes calldata row, uint256[] memory w) private pure returns (bytes32 digest, uint256 value) {
        uint256 bad = uint32(WhirField.NonCanonicalField.selector);
        assembly ("memory-safe") {
            let scratch := mload(0x40)
            calldatacopy(scratch, row.offset, row.length)
            digest := keccak256(scratch, row.length)
            let weightPtr := add(w, 32)
            let m1 := div(not(0), 0x101)
            let m2 := div(not(0), 0x10001)
            let m4 := div(not(0), 0x100000001)
            let limb := 0xffffffffffffffff
            for { let pos := row.offset } lt(pos, add(row.offset, row.length)) { pos := add(pos, 24) } {
                let x := calldataload(pos)
                x := or(shl(8, and(x, m1)), and(shr(8, x), m1))
                x := or(shl(16, and(x, m2)), and(shr(16, x), m2))
                x := or(shl(32, and(x, m4)), and(shr(32, x), m4))
                x := or(shr(192, x), or(shl(64, and(shr(128, x), limb)), shl(128, and(shr(64, x), limb))))
                if iszero(lt(x, P)) {
                    mstore(0, bad)
                    revert(28, 4)
                }
                value := addmod(value, mulmod(x, mload(weightPtr), P), P)
                weightPtr := add(weightPtr, 32)
            }
        }
    }

    function univariateWeight(uint256[] memory rs, uint256 z, uint256 start) private pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := 1
            let p := add(rs, 32)
            let end := add(p, shl(5, start))
            for { let q := add(p, shl(5, mload(rs))) } gt(q, end) {} {
                q := sub(q, 32)
                let r := mload(q)
                w := mulmod(w, addmod(sub(add(P, 1), r), mulmod(z, r, P), P), P)
                z := mulmod(z, z, P)
            }
        }
    }

    function verify(
        bytes32 expectedRoot,
        bytes32 context,
        uint256[] calldata point,
        uint256 value,
        bytes calldata proof,
        bytes calldata hints
    ) external pure returns (bool) {
        Profile memory cfg = profile();
        // At height h from the root, at most min(q,2^h) distinct query prefixes occur.
        // Summing unmatched siblings over the fixed stages gives the maximum hint lengths.
        (uint256 proofSize, uint256 maxHints) = wireSizes();
        if (proof.length != proofSize || hints.length > maxHints) {
            revert InvalidOpening();
        }
        if (point.length != (cfg.arity + 1) * readings() - 1 || value >= P || bytes32(proof[:32]) != expectedRoot) {
            revert InvalidOpening();
        }
        for (uint256 i; i < point.length; ++i) {
            if (point[i] >= P) revert InvalidOpening();
        }
        // All point and value words have a fixed width. The domain binds the arity.
        bytes32 instance = keccak256(abi.encodePacked(context, point, value));
        State memory s;
        s.rs = new uint256[](cfg.arity);
        s.sponge.begin(abi.encodePacked(cfg.domain, SESSION, instance, expectedRoot));
        s.pos = 32;
        uint256 o = sample(s, proof, 0);
        s.mix[0] = challenge(s.sponge);
        s.sum = addmod(value, mulmod(o, s.mix[0], P), P);
        for (uint256 i = readings() - 1; i != 0; --i) {
            s.sum = addmod(point[i * (cfg.arity + 1) - 1], mulmod(s.mix[0], s.sum, P), P);
        }
        s.table = powers(cfg.generator);
        s.root = expectedRoot;
        s.cfg = cfg;
        rounds(s, proof, hints);
        uint256 poly = finish(s, proof, hints);
        check(s, poly, point);
        return true;
    }

    function rounds(State memory s, bytes calldata proof, bytes calldata hints) private pure {
        Profile memory cfg = s.cfg;
        for (uint256 stage; stage < cfg.stages; ++stage) {
            fold(s, proof, stage == 0 ? 4 : 5, cfg.foldWork[stage]);
            if (stage + 1 == cfg.stages) break;
            bytes32 next = bytes32(proof[s.pos:s.pos + 32]);
            s.pos += 32;
            s.sponge.begin(abi.encodePacked(next));
            uint256 o = sample(s, proof, stage + 1);
            uint256[] memory ys = openRows(s, proof, hints, stage);
            uint256 mix = challenge(s.sponge);
            s.mix[stage + 1] = mix;
            uint256 coeff = mix;
            s.sum = addmod(s.sum, o, P);
            for (uint256 j; j < ys.length; ++j) {
                s.sum = addmod(s.sum, mulmod(coeff, ys[j], P), P);
                coeff = mulmod(coeff, mix, P);
            }
            s.root = next;
        }
    }

    function finish(State memory s, bytes calldata proof, bytes calldata hints) private pure returns (uint256 poly) {
        Profile memory cfg = s.cfg;
        uint256 bits = cfg.arity - s.cursor;
        uint256 len = 1 << bits;
        uint256[] memory v = new uint256[](len);
        for (uint256 i; i < len; ++i) {
            v[i] = scalar(proof, s.pos + 24 * i);
        }
        s.sponge.begin(proof[s.pos:s.pos + 24 * len]);
        s.pos += 24 * len;
        uint256[] memory ysLast = openRows(s, proof, hints, cfg.stages - 1);
        for (uint256 j; j < ysLast.length; ++j) {
            uint256 val;
            uint256 z = s.points[cfg.stages - 1][j];
            for (uint256 i = len; i != 0; --i) {
                val = addmod(v[i - 1], mulmod(z, val, P), P);
            }
            if (val != ysLast[j]) revert InvalidOpening();
        }
        fold(s, proof, bits, type(uint64).max);
        if (s.pos != proof.length || s.hint != hints.length) revert InvalidOpening();
        uint256[] memory w = weights(s, bits);
        for (uint256 i; i < len; ++i) {
            poly = addmod(poly, mulmod(w[i], v[i], P), P);
        }
    }

    function evalWeight(uint256[] memory rs, uint256[] calldata point, uint256 start) private pure returns (uint256 w) {
        w = 1;
        for (uint256 i; i < rs.length; ++i) {
            uint256 x = point[start + i];
            uint256 r = rs[i];
            w = mulmod(w, addmod(mulmod(x, r, P), mulmod(P + 1 - x, P + 1 - r, P), P), P);
        }
    }

    function check(State memory s, uint256 poly, uint256[] calldata point) private pure {
        Profile memory cfg = s.cfg;
        uint256 weight = evalWeight(s.rs, point, 0);
        uint256 oodMix = s.mix[0];
        for (uint256 i = 1; i < readings(); ++i) {
            weight = addmod(weight, mulmod(oodMix, evalWeight(s.rs, point, i * (cfg.arity + 1)), P), P);
            oodMix = mulmod(oodMix, s.mix[0], P);
        }
        weight = addmod(weight, mulmod(oodMix, univariateWeight(s.rs, s.ood[0], 0), P), P);
        for (uint256 stage = 1; stage < cfg.stages; ++stage) {
            uint256 off = 4 + (stage - 1) * 5;
            weight = addmod(weight, univariateWeight(s.rs, s.ood[stage], off), P);
            uint256 coeff = s.mix[stage];
            uint256[] memory zs = s.points[stage - 1];
            for (uint256 j; j < zs.length; ++j) {
                weight = addmod(weight, mulmod(coeff, univariateWeight(s.rs, zs[j], off), P), P);
                coeff = mulmod(coeff, s.mix[stage], P);
            }
        }
        if (poly == 0 || mulmod(poly, weight, P) != s.sum) revert InvalidOpening();
    }
}

/// Smaller dense control from the same reference parameter generator, with 128 permutation rows.
contract SampleNibbleOpeningVerifier is NibbleOpeningVerifier {
    function wireSizes() internal pure override returns (uint256, uint256) {
        return (1232, 120992);
    }

    function profile() internal pure override returns (Profile memory p) {
        p.arity = 19;
        p.stages = 4;
        p.depth = 20;
        p.generator = 2148618627419982265633988426035087079289652742006912843108;
        p.domain =
            hex"a31c722d42168225da8911f7d4b3a3061d501142eca7c118f3a62f636a0184ffd92f7aadaad85166be2aee630acbf4536d29ab4ef6d1696d6970a5c945ba7243";
        p.foldWork = [type(uint64).max, type(uint64).max, type(uint64).max, 17209756074109366272, uint64(0)];
    }
}

/// One native root verifier's hash states and WHIR row witnesses fit in 26 variables.
contract NativeTraceOpeningVerifier is NibbleOpeningVerifier {
    function wireSizes() internal pure override returns (uint256, uint256) {
        return (1784, 163464);
    }

    function profile() internal pure override returns (Profile memory p) {
        p.arity = 26;
        p.stages = 5;
        p.depth = 27;
        p.generator = 2351975653339948505569424120336667830552196229922017102524;
        p.domain =
            hex"c9184a84a1b501d4955391913fec7fb16996a24db5ba263b99f95967cf0ecfa397a062d616fd710b8d4743c82be0a50d3667421c1bfe3d583b29b0eacf348325";
        p.foldWork = [type(uint64).max, type(uint64).max, 4302439018527341568, 134451219328979424, 4201600604030607];
    }
}

/// WHIR batches two evaluations of the same table with the initial OOD reading.
/// The encoded coordinates are first point, first value, second point; value is the second value.
contract NativeTracePairOpeningVerifier is NativeTraceOpeningVerifier {
    function readings() internal pure override returns (uint256) {
        return 2;
    }
}

/// The 507 sponge permutations and their 169 native WHIR input rows share this table.
contract NativeRowSpongeOpeningVerifier is NibbleOpeningVerifier {
    function wireSizes() internal pure override returns (uint256, uint256) {
        return (1544, 132224);
    }

    function profile() internal pure override returns (Profile memory p) {
        p.arity = 22;
        p.stages = 4;
        p.depth = 23;
        p.generator = 26028205923938672702094318334587855038000762491652405797;
        p.domain =
            hex"0b58c09dae8ae526319b4b35e73271a06dcffd25dcfdc2d84913257573f262e7485bf2d164c6ec786cc7d2a045e5eae03ba82f2d9df0401ec897f1879288a675";
        p.foldWork = [type(uint64).max, type(uint64).max, type(uint64).max, 2151219509263670784, uint64(0)];
    }
}

contract NativeRowTripleOpeningVerifier is NativeRowSpongeOpeningVerifier {
    function readings() internal pure override returns (uint256) {
        return 3;
    }
}
