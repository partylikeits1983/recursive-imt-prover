// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {WHIR_PRIME as P, WhirField, WhirTranscript} from "./WhirTranscript.sol";
import {WhirMerkle} from "./WhirMerkle.sol";

/// Fixed 22-variable WHIR opening for an application-defined public linear form.
abstract contract PrimeWhirReduction {
    using WhirTranscript for WhirTranscript.State;

    bytes internal constant DOMAIN =
        hex"a82b71a231a3d0b811471637fd3b11e7ff101a8a3924a57f38b546705af58e6c33352a46f0c416a99b475638479a42235f4ccb4731ec694737c56f5b238daf34fc8c823d960630bb11967f14bd08db1a57abb3fb0bee14ec3c291d2d9e2f8a42";

    error InvalidStatement();
    error InvalidProof();
    error InvalidWork(uint256 round);
    error InvalidFinalRow();
    error InvalidFinalSum();

    struct Queries {
        uint256[] points;
        uint256[] values;
    }

    struct Schedule {
        bytes domain;
        uint256 generator;
        uint256 depth;
        uint256 maxHints;
        uint8[7] queries;
        uint64[7] thresholds;
    }

    /// Fixed by the deployed verifier. The prover cannot select a schedule.
    function schedule() internal pure virtual returns (Schedule memory cfg) {
        cfg.domain = DOMAIN;
        cfg.generator = 934650972362265999028062457054462628285482693704334323590406443310927365533;
        cfg.depth = 23;
        cfg.maxHints = 162_840;
        cfg.queries = [62, 41, 31, 25, 21, 18, 16];
        cfg.thresholds = [
            uint64(437374267203256),
            609254173216299,
            1984821698187546,
            5319701810318028,
            12932261597155760,
            14970709331407514,
            66020828151507144
        ];
    }

    struct State {
        WhirTranscript.State sponge;
        Schedule cfg;
        uint256 pos;
        uint256 hint;
        uint256 sum;
        uint256[22] challenges;
        uint256[7] ood;
        uint256[7] mix;
        Queries[7] queries;
    }

    /// Run WHIR through its final sumcheck. The caller supplies the independently derived
    /// public linear-form weight at the returned challenges to checkClosing.
    function reduce(bytes32 expectedRoot, bytes32 instance, uint256 value, bytes calldata proof, bytes calldata hints)
        internal
        pure
        returns (State memory s, uint256 poly)
    {
        if (proof.length != 1976 || bytes32(proof[:32]) != expectedRoot || value >= P) revert InvalidStatement();
        s.cfg = schedule();
        if (hints.length > s.cfg.maxHints) revert InvalidProof();
        s.sponge.begin(abi.encodePacked(s.cfg.domain, instance, expectedRoot));
        s.pos = 32;
        uint256 oodValue = sampleOod(s, proof, 0);
        s.mix[0] = s.sponge.field();
        s.sum = addmod(value, mulmod(s.mix[0], oodValue, P), P);
        bytes32 root = expectedRoot;
        uint256[96] memory powers = domainPowers(s.cfg.generator);
        for (uint256 round; round < 7; ++round) {
            sumcheck(s, proof, 3 * round, 3);
            if (round == 6) break;
            bytes32 next = bytes32(proof[s.pos:s.pos + 32]);
            s.pos += 32;
            s.sponge.begin(abi.encodePacked(next));
            oodValue = sampleOod(s, proof, round + 1);
            s.queries[round] = openRows(s, proof, hints, root, round, powers);
            uint256 mix = s.sponge.field();
            s.mix[round + 1] = mix;
            uint256 weight = mix;
            s.sum = addmod(s.sum, oodValue, P);
            for (uint256 i; i < s.queries[round].values.length; ++i) {
                s.sum = addmod(s.sum, mulmod(weight, s.queries[round].values[i], P), P);
                weight = mulmod(weight, mix, P);
            }
            root = next;
        }

        uint256 a = WhirField.read(proof, s.pos);
        uint256 b = WhirField.read(proof, s.pos + 32);
        s.sponge.begin(proof[s.pos:s.pos + 64]);
        s.pos += 64;
        Queries memory last = openRows(s, proof, hints, root, 6, powers);
        for (uint256 i; i < last.points.length; ++i) {
            if (last.values[i] != addmod(a, mulmod(last.points[i], b, P), P)) revert InvalidFinalRow();
        }
        sumcheck(s, proof, 21, 1);
        poly = addmod(a, mulmod(s.challenges[21], addmod(b, P - a, P), P), P);
        if (poly == 0) revert InvalidFinalSum();
        if (s.pos != proof.length || s.hint != hints.length) revert InvalidProof();
    }

    function sampleOod(State memory s, bytes calldata proof, uint256 stage) private pure returns (uint256 value) {
        s.ood[stage] = s.sponge.field();
        value = WhirField.read(proof, s.pos);
        s.sponge.begin(proof[s.pos:s.pos + 32]);
        s.pos += 32;
    }

    function sumcheck(State memory s, bytes calldata proof, uint256 start, uint256 rounds) private pure {
        for (uint256 i; i < rounds; ++i) {
            uint256 c0 = WhirField.read(proof, s.pos);
            uint256 c2 = WhirField.read(proof, s.pos + 32);
            s.sponge.begin(proof[s.pos:s.pos + 64]);
            s.pos += 64;
            uint256 r = s.sponge.field();
            s.challenges[start + i] = r;
            uint256 c1 = addmod(s.sum, P - addmod(addmod(c0, c0, P), c2, P), P);
            s.sum = addmod(c0, mulmod(r, addmod(c1, mulmod(c2, r, P), P), P), P);
        }
    }

    function work(State memory s, bytes calldata proof, uint256 round) private pure {
        bytes memory challenge = s.sponge.draw(32);
        bytes calldata nonce = proof[s.pos:s.pos + 8];
        bytes32 digest = keccak256(abi.encodePacked(challenge, nonce, bytes24(0)));
        if (uint64(WhirField.reverse(uint256(digest))) > s.cfg.thresholds[round]) revert InvalidWork(round);
        s.sponge.begin(nonce);
        s.pos += 8;
    }

    function openRows(
        State memory s,
        bytes calldata proof,
        bytes calldata hints,
        bytes32 root,
        uint256 round,
        uint256[96] memory powers
    ) private pure returns (Queries memory opened) {
        work(s, proof, round);
        uint256 n = s.cfg.queries[round];
        uint256 depth = s.cfg.depth - round;
        uint256 mask = (1 << depth) - 1;
        bytes memory random = s.sponge.draw(n * 3);
        uint256[] memory indices = new uint256[](n);
        opened.points = new uint256[](n);
        opened.values = new uint256[](n);
        bytes32[] memory hashes = new bytes32[](n);
        uint256[8] memory weights = rowWeights(s, round);
        if (WhirField.reverse(uint256(bytes32(bytes8(hints[s.hint:s.hint + 8])))) != n * 8) revert InvalidProof();
        s.hint += 8;
        // The reference stores cosets consecutively, with evaluations ordered inside each coset.
        uint256 logCoset = 19 - 3 * round;
        for (uint256 i; i < n; ++i) {
            uint256 j = 3 * i;
            uint256 idx =
                ((uint256(uint8(random[j])) << 16) | (uint256(uint8(random[j + 1])) << 8) | uint8(random[j + 2])) & mask;
            indices[i] = idx;
            uint256 exponent = ((idx >> logCoset) | ((idx << (depth - logCoset)) & mask)) << round;
            uint256 z = 1;
            assembly ("memory-safe") {
                for { let addr := powers } exponent { addr := add(addr, 512) } {
                    z := mulmod(z, mload(add(addr, shl(5, and(exponent, 15)))), P)
                    exponent := shr(4, exponent)
                }
            }
            opened.points[i] = z;
            (hashes[i], opened.values[i]) = foldRow(hints[s.hint:s.hint + 256], weights);
            s.hint += 256;
        }
        s.hint = WhirMerkle.verify(root, indices, hashes, depth, hints, s.hint);
    }

    /// One authenticated row has exactly eight canonical little-endian scalars.
    /// Keep a single 256-byte scratch region for hashing and avoid constructing eight slices.
    function foldRow(bytes calldata row, uint256[8] memory weights) private pure returns (bytes32 digest, uint256 y) {
        assembly ("memory-safe") {
            let scratch := mload(64)
            calldatacopy(scratch, row.offset, 256)
            digest := keccak256(scratch, 256)
        }
        for (uint256 i; i < 8; ++i) {
            uint256 raw;
            assembly ("memory-safe") {
                raw := calldataload(add(row.offset, shl(5, i)))
            }
            uint256 x = WhirField.reverse(raw);
            if (x >= P) revert WhirField.NonCanonicalField();
            y = addmod(y, mulmod(weights[i], x, P), P);
        }
    }

    /// All seven query domains are subgroups of the first one. Window k stores
    /// g^(d * 16^k) for every digit d of the first-domain exponent (at most 24 bits).
    function domainPowers(uint256 generator) private pure returns (uint256[96] memory powers) {
        assembly ("memory-safe") {
            for { let window := powers } lt(window, add(powers, 3072)) { window := add(window, 512) } {
                let value := 1
                for { let pos := window } lt(pos, add(window, 512)) { pos := add(pos, 32) } {
                    mstore(pos, value)
                    value := mulmod(value, generator, P)
                }
                generator := value
            }
        }
    }

    function rowWeights(State memory s, uint256 round) private pure returns (uint256[8] memory weights) {
        weights[0] = 1;
        for (uint256 bit; bit < 3; ++bit) {
            uint256 r = s.challenges[3 * round + 2 - bit];
            uint256 stride = 1 << bit;
            for (uint256 i; i < stride; ++i) {
                uint256 one = mulmod(weights[i], r, P);
                weights[i] = addmod(weights[i], P - one, P);
                weights[i + stride] = one;
            }
        }
    }

    function univariateWeight(State memory s, uint256 z, uint256 start) private pure returns (uint256 product) {
        uint256[22] memory challenges = s.challenges;
        assembly ("memory-safe") {
            product := 1
            let end := add(challenges, shl(5, start))
            for { let cursor := add(challenges, 704) } gt(cursor, end) {} {
                cursor := sub(cursor, 32)
                let r := mload(cursor)
                product := mulmod(product, addmod(sub(add(P, 1), r), mulmod(r, z, P), P), P)
                z := mulmod(z, z, P)
            }
        }
    }

    function checkClosing(State memory s, uint256 poly, uint256 weight) internal pure {
        weight = addmod(weight, mulmod(s.mix[0], univariateWeight(s, s.ood[0], 0), P), P);
        for (uint256 stage = 1; stage < 7; ++stage) {
            uint256 cursor = 3 * stage;
            weight = addmod(weight, univariateWeight(s, s.ood[stage], cursor), P);
            uint256 coeff = s.mix[stage];
            uint256[] memory points = s.queries[stage - 1].points;
            for (uint256 i; i < points.length; ++i) {
                weight = addmod(weight, mulmod(coeff, univariateWeight(s, points[i], cursor), P), P);
                coeff = mulmod(coeff, s.mix[stage], P);
            }
        }
        if (mulmod(poly, weight, P) != s.sum) revert InvalidFinalSum();
    }
}

contract PrimeWhirOpeningVerifier is PrimeWhirReduction {
    function verify(
        bytes32 expectedRoot,
        bytes32 context,
        uint256[22] calldata point,
        uint256 value,
        bytes calldata proof,
        bytes calldata hints
    ) external pure returns (bool) {
        for (uint256 i; i < 22; ++i) {
            if (point[i] >= P) revert InvalidStatement();
        }
        bytes32 instance = keccak256(abi.encode(context, point, value));
        (State memory s, uint256 poly) = reduce(expectedRoot, instance, value, proof, hints);
        uint256 weight = 1;
        for (uint256 i; i < 22; ++i) {
            uint256 r = s.challenges[i];
            uint256 x = point[i];
            weight = mulmod(weight, addmod(mulmod(P + 1 - x, P + 1 - r, P), mulmod(x, r, P), P), P);
        }
        checkClosing(s, poly, weight);
        return true;
    }
}
