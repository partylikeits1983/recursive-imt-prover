// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeMidpointPolicy as Policy} from "./NativeMidpointPolicy.sol";

import {NativeKeccak as K} from "./NativeKeccak.sol";
import {NativeField as F} from "./NativeField.sol";
import {NativeMerkle} from "./NativeMerkle.sol";
import {NativeFold} from "./NativeFold.sol";
import {NativeWhirInitial as Initial} from "./NativeWhirInitial.sol";

/// Subsequent rounds of the shared 26-variable additive WHIR opening.
/// The enclosing verifier retains the challenges for the final weight equation.
library NativeWhirRounds {
    error WrongShape();
    error WrongFinalEvaluation();

    struct State {
        K.Stream stream;
        bytes32 cap;
        uint192 sum;
        uint192[2] answers;
        uint192[] values;
    }

    struct Witness {
        bytes wire;
        bytes rows;
        bytes32[] siblings;
    }

    struct Challenges {
        uint192 alpha;
        uint192[] point;
        uint192[2] oods;
        uint256[71] indices;
    }

    // Generated from the pinned native SumcheckShape and Poly64 Cantor basis.
    bytes internal constant DOMAIN_PREFIX =
        hex"6a000000000000000170332d73756d636865636b2d717561647261746963000000000000000000000000000000000000000000000000000000000000000000000000000000000015";
    bytes internal constant DOMAIN_IDS =
        hex"67d17e7c21878aabfbb127dd3f5d4a138a41afceff007273b5a2ecf10d0a0fc9827451dc62723243e0f7de319479196542fb7360f86f3fc8f24c5e45081b60055201afccae485b9c2ad77aeba97b3a4677d51443ce531d217546d946615f504da340c191312011736b2970612ff4c8b054b293a237d9b7ee319dac3733ac65f822ca505e164b361610b3f4a4a2bc952567523060acb25c24b473c15af495c9599bfa85350d2308fb2b38ff3ffde7e76da281be85ade9e5cd42fc63f081142158";
    bytes internal constant DOMAIN_SUFFIX = hex"00000005000000010080000000000000";
    bytes internal constant CANTOR =
        hex"000000000000000119c9369f278adc03b848d14948d52b97e5f0921e86ad769e454a70e754ee7a57af1869279f21569f501d2518e3ce5a54189be8f8f84c1b8412f4ab0a52ba096907732d7d6990c81706ec364d0a087b2c0671f0101819757d1e3cc5732db6a35fa30ac69959393f9a5f1d9ba5c49d877fa221e6bddc52370b5a8a2150f1199d10a646c4ced5ebfb52ed78145bce5f13b5535abdf47e23045b1f495b2fc7c16f0cbae647e26214676fe289803ea3111327f438b5b841a8e6a24133c799343d2e770128bc1f80582770";

    function start(Initial.Fold memory first, Initial.Query memory q, uint192[71] memory values)
        internal
        pure
        returns (State memory s)
    {
        s.stream = q.stream;
        s.cap = q.nextCap;
        s.sum = first.sum;
        s.answers = q.answers;
        s.values = new uint192[](Policy.FIRST_COUNT);
        for (uint256 i; i < Policy.FIRST_COUNT; ++i) {
            s.values[i] = values[i];
        }
    }

    function fold(State memory s, uint256 stage, bytes calldata wire, bool four)
        private
        pure
        returns (uint192[] memory point)
    {
        uint256 last = four ? 4 : 5;
        bool closing = stage == last;
        uint256 rounds = closing ? last : (four ? 4 : 3);
        uint256 bits = closing ? 0 : (four ? uint8(Policy.ROUND_FOLD_BITS[stage]) : 12 + stage);
        uint256 width = bits == 0 ? 48 : 56;
        if (stage > last || wire.length != rounds * width) revert WrongShape();
        bytes memory ids = four ? Policy.FOLD_IDS : DOMAIN_IDS;
        bytes32 id;
        assembly ("memory-safe") { id := mload(add(add(ids, 32), shl(5, stage))) }
        point = new uint192[](rounds);
        for (uint256 i; i < rounds; ++i) {
            bytes calldata msgBytes = wire[i * width:(i + 1) * width];
            s.stream.blockHash = i == 0
                ? keccak256(abi.encodePacked(s.stream.blockHash, DOMAIN_PREFIX, id, DOMAIN_SUFFIX, msgBytes))
                : keccak256(abi.encodePacked(s.stream.blockHash, msgBytes));
            s.stream.consumedWords = 0;
            if (bits != 0 && K.sample64(s.stream) & ((uint256(1) << bits) - 1) != 0) {
                revert Initial.InvalidProofOfWork();
            }
            uint192 r = K.sample192(s.stream);
            point[i] = r;
            s.sum = F.sumcheckRound(s.sum, K.read192(msgBytes, 0), K.read192(msgBytes, 24), r);
        }
    }

    function absorb(K.Stream memory stream, bytes calldata data) private pure {
        stream.blockHash = keccak256(abi.encodePacked(stream.blockHash, data));
        stream.consumedWords = 0;
    }

    function queryCount(uint256 stage, bool four) internal pure returns (uint256) {
        if (four) {
            if (stage >= 4) revert WrongShape();
            return uint8(Policy.ROUND_COUNTS[stage]);
        }
        if (stage > 4) revert WrongShape();
        return uint8(bytes5(hex"1f1a161311")[stage]);
    }

    function draw(K.Stream memory stream, uint256 depth, uint256 count)
        private
        pure
        returns (uint256[71] memory indices)
    {
        uint256 cursor;
        for (uint256 bins = 32; bins != 0; bins >>= 1) {
            if (count & bins == 0) continue;
            uint256 width = (1 << depth) / bins;
            for (uint256 j; j < bins; ++j) {
                indices[cursor++] = j * width + (K.sample64(stream) & (width - 1));
            }
        }
    }

    /// Open eight extension coefficients per sorted distinct row against the
    /// previous transcript commitment. Restore the original query order.
    function authenticatedRows(bytes32 cap, uint256 depth, uint256 count, Challenges memory c, Witness calldata w)
        private
        pure
        returns (uint192[] memory values)
    {
        values = new uint192[](count);
        uint256 scratch;
        assembly ("memory-safe") { scratch := mload(0x40) }
        (uint256[] memory ids, uint256[71] memory ranks) = NativeFold.queryOrder(c.indices, count);
        uint256 width = 1 << c.point.length;
        NativeMerkle.verify(cap, depth, 24 * width, ids, w.rows, w.siblings);
        uint192[] memory reduced = new uint192[](ids.length);
        uint192[][4] memory multipliers;
        for (uint256 d; d < c.point.length; ++d) {
            multipliers[d] = F.multiplierTable(c.point[d]);
        }
        uint192[16] memory row;
        for (uint256 i; i < ids.length; ++i) {
            for (uint256 j; j < width; ++j) {
                row[j] = K.read192(w.rows, 24 * (i * width + j));
            }
            for (uint256 d; d < c.point.length; ++d) {
                for (uint256 j; j < width >> (1 + d); ++j) {
                    uint192 a = row[2 * j];
                    row[j] = a ^ F.multiplyFixed(multipliers[d], a ^ row[2 * j + 1]);
                }
            }
            reduced[i] = row[0];
        }
        for (uint256 i; i < count; ++i) {
            values[i] = reduced[ranks[i]];
        }
        // Only the output array survives. Restore clean scratch memory so the
        // next query batch can reuse the same address range without expanding it.
        assembly ("memory-safe") {
            calldatacopy(scratch, calldatasize(), sub(mload(0x40), scratch))
            mstore(0x40, scratch)
        }
    }

    function commitNext(State memory s, Challenges memory c, bytes calldata message, bool last) private pure {
        if (last) {
            absorb(s.stream, message);
        } else {
            s.cap = bytes32(message[:32]);
            absorb(s.stream, message[:32]);
            for (uint256 i; i < Policy.INITIAL_OODS; ++i) {
                uint256 at = 32 + 24 * i;
                c.oods[i] = K.sample192(s.stream);
                s.answers[i] = K.read192(message, at);
                absorb(s.stream, message[at:i + 1 == Policy.INITIAL_OODS ? message.length : at + 24]);
            }
        }
    }

    function foldBytes(uint256 stage, bool four) internal pure returns (uint256) {
        return four ? 4 * (Policy.ROUND_FOLD_BITS[stage] == 0 ? uint256(48) : 56) : 168;
    }

    function challenges(State memory s, uint256 stage, Witness calldata w, bool four)
        internal
        pure
        returns (Challenges memory c)
    {
        uint256 count = queryCount(stage, four);
        if (s.values.length != (stage == 0 ? Policy.FIRST_COUNT : queryCount(stage - 1, four))) revert WrongShape();
        uint256 message = foldBytes(stage, four);
        bool last = stage == (four ? 3 : 4);
        uint256 payload = last ? (four ? 384 : 768) : (32 + 24 * Policy.INITIAL_OODS);
        if (w.wire.length != message + payload + 8) revert WrongShape();
        // The carried sum occupies power zero. OOD evaluations occupy powers
        // one and two, followed by all prior row evaluations in draw order.
        c.alpha = K.sample192(s.stream);
        uint192 combined;
        for (uint256 i = s.values.length; i > 0; --i) {
            combined = s.values[i - 1] ^ F.mul(c.alpha, combined);
        }
        for (uint256 i = Policy.INITIAL_OODS; i > 0; --i) {
            combined = s.answers[i - 1] ^ F.mul(c.alpha, combined);
        }
        s.sum ^= F.mul(c.alpha, combined);
        c.point = fold(s, stage, w.wire[:message], four);
        commitNext(s, c, w.wire[message:], last);
        uint256 bits = four ? uint8(Policy.ROUND_QUERY_BITS[stage]) : uint8(bytes5(hex"0f0b0b0b09")[stage]);
        if (K.sample64(s.stream) & ((uint256(1) << bits) - 1) != 0) revert Initial.InvalidProofOfWork();
        uint256 depth = (four ? 24 : 26) - stage;
        c.indices = draw(s.stream, depth, count);
    }

    function step(State memory s, uint256 stage, Witness calldata w, bool four)
        internal
        pure
        returns (Challenges memory c)
    {
        bytes32 previous = s.cap;
        c = challenges(s, stage, w, four);
        s.values = authenticatedRows(previous, (four ? 24 : 26) - stage, queryCount(stage, four), c, w);
        if (stage == (four ? 3 : 4)) {
            checkFinalRows(w.wire[foldBytes(stage, four):w.wire.length - 8], c.indices, s.values);
        }
    }

    function domainPoint(uint256 index) internal pure returns (uint64 value) {
        if (index >= 1 << 26) revert WrongShape();
        bytes memory basis = CANTOR;
        for (uint256 i; index != 0; ++i) {
            if (index & 1 != 0) {
                uint64 vector;
                assembly ("memory-safe") { vector := shr(192, mload(add(add(basis, 32), shl(3, i)))) }
                value ^= vector;
            }
            index >>= 1;
        }
    }

    function checkFinalRows(bytes calldata poly, uint256[71] memory indices, uint192[] memory values) internal pure {
        uint256 width = poly.length / 24;
        uint192[32] memory polys;
        for (uint256 i; i < values.length; ++i) {
            // The additive encoding evaluates the final entries as novel-basis
            // coefficients. Each fold is even + W_d(x) * odd.
            uint64 x = domainPoint(indices[i]);
            for (uint256 j; j < width; ++j) {
                polys[j] = K.read192(poly, 24 * j);
            }
            for (uint256 n = width / 2; n != 0; n >>= 1) {
                for (uint256 j; j < n; ++j) {
                    uint192 a = polys[2 * j];
                    polys[j] = a ^ F.scale(polys[2 * j + 1], x);
                }
                x ^= uint64(F.square(x));
            }
            if (values[i] != polys[0]) revert WrongFinalEvaluation();
        }
    }

    function finalFold(State memory s, bytes calldata wire, bool four) internal pure returns (uint192[] memory) {
        return fold(s, four ? 4 : 5, wire, four);
    }
}
