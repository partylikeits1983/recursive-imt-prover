// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {PrimeWhirReduction} from "./PrimeWhirOpeningVerifier.sol";
import {WHIR_PRIME as P} from "./WhirTranscript.sol";
import {KeccakSegmentRow} from "./KeccakSegmentRow.sol";

/// Stores the canonical checkpoints of the all-zero Keccak input as immutable
/// code. The first word is zero, so executing the data contract stops immediately.
contract TerminalSegmentPadding {
    constructor() {
        uint256[64] memory words = KeccakSegmentRow.row(new bytes(200));
        assembly ("memory-safe") { return(words, 2048) }
    }
}

/// Checks the public rows and authenticates both batched segment endpoint readings.
/// A transition argument must use these readings when checking the private active rows.
abstract contract TerminalSegmentTable is PrimeWhirReduction {
    bytes32 private constant KEY = 0x494900e0fa468212ed93087501b2ca91a608331d9a12070b6cc05133943e7405;
    uint256 private constant FINAL_ROW = 21670;
    error WrongParent();
    address private immutable paddingTable = address(new TerminalSegmentPadding());

    struct SegmentQueries {
        uint256[22] known;
        uint256[22] inputs;
        uint256[22] outputs;
        uint256 mix;
    }

    function checkTable(
        bytes32 parent,
        bytes32 left,
        bytes32 right,
        bytes32 root,
        uint256[2] calldata readings,
        bytes calldata proof,
        bytes calldata hints
    ) internal view returns (uint256[22] memory outputPoint, bytes32 context, uint256 value) {
        bytes memory message = abi.encodePacked("IMT-AGG-NODE-V2", left, uint8(32), right, uint8(32));
        if (keccak256(message) != parent) revert WrongParent();
        if (readings[0] >= P || readings[1] >= P) revert InvalidStatement();
        context = keccak256(
            abi.encodePacked("recursive-imt/three-round-checkpoints/v1", KEY, parent, left, right, uint8(64))
        );
        bytes32 seed = keccak256(abi.encode(context, root));
        SegmentQueries memory q;
        for (uint8 i; i < 22; ++i) {
            q.known[i] = challenge(seed, 0, i);
            q.inputs[i] = challenge(seed, 1, i);
            q.outputs[i] = challenge(seed, 2, i);
        }
        q.mix = challenge(keccak256(abi.encode(seed, readings)), 3, 0);
        value = addmod(
            knownValue(q.known, message), mulmod(q.mix, addmod(readings[0], mulmod(q.mix, readings[1], P), P), P), P
        );
        bytes32 instance = keccak256(abi.encode(context, root, readings, value));
        (State memory s, uint256 poly) = reduce(root, instance, value, proof, hints);
        checkClosing(s, poly, weight(q, s.challenges));
        return (q.outputs, context, value);
    }

    function challenge(bytes32 seed, uint8 family, uint8 index) internal pure returns (uint256) {
        // Reuse the same preimage for both halves of the wide field challenge.
        uint256 hi;
        uint256 lo;
        assembly ("memory-safe") {
            let buf := mload(0x40)
            mstore(buf, "recursive-imt/segment-challenge/")
            mstore(add(buf, 32), "v1")
            mstore(add(buf, 34), seed)
            mstore8(add(buf, 66), family)
            mstore8(add(buf, 67), index)
            mstore8(add(buf, 68), 0)
            hi := keccak256(buf, 69)
            mstore8(add(buf, 68), 1)
            lo := keccak256(buf, 69)
        }
        return addmod(mulmod(hi, addmod(type(uint256).max, 1, P), P), lo, P);
    }

    // MSB is the child role. The two copies of the fixed circuit have identical row ranges.
    function rowMass(uint256[22] memory x, uint256[22] memory r, bool closing)
        private
        pure
        returns (uint256 equal, uint256 above)
    {
        equal = 1;
        for (uint256 i = 1; i < 16; ++i) {
            uint256 one = x[i];
            uint256 zero = P + 1 - one;
            if (closing) {
                one = mulmod(one, r[i], P);
                zero = mulmod(zero, P + 1 - r[i], P);
            }
            above = mulmod(above, addmod(one, zero, P), P);
            if (((FINAL_ROW >> (15 - i)) & 1) == 0) {
                above = addmod(above, mulmod(equal, one, P), P);
                equal = mulmod(equal, zero, P);
            } else {
                equal = mulmod(equal, one, P);
            }
        }
    }

    function knownValue(uint256[22] memory x, bytes memory message) private view returns (uint256) {
        (uint256 node, uint256 padding) = rowMass(x, x, false);
        bytes memory blockData = abi.encodePacked(message, hex"01", new bytes(53), hex"80", new bytes(64));
        uint256[64] memory actual = KeccakSegmentRow.row(blockData);
        uint256[64] memory dummy;
        address stored = paddingTable;
        assembly ("memory-safe") { extcodecopy(stored, dummy, 0, 2048) }
        for (uint256 i; i < 64; ++i) {
            actual[i] = addmod(mulmod(node, actual[i], P), mulmod(padding, dummy[i], P), P);
        }
        for (uint256 bit; bit < 6; ++bit) {
            for (uint256 i; i < (32 >> bit); ++i) {
                uint256 a = actual[2 * i];
                actual[i] = addmod(a, mulmod(x[21 - bit], addmod(actual[2 * i + 1], P - a, P), P), P);
            }
        }
        return actual[0];
    }

    function eqProduct(uint256[22] memory a, uint256[22] memory b, uint256 start, uint256 end)
        private
        pure
        returns (uint256 v)
    {
        v = 1;
        for (uint256 i = start; i < end; ++i) {
            v = mulmod(v, addmod(mulmod(a[i], b[i], P), mulmod(P + 1 - a[i], P + 1 - b[i], P), P), P);
        }
    }

    function eq3(uint256[22] memory p, uint256 offset) internal pure returns (uint256[8] memory eq) {
        eq[0] = 1;
        for (uint256 bit; bit < 3; ++bit) {
            uint256 stride = 1 << bit;
            for (uint256 i; i < stride; ++i) {
                uint256 high = mulmod(eq[i], p[offset + 2 - bit], P);
                eq[i + stride] = high;
                eq[i] = addmod(eq[i], P - high, P);
            }
        }
    }

    function inputWeight(uint256[22] memory a, uint256[22] memory r) private pure returns (uint256) {
        uint256[8] memory ac = eq3(a, 19);
        uint256[8] memory rc = eq3(r, 19);
        uint256 chunks = addmod(eqProduct(a, r, 19, 22), P - mulmod(ac[7], rc[7], P), P);
        return mulmod(eqProduct(a, r, 0, 19), chunks, P);
    }

    function outputWeight(uint256[22] memory b, uint256[22] memory r) private pure returns (uint256) {
        uint256[8] memory seg = eq3(b, 16);
        uint256[8] memory chunk = eq3(b, 19);
        uint256[8] memory readSeg = eq3(r, 16);
        uint256[8] memory readChunk = eq3(r, 19);
        uint256 shift;
        uint256 chunks;
        uint256 tail;
        for (uint256 i; i < 7; ++i) {
            shift = addmod(shift, mulmod(seg[i], readSeg[i + 1], P), P);
            chunks = addmod(chunks, mulmod(chunk[i], readChunk[i], P), P);
            tail = addmod(tail, mulmod(chunk[i], readSeg[i], P), P);
        }
        uint256 col = addmod(mulmod(shift, chunks, P), mulmod(mulmod(seg[7], readChunk[7], P), tail, P), P);
        return mulmod(eqProduct(b, r, 0, 16), col, P);
    }

    function weight(SegmentQueries memory q, uint256[22] memory r) private pure returns (uint256) {
        (uint256 node, uint256 padding) = rowMass(q.known, r, true);
        uint256 known =
            mulmod(addmod(node, padding, P), mulmod(eqProduct(q.known, r, 0, 1), eqProduct(q.known, r, 16, 22), P), P);
        return addmod(
            known,
            mulmod(q.mix, addmod(inputWeight(q.inputs, r), mulmod(q.mix, outputWeight(q.outputs, r), P), P), P),
            P
        );
    }
}

contract TerminalSegmentVerifier is TerminalSegmentTable {
    function verifySegments(
        bytes32 parent,
        bytes32 left,
        bytes32 right,
        bytes32 root,
        uint256[2] calldata readings,
        bytes calldata proof,
        bytes calldata hints
    ) external view returns (bool) {
        checkTable(parent, left, right, root, readings, proof, hints);
        return true;
    }
}
