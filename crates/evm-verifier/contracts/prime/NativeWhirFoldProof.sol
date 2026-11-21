// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NibbleSumcheck} from "./NibbleSumcheck.sol";
import {NibbleOpeningVerifier} from "./NibbleOpeningVerifier.sol";
import {NativeFold} from "../imt/NativeFold.sol";
import {NativeKeccak} from "../imt/NativeKeccak.sol";

/// Checks every row fold in the four-variable native WHIR opening, in query order.
/// The enclosing native verifier supplies the authenticated rows and transcript draws.
contract NativeWhirFoldProof is NibbleSumcheck {
    error WrongFoldGeometry();
    constructor(NibbleOpeningVerifier pcs) NibbleSumcheck(pcs) {}

    struct Mix {
        uint256 t;
        uint256[3] eta;
        uint256 a;
        uint256 b;
        uint256 ports;
        uint256 range;
        uint256[] rows;
        uint256[] rangeRows;
        uint256[] rangeCols;
    }

    function mix(bytes32 seed) private pure returns (Mix memory m) {
        m.t = coin(seed, 0, 0);
        for (uint8 i; i < 3; ++i) {
            m.eta[i] = coin(seed, 1, i);
        }
        m.a = coin(seed, 2, 0);
        m.b = coin(seed, 2, 1);
        m.ports = coin(seed, 2, 2);
        m.range = coin(seed, 2, 3);
        m.rows = coins(seed, 3, 8);
        m.rangeRows = coins(seed, 4, 8);
        m.rangeCols = coins(seed, 5, 11);
    }

    function usesDigests() internal pure virtual returns (bool) {
        return false;
    }

    function fingerprint(bytes calldata rows, bytes calldata values, Mix memory m)
        private
        pure
        returns (uint256 result)
    {
        bool raw = !usesDigests();
        uint256 a = m.a;
        uint256 b = m.b;
        assembly ("memory-safe") {
            // Reverse bytes within four independent 64-bit words from one calldata load.
            function words(p) -> x {
                x := calldataload(p)
                let mask := div(not(0), 0x101)
                x := or(shl(8, and(x, mask)), and(shr(8, x), mask))
                mask := div(not(0), 0x10001)
                x := or(shl(16, and(x, mask)), and(shr(16, x), mask))
                mask := div(not(0), 0x100000001)
                x := or(shl(32, and(x, mask)), and(shr(32, x), mask))
            }
            function tail(v, w, base) -> y { y := addmod(and(w, 0xffffffffffffffff), mulmod(base, v, P), P) }
            let row := add(rows.offset, rows.length)
            let v := add(values.offset, values.length)
            for {} gt(v, values.offset) {} {
                v := sub(v, 24)
                let w := shr(64, words(v))
                let partial := tail(tail(and(w, 0xffffffffffffffff), shr(64, w), b), shr(128, w), b)
                for { let end := sub(row, mul(raw, 384)) } gt(row, end) {} {
                    row := sub(row, 32)
                    w := words(row)
                    partial := tail(tail(tail(tail(partial, w, b), shr(64, w), b), shr(128, w), b), shr(192, w), b)
                }
                result := addmod(partial, mulmod(a, result, P), P)
            }
        }
    }

    // MLE of x^i at a Boolean index i with the least-significant bit last.
    function geometric(uint256[] memory u, uint256 start, uint256 bits, uint256 x) private pure returns (uint256 acc) {
        acc = 1;
        while (bits != 0) {
            uint256 r = u[start + --bits];
            acc = mulmod(acc, addmod(P + 1 - r, mulmod(r, x, P), P), P);
            x = mulmod(x, x, P);
        }
    }

    function modulusAt(uint256 t) private pure returns (uint256 value) {
        uint256 t2 = mulmod(t, t, P);
        uint256 t4 = mulmod(t2, t2, P);
        uint256 t64 = t4;
        for (uint256 i; i < 4; ++i) {
            t64 = mulmod(t64, t64, P);
        }
        return addmod(addmod(addmod(1, t, P), mulmod(t, t2, P), P), addmod(t4, t64, P), P);
    }

    function sumPowers(uint256 t) private pure returns (uint256 z) {
        z = 1;
        for (uint256 i; i < 7; ++i) {
            z = mulmod(z, addmod(t, 1, P), P);
            t = mulmod(t, t, P);
        }
    }

    // The same eight monomials are shared by every native weight of every row.
    function byteTable(uint256 t) private pure returns (uint256[256] memory table, uint256 t8) {
        t8 = 1;
        for (uint256 n = 1; n < 256; n *= 2) {
            for (uint256 j; j < n; ++j) {
                table[n + j] = addmod(table[j], t8, P);
            }
            t8 = mulmod(t8, t, P);
        }
    }

    function polynomial(uint256 w, uint256[256] memory table, uint256 t8) private pure returns (uint256 value) {
        assembly ("memory-safe") {
            for { let bit := 64 } bit {} {
                bit := sub(bit, 8)
                value := addmod(mload(add(table, shl(5, and(255, shr(bit, w))))), mulmod(value, t8, P), P)
            }
        }
    }

    function dot3(uint256 a, uint256 b, uint256 c, uint256[3] memory e) private pure returns (uint256) {
        return addmod(addmod(mulmod(a, e[0], P), mulmod(b, e[1], P), P), mulmod(c, e[2], P), P);
    }

    function inputWeight(Mix memory m, uint256[] memory x, uint256[] memory wordEq, bytes calldata draws)
        private
        pure
        returns (uint256 total)
    {
        uint256[] memory rowEq = weights(m.rows, 0, 8);
        uint256[] memory rowX = weights(x, 0, 8);
        (uint256[256] memory table, uint256 t8) = byteTable(m.t);
        uint256[5] memory count = [uint256(71), 35, 26, 20, 17];
        uint256 row;
        uint256 offset;
        for (uint256 s; s < 5; ++s) {
            uint256 dims = s == 0 ? 6 : 4;
            uint192[] memory binaryPoint = new uint192[](dims);
            for (uint256 j; j < dims; ++j) {
                binaryPoint[dims - 1 - j] = NativeKeccak.read192(draws, offset);
                offset += 24;
            }
            uint192[] memory w = NativeFold.weights(binaryPoint);
            uint256 term;
            uint256 width = s == 0 ? 48 : 16;
            for (uint256 j; j < width; ++j) {
                uint256 a = polynomial(w[j], table, t8);
                uint256 b = polynomial(w[j] >> 64, table, t8);
                uint256 c = polynomial(w[j] >> 128, table, t8);
                uint256 slot = 72 + (s == 0 ? j : 3 * j);
                term = addmod(term, mulmod(wordEq[slot], dot3(a, b, c, m.eta), P), P);
                if (s != 0) {
                    term = addmod(term, mulmod(wordEq[slot + 1], dot3(c, addmod(a, c, P), b, m.eta), P), P);
                    term =
                        addmod(term, mulmod(wordEq[slot + 2], dot3(b, addmod(b, c, P), addmod(a, c, P), m.eta), P), P);
                }
            }
            uint256 selector;
            uint256 end = row + count[s];
            for (; row < end; ++row) {
                selector = addmod(selector, mulmod(rowEq[row], rowX[row], P), P);
            }
            total = addmod(total, mulmod(selector, term, P), P);
        }
    }

    function closing(Mix memory m, uint256[] memory x, uint256[3] memory moment, bytes calldata draws)
        private
        pure
        returns (uint256 v)
    {
        uint256[] memory wordEq = weights(x, 8, 7);
        uint256 rowEq = equality(m.rows, 0, x, 0, 8);
        uint256 coeff = inputWeight(m, x, wordEq, draws);
        uint256 modValue = modulusAt(m.t);
        for (uint256 j; j < 3; ++j) {
            uint256 cq = addmod(wordEq[120 + j], mulmod(modValue, wordEq[123 + j], P), P);
            coeff = addmod(coeff, P - mulmod(rowEq, mulmod(m.eta[j], cq, P), P), P);
        }
        uint256[] memory powers = new uint256[](4);
        powers[0] = 1;
        for (uint256 k = 1; k < 4; ++k) {
            powers[k] = mulmod(powers[k - 1], m.t, P);
        }
        (uint256 bits,, uint256 range) = bitPolynomials(moment, powers, new uint256[](4));
        uint256 t4 = mulmod(powers[3], m.t, P);
        v = mulmod(mulmod(coeff, geometric(x, 15, 4, t4), P), bits, P);
        uint256[] memory slab = weights(x, 8, 4);
        uint256 carry;
        for (uint256 j; j < 3; ++j) {
            uint256 limb =
                addmod(slab[j * 3], addmod(mulmod(16, slab[3 * j + 1], P), mulmod(256, slab[3 * j + 2], P), P), P);
            carry = addmod(carry, mulmod(m.eta[j], limb, P), P);
        }
        carry = mulmod(mulmod(carry, 2, P), mulmod(rowEq, geometric(x, 12, 7, m.t), P), P);
        uint256 ports;
        uint256 skip = usesDigests() ? 48 : 0;
        for (uint256 i = 51; i != skip; --i) {
            ports = addmod(wordEq[71 + i], mulmod(m.b, ports, P), P);
        }
        ports = mulmod(ports, mulmod(m.ports, mulmod(geometric(x, 0, 8, m.a), geometric(x, 15, 4, 16), P), P), P);
        v = addmod(v, mulmod(moment[0], addmod(ports, P - carry, P), P), P);
        uint256 rangeWeight =
            mulmod(m.range, mulmod(equality(x, 0, m.rangeRows, 0, 8), equality(x, 8, m.rangeCols, 0, 11), P), P);
        return addmod(v, mulmod(rangeWeight, range, P), P);
    }

    function openingProofBytes() external pure virtual returns (uint256) {
        return 1232;
    }

    function domain() internal pure virtual returns (string memory) {
        return "recursive-imt/native-whir-fold-rows/v1";
    }

    function foldIdentity(
        bytes32 root,
        bytes calldata draws,
        bytes calldata rows,
        bytes calldata values,
        bytes calldata digits
    ) internal pure returns (Claim memory upper, uint256[3] memory moment) {
        if (
            draws.length != 22 * 24 || rows.length != (usesDigests() ? 240 * 32 : 169 * 384)
                || values.length != 169 * 24
        ) {
            revert WrongFoldGeometry();
        }
        bytes32 seed = keccak256(abi.encodePacked(domain(), root, keccak256(draws), keccak256(rows), keccak256(values)));
        Mix memory m = mix(seed);
        uint256 bias = mulmod(6, mulmod(addmod(m.eta[0], addmod(m.eta[1], m.eta[2], P), P), sumPowers(m.t), P), P);
        uint256 sum = addmod(mulmod(m.ports, fingerprint(rows, values, m), P), P - bias, P);
        (upper, moment) = upperClaim(seed, sum, digits, 19);
        if (upper.sum != closing(m, upper.point, moment, draws)) revert InvalidDigits();
    }

    function verifyFolds(
        bytes32 root,
        bytes calldata draws,
        bytes calldata rows,
        bytes calldata values,
        bytes calldata digits,
        bytes calldata proof,
        bytes calldata hints
    ) external view returns (bool) {
        (Claim memory upper, uint256[3] memory moment) = foldIdentity(root, draws, rows, values, digits);
        openMoments(upper, moment, root, digits, proof, hints);
        return true;
    }
}

contract NativeTraceFoldProof is NativeWhirFoldProof {
    constructor(NibbleOpeningVerifier pcs) NativeWhirFoldProof(pcs) {}

    function reduceFolds(
        bytes32 root,
        bytes calldata draws,
        bytes calldata rows,
        bytes calldata values,
        bytes calldata digits
    ) external pure returns (Reading memory) {
        (Claim memory upper, uint256[3] memory moment) = foldIdentity(root, draws, rows, values, digits);
        return reduceMoments(upper, moment, digits);
    }

    function openingProofBytes() external pure virtual override returns (uint256) {
        return 1784;
    }

    function domain() internal pure virtual override returns (string memory) {
        return "recursive-imt/native-whir-fold-hash-trace/v1";
    }

    function openingPoint(uint256[] memory point) internal pure virtual override returns (uint256[] memory z) {
        z = new uint256[](26);
        for (uint256 i; i < 13; ++i) {
            z[i + 1] = point[i];
        }
        // Row MSB zero, segment 4 (100), lanes 28..31 (111xx).
        z[14] = 1;
        z[17] = 1;
        z[18] = 1;
        z[19] = 1;
        for (uint256 i = 13; i < 19; ++i) {
            z[i + 7] = point[i];
        }
    }
}

/// The source words are bound to authenticated row digests by the sponge and Keccak reductions.
contract NativeSpongeFoldReduction is NativeTraceFoldProof {
    constructor(NibbleOpeningVerifier pcs) NativeTraceFoldProof(pcs) {}

    function openingProofBytes() external pure override returns (uint256) {
        return 1544;
    }

    function usesDigests() internal pure override returns (bool) {
        return true;
    }

    function domain() internal pure override returns (string memory) {
        return "recursive-imt/native-row-fold-digests/v1";
    }

    function openingPoint(uint256[] memory point) internal pure override returns (uint256[] memory z) {
        z = new uint256[](22);
        z[0] = 1;
        for (uint256 i; i < 8; ++i) {
            z[i + 1] = point[i];
        }
        for (uint256 i = 8; i < 19; ++i) {
            z[i + 3] = point[i];
        }
    }
}
