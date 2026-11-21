// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {NativeRingWeight} from "../contracts/imt/NativeRingWeight.sol";
import {NativeField as F} from "../contracts/imt/NativeField.sol";
import {NativeRingCertificate} from "../contracts/imt/NativeRingCertificate.sol";
import {FixtureReader} from "./NativeKeccak.t.sol";

contract NativeRingCertificateTest {
    FixtureReader private constant VM = FixtureReader(address(uint160(uint256(keccak256("hevm cheat code")))));
    NativeRingCertificate private immutable verifier = new NativeRingCertificate();

    function testCertificateFrom64ClientRoot() external view {
        bytes memory callData = VM.readFileBinary("test/fixtures/terminal-ring-certificate.bin");
        // Rust ring-switch weight from the terminal64 four-variable proof.
        (bool ok, bytes memory result) = address(verifier).staticcall(callData);
        require(ok && abi.decode(result, (uint192)) == 0x972e5576e6dd36e30568c17f9bf07fd986f9ae0e730ccc4b);
        // The final eight ABI padding bytes follow the last map entry.
        callData[callData.length - 9] ^= 0x01;
        (ok, result) = address(verifier).staticcall(callData);
        require(!ok && bytes4(result) == NativeRingCertificate.InvalidRingCertificate.selector);
    }
}

contract NativeRingWeightTest {
    function weight(uint192[32] memory reading, uint192[26] memory draw, uint192[8] memory batching)
        external
        pure
        returns (uint192)
    {
        return NativeRingWeight.evaluate(reading, draw, batching);
    }

    function coefficientEvaluation(uint192 x, uint192[8] memory batching) private pure returns (uint192) {
        uint192[256] memory values;
        for (uint256 j; j < 192; ++j) {
            values[j] = (x >> j) & 1;
        }
        for (uint256 d; d < 8; ++d) {
            for (uint256 j; j < 128 >> d; ++j) {
                uint192 a = values[2 * j];
                values[j] = a ^ F.mul(batching[7 - d], a ^ values[2 * j + 1]);
            }
        }
        return values[0];
    }

    function testTensorProductAtMixedAndBooleanCoordinates() external pure {
        uint192[8] memory batching;
        uint192[32] memory reading;
        uint192[26] memory draw;
        for (uint256 i; i < 8; ++i) {
            batching[i] = uint192(uint256(keccak256(abi.encode(i))));
        }
        (reading[2], reading[19]) = (batching[0], batching[4]);
        (draw[23], draw[6]) = (batching[2], batching[7]);
        // A fixed Boolean high coordinate contributes its ordinary equality gate.
        reading[0] = 1;
        draw[25] = batching[3];
        uint192 a = reading[2];
        uint192 c = reading[19];
        uint192 b = 1 ^ draw[23];
        uint192 d = 1 ^ draw[6];
        uint192 expected = F.mul(coefficientEvaluation(1, batching), F.mul(b, d))
            ^ F.mul(coefficientEvaluation(a, batching), d) ^ F.mul(coefficientEvaluation(c, batching), b)
            ^ coefficientEvaluation(F.mul(a, c), batching);
        require(NativeRingWeight.evaluate(reading, draw, batching) == F.mul(expected, draw[25]));
        // 11xxxxxx addresses the 64 padding rows, for any values of the low coordinates.
        batching[0] = 1;
        batching[1] = 1;
        require(NativeRingWeight.evaluate(reading, draw, batching) == 0);
    }
}
