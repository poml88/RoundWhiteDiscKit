import XCTest
import CryptoKit
@testable import RoundWhiteDiscKit

final class SessionKeyTests: XCTestCase {
    override func setUpWithError() throws {
        try installRuntimeTablesForTests()
    }


    func testDeriveThrowsNotYetSpecified() {
        let inputs = SessionKeyInputs(
            sharedEphStatic: Data(repeating: 0xaa, count: 32),
            sharedEphEph:    Data(repeating: 0xbb, count: 32),
            k1:              Data(repeating: 0xcc, count: 16),
            k2:              Data(repeating: 0xdd, count: 16),
            extra:           Data()
        )
        XCTAssertThrowsError(try SessionKey.derive(inputs)) { err in
            guard case SessionKeyError.notYetSpecified = err else {
                XCTFail("expected notYetSpecified, got \(err)")
                return
            }
        }
    }

    func testInputsEquatable() {
        let i1 = SessionKeyInputs(
            sharedEphStatic: Data([0x01]), sharedEphEph: Data([0x02]),
            k1: Data([0x03]), k2: Data([0x04]), extra: Data([0x05])
        )
        let i2 = SessionKeyInputs(
            sharedEphStatic: Data([0x01]), sharedEphEph: Data([0x02]),
            k1: Data([0x03]), k2: Data([0x04]), extra: Data([0x05])
        )
        XCTAssertEqual(i1, i2)
    }

    func testBundledFirstPairEntrySourceMatchesPythonReference() {
        let source = FirstPairSourceSlice.bundled6388f0LowSeedEntrySource
        XCTAssertEqual(source.count, 0x214)
        XCTAssertEqual(
            Data(SHA256.hash(data: source)).hex,
            "263e4b14637a6779be45abeaf3b688cfe34df4614cb928cb3ee7d883acfa028a"
        )
    }

    func testFirstPairPhase5SourceFromSensorPublicKeysMatchesPythonReferenceVector() throws {
        let entrySource = Data((0..<0x214).map { index in UInt8((index * 5 + 1) & 7) })
        let nullEntropy = Data((0..<0x11a).map { index in UInt8((index * 11 + 3) & 0xff) })
        let generatorPoint65 = dataFromHex(
            "04" +
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        )

        let inputs = FirstPairPhase5KeyInputs(
            entrySource: entrySource,
            nullEntropy11A: nullEntropy,
            sensorEphemeralPub65: generatorPoint65,
            sensorStaticPub65: generatorPoint65
        )
        let material = try SessionKey.deriveFirstPairPhase5Material(inputs)
        XCTAssertEqual(material.nullEntropy11A, nullEntropy)
        XCTAssertEqual(material.nullAttempts, 1)
        XCTAssertEqual(
            material.source66.hex,
            "04040706000606020005070707050402050701070106000602000707060002050402" +
            "0407050605040400060004020400000106060102060205030303040600040606"
        )

        let rawKey = try SessionKey.deriveFirstPairPhase5RawKey(inputs)
        XCTAssertEqual(rawKey, material.rawKey)
        XCTAssertEqual(material.rawKey, try Phase5KeySchedule.deriveRawKey(input66: material.source66))
    }

    func testFirstPairPhase5MaterialMatchesSingleRunEntropyTrace() throws {
        let entropy = dataFromHex(
            "0101050002040400000305000501050006020600020307070405030604020407" +
            "0507010501060703030103070701030606050003010703010404020603070501" +
            "0504020706020404060201000603070606050303070606010105070601030103" +
            "0502040401020201070503060100070002010406070306070105050404040300" +
            "0506060007070707060103060603000601010601000404000500010102000703" +
            "0306030705030107040406070401050003070700050104000001030106070002" +
            "0704020302020606000504060700070507040306070607020505040505010204" +
            "0702000606060507010400030101020500020400070201030400010502010604" +
            "0301060206020102000507020400000404050706010002050305"
        )
        let sensorEphemeral = dataFromHex(
            "04" +
            "e40ff95713629069c7be93644140a6d641435b84cb343adb3a208571b20b29a4" +
            "8322a60f864b12c1136cba8171ec68f0adce245a9f8be567d05c18bbe528b016"
        )
        let sensorStatic = dataFromHex(
            "04" +
            "3e1f46f25d44b3d72a8c37dcfebc7c339ed01fc5668a6387458084ac9cafebe" +
            "7438b649f76b81eeca9343287da162b07c5c07362997e40e13035df14cdf3d5d8"
        )

        let material = try SessionKey.deriveFirstPairPhase5Material(
            FirstPairPhase5KeyInputs(
                entrySource: FirstPairSourceSlice.bundled6388f0LowSeedEntrySource,
                nullEntropy11A: entropy,
                sensorEphemeralPub65: sensorEphemeral,
                sensorStaticPub65: sensorStatic
            )
        )

        XCTAssertEqual(material.nullAttempts, 1)
        XCTAssertEqual(material.nullEntropy11A, entropy)
        XCTAssertEqual(
            material.source66.hex,
            "040404070404070200010700040400070602030604040602030706060405020003" +
            "050701010602000206010207070005060307000202000300010003040004060203"
        )
        XCTAssertEqual(material.rawKey.hex, "3fad08acb65701a8552a31a003ab2556")
        XCTAssertEqual(
            Data(SHA256.hash(data: material.source66)).hex,
            "8ceeb7ddd894f8100cf50519140be9dc53f560014392aac96a808833b39339d9"
        )
    }

    func testFirstPairPhase5SourceRejectsInvalidSensorPointEncoding() throws {
        let inputs = FirstPairPhase5KeyInputs(
            entrySource: Data((0..<0x214).map { index in UInt8((index * 5 + 1) & 7) }),
            nullEntropy11A: Data(repeating: 0, count: 0x11a),
            sensorEphemeralPub65: Data([0x05]),
            sensorStaticPub65: Data(repeating: 0x04, count: 65)
        )
        XCTAssertThrowsError(try SessionKey.deriveFirstPairPhase5Source(inputs)) { error in
            guard case SessionKeyError.invalidSensorPointEncoding(
                label: "sensor ephemeral",
                count: 1,
                prefix: 0x05
            ) = error else {
                XCTFail("expected invalidSensorPointEncoding, got \(error)")
                return
            }
        }
    }

    func testFirstPairPhase5MaterialEntropySourceRejectsInvalidAttemptLimit() throws {
        let generatorPoint65 = dataFromHex(
            "04" +
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        )
        XCTAssertThrowsError(
            try SessionKey.deriveFirstPairPhase5Material(
                entrySource: Data((0..<0x214).map { index in UInt8((index * 5 + 1) & 7) }),
                sensorEphemeralPub65: generatorPoint65,
                sensorStaticPub65: generatorPoint65,
                maxAttempts: 0
            ) { _ in
                XCTFail("entropy source should not be called")
                return Data()
            }
        ) { error in
            guard case FirstPairSourceSliceError.invalid633fa8NullMaxAttempts(0) = error else {
                XCTFail("expected invalid633fa8NullMaxAttempts, got \(error)")
                return
            }
        }
    }

    private func dataFromHex(_ hex: String) -> Data {
        precondition(hex.count % 2 == 0)
        var bytes: [UInt8] = []
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else {
                preconditionFailure("invalid hex byte")
            }
            bytes.append(byte)
            index = next
        }
        return Data(bytes)
    }
}
