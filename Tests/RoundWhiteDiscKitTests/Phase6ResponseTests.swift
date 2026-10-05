import XCTest
@testable import RoundWhiteDiscKit

final class Phase6ResponseTests: XCTestCase {
    private let phase5Key = Data((0x00..<0x10).map(UInt8.init))
    private let phase6Plaintext = Data((0x10..<0x48).map(UInt8.init))
    private let phase6Nonce = Data([0x22, 0x04, 0x00, 0x00, 0x7f, 0x43, 0x8e])
    private let liveWire = Data(hexString:
        "85aa09d24bfcd0cddc7984d10e7451b34595c5" +
        "ab3947106858d729a947ee2f372a2403d9e728" +
        "34a82f870f16b415afa032654b1572c848361b" +
        "ef399535040000a4e148"
    )

    func testCapturedPhase6ResponseDecodesWireFields() throws {
        let response = try Phase6Response.decode(liveWire)
        XCTAssertEqual(response.ciphertext.count, 56)
        XCTAssertEqual(response.tag.hex, "1bef3995")
        XCTAssertEqual(response.nonce.hex, "35040000a4e148")
    }

    func testCapturedFirstPairPhase6ResponseDecodesWireFields() throws {
        let wire = Data(hexString:
            "c7abf31874dc02e9f775b8ef83906a35632c99" +
            "8ca6c34ca81d4410c0a062d18ac0c8859e92a3" +
            "8c1c7521198de87394b2086b4e458cf7fe8161" +
            "9540f208000000f38356"
        )

        let response = try Phase6Response.decode(wire)
        XCTAssertEqual(response.tag.hex, "619540f2")
        XCTAssertEqual(response.nonce.hex, "08000000f38356")
    }

    func testStandardAESPhase6ResponseDecryptsToSessionMaterial() throws {
        let response = try Phase6Response.decode(standardAESWire())
        let aes = AESCCM.commonCryptoBlockEncrypt(key: phase5Key)
        let material = try response.decrypt(aes: aes)

        XCTAssertEqual(response.nonce, phase6Nonce)
        XCTAssertEqual(material.phoneR2, Data((0x10..<0x20).map(UInt8.init)))
        XCTAssertEqual(material.sensorR1, Data((0x20..<0x30).map(UInt8.init)))
        XCTAssertEqual(material.kEnc, Data((0x30..<0x40).map(UInt8.init)))
        XCTAssertEqual(material.ivEnc, Data((0x40..<0x48).map(UInt8.init)))
    }

    func testTamperedPhase6ResponseFailsAuth() throws {
        var tampered = try standardAESWire()
        tampered[0] ^= 0x01
        let response = try Phase6Response.decode(tampered)
        let aes = AESCCM.commonCryptoBlockEncrypt(key: phase5Key)

        XCTAssertThrowsError(try response.decrypt(aes: aes)) { error in
            guard case AESCCMError.macMismatch = error else {
                XCTFail("expected macMismatch, got \(error)")
                return
            }
        }
    }

    private func standardAESWire() throws -> Data {
        let aes = AESCCM.commonCryptoBlockEncrypt(key: phase5Key)
        let (ciphertext, tag) = try AESCCM.encrypt(
            nonce: phase6Nonce,
            plaintext: phase6Plaintext,
            tagLength: Phase6Response.tagSize,
            aes: aes
        )
        return ciphertext + tag + phase6Nonce
    }
}

private extension Data {
    init(hexString: String) {
        var data = Data(capacity: hexString.count / 2)
        var idx = hexString.startIndex
        while idx < hexString.endIndex {
            let next = hexString.index(idx, offsetBy: 2)
            if let b = UInt8(hexString[idx..<next], radix: 16) {
                data.append(b)
            }
            idx = next
        }
        self = data
    }
}
