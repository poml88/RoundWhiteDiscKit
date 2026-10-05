import CryptoKit
import XCTest
@testable import RoundWhiteDiscKit

/// Vectors produced by the Python librecrypto reference with fixed scalars
/// (phone ephemeral 0x1111, sensor ephemeral 0x2222, sensor static 0x3333) and
/// the ROW credential.
final class AppIdentityTests: XCTestCase {
    private let sensorEphemeral = Data(vectorHex: "04a62f048f367359809c2d46c2049d7d7bf268c3c073c472753cb18a24a8ad20b1caccf8104b666795c7f35dac9dc444b3c2c61978198c49859955b99956da5edb")
    private let sensorStatic = Data(vectorHex: "048570e95d85825286db92c78317679bdd8ffe3c90d0af84291bf64132b66fcc99c926f087212d75b1f4dbc5d4999b4c5605adf66db801a4de371cdad39ebc55e5")
    private let expectedAuthKey = Data(vectorHex: "74699708747ac4915dec3a8e6d1bbfc2")
    private let expectedAnswer = Data(vectorHex: "c20da36dbe1f8e333564fcf066ae426c1f1b02ca77a7198bc703faf0eea014d416b29794248a8c65a1a2a3a4a5a6a7")
    private let sensorReply = Data(vectorHex: "2c0e3fe117d39f87658e689cb8c9f1438caf04a2db55b9eba883feeb1ddde9b572a40d2e0f2c31469061809dde8d7876211400b1b8250708ee5205f8b1b2b3b4b5b6b7")

    private func installedIdentities() throws -> [AppIdentity] {
        if !AppIdentities.isInstalled {
            let url = URL(fileURLWithPath: "\(#filePath)")
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("RemoteTables/roundwhitedisckit-app-identities-v1.xz")
            guard let blob = try? Data(contentsOf: url) else {
                throw XCTSkip("app identities blob not found at \(url.path); run Scripts/build_app_identities_blob.py")
            }
            try AppIdentities.install(blob)
        }
        return try AppIdentities.installed()
    }

    private func identity(_ label: String) throws -> AppIdentity {
        try XCTUnwrap(installedIdentities().first { $0.label == label })
    }

    func testForeignBlobIsRejected() throws {
        let foreign = try (Data(#"{"format":1,"curve":"P-256","identities":[]}"#.utf8) as NSData).compressed(using: .lzma) as Data
        XCTAssertThrowsError(try AppIdentities.install(foreign)) { error in
            XCTAssertEqual(error as? AppIdentityError, .digestMismatch)
        }
    }

    private func scalar(_ value: UInt16) throws -> P256.KeyAgreement.PrivateKey {
        var raw = Data(count: 32)
        raw[30] = UInt8(value >> 8)
        raw[31] = UInt8(value & 0xff)
        return try P256.KeyAgreement.PrivateKey(rawRepresentation: raw)
    }

    func testBlobIdentitiesLoadAndSelfCheck() throws {
        XCTAssertEqual(try installedIdentities().map(\.label), ["ROW", "US"])
    }

    func testAuthKeyMatchesLibrecrypto() throws {
        let key = try identity("ROW").authKey(
            phoneEphemeral: scalar(0x1111),
            sensorEphemeral: EphemeralExchange.parsePeerPubkey(sensorEphemeral),
            sensorStatic: EphemeralExchange.parsePeerPubkey(sensorStatic)
        )
        XCTAssertEqual(key, expectedAuthKey)
    }

    func testChallengeAnswerAndSessionMatchLibrecrypto() throws {
        let aes = try AppIdentity.phase5Cipher(expectedAuthKey)
        let challenge = Data(0..<16)
        let appNonce = Data(0x40..<0x50)
        let phase5 = try Phase5Challenge.encrypt(
            plaintext: challenge + appNonce + Data(vectorHex: "deadbeef"),
            aes: aes,
            nonce: Data(vectorHex: "a1a2a3a4a5a6a7")
        )
        // librecrypto returns ct||tag||nonce; the wire form pads ct||tag instead.
        XCTAssertEqual(phase5.logicalBytes, expectedAnswer.prefix(Phase5Challenge.logicalSize))

        let session = try Phase6Response.decode(sensorReply).decrypt(aes: aes)
        XCTAssertEqual(session.phoneR2, appNonce)
        XCTAssertEqual(session.sensorR1, challenge)
        XCTAssertEqual(session.kEnc, Data(0x80..<0x90))
        XCTAssertEqual(session.ivEnc, Data(0x90..<0x98))
    }

    private func patchInfo(securityVersion: UInt16, region: UInt16) throws -> Libre3NFCPatchInfo {
        var frame = Data(count: 29)
        frame[1] = 0xa5
        frame[3] = UInt8(securityVersion & 0xff)
        frame[5] = UInt8(region & 0xff)
        frame[15] = 4
        return try Libre3NFCPatchInfo(raw: frame)
    }

    func testSelectionByRegion() throws {
        let identities = try installedIdentities()
        // A US-region Libre 3 Plus (0R2R9H9W0) dropped the link on the US
        // certificate and paired with ROW.
        let us = try AppIdentities.select(from: identities, for: patchInfo(securityVersion: 1, region: 2))
        XCTAssertEqual(us.identity.label, "ROW")
        XCTAssertTrue(us.matched)

        let europe = try AppIdentities.select(from: identities, for: patchInfo(securityVersion: 1, region: 1))
        XCTAssertEqual(europe.identity.label, "ROW")
        XCTAssertTrue(europe.matched)

        let unknown = try AppIdentities.select(from: identities, for: patchInfo(securityVersion: 1, region: 9))
        XCTAssertEqual(unknown.identity.label, "ROW")
        XCTAssertFalse(unknown.matched)
    }
}

private extension Data {
    init(vectorHex hex: String) {
        self.init(stride(from: 0, to: hex.count, by: 2).map { offset in
            let start = hex.index(hex.startIndex, offsetBy: offset)
            return UInt8(hex[start..<hex.index(start, offsetBy: 2)], radix: 16)!
        })
    }
}
