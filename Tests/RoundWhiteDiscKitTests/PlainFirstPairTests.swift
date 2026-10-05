import XCTest
import CryptoKit
@testable import RoundWhiteDiscKit

final class PlainFirstPairTests: XCTestCase {
    private let ephemeralSecret = Data((0x00..<0x20).map(UInt8.init))
    private let staticSecret = Data((0x20..<0x40).map(UInt8.init))
    private let blePIN = Data([0x32, 0x25, 0xec, 0x72])

    func testPlainPhase5KeyMatchesReferenceSingleStepKDF() throws {
        // Python: hashlib.sha256(b"\0\0\0\1" + first + second).digest()[:16]
        XCTAssertEqual(
            try PlainPhase5Key.derive(
                ephemeralSecret: ephemeralSecret,
                staticSecret: staticSecret
            ).hex,
            "494a7a870fa4fe978918cfeab53a6282"
        )
        XCTAssertEqual(
            try PlainPhase5Key.derive(
                ephemeralSecret: staticSecret,
                staticSecret: ephemeralSecret
            ).hex,
            "c66aae1f0221dd0290a9e853c9cbd2d3"
        )
    }

    func testPlainPhase5KeyRejectsWrongSecretLength() {
        XCTAssertThrowsError(
            try PlainPhase5Key.derive(
                ephemeralSecret: Data(count: 31),
                staticSecret: staticSecret
            )
        ) { error in
            XCTAssertEqual(error as? PlainPairingError, .invalidSharedSecretLength(31))
        }
    }

    func testIdentityRequiresMatchingPrivateKey() throws {
        let key = P256.KeyAgreement.PrivateKey()
        let cert = try Self.phoneCert(staticPub: key.publicKey.x963Representation)

        XCTAssertNoThrow(try PlainPairingIdentity(phoneCert: cert, staticPrivateKeyRaw: key.rawRepresentation))
        XCTAssertThrowsError(
            try PlainPairingIdentity(
                phoneCert: cert,
                staticPrivateKeyRaw: P256.KeyAgreement.PrivateKey().rawRepresentation
            )
        ) { error in
            XCTAssertEqual(error as? PlainPairingError, .staticPrivateKeyDoesNotMatchCertificate)
        }
        XCTAssertThrowsError(
            try PlainPairingIdentity(phoneCert: cert, staticPrivateKeyRaw: Data(count: 32))
        ) { error in
            XCTAssertEqual(error as? PlainPairingError, .invalidStaticPrivateKey)
        }
    }

    func testPlainFirstPairCompletesAgainstSimulatedSensor() async throws {
        let identity = try Self.makeIdentity()
        let sensor = SimulatedPlainSensor(blePIN: blePIN)
        let flow = PairingFlow(
            transport: sensor,
            phoneCert: identity.phoneCert,
            phoneEph: EphemeralKeyPair(privateKey: P256.KeyAgreement.PrivateKey()),
            sensorCertSigningKeys: []
        )

        let result: CommandGatedAuthorizationHandshakeResult = try await flow.runCommandGatedAuthorizationHandshake(
            blePIN: blePIN,
            identity: identity
        )

        let sensorKey = try await sensor.derivedKey()
        XCTAssertEqual(result.phase5Key, sensorKey)
        XCTAssertEqual(result.handshake.sessionMaterial.kEnc, sensor.kEnc)
        XCTAssertEqual(result.handshake.sessionMaterial.ivEnc, sensor.ivEnc)
        XCTAssertEqual(result.handshake.sessionMaterial.sensorR1, sensor.r1)
        let commands = await sensor.commandWrites
        XCTAssertEqual(commands, [0x01, 0x02, 0x03, 0x09, 0x0d, 0x0e, 0x11, 0x08])

        // Reconnect with only the saved plain key; no certificate is configured.
        let reconnectFlow = PairingFlow(transport: sensor)
        let reconnect = try await reconnectFlow.runCachedReconnectHandshake(
            tail4: blePIN,
            phase5Key: result.phase5Key
        )
        XCTAssertEqual(reconnect.sessionMaterial.kEnc, sensor.kEnc)
        XCTAssertEqual(reconnect.sessionMaterial.ivEnc, sensor.ivEnc)
        let reconnectCommands = await sensor.commandWrites
        XCTAssertEqual(reconnectCommands, commands + [0x11, 0x08])
    }

    func testPlainFirstPairFailsWhenSensorUsesOtherOrder() async throws {
        let identity = try Self.makeIdentity()
        let sensor = SimulatedPlainSensor(blePIN: blePIN, reverseSecrets: true)
        let flow = PairingFlow(
            transport: sensor,
            phoneCert: identity.phoneCert,
            sensorCertSigningKeys: []
        )

        do {
            _ = try await flow.runCommandGatedAuthorizationHandshake(
                blePIN: blePIN,
                identity: identity
            )
            XCTFail("Sensor should not answer Phase 6 for a Phase 5 under the wrong key")
        } catch is SimulatedSensorSilent {
        }
        let rejected = await sensor.rejectedPhase5
        XCTAssertTrue(rejected)
    }

    func testAuthorizationRejectsMismatchedCertificateBeforeTransportUse() async throws {
        let identity = try Self.makeIdentity()
        let otherIdentity = try Self.makeIdentity()
        let sensor = SimulatedPlainSensor(blePIN: blePIN)
        let flow = PairingFlow(
            transport: sensor,
            phoneCert: otherIdentity.phoneCert,
            sensorCertSigningKeys: []
        )

        do {
            _ = try await flow.runCommandGatedAuthorizationHandshake(
                blePIN: blePIN,
                identity: identity
            )
            XCTFail("A different phone certificate must be rejected before any wire traffic")
        } catch let error as PlainPairingError {
            XCTAssertEqual(error, .staticPrivateKeyDoesNotMatchCertificate)
        }
        let commands = await sensor.commandWrites
        XCTAssertTrue(commands.isEmpty)
    }

    private static func makeIdentity() throws -> PlainPairingIdentity {
        let key = P256.KeyAgreement.PrivateKey()
        let cert = try phoneCert(staticPub: key.publicKey.x963Representation)
        return try PlainPairingIdentity(phoneCert: cert, staticPrivateKey: key)
    }

    private static func phoneCert(staticPub: Data) throws -> PhoneCert {
        var raw = Data([0x03, 0x00]) + Data((1...16).map(UInt8.init)) + Data(count: 15)
        raw.append(staticPub)
        raw.append(Data(count: 64))
        return try PhoneCert(raw: raw)
    }
}

private struct SimulatedSensorSilent: Error {}

/// A sensor that runs the plain single-step KDF on its own side, accepts a
/// Phase 5 message only when it decrypts under that key, and answers Phase 6.
private actor SimulatedPlainSensor: CommandPairingTransport {
    nonisolated let r1 = Data((0x10..<0x20).map(UInt8.init))
    nonisolated let kEnc = Data((0x50..<0x60).map(UInt8.init))
    nonisolated let ivEnc = Data((0x60..<0x68).map(UInt8.init))
    private let challengeNonce = Data([0x21, 0x04, 0x00, 0x00, 0x8f, 0x8c, 0x4b])
    private let phase6Nonce = Data([0x22, 0x04, 0x00, 0x00, 0x7f, 0x43, 0x8e])
    private let sensorStatic = P256.KeyAgreement.PrivateKey()
    private let sensorEphemeral = P256.KeyAgreement.PrivateKey()
    private let reverseSecrets: Bool
    private let blePIN: Data
    private var phoneStaticPub: Data?
    private var phoneEphemeralPub: Data?
    private var phase6: Data?
    private var lastCommand: UInt8?
    private(set) var commandWrites: [UInt8] = []
    private(set) var rejectedPhase5 = false

    init(blePIN: Data, reverseSecrets: Bool = false) {
        self.reverseSecrets = reverseSecrets
        self.blePIN = blePIN
    }

    func derivedKey() throws -> Data {
        guard let phoneStaticPub, let phoneEphemeralPub else { throw SimulatedSensorSilent() }
        let ephemeral = try sensorEphemeral.sharedSecretFromKeyAgreement(
            with: P256.KeyAgreement.PublicKey(x963Representation: phoneEphemeralPub)
        ).withUnsafeBytes { Data($0) }
        let statical = try sensorStatic.sharedSecretFromKeyAgreement(
            with: P256.KeyAgreement.PublicKey(x963Representation: phoneStaticPub)
        ).withUnsafeBytes { Data($0) }
        let (first, second) = reverseSecrets ? (statical, ephemeral) : (ephemeral, statical)
        return Data(SHA256.hash(data: Data([0, 0, 0, 1]) + first + second).prefix(16))
    }

    func write(_ message: Data, to characteristic: BleCharRef) async throws {
        switch characteristic {
        case .certHandshake where message.count == PhoneCert.totalSize:
            phoneStaticPub = try PhoneCert(raw: message).staticPub
        case .certHandshake:
            phoneEphemeralPub = message.prefix(65)
        case .challenge:
            try receivePhase5(message)
        }
    }

    private func receivePhase5(_ wire: Data) throws {
        let aes = AESCCM.commonCryptoBlockEncrypt(key: try derivedKey())
        let challenge = try Phase5Challenge.decode(wire)
        guard let plaintext = try? challenge.decrypt(aes: aes, nonce: challengeNonce),
              plaintext.prefix(16) == r1,
              plaintext.suffix(4) == blePIN else {
            rejectedPhase5 = true
            return
        }
        let phoneR2 = plaintext.subdata(in: 16..<32)
        let (ciphertext, tag) = try AESCCM.encrypt(
            nonce: phase6Nonce,
            plaintext: phoneR2 + r1 + kEnc + ivEnc,
            tagLength: Phase6Response.tagSize,
            aes: aes
        )
        phase6 = ciphertext + tag + phase6Nonce
    }

    func awaitNotify(on characteristic: BleCharRef, exactly n: Int) async throws -> Data {
        switch (characteristic, n) {
        case (.certHandshake, SensorCert.totalSize):
            return Data(count: 11) + sensorStatic.publicKey.x963Representation + Data(count: 64)
        case (.certHandshake, 65):
            return sensorEphemeral.publicKey.x963Representation
        case (.challenge, 23):
            return r1 + challengeNonce
        case (.challenge, Phase6Response.wireSize):
            guard let phase6 else { throw SimulatedSensorSilent() }
            return phase6
        default:
            throw SimulatedSensorSilent()
        }
    }

    func writeCommand(_ command: UInt8) async throws {
        commandWrites.append(command)
        lastCommand = command
    }

    func awaitCommandResponse(timeout: TimeInterval) async throws -> Data {
        switch lastCommand {
        case 0x03: return Data([0x04])
        case 0x09: return Data([0x0a])
        case 0x0e: return Data([0x0f])
        case 0x11: return Data([0x08, 0x17])
        case 0x08: return Data([0x08, 0x43])
        default: throw SimulatedSensorSilent()
        }
    }
}
