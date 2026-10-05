import Foundation
import CryptoKit

// Experimental VM-free first-pair Phase 5 key (probe branch).
//
// The white-box first-pair path ends in an encoded SHA-256 whose input is
// `00 00 00 01 || A32 || B32` and whose first 16 output bytes become the
// Phase 5 key. That is the NIST SP 800-56A single-step KDF with counter 1 and
// no OtherInfo. A and B are derived from the two ECDH products the white-box
// computes, ECDH(phone_eph, sensor_eph) and ECDH(phone_static, sensor_static),
// but the white-box blinds both private scalars, so the plain order of A and B
// is not grounded yet. `PlainPhase5SecretOrder` lets a live probe try both.
//
// Unlike the native path, this needs the phone certificate's plain static
// private key, so it only works with an identity whose private key is known.
// The resulting key drives standard AES-CCM (CommonCrypto), not `LibAES`.

public enum PlainPhase5SecretOrder: String, CaseIterable, Sendable {
    /// `SHA-256(00000001 || ECDH(eph, sensorEph) || ECDH(static, sensorStatic))`.
    case ephemeralFirst
    /// `SHA-256(00000001 || ECDH(static, sensorStatic) || ECDH(eph, sensorEph))`.
    case staticFirst
}

public enum PlainPairingError: Error, Equatable {
    case invalidStaticPrivateKey
    /// The private key does not produce the certificate's static public key.
    case staticPrivateKeyDoesNotMatchCertificate
    /// The flow's phone ephemeral public key is not `privateKey * G`, e.g. a
    /// native first-pair ephemeral whose public point is built separately.
    case phoneEphemeralIsNotPlain
    case invalidSharedSecretLength(Int)
}

/// A phone certificate together with its plain static private key.
public struct PlainPairingIdentity: Sendable {
    public let phoneCert: PhoneCert
    public let staticPrivateKey: P256.KeyAgreement.PrivateKey

    public init(phoneCert: PhoneCert, staticPrivateKey: P256.KeyAgreement.PrivateKey) throws {
        guard staticPrivateKey.publicKey.x963Representation == phoneCert.staticPub else {
            throw PlainPairingError.staticPrivateKeyDoesNotMatchCertificate
        }
        self.phoneCert = phoneCert
        self.staticPrivateKey = staticPrivateKey
    }

    /// - Parameter staticPrivateKeyRaw: 32-byte big-endian P-256 private scalar.
    public init(phoneCert: PhoneCert, staticPrivateKeyRaw: Data) throws {
        let key: P256.KeyAgreement.PrivateKey
        do {
            key = try P256.KeyAgreement.PrivateKey(rawRepresentation: staticPrivateKeyRaw)
        } catch {
            throw PlainPairingError.invalidStaticPrivateKey
        }
        try self.init(phoneCert: phoneCert, staticPrivateKey: key)
    }
}

public enum PlainPhase5Key {
    public static let counter = Data([0x00, 0x00, 0x00, 0x01])

    /// Derive the 16-byte Phase 5 AES key from the two raw ECDH secrets
    /// (32-byte big-endian x-coordinates, as CryptoKit returns them).
    public static func derive(
        ephemeralSecret: Data,
        staticSecret: Data,
        order: PlainPhase5SecretOrder
    ) throws -> Data {
        for secret in [ephemeralSecret, staticSecret] where secret.count != 32 {
            throw PlainPairingError.invalidSharedSecretLength(secret.count)
        }
        let (first, second) = order == .ephemeralFirst
            ? (ephemeralSecret, staticSecret)
            : (staticSecret, ephemeralSecret)
        let digest = SHA256.hash(data: counter + first + second)
        return Data(digest.prefix(16))
    }
}
