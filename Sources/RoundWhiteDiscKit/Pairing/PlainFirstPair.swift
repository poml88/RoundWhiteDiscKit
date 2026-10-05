import Foundation
import CryptoKit

// VM-free Phase 5 key: the NIST SP 800-56A single-step KDF with counter 1
// and no OtherInfo. The ephemeral ECDH secret precedes the static ECDH
// secret, as verified live. The first 16 SHA-256 bytes drive standard AES-CCM.

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
        staticSecret: Data
    ) throws -> Data {
        for secret in [ephemeralSecret, staticSecret] where secret.count != 32 {
            throw PlainPairingError.invalidSharedSecretLength(secret.count)
        }
        let digest = SHA256.hash(data: counter + ephemeralSecret + staticSecret)
        return Data(digest.prefix(16))
    }
}
