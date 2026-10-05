import Foundation
import CryptoKit

// Phase 3/4 ephemeral P-256 ECDH.
//
// The phone generates a fresh P-256 keypair, sends the uncompressed
// pubkey (65B) on handle 0x002d, and receives the sensor's ephemeral
// pubkey (65B notify on the same handle).
//
// The Phase 5 KDF combines phone_eph × sensor_eph with
// phone_static × sensor_static (see `PlainPhase5Key`).
//
// CryptoKit's `P256.KeyAgreement` exposes raw X9.63 public-key encoding
// (`x963Representation`) which IS the 65B uncompressed-point format the
// protocol uses on the wire. No custom point parsing needed.

public struct EphemeralKeyPair: Sendable {
    public let privateKey: P256.KeyAgreement.PrivateKey
    public let publicKey65: Data   // 04 || X || Y

    public init() {
        let priv = P256.KeyAgreement.PrivateKey()
        self.privateKey = priv
        self.publicKey65 = priv.publicKey.x963Representation
    }

    /// Construct from a previously-saved private key (e.g. for replay tests).
    public init(privateKey: P256.KeyAgreement.PrivateKey) {
        self.privateKey = privateKey
        self.publicKey65 = privateKey.publicKey.x963Representation
    }
}

public enum EphemeralExchange {

    /// Parse a 65-byte uncompressed P-256 point as a CryptoKit public key.
    public static func parsePeerPubkey(_ raw65: Data) throws -> P256.KeyAgreement.PublicKey {
        guard raw65.count == 65, raw65.first == 0x04 else {
            throw EphemeralExchangeError.invalidEncoding
        }
        return try P256.KeyAgreement.PublicKey(x963Representation: raw65)
    }

    /// Compute a single ECDH shared secret as raw 32 bytes.
    public static func sharedSecret(
        privateKey: P256.KeyAgreement.PrivateKey,
        peer: P256.KeyAgreement.PublicKey
    ) throws -> Data {
        let s = try privateKey.sharedSecretFromKeyAgreement(with: peer)
        return s.withUnsafeBytes { Data($0) }
    }
}

public enum EphemeralExchangeError: Error, Equatable {
    case invalidEncoding
}
