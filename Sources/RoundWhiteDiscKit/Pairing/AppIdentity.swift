import CryptoKit
import Foundation

/// An app credential with a plain static key: the phone certificate plus the
/// P-256 scalar behind its public key. Pairing with one needs no runtime
/// tables — kAuth is plain ECDH and SHA-256, and Phase 5/6 use standard AES.
public struct AppIdentity: Sendable {
    public let label: String
    public let productType: UInt8
    public let securityVersion: UInt16
    public let regions: [UInt16]
    public let isDefault: Bool
    public let privateKey: P256.KeyAgreement.PrivateKey
    public let certificate: PhoneCert

    /// NIST SP 800-56A concat KDF: `SHA-256(00000001 || Ze || Zs)[0..<16]`, where
    /// Ze is ephemeral × sensor ephemeral and Zs is our static × sensor static.
    public func authKey(
        phoneEphemeral: P256.KeyAgreement.PrivateKey,
        sensorEphemeral: P256.KeyAgreement.PublicKey,
        sensorStatic: P256.KeyAgreement.PublicKey
    ) throws -> Data {
        let ze = try EphemeralExchange.sharedSecret(privateKey: phoneEphemeral, peer: sensorEphemeral)
        let zs = try EphemeralExchange.sharedSecret(privateKey: privateKey, peer: sensorStatic)
        let digest = SHA256.hash(data: Data([0, 0, 0, 1]) + ze + zs)
        return Data(digest.prefix(16))
    }

    /// Standard AES for the Phase 5/6 exchange under a kAuth from `authKey`.
    public static let phase5Cipher: (Data) throws -> AESBlockEncrypt = { key in
        AESCCM.commonCryptoBlockEncrypt(key: key)
    }
}

public struct AppIdentitySelection: Sendable {
    public let identity: AppIdentity
    /// False when no identity lists this sensor's product type, security
    /// version and region, and the default was used instead.
    public let matched: Bool
}

/// Like the runtime tables, the identities ship as a remote xz blob built by
/// Scripts/build_app_identities_blob.py; the host app downloads it and calls
/// `install(_:)`.
public enum AppIdentities {
    /// SHA-256 of the decompressed JSON, printed by the build script.
    static let expectedPayloadSHA256 = "da98c35547c0b53a331186936f057fcdbc26a0a6f2e3a16e3c6f939beb9311ca"

    private static let lock = NSLock()
    private static var current: [AppIdentity]?

    /// Decompresses, verifies and parses the blob. Throws without changing
    /// state if it is invalid.
    public static func install(_ blob: Data) throws {
        let payload: Data
        do {
            payload = try (blob as NSData).decompressed(using: .lzma) as Data
        } catch {
            throw AppIdentityError.decompressionFailed
        }
        let digest = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        guard digest == expectedPayloadSHA256 else {
            throw AppIdentityError.digestMismatch
        }
        let identities = try load(json: payload)
        lock.withLock { current = identities }
    }

    public static var isInstalled: Bool {
        lock.withLock { current != nil }
    }

    public static func installed() throws -> [AppIdentity] {
        guard let identities = lock.withLock({ current }) else {
            throw AppIdentityError.notInstalled
        }
        return identities
    }

    static func load(json: Data) throws -> [AppIdentity] {
        let file = try JSONDecoder().decode(File.self, from: json)
        guard file.format == 1, file.curve == "P-256" else {
            throw AppIdentityError.unsupportedFormat(file.format, file.curve)
        }
        return try file.identities.map { entry in
            guard let scalar = Data(appIdentityHex: entry.privateKeyHex),
                  let certRaw = Data(appIdentityHex: entry.certificateHex) else {
                throw AppIdentityError.badHex(entry.label)
            }
            let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: scalar)
            let certificate = try PhoneCert(raw: certRaw)
            guard privateKey.publicKey.x963Representation == certificate.staticPub else {
                throw AppIdentityError.keyCertificateMismatch(entry.label)
            }
            return AppIdentity(
                label: entry.label,
                productType: entry.productType,
                securityVersion: entry.securityVersion,
                regions: entry.regions,
                isDefault: entry.default,
                privateKey: privateKey,
                certificate: certificate
            )
        }
    }

    public static func select(from identities: [AppIdentity], for patchInfo: Libre3NFCPatchInfo) throws -> AppIdentitySelection {
        func fits(_ identity: AppIdentity) -> Bool {
            guard identity.productType == patchInfo.productType else { return false }
            guard identity.securityVersion == patchInfo.securityVersion else { return false }
            return identity.regions.contains(patchInfo.region)
        }
        if let match = identities.first(where: fits) {
            return AppIdentitySelection(identity: match, matched: true)
        }
        guard let fallback = identities.first(where: \.isDefault) ?? identities.first else {
            throw AppIdentityError.noIdentities
        }
        return AppIdentitySelection(identity: fallback, matched: false)
    }

    private struct File: Decodable {
        let format: Int
        let curve: String
        let identities: [Entry]
    }

    private struct Entry: Decodable {
        let label: String
        let productType: UInt8
        let securityVersion: UInt16
        let regions: [UInt16]
        let `default`: Bool
        let privateKeyHex: String
        let certificateHex: String
    }
}

public enum AppIdentityError: Error, Equatable {
    case notInstalled
    case decompressionFailed
    case digestMismatch
    case unsupportedFormat(Int, String)
    case badHex(String)
    case keyCertificateMismatch(String)
    case noIdentities
}

private extension Data {
    init?(appIdentityHex hex: String) {
        guard hex.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}
