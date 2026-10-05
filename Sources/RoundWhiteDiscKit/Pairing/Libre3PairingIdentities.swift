import Foundation

public enum Libre3PairingIdentitiesError: Error, Equatable {
    case identityFileMissing
    case invalidJSON
    case unsupportedFormat(Int)
    case unsupportedCurve(String)
    case invalidHex(field: String)
    case invalidDefaultCount(productType: UInt8, securityVersion: UInt16, count: Int)
    case noIdentity(productType: UInt8, securityVersion: UInt16)
}

/// Validated phone identities, grouped by sensor product and security version.
public struct Libre3PairingIdentities: Sendable {
    public struct Entry: Sendable {
        public let label: String
        public let productType: UInt8
        public let securityVersion: UInt16
        public let regions: [UInt8]
        public let isDefault: Bool
        public let identity: PlainPairingIdentity

        /// Apps can supply their own already-validated identities.
        public init(
            label: String,
            productType: UInt8,
            securityVersion: UInt16,
            regions: [UInt8],
            isDefault: Bool,
            identity: PlainPairingIdentity
        ) {
            self.label = label
            self.productType = productType
            self.securityVersion = securityVersion
            self.regions = regions
            self.isDefault = isDefault
            self.identity = identity
        }
    }

    public let entries: [Entry]

    public init(entries: [Entry]) throws {
        let groups = Dictionary(grouping: entries) {
            ProductSecurityVersion(productType: $0.productType, securityVersion: $0.securityVersion)
        }
        for (group, entries) in groups {
            let count = entries.filter(\.isDefault).count
            guard count == 1 else {
                throw Libre3PairingIdentitiesError.invalidDefaultCount(
                    productType: group.productType,
                    securityVersion: group.securityVersion,
                    count: count
                )
            }
        }
        self.entries = entries
    }

    public init(jsonData: Data) throws {
        let file: IdentityFile
        do {
            file = try JSONDecoder().decode(IdentityFile.self, from: jsonData)
        } catch {
            // Decoder diagnostics can contain input values; never expose key material.
            throw Libre3PairingIdentitiesError.invalidJSON
        }
        guard file.format == 1 else {
            throw Libre3PairingIdentitiesError.unsupportedFormat(file.format)
        }
        guard file.curve == "P-256" else {
            throw Libre3PairingIdentitiesError.unsupportedCurve(file.curve)
        }
        let entries = try file.identities.map { entry in
            let certificate = try PhoneCert(raw: Self.decodeHex(entry.certificateHex, field: "certificateHex"))
            let identity = try PlainPairingIdentity(
                phoneCert: certificate,
                staticPrivateKeyRaw: Self.decodeHex(entry.privateKeyHex, field: "privateKeyHex")
            )
            return Entry(
                label: entry.label,
                productType: entry.productType,
                securityVersion: entry.securityVersion,
                regions: entry.regions,
                isDefault: entry.isDefault,
                identity: identity
            )
        }
        try self.init(entries: entries)
    }

    /// The git-ignored file is optional in a fresh checkout.
    public static func bundled() throws -> Libre3PairingIdentities {
        guard let url = Bundle.module.url(forResource: "RWDKAppIdentities", withExtension: "json") else {
            throw Libre3PairingIdentitiesError.identityFileMissing
        }
        return try Libre3PairingIdentities(jsonData: Data(contentsOf: url))
    }

    /// Select once: an explicit region match wins, otherwise use the group's default.
    /// The entry's label identifies the selection in logs; pass `entry.identity` to the handshake.
    public func identity(productType: UInt8, securityVersion: UInt16, region: UInt8) throws -> Entry {
        let candidates = entries.filter { $0.productType == productType && $0.securityVersion == securityVersion }
        guard let entry = candidates.first(where: { $0.regions.contains(region) })
                ?? candidates.first(where: \.isDefault) else {
            throw Libre3PairingIdentitiesError.noIdentity(productType: productType, securityVersion: securityVersion)
        }
        return entry
    }

    private struct ProductSecurityVersion: Hashable {
        let productType: UInt8
        let securityVersion: UInt16
    }

    private struct IdentityFile: Decodable {
        let format: Int
        let curve: String
        let identities: [JSONEntry]
    }

    private struct JSONEntry: Decodable {
        let label: String
        let productType: UInt8
        let securityVersion: UInt16
        let regions: [UInt8]
        let isDefault: Bool
        let privateKeyHex: String
        let certificateHex: String

        enum CodingKeys: String, CodingKey {
            case label, productType, securityVersion, regions, privateKeyHex, certificateHex
            case isDefault = "default"
        }
    }

    private static func decodeHex(_ value: String, field: String) throws -> Data {
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty, bytes.count.isMultiple(of: 2) else {
            throw Libre3PairingIdentitiesError.invalidHex(field: field)
        }
        func nibble(_ byte: UInt8) throws -> UInt8 {
            switch byte {
            case 48...57: return byte - 48
            case 65...70: return byte - 65 + 10
            case 97...102: return byte - 97 + 10
            default: throw Libre3PairingIdentitiesError.invalidHex(field: field)
            }
        }
        var data = Data(capacity: bytes.count / 2)
        for index in stride(from: 0, to: bytes.count, by: 2) {
            let high = try nibble(bytes[index])
            let low = try nibble(bytes[index + 1])
            data.append((high << 4) | low)
        }
        return data
    }
}
