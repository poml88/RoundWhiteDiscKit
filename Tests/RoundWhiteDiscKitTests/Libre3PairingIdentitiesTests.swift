import XCTest
import CryptoKit
@testable import RoundWhiteDiscKit

final class Libre3PairingIdentitiesTests: XCTestCase {
    func testSelectsExplicitRegionBeforeDefault() throws {
        let row = try Fixture()
        let us = try Fixture()
        let identities = try load([
            row.json(label: "ROW", regions: [1, 4, 8], isDefault: true),
            us.json(label: "US", regions: [2], isDefault: false),
        ])

        for region in [UInt8(1), 4, 8] {
            let selected = try identities.identity(productType: 4, securityVersion: 1, region: region)
            XCTAssertEqual(selected.label, "ROW")
            XCTAssertEqual(selected.identity.phoneCert, row.identity.phoneCert)
        }
        let selected = try identities.identity(productType: 4, securityVersion: 1, region: 2)
        XCTAssertEqual(selected.label, "US")
        XCTAssertEqual(selected.identity.phoneCert, us.identity.phoneCert)
    }

    func testUnlistedAndUnknownRegionsUseDefault() throws {
        let row = try Fixture()
        let us = try Fixture()
        let identities = try load([
            row.json(label: "ROW", regions: [1], isDefault: true),
            us.json(label: "US", regions: [2], isDefault: false),
        ])

        for region in [UInt8(0), 4, 8, 127, 255] {
            let selected = try identities.identity(productType: 4, securityVersion: 1, region: region)
            XCTAssertEqual(selected.label, "ROW")
            XCTAssertEqual(selected.identity.phoneCert, row.identity.phoneCert)
        }
    }

    func testSelectionStaysWithinProductAndSecurityVersion() throws {
        let first = try Fixture()
        let otherVersion = try Fixture()
        let otherProduct = try Fixture()
        let identities = try load([
            first.json(label: "first", regions: [1], isDefault: true),
            otherVersion.json(label: "version", securityVersion: 0x1234, regions: [1], isDefault: true),
            otherProduct.json(label: "product", productType: 5, regions: [1], isDefault: true),
        ])

        let version = try identities.identity(productType: 4, securityVersion: 0x1234, region: 1)
        XCTAssertEqual(version.label, "version")
        XCTAssertEqual(version.identity.phoneCert, otherVersion.identity.phoneCert)
        let product = try identities.identity(productType: 5, securityVersion: 1, region: 1)
        XCTAssertEqual(product.label, "product")
        XCTAssertEqual(product.identity.phoneCert, otherProduct.identity.phoneCert)
        for (productType, securityVersion) in [(UInt8(4), UInt16(2)), (UInt8(6), UInt16(1))] {
            XCTAssertThrowsError(try identities.identity(productType: productType, securityVersion: securityVersion, region: 1)) {
                XCTAssertEqual($0 as? Libre3PairingIdentitiesError, .noIdentity(productType: productType, securityVersion: securityVersion))
            }
        }
    }

    func testRequiresExactlyOneDefaultPerGroup() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try load([fixture.json(label: "missing", regions: [1], isDefault: false)])) {
            XCTAssertEqual($0 as? Libre3PairingIdentitiesError, .invalidDefaultCount(productType: 4, securityVersion: 1, count: 0))
        }
        XCTAssertThrowsError(try load([
            fixture.json(label: "first", regions: [1], isDefault: true),
            fixture.json(label: "second", regions: [2], isDefault: true),
        ])) {
            XCTAssertEqual($0 as? Libre3PairingIdentitiesError, .invalidDefaultCount(productType: 4, securityVersion: 1, count: 2))
        }
        // A valid group's default cannot satisfy a different group's requirement.
        XCTAssertThrowsError(try load([
            fixture.json(label: "valid", regions: [1], isDefault: true),
            fixture.json(label: "missing", securityVersion: 2, regions: [1], isDefault: false),
        ])) {
            XCTAssertEqual($0 as? Libre3PairingIdentitiesError, .invalidDefaultCount(productType: 4, securityVersion: 2, count: 0))
        }
    }

    func testAppsCanSupplyValidatedIdentities() throws {
        let fixture = try Fixture()
        let identities = try Libre3PairingIdentities(entries: [
            .init(label: "app", productType: 4, securityVersion: 1, regions: [], isDefault: true, identity: fixture.identity),
        ])
        let selected = try identities.identity(productType: 4, securityVersion: 1, region: 2)
        XCTAssertEqual(selected.label, "app")
        XCTAssertEqual(selected.identity.phoneCert, fixture.identity.phoneCert)
        XCTAssertThrowsError(try Libre3PairingIdentities(entries: [
            .init(label: "app", productType: 4, securityVersion: 1, regions: [], isDefault: false, identity: fixture.identity),
        ])) {
            XCTAssertEqual($0 as? Libre3PairingIdentitiesError, .invalidDefaultCount(productType: 4, securityVersion: 1, count: 0))
        }
    }

    func testRejectsUnsupportedFormatAndCurve() throws {
        XCTAssertThrowsError(try load([], format: 2)) {
            XCTAssertEqual($0 as? Libre3PairingIdentitiesError, .unsupportedFormat(2))
        }
        XCTAssertThrowsError(try load([], curve: "P-384")) {
            XCTAssertEqual($0 as? Libre3PairingIdentitiesError, .unsupportedCurve("P-384"))
        }
    }

    func testRejectsMalformedJSONAndMissingFields() {
        for json in ["{", #"{"format":1,"curve":"P-256"}"#, #"{"format":1,"curve":"P-256","identities":[{}]}"#] {
            XCTAssertThrowsError(try Libre3PairingIdentities(jsonData: Data(json.utf8))) {
                XCTAssertEqual($0 as? Libre3PairingIdentitiesError, .invalidJSON)
            }
        }
    }

    func testValidatesHexAndPrivateKeyAgainstCertificate() throws {
        let fixture = try Fixture()
        for invalid in ["", "0", "gg", "+1"] {
            XCTAssertThrowsError(try load([
                fixture.json(label: "bad", regions: [1], isDefault: true, privateKeyHex: invalid),
            ])) {
                XCTAssertEqual($0 as? Libre3PairingIdentitiesError, .invalidHex(field: "privateKeyHex"))
            }
        }
        XCTAssertThrowsError(try load([
            fixture.json(label: "bad", regions: [1], isDefault: true, certificateHex: "gg"),
        ])) {
            XCTAssertEqual($0 as? Libre3PairingIdentitiesError, .invalidHex(field: "certificateHex"))
        }
        XCTAssertThrowsError(try load([
            fixture.json(label: "mismatch", regions: [1], isDefault: true, privateKeyHex: P256.KeyAgreement.PrivateKey().rawRepresentation.hex),
        ])) {
            XCTAssertEqual($0 as? PlainPairingError, .staticPrivateKeyDoesNotMatchCertificate)
        }
        XCTAssertThrowsError(try load([
            fixture.json(label: "zero", regions: [1], isDefault: true, privateKeyHex: Data(count: 32).hex),
        ])) {
            XCTAssertEqual($0 as? PlainPairingError, .invalidStaticPrivateKey)
        }
        XCTAssertNoThrow(try load([
            fixture.json(label: "uppercase", regions: [1], isDefault: true,
                         privateKeyHex: fixture.identity.staticPrivateKey.rawRepresentation.hex.uppercased(),
                         certificateHex: fixture.identity.phoneCert.raw.hex.uppercased()),
        ]))
    }

    func testBundledIdentityFileLoadsWhenPresent() throws {
        let identities: Libre3PairingIdentities
        do {
            identities = try Libre3PairingIdentities.bundled()
        } catch Libre3PairingIdentitiesError.identityFileMissing {
            throw XCTSkip("RWDKAppIdentities.json is not bundled in this checkout")
        }
        // Loading validates every real key/certificate pair. Assert only metadata
        // and sizes so a failure cannot print any real key or certificate bytes.
        XCTAssertFalse(identities.entries.isEmpty)
        for entry in identities.entries {
            let selected = try identities.identity(
                productType: entry.productType,
                securityVersion: entry.securityVersion,
                region: entry.regions.first ?? 0
            )
            XCTAssertEqual(selected.label, entry.label)
            XCTAssertEqual(selected.identity.phoneCert.raw.count, PhoneCert.totalSize)
        }
    }

    private func load(_ entries: [String], format: Int = 1, curve: String = "P-256") throws -> Libre3PairingIdentities {
        let json = """
        {"format":\(format),"curve":"\(curve)","identities":[\(entries.joined(separator: ","))]}
        """
        return try Libre3PairingIdentities(jsonData: Data(json.utf8))
    }

    /// All inline fixtures use freshly generated keys and synthetic certificates.
    private struct Fixture {
        let identity: PlainPairingIdentity

        init() throws {
            let key = P256.KeyAgreement.PrivateKey()
            let raw = Data([0x03, 0x00]) + Data(count: 31) + key.publicKey.x963Representation + Data(count: 64)
            identity = try PlainPairingIdentity(phoneCert: PhoneCert(raw: raw), staticPrivateKey: key)
        }

        func json(
            label: String,
            productType: UInt8 = 4,
            securityVersion: UInt16 = 1,
            regions: [UInt8],
            isDefault: Bool,
            privateKeyHex: String? = nil,
            certificateHex: String? = nil
        ) -> String {
            """
            {"label":"\(label)","productType":\(productType),"securityVersion":\(securityVersion),"regions":\(regions),"default":\(isDefault),"privateKeyHex":"\(privateKeyHex ?? identity.staticPrivateKey.rawRepresentation.hex)","certificateHex":"\(certificateHex ?? identity.phoneCert.raw.hex)"}
            """
        }
    }
}
