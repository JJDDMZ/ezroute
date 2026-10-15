import XCTest
@testable import EZSwitchCore

final class ClashBootstrapTests: XCTestCase {
    func testDefaultGlobalAndOwnedLegacyAreInstalledOnceAndBackedUp() throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let profiles = root.appendingPathComponent("profiles"); try FileManager.default.createDirectory(at: profiles, withIntermediateDirectories: true)
        let global = profiles.appendingPathComponent("Script.js"), local = profiles.appendingPathComponent("local.js")
        let original = "// user template\nfunction main(config, profileName) { return config; }\n"
        try Data(original.utf8).write(to: global); try Data("owned-legacy".utf8).write(to: local)
        let registry = Data(#"{"current":"A","items":[{"uid":"Script","type":"script","file":"Script.js"},{"uid":"S","type":"script","file":"local.js"},{"uid":"A","type":"remote","option":{"script":"S"}}]}"#.utf8)
        let backup = root.appendingPathComponent("backup")
        let first = try ClashBootstrap.install(directory: root, registry: registry, backupDirectory: backup,
            script: "managed", ownedLegacy: "owned-legacy")
        XCTAssertTrue(first)
        XCTAssertEqual(try String(contentsOf: global, encoding: .utf8), "managed")
        XCTAssertEqual(try String(contentsOf: local, encoding: .utf8), ClashBootstrap.identityScript)
        XCTAssertEqual(try String(contentsOf: backup.appendingPathComponent("global-original.js"), encoding: .utf8), original)
        XCTAssertEqual(try String(contentsOf: backup.appendingPathComponent("legacy-S.js"), encoding: .utf8), "owned-legacy")
        XCTAssertFalse(try ClashBootstrap.install(directory: root, registry: registry, backupDirectory: backup,
            script: "managed", ownedLegacy: "owned-legacy"))
        XCTAssertTrue(try ClashBootstrap.install(directory: root, registry: registry, backupDirectory: backup,
            script: "managed-v2", ownedLegacy: "owned-legacy"))
    }
    func testCustomGlobalIsPreservedAndInstallationRefused() throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let profiles = root.appendingPathComponent("profiles"); try FileManager.default.createDirectory(at: profiles, withIntermediateDirectories: true)
        let file = profiles.appendingPathComponent("Script.js")
        try Data("function main(config) { config.rules = []; return config; }".utf8).write(to: file)
        XCTAssertThrowsError(try ClashBootstrap.install(directory: root, registry: registry,
            backupDirectory: root.appendingPathComponent("backup"), script: "managed", ownedLegacy: "owned"))
        XCTAssertTrue(try String(contentsOf: file, encoding: .utf8).contains("config.rules"))
    }
    func testCustomLocalAndSymlinkCannotBeOverwritten() throws {
        let root = try temporary(); defer { try? FileManager.default.removeItem(at: root) }
        let profiles = root.appendingPathComponent("profiles"); try FileManager.default.createDirectory(at: profiles, withIntermediateDirectories: true)
        let global = profiles.appendingPathComponent("Script.js")
        try Data(ClashBootstrap.identityScript.utf8).write(to: global)
        let local = profiles.appendingPathComponent("local.js"); try Data("custom".utf8).write(to: local)
        let custom = Data(#"{"current":"A","items":[{"uid":"Script","type":"script","file":"Script.js"},{"uid":"S","type":"script","file":"local.js"},{"uid":"A","option":{"script":"S"}}]}"#.utf8)
        XCTAssertThrowsError(try ClashBootstrap.install(directory: root, registry: custom,
            backupDirectory: root.appendingPathComponent("backup"), script: "managed", ownedLegacy: "owned"))
        XCTAssertEqual(try String(contentsOf: global, encoding: .utf8), ClashBootstrap.identityScript)
        try FileManager.default.removeItem(at: global)
        try FileManager.default.createSymbolicLink(at: global, withDestinationURL: local)
        XCTAssertThrowsError(try ClashBootstrap.install(directory: root, registry: registry,
            backupDirectory: root.appendingPathComponent("backup"), script: "managed", ownedLegacy: "owned"))
        XCTAssertEqual(try String(contentsOf: local, encoding: .utf8), "custom")
    }
    private var registry: Data { Data(#"{"current":"A","items":[{"uid":"Script","type":"script","file":"Script.js"},{"uid":"A","option":{"script":"Script"}}]}"#.utf8) }
    private func temporary() throws -> URL {
        let root = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("ez-bootstrap-tests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true); return root
    }
}
