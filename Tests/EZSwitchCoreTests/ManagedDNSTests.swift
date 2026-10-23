import Foundation
import XCTest
@testable import EZSwitchCore

@MainActor final class ManagedDNSTests: XCTestCase {
    // These tests catch losing DHCP/manual settings, adopting someone else's edit,
    // missing crash recovery, and writing before the recovery record is durable.
    func testDHCPRestoredAfterTakeoverAndRestart() throws {
        let backend = DNSBackendFixture()
        let journal = temporaryJournal(); defer { try? FileManager.default.removeItem(at: journal.deletingLastPathComponent()) }
        let manager = ManagedDNS(backend: backend, journalURL: journal)
        try manager.synchronize(interface: "en6", address: "198.18.0.2")
        XCTAssertEqual(try addresses(backend.settings), ["198.18.0.2"])
        XCTAssertTrue(FileManager.default.fileExists(atPath: journal.path))
        // A new object uses the durable record rather than backing up its own DNS.
        let restarted = ManagedDNS(backend: backend, journalURL: journal)
        try restarted.restore()
        XCTAssertNil(backend.settings)
        XCTAssertFalse(FileManager.default.fileExists(atPath: journal.path))
    }
    func testManualSettingsAndSearchDomainsSurviveIdempotentTakeover() throws {
        let backend = DNSBackendFixture()
        backend.settings = try plist(["ServerAddresses": ["9.9.9.9", "2001:4860:4860::8888"], "SearchDomains": ["example.test"]])
        let original = backend.settings
        let journal = temporaryJournal(); defer { try? FileManager.default.removeItem(at: journal.deletingLastPathComponent()) }
        let manager = ManagedDNS(backend: backend, journalURL: journal)
        try manager.synchronize(interface: "en6", address: "198.18.0.2")
        try manager.synchronize(interface: "en6", address: "198.18.0.2")
        XCTAssertEqual(backend.writes, 1)
        XCTAssertEqual(try dictionary(backend.settings)?["SearchDomains"] as? [String], ["example.test"])
        try manager.restore()
        XCTAssertTrue(ManagedDNS.equivalent(backend.settings, original))
    }
    func testExternalEditIsNotOverwrittenOnRestore() throws {
        let backend = DNSBackendFixture()
        let journal = temporaryJournal(); defer { try? FileManager.default.removeItem(at: journal.deletingLastPathComponent()) }
        let manager = ManagedDNS(backend: backend, journalURL: journal)
        try manager.synchronize(interface: "en6", address: "198.18.0.2")
        backend.settings = try plist(["ServerAddresses": ["8.8.8.8"]])
        XCTAssertThrowsError(try manager.synchronize(interface: "en6", address: "198.18.0.2"))
        try manager.restore()
        XCTAssertEqual(try addresses(backend.settings), ["8.8.8.8"])
        XCTAssertEqual(backend.writes, 1)
    }
    func testFailedApplyKeepsOriginalForRecovery() throws {
        let backend = DNSBackendFixture(); backend.failAfterWrite = true
        let journal = temporaryJournal(); defer { try? FileManager.default.removeItem(at: journal.deletingLastPathComponent()) }
        let manager = ManagedDNS(backend: backend, journalURL: journal)
        XCTAssertThrowsError(try manager.synchronize(interface: "en6", address: "198.18.0.2"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: journal.path))
        backend.failAfterWrite = false
        try ManagedDNS(backend: backend, journalURL: journal).restore()
        XCTAssertNil(backend.settings)
    }
    func testRestoreRetriesApplyAfterCommitSucceededButApplyFailed() throws {
        let backend = DNSBackendFixture()
        let journal = temporaryJournal(); defer { try? FileManager.default.removeItem(at: journal.deletingLastPathComponent()) }
        let manager = ManagedDNS(backend: backend, journalURL: journal)
        try manager.synchronize(interface: "en6", address: "198.18.0.2")
        backend.failAfterWrite = true
        XCTAssertThrowsError(try manager.restore())
        XCTAssertNil(backend.settings) // Saved preferences restored, running resolver not notified.
        XCTAssertTrue(FileManager.default.fileExists(atPath: journal.path))
        backend.failAfterWrite = false
        try ManagedDNS(backend: backend, journalURL: journal).restore()
        XCTAssertEqual(backend.writes, 3) // takeover, failed restore, retry commit+apply
        XCTAssertFalse(FileManager.default.fileExists(atPath: journal.path))
    }
    func testDeniedInitialAuthorizationDoesNotLeaveFalseRecoveryObligation() throws {
        let backend = DNSBackendFixture(); backend.denyBeforeWrite = true
        let journal = temporaryJournal(); defer { try? FileManager.default.removeItem(at: journal.deletingLastPathComponent()) }
        let manager = ManagedDNS(backend: backend, journalURL: journal)
        XCTAssertThrowsError(try manager.synchronize(interface: "en6", address: "198.18.0.2"))
        XCTAssertNil(backend.settings)
        XCTAssertFalse(FileManager.default.fileExists(atPath: journal.path))
        try manager.restore()
        XCTAssertEqual(backend.writes, 0)
    }
    func testJournalFailurePreventsSystemWrite() throws {
        let backend = DNSBackendFixture()
        let directory = temporaryJournal().deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("file")
        try Data().write(to: file)
        let manager = ManagedDNS(backend: backend, journalURL: file.appendingPathComponent("impossible"))
        XCTAssertThrowsError(try manager.synchronize(interface: "en6", address: "198.18.0.2"))
        XCTAssertEqual(backend.writes, 0)
    }
    func testServiceIdentityMismatchPreventsRestoreToReplacementDevice() throws {
        let backend = DNSBackendFixture()
        let journal = temporaryJournal(); defer { try? FileManager.default.removeItem(at: journal.deletingLastPathComponent()) }
        let manager = ManagedDNS(backend: backend, journalURL: journal)
        try manager.synchronize(interface: "en6", address: "198.18.0.2")
        backend.interface = "en9"
        XCTAssertThrowsError(try manager.restore())
        XCTAssertEqual(backend.writes, 1)
        XCTAssertTrue(FileManager.default.fileExists(atPath: journal.path))
    }
    func testNoUSBRestoresInsteadOfChangingWiFi() throws {
        let backend = DNSBackendFixture()
        let journal = temporaryJournal(); defer { try? FileManager.default.removeItem(at: journal.deletingLastPathComponent()) }
        let manager = ManagedDNS(backend: backend, journalURL: journal)
        try manager.synchronize(interface: "en6", address: "198.18.0.2")
        try manager.synchronize(interface: nil, address: nil)
        XCTAssertNil(backend.settings)
        XCTAssertEqual(backend.touchedServices, ["usb-service", "usb-service"])
    }
    func testRuntimeTUNDNSUsesActualAddressAndRejectsUnusableConfiguration() throws {
        let runtime = try JSONSerialization.data(withJSONObject: ["tun": ["enable": true, "auto-route": true,
            "dns-hijack": ["any:53"], "inet4-address": ["198.19.0.1/30"]]])
        XCTAssertEqual(try TunnelDNSAddress.resolve(runtime), "198.19.0.2")
        for tun: [String: Any] in [
            ["enable": false, "inet4-address": ["198.18.0.1/30"]],
            ["enable": true, "auto-route": true, "dns-hijack": [], "inet4-address": ["198.18.0.1/30"]],
            ["enable": true, "auto-route": true, "dns-hijack": ["any:53"], "inet4-address": ["198.18.0.1/32"]]
        ] {
            XCTAssertThrowsError(try TunnelDNSAddress.resolve(JSONSerialization.data(withJSONObject: ["tun": tun])))
        }
    }
    private func temporaryJournal() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("ez-dns-test-\(UUID())/dns.json")
    }
    private func plist(_ value: [String: Any]) throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: value, format: .binary, options: 0)
    }
    private func dictionary(_ value: Data?) throws -> [String: Any]? {
        try value.map { try PropertyListSerialization.propertyList(from: $0, format: nil) as! [String: Any] }
    }
    private func addresses(_ value: Data?) throws -> [String]? { try dictionary(value)?["ServerAddresses"] as? [String] }
}

@MainActor private final class DNSBackendFixture: ManagedDNSBackend {
    var settings: Data?
    var interface = "en6"
    var writes = 0
    var touchedServices: [String] = []
    var failAfterWrite = false
    var denyBeforeWrite = false
    func service(for interface: String) throws -> DNSService {
        guard interface == self.interface else { throw ManagedDNSError.serviceUnavailable }
        return DNSService(id: "usb-service", interface: interface, configuration: settings)
    }
    func service(id: String) throws -> DNSService? {
        DNSService(id: id, interface: interface, configuration: settings)
    }
    func replace(_ service: DNSService, with configuration: Data?) throws {
        if denyBeforeWrite { throw ManagedDNSError.authorizationDenied }
        guard service.id == "usb-service", service.interface == interface,
              ManagedDNS.equivalent(service.configuration, settings) else { throw ManagedDNSError.changedExternally }
        writes += 1; touchedServices.append(service.id); settings = configuration
        if failAfterWrite { throw ManagedDNSError.writeFailed }
    }
}

@MainActor final class DNSRoutingControllerTests: XCTestCase {
    func testUSBVerifiedBeforeDNSAndTunnelOffRestores() async throws {
        let backend = DNSBackendFixture(); let controller = DNSControllerFixture()
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("ez-dns-controller-\(UUID())/dns.json")
        defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
        let dns = ManagedDNS(backend: backend, journalURL: file)
        let wrapped = DNSRoutingController(controller: controller, dns: dns, runtime: { try self.runtime() }, selectedUSB: { "en6" })
        controller.verified = false
        let unverified = try await wrapped.verify(configuration: configuration(), shouldContinue: { true })
        XCTAssertFalse(unverified); XCTAssertNil(backend.settings)
        controller.verified = true
        let verified = try await wrapped.verify(configuration: configuration(), shouldContinue: { true })
        XCTAssertTrue(verified); XCTAssertNotNil(backend.settings)
        controller.tun = false
        let enabled = try await wrapped.tunnelEnabled()
        XCTAssertFalse(enabled); XCTAssertNil(backend.settings)
    }
    func testRuntimeYieldDoesNotApplyDNSAfterUSBChanges() async throws {
        let backend = DNSBackendFixture(); let controller = DNSControllerFixture()
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("ez-dns-controller-\(UUID())/dns.json")
        defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
        let dns = ManagedDNS(backend: backend, journalURL: file)
        var usb: String? = "en6"
        let wrapped = DNSRoutingController(controller: controller, dns: dns, runtime: {
            usb = nil; return try self.runtime()
        }, selectedUSB: { usb })
        let result = try await wrapped.verify(configuration: configuration(), shouldContinue: { usb != nil })
        XCTAssertFalse(result); XCTAssertNil(backend.settings)
    }
    func testOffAndBlockedConfigurationRestoreDNS() async throws {
        let backend = DNSBackendFixture(); let controller = DNSControllerFixture()
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("ez-dns-controller-\(UUID())/dns.json")
        defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
        let dns = ManagedDNS(backend: backend, journalURL: file)
        var usb: String? = "en6"
        let wrapped = DNSRoutingController(controller: controller, dns: dns, runtime: { try self.runtime() }, selectedUSB: { usb })
        _ = try await wrapped.verify(configuration: configuration(), shouldContinue: { true })
        usb = nil
        _ = try await wrapped.verify(configuration: configuration(), shouldContinue: { true })
        XCTAssertNil(backend.settings)
        usb = "en6"
        _ = try await wrapped.verify(configuration: configuration(), shouldContinue: { true })
        let blocked = try JSONSerialization.data(withJSONObject: ["mode": "rule", "interface-name": "en6", "proxies": []])
        _ = try await wrapped.verify(configuration: blocked, shouldContinue: { true })
        XCTAssertNil(backend.settings)
    }
    func testUnreachableCoreRestoresDNS() async throws {
        let backend = DNSBackendFixture(); let controller = DNSControllerFixture()
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("ez-dns-controller-\(UUID())/dns.json")
        defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
        let dns = ManagedDNS(backend: backend, journalURL: file)
        let wrapped = DNSRoutingController(controller: controller, dns: dns, runtime: { try self.runtime() }, selectedUSB: { "en6" })
        _ = try await wrapped.verify(configuration: configuration(), shouldContinue: { true })
        controller.unavailable = true
        do { _ = try await wrapped.tunnelEnabled(); XCTFail("Expected unavailable controller") } catch {}
        XCTAssertNil(backend.settings)
    }
    private func configuration() throws -> Data {
        try JSONSerialization.data(withJSONObject: ["mode": "rule", "interface-name": "en6", "proxies": [["type": "trojan"]]])
    }
    private func runtime() throws -> Data {
        try JSONSerialization.data(withJSONObject: ["tun": ["enable": true, "auto-route": true,
            "dns-hijack": ["any:53"], "inet4-address": ["198.18.0.1/30"]]])
    }
}

@MainActor private final class DNSControllerFixture: RoutingController {
    var tun = true; var verified = true; var unavailable = false
    func tunnelEnabled() async throws -> Bool {
        if unavailable { throw MihomoClientError.unavailable }
        return tun
    }
    func apply(configuration: Data) async throws {}
    func closeConnections() async throws {}
    func flushDNS() async throws {}
    func selections() async throws -> [String: String] { [:] }
    func restoreSelections(_ selections: [String: String], configuration: Data,
                           shouldContinue: @escaping @MainActor () async throws -> Bool) async throws -> Bool { try await shouldContinue() }
    func verify(configuration: Data, shouldContinue: @escaping @MainActor () async throws -> Bool) async throws -> Bool {
        guard verified else { return false }
        return try await shouldContinue()
    }
}
