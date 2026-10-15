import XCTest
import Darwin
@testable import EZSwitchCore

final class RoutingSelfCheckTests: XCTestCase {
    func testMissingConnectionCannotBeReportedAsForbiddenProxy() {
        let mode = RoutingDecision(mode: .blocked, proxyInterface: nil, directInterface: nil)
        XCTAssertEqual(RoutingSelfCheck.assess(binding: nil, isDirect: true, decision: mode,
            physicalInterfaces: [], captureComplete: false), .unknown)
    }
    func testAutomaticGroupNodeChangesAreIncludedInDiagnosticSnapshot() throws {
        let data = try JSONSerialization.data(withJSONObject: ["proxies": [
            "Speed": ["type": "URLTest", "now": "A"],
            "Backup": ["type": "Fallback", "now": "B"],
            "Pick": ["type": "Selector", "now": "C"]]])
        XCTAssertEqual(try RoutingSelfCheck.diagnosticSelections(data), ["Speed": "A", "Backup": "B", "Pick": "C"])
        XCTAssertThrowsError(try RoutingSelfCheck.diagnosticSelections(Data("{}".utf8)))
    }
    func testDomainNormalizationAndDuplicateRejection() throws {
        XCTAssertEqual(try RoutingSiteList.normalize("  GitHub.COM.  "), "github.com")
        let defaults = UserDefaults(suiteName: "ez-sites-\(UUID())")!
        let list = RoutingSiteList(defaults: defaults)
        XCTAssertThrowsError(try list.add("GITHUB.COM"))
    }
    func testDomainInputRejectsCommandsURLsAndLocalAddresses() {
        for host in ["https://example.com", "a.com/path", "a.com:443", "a@b.com", "127.0.0.1", "::1", "localhost", "a.local", "a.com;id", "$(id).com", "-bad.com", "a..com", "中文.com"] {
            XCTAssertThrowsError(try RoutingSiteList.normalize(host), host)
        }
    }
    func testListPersistsRemovalAdditionAndEmptyList() throws {
        let defaults = UserDefaults(suiteName: "ez-sites-\(UUID())")!
        let list = RoutingSiteList(defaults: defaults)
        for site in list.sites { list.remove(host: site.host) }
        XCTAssertTrue(RoutingSiteList(defaults: defaults).sites.isEmpty)
        try list.add("example.com")
        XCTAssertEqual(RoutingSiteList(defaults: defaults).sites.map(\.host), ["example.com"])
    }
    func testProxyOnUnregisteredWifiFailsWhileDirectPasses() {
        let mode = RoutingDecision(mode: .directOnly, proxyInterface: nil, directInterface: "en0")
        XCTAssertEqual(RoutingSelfCheck.assess(binding: "en0", isDirect: false, decision: mode, physicalInterfaces: ["en0"], captureComplete: true), .fail)
        XCTAssertEqual(RoutingSelfCheck.assess(binding: "en0", isDirect: true, decision: mode, physicalInterfaces: ["en0"], captureComplete: true), .pass)
    }
    func testSplitChecksActualDirectAndProxyInterfaces() {
        let mode = RoutingDecision(mode: .split, proxyInterface: "en5", directInterface: "en0")
        XCTAssertEqual(RoutingSelfCheck.assess(binding: "en5", isDirect: false, decision: mode, physicalInterfaces: ["en5"], captureComplete: true), .pass)
        XCTAssertEqual(RoutingSelfCheck.assess(binding: "en5", isDirect: false, decision: mode, physicalInterfaces: ["en5", "en0"], captureComplete: true), .fail)
        XCTAssertEqual(RoutingSelfCheck.assess(binding: "en0", isDirect: true, decision: mode, physicalInterfaces: ["en0"], captureComplete: true), .pass)
    }
    func testMissingCaptureOrDropDoesNotPass() {
        let mode = RoutingDecision(mode: .usbHotspot, proxyInterface: "en5", directInterface: "en5")
        XCTAssertEqual(RoutingSelfCheck.assess(binding: "en5", isDirect: true, decision: mode, physicalInterfaces: [], captureComplete: true), .unknown)
        XCTAssertEqual(RoutingSelfCheck.assess(binding: "en5", isDirect: true, decision: mode, physicalInterfaces: ["en5"], captureComplete: false), .unknown)
        XCTAssertEqual(RoutingSelfCheck.assess(binding: nil, isDirect: true, decision: mode, physicalInterfaces: ["en5"], captureComplete: true), .unknown)
    }
    func testAggregateNeverConvertsPartialCoverageToPass() {
        XCTAssertEqual(RoutingSelfCheck.overall([.pass, .unknown]), .unknown)
        XCTAssertEqual(RoutingSelfCheck.overall([.pass, .fail, .unknown]), .fail)
        XCTAssertEqual(RoutingSelfCheck.overall([]), .unknown)
        XCTAssertEqual(RoutingSelfCheck.overall([.pass, .pass]), .pass)
    }
    func testPacketAssociationRequiresProcessDirectionAndExactEndpoint() {
        let packets = """
        12:00:00.1 (en5, Out, proc verge-mihomo:123) IP 172.20.10.2.53122 > 203.0.113.7.8443: tcp 50
        12:00:00.2 (en0, Out, proc browser:124) IP 192.0.2.2.52000 > 203.0.113.7.8443: tcp 50
        12:00:00.3 (en0, In, proc verge-mihomo:123) IP 203.0.113.7.8443 > 192.0.2.2.52000: tcp 50
        12:00:00.4 (en0, Out, proc verge-mihomo:123) IP 192.0.2.2.52000 > 203.0.113.70.8443: tcp 50
        """
        XCTAssertEqual(RoutingSelfCheck.physicalInterfaces(packets: packets, address: "203.0.113.7", port: 8443), ["en5"])
        XCTAssertTrue(RoutingSelfCheck.physicalInterfaces(packets: packets, address: "203.0.113.7", port: 443).isEmpty)
    }
    func testIpv6PhysicalEndpointIsParsed() {
        let line = "12:00:00.1 (en5, Out, proc verge-mihomo:123) IP6 2001:db8::2.53122 > 2001:db8::7.443: tcp 50"
        XCTAssertEqual(RoutingSelfCheck.physicalInterfaces(packets: line, address: "2001:db8::7", port: 443), ["en5"])
    }
    func testAppleMetadataOrderAndLowercaseDirectionAreAccepted() {
        let line = "12:00:00.1 (en5, proc verge-mihomo:123, out) IP 172.20.10.2.53122 > 203.0.113.7.8443: tcp 50"
        XCTAssertEqual(RoutingSelfCheck.physicalInterfaces(packets: line, address: "203.0.113.7", port: 8443), ["en5"])
    }
    func testEndpointRejectsAmbiguousNodeAddressesAndUnrelatedPorts() throws {
        func frame(_ address: String, port: String = "51000") throws -> Data {
            try JSONSerialization.data(withJSONObject: ["connections": [["id": "new", "metadata": [
                "sourceIP": "127.0.0.1", "sourcePort": port, "host": "example.com", "remoteDestination": address],
                "chains": ["Phone"], "rule": "DomainSuffix"]]])
        }
        let config = try JSONSerialization.data(withJSONObject: ["proxies": [["name": "Phone", "type": "trojan", "port": 8443]]])
        let found = try RoutingWebsiteEndpoint.find(host: "example.com", localPort: 51000, previousIDs: [],
            observations: [frame("203.0.113.7")], configuration: config)
        XCTAssertEqual(found?.address, "203.0.113.7")
        XCTAssertEqual(found?.port, 8443)
        XCTAssertNil(try RoutingWebsiteEndpoint.find(host: "example.com", localPort: 51000, previousIDs: [],
            observations: [frame("203.0.113.7"), frame("203.0.113.8")], configuration: config))
        XCTAssertNil(try RoutingWebsiteEndpoint.find(host: "example.com", localPort: 51000, previousIDs: [],
            observations: [frame("203.0.113.7", port: "51001")], configuration: config))
    }
    func testCapturePreparationCreatesReadableFilesWithRealMacOSACL() async throws {
        let id = UUID()
        let command = try RoutingCaptureCommand.make(interfaces: ["en0"], uid: getuid(), id: id)
        let start = try XCTUnwrap(command.range(of: "/usr/sbin/tcpdump -i"))
        // Execute only mkdir/chmod/trap on our own temporary files, never tcpdump or administrator work.
        let prepare = String(command[..<start.lowerBound]) + "\n/bin/test -r '\(RoutingCaptureCommand.directory(id))/status'\nEZ_CAPTURE_SCRIPT\n"
        let result = try await ProcessRunner.run(executable: "/bin/sh", arguments: ["-c", prepare])
        XCTAssertEqual(result.exitCode, 0, result.output)
        XCTAssertFalse(FileManager.default.fileExists(atPath: RoutingCaptureCommand.directory(id)))
    }
    func testCaptureEndReturnsStatisticsWithoutPacketPayload() async throws {
        let id = UUID()
        let stub = URL(fileURLWithPath: "/private/tmp/ez-capture-stub-\(UUID()).sh")
        defer { try? FileManager.default.removeItem(at: stub) }
        try """
        /bin/echo 'PRIVATE_PACKET_PAYLOAD'
        /usr/bin/printf '%s\\n' 'listening on pktap' '1 packet captured' '1 packet received by filter' '0 packets dropped by kernel' >&2
        """.write(to: stub, atomically: true, encoding: .utf8)
        var command = try RoutingCaptureCommand.make(interfaces: ["en0"], uid: getuid(), id: id)
        let start = try XCTUnwrap(command.range(of: "/usr/sbin/tcpdump -i"))
        let end = try XCTUnwrap(command.range(of: "\nc=$!", range: start.lowerBound..<command.endIndex))
        // Replace only the external capture process; execute our actual preparation, stopping and cleanup.
        let directory = RoutingCaptureCommand.directory(id)
        command.replaceSubrange(start.lowerBound..<end.lowerBound,
            with: "/bin/sh '\(stub.path)' > '\(directory)/packets' 2> '\(directory)/status' &")
        let result = try await ProcessRunner.run(executable: "/bin/sh", arguments: ["-c", command], timeout: 5)
        XCTAssertEqual(result.exitCode, 0, result.output)
        XCTAssertFalse(result.output.contains("PRIVATE_PACKET_PAYLOAD"))
        XCTAssertEqual(RoutingCaptureOutcome.parse(result), .complete)
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory))
    }
    func testRunningCaptureCanStopGracefullyWhenInterruptIsUnavailable() async throws {
        let result = try await runWaitingCapture(ignoresTermination: false)
        XCTAssertEqual(result.exitCode, 0, result.output)
        XCTAssertEqual(RoutingCaptureOutcome.parse(result), .complete, result.output)
    }
    func testRunningCaptureIgnoringBothStopSignalsRemainsIncomplete() async throws {
        let result = try await runWaitingCapture(ignoresTermination: true)
        XCTAssertEqual(result.exitCode, 0, result.output)
        XCTAssertEqual(RoutingCaptureOutcome.parse(result), .forcedTermination, result.output)
    }
    func testGracefulStopDoesNotHideCaptureFailure() async throws {
        let result = try await runWaitingCapture(ignoresTermination: false, exitCode: 1)
        XCTAssertEqual(result.exitCode, 0, result.output)
        XCTAssertEqual(RoutingCaptureOutcome.parse(result), .captureFailed, result.output)
    }
    func testBlockedAndIgnoredAdministratorSignalsAreResetBeforeCapture() async throws {
        let result = try await runWaitingCapture(ignoresTermination: false, inheritedSignals: true)
        XCTAssertEqual(RoutingCaptureOutcome.parse(result), .complete, result.output)
    }

    private func runWaitingCapture(ignoresTermination: Bool, exitCode: Int = 0, inheritedSignals: Bool = false) async throws -> ProcessResult {
        let id = UUID()
        let stub = URL(fileURLWithPath: "/private/tmp/ez-capture-wait-\(UUID()).sh")
        defer { try? FileManager.default.removeItem(at: stub) }
        let stats = "/usr/bin/printf '%s\\n' '1 packet captured' '1 packet received by filter' '0 packets dropped by kernel' >&2"
        let termination = ignoresTermination ? "trap '' TERM\n" + stats : "trap \"\(stats); exit \(exitCode)\" TERM"
        try """
        trap '' INT
        \(termination)
        /bin/echo 'listening on pktap' >&2
        : > '\(RoutingCaptureCommand.stopFile(id))'
        while :; do /bin/sleep 0.05; done
        """.write(to: stub, atomically: true, encoding: .utf8)
        var command = try RoutingCaptureCommand.make(interfaces: ["en0"], uid: getuid(), id: id)
        let start = try XCTUnwrap(command.range(of: "/usr/sbin/tcpdump -i"))
        let end = try XCTUnwrap(command.range(of: "\nc=$!", range: start.lowerBound..<command.endIndex))
        let directory = RoutingCaptureCommand.directory(id)
        // Substitute only live packet collection; our actual shell owns signaling, wait and cleanup.
        command.replaceSubrange(start.lowerBound..<end.lowerBound,
            with: "/bin/sh '\(stub.path)' > '\(directory)/packets' 2> '\(directory)/status' &")
        let launcher = #"$SIG{TERM}='IGNORE'; $SIG{HUP}='IGNORE'; $SIG{CHLD}='IGNORE'; POSIX::sigprocmask(POSIX::SIG_BLOCK(), POSIX::SigSet->new(POSIX::SIGINT(), POSIX::SIGTERM(), POSIX::SIGHUP(), POSIX::SIGCHLD())) or die; exec '/bin/sh', '-c', $ARGV[0] or die;"#
        let result = try await ProcessRunner.run(executable: inheritedSignals ? "/usr/bin/perl" : "/bin/sh",
            arguments: inheritedSignals ? ["-MPOSIX", "-e", launcher, command] : ["-c", command], timeout: 10)
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory))
        XCTAssertFalse(FileManager.default.fileExists(atPath: RoutingCaptureCommand.stopFile(id)))
        return result
    }
    func testCaptureCommandRejectsUnsafeInterfaces() {
        XCTAssertThrowsError(try RoutingCaptureCommand.make(interfaces: ["en0;id"], uid: 501, id: UUID()))
        XCTAssertThrowsError(try RoutingCaptureCommand.make(interfaces: [], uid: 501, id: UUID()))
        XCTAssertThrowsError(try RoutingCaptureCommand.make(interfaces: ["en0"], uid: 0, id: UUID()))
    }
    func testGeneratedCaptureCommandParsesWithoutExecutingPrivilegedWork() async throws {
        let command = try RoutingCaptureCommand.make(interfaces: ["en5", "en0"], uid: 501, id: UUID())
        let shell = URL(fileURLWithPath: "/private/tmp/ez-capture-syntax-\(UUID()).sh")
        let compiled = shell.appendingPathExtension("scpt")
        defer { try? FileManager.default.removeItem(at: shell); try? FileManager.default.removeItem(at: compiled) }
        try command.write(to: shell, atomically: true, encoding: .utf8)
        let result = try await ProcessRunner.run(executable: "/bin/sh", arguments: ["-n", shell.path])
        XCTAssertEqual(result.exitCode, 0, result.output)
        let escaped = command.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let appleScript = "do shell script \"\(escaped)\" with administrator privileges with prompt \"EZ Switch\""
        let parsed = try await ProcessRunner.run(executable: "/usr/bin/osacompile", arguments: ["-o", compiled.path, "-e", appleScript])
        XCTAssertEqual(parsed.exitCode, 0, parsed.output)
    }
}
