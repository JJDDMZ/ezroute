import XCTest
@testable import EZSwitchCore

@MainActor final class MihomoClientTests: XCTestCase {
    func testUnixRequestUsesLocalHostAndReturnsLargeResponseWithoutTruncation() async throws {
        let server = try LocalController(status: 200, body: String(repeating: "x", count: 90_000))
        defer { server.stop() }
        let client = MihomoClient(socketPath: server.socket.path, temporaryRoot: server.directory)
        let response = try await client.read(path: "/configs")
        XCTAssertEqual(response.count, 90_000)
        let request = try server.request()
        XCTAssertEqual(request["host"] as? String, "localhost")
        XCTAssertEqual(request["method"] as? String, "GET")
        XCTAssertEqual(request["path"] as? String, "/configs")
        XCTAssertEqual(request["authorization"] as? String, "")
        XCTAssertFalse(server.hasRemainingRequests())
    }

    func testFullReloadTransmitsPayloadAndPinsControllerToSameSocket() async throws {
        let server = try LocalController(status: 204, body: "")
        defer { server.stop() }
        let client = MihomoClient(socketPath: server.socket.path, temporaryRoot: server.directory)
        try await client.apply(configuration: Data("{\"mode\":\"direct\",\"secret\":\"test-secret\"}".utf8))
        let request = try server.request()
        XCTAssertEqual(request["method"] as? String, "PUT")
        XCTAssertEqual(request["path"] as? String, "/configs?force=true")
        let body = try JSONSerialization.jsonObject(with: Data((request["body"] as! String).utf8)) as! [String: Any]
        let payload = try JSONSerialization.jsonObject(with: Data((body["payload"] as! String).utf8)) as! [String: Any]
        XCTAssertEqual(payload["mode"] as? String, "direct")
        XCTAssertEqual(payload["external-controller-unix"] as? String, server.socket.path)
        XCTAssertEqual(payload["secret"] as? String, "test-secret")
        XCTAssertFalse(server.hasRemainingRequests())
    }

    func testDnsFlushUsesLocalPostEndpoint() async throws {
        let server = try LocalController(status: 204, body: "")
        defer { server.stop() }
        try await MihomoClient(socketPath: server.socket.path, temporaryRoot: server.directory).flushDNS()
        let request = try server.request()
        XCTAssertEqual(request["method"] as? String, "POST")
        XCTAssertEqual(request["path"] as? String, "/cache/dns/flush")
    }

    func testSelectorRestorationEscapesNamesAndOnlyRestoresValidMembers() async throws {
        let server = try LocalController(status: 204, body: "")
        defer { server.stop() }
        let client = MihomoClient(socketPath: server.socket.path, temporaryRoot: server.directory)
        let config = try JSONSerialization.data(withJSONObject: ["proxy-groups": [["name": "Group / A", "type": "select", "proxies": ["Node"]]]])
        try await client.restoreSelections(["Group / A": "Node", "Removed": "Foreign"], configuration: config)
        let request = try server.request()
        XCTAssertEqual(request["method"] as? String, "PUT")
        XCTAssertEqual(request["path"] as? String, "/proxies/Group%20%2F%20A")
        let body = try JSONSerialization.jsonObject(with: Data((request["body"] as! String).utf8)) as! [String: String]
        XCTAssertEqual(body, ["name": "Node"])
    }

    func testSelectorRestorationStopsAfterFirstRequestWhenAuthorizationChanges() async throws {
        let server = try LocalController(status: 204, body: "")
        defer { server.stop() }
        let client = MihomoClient(socketPath: server.socket.path, temporaryRoot: server.directory)
        let config = try JSONSerialization.data(withJSONObject: ["proxy-groups": [
            ["name": "First", "type": "select", "proxies": ["Node"]],
            ["name": "Second", "type": "select", "proxies": ["Node"]]]])
        let gate = RequestGate()
        let restored = try await client.restoreSelections(["First": "Node", "Second": "Node"], configuration: config,
            shouldContinue: { await gate.allow() })
        XCTAssertFalse(restored)
        XCTAssertEqual(try server.request()["path"] as? String, "/proxies/First")
    }

    func testDiagnosticVerificationInterruptionIsNotConfigurationMismatch() async throws {
        let server = try LocalController(status: 200, body: "{}")
        defer { server.stop() }
        let gate = RequestGate()
        do {
            _ = try await RoutingDiagnosticVerification.verify(
                client: MihomoClient(socketPath: server.socket.path, temporaryRoot: server.directory),
                configuration: Data("{}".utf8), authorized: { await gate.allow() })
            XCTFail("Incomplete comparison must throw instead of reporting mismatch")
        } catch RoutingDiagnosticInterruption.stateChanged { }
        XCTAssertEqual(try server.request()["path"] as? String, "/configs")
    }

    func testVerificationStopsAfterFirstReadWhenAuthorizationChanges() async throws {
        let server = try LocalController(status: 200, body: "{}")
        defer { server.stop() }
        let gate = RequestGate()
        let verified = try await MihomoClient(socketPath: server.socket.path, temporaryRoot: server.directory)
            .verify(configuration: Data("{}".utf8), shouldContinue: { await gate.allow() })
        XCTAssertFalse(verified)
        XCTAssertEqual(try server.request()["path"] as? String, "/configs")
    }

    func testYamlPayloadDoesNotEscapeSlashesInControllerPathOrUrls() async throws {
        let server = try LocalController(status: 204, body: "")
        defer { server.stop() }
        let client = MihomoClient(socketPath: server.socket.path, temporaryRoot: server.directory)
        try await client.apply(configuration: Data("{\"url\":\"https://example.invalid/test\",\"label\":\"🇨🇳\"}".utf8))
        let request = try server.request()
        let body = try JSONSerialization.jsonObject(with: Data((request["body"] as! String).utf8)) as! [String: Any]
        let payload = try XCTUnwrap(body["payload"] as? String)
        XCTAssertFalse(payload.contains("\\/"), "Mihomo parses payload as YAML and rejects JSON slash escapes")
        XCTAssertTrue(payload.contains("🇨🇳"))
    }

    func testControllerErrorDoesNotReturnSensitiveResponse() async throws {
        let server = try LocalController(status: 400, body: "sensitive-test-payload")
        defer { server.stop() }
        let client = MihomoClient(socketPath: server.socket.path, temporaryRoot: server.directory)
        do { _ = try await client.read(path: "/configs"); XCTFail("Expected controller error") }
        catch { XCTAssertFalse(error.localizedDescription.contains("sensitive-test-payload")) }
    }

    func testGeneratedYamlIsReadWithoutTruncationAndTemporaryPayloadsRemoved() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ez-client-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let source = dir.appendingPathComponent("config.yaml")
        try Data(("mode: rule\nsecret: " + String(repeating: "x", count: 90_000)).utf8).write(to: source)
        let output = try await MihomoClient.readGeneratedConfiguration(at: source)
        let config = try JSONSerialization.jsonObject(with: output) as! [String: Any]
        XCTAssertEqual((config["secret"] as? String)?.count, 90_000)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path), ["config.yaml"])
    }
}

private actor RequestGate {
    private var checks = 0
    func allow() -> Bool { checks += 1; return checks == 1 }
}

private final class LocalController {
    let directory: URL
    let socket: URL
    private let process = Process()
    init(status: Int, body: String) throws {
        directory = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("ez-api-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                              attributes: [.posixPermissions: 0o700])
        socket = directory.appendingPathComponent("api.sock")
        let script = directory.appendingPathComponent("server.py")
        let text = """
        import socket,json,pathlib,sys
        root=pathlib.Path(sys.argv[1])
        s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.bind(str(root/'api.sock'));s.listen(1)
        (root/'ready').write_text('ready')
        c,_=s.accept();data=b''
        while b'\\r\\n\\r\\n' not in data:data+=c.recv(8192)
        header,body=data.split(b'\\r\\n\\r\\n',1)
        lines=header.decode().split('\\r\\n');method,path,_=lines[0].split(' ')
        headers=dict(line.split(': ',1) for line in lines[1:]);length=int(headers.get('Content-Length','0'))
        while len(body)<length:body+=c.recv(8192)
        (root/'request.json').write_text(json.dumps({'host':headers.get('Host'),'method':method,'path':path,'authorization':headers.get('Authorization',''),'body':body.decode()}))
        response=\(String(reflecting: body)).encode()
        c.sendall(('HTTP/1.1 \(status) Test\\r\\nContent-Length: '+str(len(response))+'\\r\\nConnection: close\\r\\n\\r\\n').encode()+response)
        c.close();s.close()
        """
        // Swift's reflected string escapes are compatible for this ASCII fixture.
        try Data(text.utf8).write(to: script)
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = [script.path, directory.path]
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run()
        let limit = Date().addingTimeInterval(5)
        while !FileManager.default.fileExists(atPath: directory.appendingPathComponent("ready").path) {
            guard process.isRunning, Date() < limit else { stop(); throw CocoaError(.fileReadUnknown) }
            Thread.sleep(forTimeInterval: 0.01)
        }
    }
    func request() throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: Data(contentsOf: directory.appendingPathComponent("request.json"))) as! [String: Any]
    }
    func hasRemainingRequests() -> Bool {
        (try? FileManager.default.contentsOfDirectory(atPath: directory.path))?.contains(where: { $0.hasPrefix("ez-request") }) ?? false
    }
    func stop() {
        if process.isRunning { process.terminate() }
        try? FileManager.default.removeItem(at: directory)
    }
}
