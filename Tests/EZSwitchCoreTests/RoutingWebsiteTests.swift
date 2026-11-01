import XCTest
@testable import EZSwitchCore

final class RoutingWebsiteTests: XCTestCase {
    func testProbeTargetKeepsTheRequestedSchemeForAnAbsoluteURL() throws {
        let http = try RoutingWebsiteTester.target("http://cwcx.campus.example/")
        XCTAssertEqual(http.host, "cwcx.campus.example")
        XCTAssertEqual(http.url, "http://cwcx.campus.example/")
        XCTAssertEqual(http.proto, "=http")
        let https = try RoutingWebsiteTester.target("https://www.bilibili.com/")
        XCTAssertEqual(https.host, "www.bilibili.com")
        XCTAssertEqual(https.proto, "=https")
    }

    func testProbeTargetRefusesNonWebSchemesIncompleteURLsAndEmbeddedCredentials() {
        for raw in ["ftp://example.com/", "file:///etc/passwd", "http://", "example.com", "",
                    "http://user:pw@example.com/", "//example.com/"] {
            XCTAssertThrowsError(try RoutingWebsiteTester.target(raw), raw)
        }
    }

    @MainActor func testWebsiteWaitResumesAfterReadOnlyCheck() async throws {
        var reads = 0
        let allowed = try await RoutingWebsiteReadiness.waitUntilReady {
            reads += 1
            return reads == 1 ? .checking : .ready
        }
        XCTAssertTrue(allowed)
        XCTAssertEqual(reads, 2)
    }

    @MainActor func testWebsiteWaitStopsWhenRoutingBecomesUnavailable() async throws {
        var reads = 0
        let allowed = try await RoutingWebsiteReadiness.waitUntilReady {
            reads += 1
            return reads == 1 ? .checking : .unavailable
        }
        XCTAssertFalse(allowed)
    }

    @MainActor func testWebsiteWaitHasBoundedTimeout() async throws {
        let allowed = try await RoutingWebsiteReadiness.waitUntilReady(timeout: .zero) { .checking }
        XCTAssertFalse(allowed)
    }

    @MainActor func testWebsiteWaitDoesNotAuthorizeReadyAfterDeadline() async throws {
        var reads = 0
        let allowed = try await RoutingWebsiteReadiness.waitUntilReady(timeout: .milliseconds(10)) {
            reads += 1
            return reads == 1 ? .checking : .ready
        }
        XCTAssertFalse(allowed)
    }

    @MainActor func testCancelledWebsiteWaitNeverAuthorizesRequest() async throws {
        let waiting = Task { @MainActor in
            try await RoutingWebsiteReadiness.waitUntilReady { .checking }
        }
        waiting.cancel()
        do {
            _ = try await waiting.value
            XCTFail("Cancelled wait must not authorize a request")
        } catch is CancellationError {}
    }

    func testMatchesOnlyNewConnectionWithThisRequestPortAndHost() throws {
        let connections = try data(["connections": [
            connection("existing", port: "51000", host: "github.com", chain: ["Phone"]),
            connection("other-port", port: "51001", host: "github.com", chain: ["Campus"]),
            connection("other-host", port: "51000", host: "example.invalid", chain: ["Campus"]),
            connection("request", port: "51000", host: "github.com", chain: ["Phone", "Select"])]])
        let route = try RoutingWebsiteEvidence.find(host: "github.com", localPort: 51000,
            previousIDs: ["existing"], observations: [connections], proxies: proxies())
        XCTAssertEqual(route?.interface, "en5")
        XCTAssertEqual(route?.isDirect, false)
    }

    func testDirectConnectionHasSeparateEvidence() throws {
        let route = try RoutingWebsiteEvidence.find(host: "www.bilibili.com", localPort: 51000,
            previousIDs: [], observations: [data(["connections": [connection("request", port: "51000", host: "www.bilibili.com", chain: ["Campus"])]])], proxies: proxies())
        XCTAssertEqual(route?.interface, "en0")
        XCTAssertEqual(route?.isDirect, true)
    }

    func testDirectOnlyBuiltinRequiresValidatedInheritedInterface() throws {
        let observations = try data(["connections": [connection("request", port: "51000", host: "example.com", chain: ["DIRECT"])]])
        let adapters = try data(["proxies": ["DIRECT": ["type": "Direct"]]])
        XCTAssertNil(try RoutingWebsiteEvidence.find(host: "example.com", localPort: 51000,
            previousIDs: [], observations: [observations], proxies: adapters))
        let inherited = try RoutingWebsiteEvidence.find(host: "example.com", localPort: 51000,
            previousIDs: [], observations: [observations], proxies: adapters, directOnlyInterface: "en0")
        XCTAssertEqual(inherited?.interface, "en0")
        XCTAssertEqual(inherited?.isDirect, true)
    }

    func testMissingOrConflictingConnectionsRemainUnknown() throws {
        XCTAssertNil(try RoutingWebsiteEvidence.find(host: "github.com", localPort: 51000, previousIDs: [], observations: [], proxies: proxies()))
        let observations = try data(["connections": [
            connection("one", port: "51000", host: "github.com", chain: ["Phone"]),
            connection("two", port: "51000", host: "github.com", chain: ["Campus"])]])
        XCTAssertNil(try RoutingWebsiteEvidence.find(host: "github.com", localPort: 51000, previousIDs: [], observations: [observations], proxies: proxies()))
    }

    func testUnknownChainDoesNotFallBackToGuessedInterface() throws {
        let observations = try data(["connections": [connection("request", port: 51000, host: "github.com", chain: ["Missing", "Select"])]])
        XCTAssertNil(try RoutingWebsiteEvidence.find(host: "github.com", localPort: 51000, previousIDs: [], observations: [observations], proxies: proxies()))
    }

    func testLanClientWithSameHostAndPortIsNotThisRequest() throws {
        var lan = connection("lan", port: 51000, host: "github.com", chain: ["Phone"])
        lan["metadata"] = ["sourceIP": "192.0.2.20", "sourcePort": "51000", "host": "github.com"]
        XCTAssertNil(try RoutingWebsiteEvidence.find(host: "github.com", localPort: 51000, previousIDs: [],
            observations: [data(["connections": [lan]])], proxies: proxies()))
        lan["metadata"] = ["sourcePort": "51000", "host": "github.com"]
        XCTAssertNil(try RoutingWebsiteEvidence.find(host: "github.com", localPort: 51000, previousIDs: [],
            observations: [data(["connections": [lan]])], proxies: proxies()))
    }

    /// 旧实现固定 8 帧、每帧 100 ms。连接只存活几十毫秒时会正好落在两帧之间,
    /// 于是快速站点永远"找不到本次请求的 Clash 连接"。
    func testObservationKeepsSamplingSoAShortLivedConnectionIsNotMissed() async {
        let visible = Data(#"{"connections":[{"id":"request","metadata":{"sourceIP":"127.0.0.1","sourcePort":51000,"host":"www.bilibili.com"},"chains":["DIRECT"]}]}"#.utf8)
        let empty = Data(#"{"connections":[]}"#.utf8)
        let plan = RoutingObservationPlan(interval: .milliseconds(20),
                                          grace: .milliseconds(40),
                                          maximum: .milliseconds(150))
        let start = ContinuousClock.now
        let frames = await RoutingWebsiteTester.observe(plan: plan) {
            // 这条连接只在 [25 ms, 75 ms) 内可见:比旧的 100 ms 间隔还短。
            let elapsed = start.duration(to: .now)
            return elapsed >= .milliseconds(25) && elapsed < .milliseconds(75) ? visible : empty
        }
        XCTAssertTrue(frames.contains { $0 == visible }, "只存活 50 ms 的连接被漏采了")
    }

    func testSummaryWithoutAProxyOutletExplainsTheModeInsteadOfLookingLikeFailure() {
        let withOutlet = RoutingDiagnosticText.physicalSummary(passCount: 2, testableCount: 2, directs: 1,
                                                               proxies: 1, proxyOutletAvailable: true, overall: .unknown)
        XCTAssertTrue(withOutlet.contains("已确认 2/2"))
        XCTAssertFalse(withOutlet.contains("没有代理出口"))

        let withoutOutlet = RoutingDiagnosticText.physicalSummary(passCount: 2, testableCount: 2, directs: 2,
                                                                  proxies: 0, proxyOutletAvailable: false, overall: .unknown)
        XCTAssertTrue(withoutOutlet.contains("已确认 2/2"), "分母只能是本模式测得到的站点")
        XCTAssertTrue(withoutOutlet.contains("本模式没有代理出口"))
        XCTAssertFalse(withoutOutlet.contains("代理出口尚待检查"))
    }

    func testHTTP403MeansHandshakeCompletedButNotWebsiteUsable() throws {
        let probe = try RoutingWebsiteProbe.parse("403 0.125 51000", exitCode: 0)
        XCTAssertEqual(probe.status, 403)
        XCTAssertEqual(probe.milliseconds, 125)
        XCTAssertEqual(probe.localPort, 51000)
        XCTAssertFalse(probe.isSuccessfulResponse)
    }

    func testProbeFailureAndMalformedOutputDoNotClaimConnectivity() throws {
        XCTAssertThrowsError(try RoutingWebsiteProbe.parse("000 1.0 51000", exitCode: 7))
        XCTAssertThrowsError(try RoutingWebsiteProbe.parse("garbage", exitCode: 0))
        XCTAssertThrowsError(try RoutingWebsiteProbe.parse("200 nan 51000", exitCode: 0))
    }

    func testGatewayRejectsDisabledTunAndUnauthorizedProxyBeforeRequest() throws {
        let decision = RoutingDecision(mode: .split, proxyInterface: "en5", directInterface: "en0")
        let valid = try data(["tun": ["enable": true], "mode": "rule", "interface-name": "en5", "mixed-port": 7890])
        let adapters = try data(["proxies": ["Node": ["type": "Trojan", "interface": "en5"],
            "EZ-Campus": ["type": "Direct", "interface": "en0"], "EZ-USB-DNS": ["type": "Direct", "interface": "en5"]]])
        XCTAssertEqual(try RoutingWebsiteTester.entryPort(general: valid, proxies: adapters, decision: decision), 7890)
        XCTAssertThrowsError(try RoutingWebsiteTester.entryPort(general:
            data(["tun": ["enable": false], "mode": "rule", "interface-name": "en5", "mixed-port": 7890]), proxies: adapters, decision: decision))
        let campusProxy = try data(["proxies": ["Node": ["type": "Trojan", "interface": "en0"]]])
        XCTAssertThrowsError(try RoutingWebsiteTester.entryPort(general: valid, proxies: campusProxy, decision: decision))
    }

    func testMissingGatewayDoesNotSelectSystemDirectOrDefaultPort() throws {
        let decision = RoutingDecision(mode: .usbHotspot, proxyInterface: "en5", directInterface: "en5")
        XCTAssertThrowsError(try RoutingWebsiteTester.entryPort(general:
            data(["tun": ["enable": true], "mode": "rule", "interface-name": "en5"]), proxies: proxies(), decision: decision))
    }

    private func proxies() throws -> Data {
        try data(["proxies": ["Phone": ["type": "Trojan", "interface": "en5"],
            "Campus": ["type": "Direct", "interface": "en0"],
            "Select": ["type": "Selector", "all": ["Phone"]]]])
    }
    private func connection(_ id: String, port: Any, host: String, chain: [String]) -> [String: Any] {
        ["id": id, "metadata": ["sourceIP": "127.0.0.1", "sourcePort": port, "host": host], "chains": chain]
    }
    private func data(_ value: Any) throws -> Data { try JSONSerialization.data(withJSONObject: value) }
}
