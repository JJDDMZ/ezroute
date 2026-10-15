import XCTest
@testable import EZSwitchCore

final class RoutingRuntimeTests: XCTestCase {
    func testVmessApiTypeUsesTheCoresActualSpelling() throws {
        var expected = config
        expected["proxies"] = [["name": "Node", "type": "vmess", "interface-name": "en5"]]
        var actual = proxies; actual["Node"]?["type"] = "Vmess"
        XCTAssertTrue(try RoutingRuntime.matches(configuration: JSONSerialization.data(withJSONObject: expected),
            general: JSONSerialization.data(withJSONObject: general),
            proxies: JSONSerialization.data(withJSONObject: ["proxies": actual]),
            rules: JSONSerialization.data(withJSONObject: ["rules": [["type": "Match", "payload": "", "proxy": "Proxy"]]])))
    }
    func testCorrectRoutingAndTunAreAccepted() throws { XCTAssertTrue(try matches()) }
    func testExplicitlyDisabledTunnelCanBeAuditedWithoutEnablingIt() throws {
        var expected = config; expected["tun"] = ["enable": false]
        var actual = general; actual["tun"] = ["enable": false]
        XCTAssertTrue(try matches(configuration: expected, general: actual))
        actual["tun"] = ["enable": true]
        XCTAssertFalse(try matches(configuration: expected, general: actual))
    }
    func testMissingExpectedTunnelStateCannotBeAccepted() throws {
        var expected = config; expected.removeValue(forKey: "tun")
        XCTAssertFalse(try matches(configuration: expected))
    }
    func testForeignOrWifiBoundNodeIsRejected() throws {
        var changed = proxies; changed["Node"]?["interface"] = "en0"
        XCTAssertFalse(try matches(proxies: changed))
        changed = proxies; changed["Foreign"] = ["type": "Trojan", "interface": "en0"]
        XCTAssertFalse(try matches(proxies: changed))
    }
    func testChangedModeDisabledTunAndChangedRulesAreRejected() throws {
        var runtime = general; runtime["mode"] = "global"
        XCTAssertFalse(try matches(general: runtime))
        runtime = general; runtime["tun"] = ["enable": false]
        XCTAssertFalse(try matches(general: runtime))
        XCTAssertFalse(try matches(rules: [["type": "Match", "payload": "", "proxy": "DIRECT"]]))
    }
    func testDirectFallbackInProxyGroupIsRejected() throws {
        var changed = proxies; changed["Proxy"]?["all"] = ["Node", "DIRECT"]
        XCTAssertFalse(try matches(proxies: changed))
    }
    private var config: [String: Any] {
        ["mode": "rule", "interface-name": "en5", "tun": ["enable": true],
         "proxies": [["name": "Node", "type": "trojan", "interface-name": "en5"]],
         "proxy-groups": [["name": "Proxy", "type": "select", "proxies": ["Node"]]], "rules": ["MATCH,Proxy"]]
    }
    private var general: [String: Any] { ["mode": "rule", "interface-name": "en5", "tun": ["enable": true]] }
    private var proxies: [String: [String: Any]] {
        ["Node": ["type": "Trojan", "interface": "en5"], "Proxy": ["type": "Selector", "all": ["Node"], "now": "Node"], "DIRECT": ["type": "Direct"], "GLOBAL": ["type": "Selector"]]
    }
    private func matches(configuration: [String: Any]? = nil, general: [String: Any]? = nil, proxies: [String: [String: Any]]? = nil,
                         rules: [[String: Any]]? = nil) throws -> Bool {
        try RoutingRuntime.matches(configuration: JSONSerialization.data(withJSONObject: configuration ?? config),
            general: JSONSerialization.data(withJSONObject: general ?? self.general),
            proxies: JSONSerialization.data(withJSONObject: ["proxies": proxies ?? self.proxies]),
            rules: JSONSerialization.data(withJSONObject: ["rules": rules ?? [["type": "Match", "payload": "", "proxy": "Proxy"]]]))
    }
}
