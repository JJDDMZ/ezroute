import XCTest
@testable import EZSwitchCore

final class RoutingConnectionSnapshotTests: XCTestCase {
    private func payload() throws -> (Data, Data) {
        let connections: [String: Any] = ["connections": [
            ["id": "a", "upload": 100, "download": 200,
             "metadata": ["host": "api.deepseek.com", "destinationIP": "1.2.3.4",
                          "destinationPort": "443", "network": "tcp"],
             "rule": "Match", "rulePayload": "", "chains": ["Phone", "Proxy"]],
            ["id": "b", "upload": 1, "download": 2,
             "metadata": ["host": "", "destinationIP": "240e::1",
                          "destinationPort": "8080", "network": "tcp"],
             "rule": "DomainSuffix", "rulePayload": "cn", "chains": ["Campus"]]]]
        let proxies: [String: Any] = ["proxies": [
            "Phone": ["type": "Trojan", "interface": "en5"],
            "Campus": ["type": "Direct", "interface": "en0"],
            "Proxy": ["type": "Selector", "all": ["Phone"]]]]
        return (try JSONSerialization.data(withJSONObject: connections),
                try JSONSerialization.data(withJSONObject: proxies))
    }

    func testRowsCarryTargetRuleAndEgress() throws {
        let (c, p) = try payload()
        let rows = try RoutingConnectionSnapshot.parse(connections: c, proxies: p, globalInterface: nil)
        XCTAssertEqual(rows.count, 2)
        XCTAssertEqual(rows[0].target, "api.deepseek.com")
        XCTAssertEqual(rows[0].egress, "en5")
        XCTAssertEqual(rows[0].received, 200)
        XCTAssertEqual(rows[0].sent, 100)
        XCTAssertEqual(rows[0].rule, "Match")
    }

    func testRowWithoutAHostFallsBackToAddressAndPort() throws {
        let (c, p) = try payload()
        let rows = try RoutingConnectionSnapshot.parse(connections: c, proxies: p, globalInterface: nil)
        XCTAssertEqual(rows[1].target, "240e::1:8080")
        XCTAssertEqual(rows[1].egress, "en0")
        XCTAssertEqual(rows[1].rule, "DomainSuffix:cn")
    }

    func testUnknownAdapterLeavesTheRowWithoutAnEgress() throws {
        let (c, _) = try payload()
        let empty = try JSONSerialization.data(withJSONObject: ["proxies": [String: Any]()])
        let rows = try RoutingConnectionSnapshot.parse(connections: c, proxies: empty, globalInterface: nil)
        XCTAssertEqual(rows.count, 2)
        XCTAssertNil(rows[0].egress)
        XCTAssertNil(rows[0].isDirect)
    }

    func testMalformedPayloadThrows() throws {
        XCTAssertThrowsError(try RoutingConnectionSnapshot.parse(
            connections: Data("{}".utf8), proxies: Data("{}".utf8), globalInterface: nil))
    }

    private func payload(_ entries: [[String: Any]]) throws -> (Data, Data) {
        let proxies: [String: Any] = ["proxies": [String: Any]()]
        return (try JSONSerialization.data(withJSONObject: ["connections": entries]),
                try JSONSerialization.data(withJSONObject: proxies))
    }

    func testNegativeCountersAreReportedAsZeroInsteadOfTrapping() throws {
        // 修正前:UInt64(-1) 触发 fatal error,测试进程崩溃而非断言失败。
        let (c, p) = try payload([["id": "neg", "upload": -1, "download": -5,
                                   "metadata": [String: Any](), "rule": "Match", "chains": []]])
        let rows = try RoutingConnectionSnapshot.parse(connections: c, proxies: p, globalInterface: nil)
        XCTAssertEqual(rows.first?.received, 0)
        XCTAssertEqual(rows.first?.sent, 0)
    }

    func testStringCountersAreParsedRatherThanSilentlyZeroed() throws {
        // 修正前:as? Int 对字符串返回 nil,静默变成 0。
        let (c, p) = try payload([["id": "str", "upload": "100", "download": "250",
                                   "metadata": [String: Any](), "rule": "Match", "chains": []]])
        let rows = try RoutingConnectionSnapshot.parse(connections: c, proxies: p, globalInterface: nil)
        XCTAssertEqual(rows.first?.received, 250)
        XCTAssertEqual(rows.first?.sent, 100)
    }

    func testOversizedCountersDoNotBecomeGarbage() throws {
        // 钉住修正实现自身:NSNumber.uint64Value 对 1e30 会返回 5076964154930102272 这样的垃圾值。
        let (c, p) = try payload([["id": "big", "upload": 1e30, "download": 1e30,
                                   "metadata": [String: Any](), "rule": "Match", "chains": []]])
        let rows = try RoutingConnectionSnapshot.parse(connections: c, proxies: p, globalInterface: nil)
        XCTAssertEqual(rows.first?.received, 0)
        XCTAssertEqual(rows.first?.sent, 0)
    }

    func testRowsWithoutAnIdentifierAreStableAcrossParses() throws {
        // 修正前:UUID() 每次不同,两次解析结果不相等。
        let (c, p) = try payload([["upload": 10, "download": 20,
                                   "metadata": ["host": "example.invalid"], "rule": "Match",
                                   "chains": []]])
        let first = try RoutingConnectionSnapshot.parse(connections: c, proxies: p, globalInterface: nil)
        let second = try RoutingConnectionSnapshot.parse(connections: c, proxies: p, globalInterface: nil)
        XCTAssertEqual(first, second)
    }

    func testRowsWithoutIdentifiersGetDistinctFallbackIDs() throws {
        // 兜底标识必须能区分指向同一目标的多条连接:只用 target 兜底会让两者 id 相同。
        let (c, p) = try payload([
            ["upload": 1, "download": 1, "metadata": ["host": "example.invalid"],
             "rule": "Match", "chains": []],
            ["upload": 2, "download": 2, "metadata": ["host": "example.invalid"],
             "rule": "Match", "chains": []]])
        let rows = try RoutingConnectionSnapshot.parse(connections: c, proxies: p, globalInterface: nil)
        XCTAssertEqual(rows.count, 2)
        XCTAssertNotEqual(rows[0].id, rows[1].id)
    }
}
