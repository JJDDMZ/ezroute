import XCTest
@testable import EZSwitchCore

final class RoutingConnectionEgressTests: XCTestCase {
    private func adapters() throws -> [String: [String: Any]] {
        ["Phone": ["type": "Trojan", "interface": "en5"],
         "Campus": ["type": "Direct", "interface": "en0"],
         "DIRECT": ["type": "Direct", "interface": ""],
         "Proxy": ["type": "Selector", "all": ["Phone"]],
         "Other": ["type": "URLTest", "all": ["Phone"]]]
    }

    func testRemoteLeafResolvesToItsBoundInterface() throws {
        let egress = RoutingConnectionEgress.find(chains: ["Phone", "Proxy"], adapters: try adapters())
        XCTAssertEqual(egress, .init(interface: "en5", isDirect: false))
    }

    func testDirectLeafResolvesToTheCampusInterface() throws {
        let egress = RoutingConnectionEgress.find(chains: ["Campus"], adapters: try adapters())
        XCTAssertEqual(egress, .init(interface: "en0", isDirect: true))
    }

    func testBuiltinDirectInheritsTheGlobalInterface() throws {
        let egress = RoutingConnectionEgress.find(chains: ["DIRECT"], adapters: try adapters(),
                                                  globalInterface: "en0")
        XCTAssertEqual(egress, .init(interface: "en0", isDirect: true))
    }

    func testBuiltinDirectWithoutAGlobalInterfaceStaysUnknown() throws {
        XCTAssertNil(RoutingConnectionEgress.find(chains: ["DIRECT"], adapters: try adapters()))
    }

    func testUnknownAdapterCannotBeGuessed() throws {
        XCTAssertNil(RoutingConnectionEgress.find(chains: ["Missing"], adapters: try adapters()))
    }

    func testEmptyChainStaysUnknown() throws {
        XCTAssertNil(RoutingConnectionEgress.find(chains: [], adapters: try adapters()))
    }

    func testConflictingLeavesStayUnknown() throws {
        var table = try adapters()
        table["Relay"] = ["type": "Trojan", "interface": "en0"]
        XCTAssertNil(RoutingConnectionEgress.find(chains: ["Phone", "Relay"], adapters: table))
    }
}
