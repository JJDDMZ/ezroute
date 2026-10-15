import XCTest
@testable import EZSwitchCore

final class RoutingEgressSectionsTests: XCTestCase {
    private func row(_ target: String, egress: String?) -> RoutingConnectionRow {
        .init(id: UUID().uuidString, target: target, network: "tcp", rule: "Match",
              chains: ["节点"], egress: egress, isDirect: false, received: 1, sent: 1)
    }

    func testAnInterfaceAppearsOnceWithBothItsUsageAndItsConnections() {
        let sections = RoutingEgressSections.build(
            connections: [row("a.com", egress: "en5"), row("b.com", egress: "en5")],
            traffic: ["en5": .init(received: 100, sent: 10)])
        XCTAssertEqual(sections.count, 1)
        XCTAssertEqual(sections[0].egress, "en5")
        XCTAssertEqual(sections[0].connections.count, 2)
        XCTAssertEqual(sections[0].usage, .init(received: 100, sent: 10))
    }

    func testAnInterfaceWithUsageButNoConnectionsStillAppears() {
        let sections = RoutingEgressSections.build(connections: [],
                                                   traffic: ["en0": .init(received: 5, sent: 5)])
        XCTAssertEqual(sections.map(\.egress), ["en0"])
        XCTAssertTrue(sections[0].connections.isEmpty)
    }

    func testAnInterfaceWithConnectionsButNoUsageStillAppears() {
        let sections = RoutingEgressSections.build(connections: [row("a.com", egress: "en5")], traffic: [:])
        XCTAssertEqual(sections.map(\.egress), ["en5"])
        XCTAssertNil(sections[0].usage)
    }

    func testSectionsWithConnectionsComeBeforeUsageOnlyOnes() {
        let sections = RoutingEgressSections.build(
            connections: [row("a.com", egress: "en5")],
            traffic: ["en5": .init(received: 1, sent: 1), "en0": .init(received: 999, sent: 999)])
        XCTAssertEqual(sections.map(\.egress), ["en5", "en0"])
    }

    func testUnknownEgressIsLastAndCarriesNoUsage() {
        let sections = RoutingEgressSections.build(
            connections: [row("a.com", egress: "en5"), row("x.com", egress: nil)],
            traffic: ["en5": .init(received: 1, sent: 1)])
        XCTAssertEqual(sections.map(\.egress), ["en5", nil])
        XCTAssertNil(sections.last?.usage)
    }

    func testEmptyInputGivesNoSections() {
        XCTAssertTrue(RoutingEgressSections.build(connections: [], traffic: [:]).isEmpty)
    }
}
