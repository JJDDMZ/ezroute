import XCTest
@testable import EZSwitchCore

/// The tunnel coupling only restores what the tunnel itself suspended. A manual
/// switch position always wins, and one restore is owed per off-to-on edge.
final class RoutingTunnelCouplingTests: XCTestCase {
    func testTunnelOffSuspendsOnlyWhenAutomaticRoutingWasOn() {
        var untouched = RoutingTunnelCoupling()
        untouched.tunnelWentOff(wasEnabled: false)
        XCTAssertFalse(untouched.suspended)

        var suspended = RoutingTunnelCoupling()
        suspended.tunnelWentOff(wasEnabled: true)
        XCTAssertTrue(suspended.suspended)
    }

    func testManualOffIsNotUndoneWhenTheTunnelComesBack() {
        var coupling = RoutingTunnelCoupling()
        coupling.userSetEnabled()
        _ = coupling.observeTunnel(enabled: false)
        XCTAssertFalse(coupling.observeTunnel(enabled: true))
        XCTAssertFalse(coupling.suspended)
    }

    func testManualChoiceClearsAPendingSuspension() {
        var coupling = RoutingTunnelCoupling()
        coupling.tunnelWentOff(wasEnabled: true)
        coupling.userSetEnabled()
        XCTAssertFalse(coupling.suspended)
        _ = coupling.observeTunnel(enabled: false)
        XCTAssertFalse(coupling.observeTunnel(enabled: true))
    }

    func testRestoreFiresOncePerOffToOnEdge() {
        var coupling = RoutingTunnelCoupling()
        coupling.tunnelWentOff(wasEnabled: true)
        XCTAssertFalse(coupling.observeTunnel(enabled: false))
        XCTAssertTrue(coupling.observeTunnel(enabled: true))
        XCTAssertFalse(coupling.observeTunnel(enabled: true))
    }

    func testSuccessfulRestoreClearsTheSuspension() {
        var coupling = RoutingTunnelCoupling()
        coupling.tunnelWentOff(wasEnabled: true)
        _ = coupling.observeTunnel(enabled: false)
        XCTAssertTrue(coupling.observeTunnel(enabled: true))
        coupling.restoreSucceeded()
        XCTAssertFalse(coupling.suspended)
        _ = coupling.observeTunnel(enabled: false)
        XCTAssertFalse(coupling.observeTunnel(enabled: true))
    }

    func testFailedRestoreRetriesOnlyOnTheNextEdge() {
        var coupling = RoutingTunnelCoupling()
        coupling.tunnelWentOff(wasEnabled: true)
        _ = coupling.observeTunnel(enabled: false)
        XCTAssertTrue(coupling.observeTunnel(enabled: true))
        coupling.restoreFailed()
        XCTAssertTrue(coupling.suspended)
        XCTAssertFalse(coupling.observeTunnel(enabled: true))
        XCTAssertFalse(coupling.observeTunnel(enabled: false))
        XCTAssertTrue(coupling.observeTunnel(enabled: true))
    }

    func testPendingSuspensionSurvivesARelaunch() {
        var before = RoutingTunnelCoupling()
        before.tunnelWentOff(wasEnabled: true)
        var after = RoutingTunnelCoupling(suspended: before.suspended)
        XCTAssertTrue(after.observeTunnel(enabled: true))
    }

    func testSuspensionStaysArmedWhileTheTunnelIsStillOff() {
        var coupling = RoutingTunnelCoupling()
        coupling.tunnelWentOff(wasEnabled: true)
        for _ in 0..<5 { XCTAssertFalse(coupling.observeTunnel(enabled: false)) }
        XCTAssertTrue(coupling.observeTunnel(enabled: true))
    }
}
