import XCTest
@testable import EZSwitchCore

// The external controller is substituted to inject network changes and API failures.
// Configuration generation and the actual coordinator remain production code.
@MainActor final class RoutingCoordinatorTests: XCTestCase {
    func testBlocksAndClosesOldConnectionsBeforeOpeningUsb() async throws {
        let controller = TestRoutingController()
        let coordinator = make(controller)
        await coordinator.reconcile()
        XCTAssertEqual(controller.appliedModes, [.blocked, .usbHotspot])
        XCTAssertEqual(controller.events.prefix(3), ["apply:blocked", "close", "flush"])
        XCTAssertEqual(coordinator.applied?.decision.mode, .usbHotspot)
    }

    func testUnchangedNetworkDoesNotReloadOrDropConnections() async throws {
        let controller = TestRoutingController(); let coordinator = make(controller)
        await coordinator.reconcile(); controller.events.removeAll()
        await coordinator.reconcile()
        XCTAssertTrue(controller.events.isEmpty)
    }

    func testReadOnlyAuditKeepsWebsiteControlsAvailableButDefersRequests() async throws {
        let controller = TestRoutingController(); let coordinator = make(controller)
        await coordinator.reconcile(); controller.events.removeAll()
        XCTAssertEqual(coordinator.websiteTestReadiness, .ready)
        controller.onVerify = {
            XCTAssertTrue(coordinator.isBusy)
            XCTAssertEqual(coordinator.websiteTestReadiness, .checking)
            XCTAssertTrue(coordinator.websiteTestReadiness.controlsAvailable)
            XCTAssertFalse(coordinator.websiteTestReadiness.canProbe)
        }
        await coordinator.audit()
        XCTAssertEqual(coordinator.websiteTestReadiness, .ready)
        XCTAssertTrue(controller.events.isEmpty)
    }

    func testRealRoutingSwitchStillDisablesWebsiteControls() async throws {
        let controller = TestRoutingController(); let coordinator = make(controller)
        XCTAssertEqual(coordinator.websiteTestReadiness, .unavailable)
        controller.afterBlock = {
            XCTAssertEqual(coordinator.state, .switching)
            XCTAssertFalse(coordinator.websiteTestReadiness.controlsAvailable)
            XCTAssertFalse(coordinator.websiteTestReadiness.canProbe)
        }
        await coordinator.reconcile()
        XCTAssertEqual(coordinator.websiteTestReadiness, .ready)
    }

    func testFailedAuditRevocationDisablesWebsiteControlsBeforeWritingBlock() async throws {
        let controller = TestRoutingController(); let coordinator = make(controller)
        await coordinator.reconcile(); controller.auditOK = false
        controller.afterBlock = {
            XCTAssertEqual(coordinator.websiteTestReadiness, .unavailable)
            XCTAssertFalse(coordinator.websiteTestReadiness.controlsAvailable)
        }
        await coordinator.audit()
        XCTAssertEqual(coordinator.websiteTestReadiness, .ready)
    }

    func testDisabledTunDuringAuditDisablesWebsiteControls() async throws {
        let controller = TestRoutingController(); let coordinator = make(controller)
        await coordinator.reconcile(); controller.tunEnabled = false
        await coordinator.audit()
        XCTAssertEqual(coordinator.state, .paused)
        XCTAssertEqual(coordinator.websiteTestReadiness, .unavailable)
    }

    func testFailureNeverOpensTargetAndReportsConfirmedBlock() async throws {
        let controller = TestRoutingController(); controller.failMode = .usbHotspot
        let coordinator = make(controller); await coordinator.reconcile()
        XCTAssertNil(coordinator.applied)
        XCTAssertEqual(coordinator.state, .blockedAfterFailure)
        XCTAssertEqual(controller.appliedModes.last, .blocked)
    }

    func testControllerUnavailableDoesNotClaimProtection() async throws {
        let controller = TestRoutingController(); controller.unavailable = true
        let coordinator = make(controller); await coordinator.reconcile()
        XCTAssertEqual(coordinator.state, .unprotected)
        XCTAssertNil(coordinator.applied)
    }

    func testInitialControllerRecoveryRetriesWithoutNetworkChange() async throws {
        let controller = TestRoutingController(); controller.unavailable = true
        let coordinator = make(controller)
        await coordinator.reconcile(); await coordinator.audit()
        XCTAssertEqual(coordinator.state, .unprotected)
        XCTAssertTrue(controller.appliedModes.isEmpty)
        controller.unavailable = false
        await coordinator.audit()
        XCTAssertEqual(controller.appliedModes, [.blocked, .usbHotspot])
        XCTAssertEqual(coordinator.state, .active)
        controller.events.removeAll()
        await coordinator.audit(); await coordinator.reconcile()
        XCTAssertTrue(controller.events.isEmpty)
    }

    func testInitialControllerRecoveryHonorsDisabledTun() async throws {
        let controller = TestRoutingController(); controller.unavailable = true
        let coordinator = make(controller); await coordinator.reconcile()
        controller.unavailable = false; controller.tunEnabled = false
        await coordinator.audit()
        XCTAssertEqual(coordinator.state, .paused)
        XCTAssertTrue(controller.appliedModes.isEmpty)
    }

    func testInitialControllerRecoveryUsesFreshIdentity() async throws {
        let controller = TestRoutingController(); controller.unavailable = true
        let holder = SnapshotHolder(.init(decision: .init(mode: .wifiHotspot, proxyInterface: "en0", directInterface: "en0"), identity: "phone"))
        let coordinator = RoutingCoordinator(controller: controller, loadBase: { try self.base() }, snapshot: { holder.value })
        await coordinator.reconcile()
        controller.unavailable = false
        controller.onTunnelCheck = {
            holder.value = .init(decision: .init(mode: .directOnly, proxyInterface: nil, directInterface: "en0"), identity: "campus")
            await coordinator.reconcile()
        }
        await coordinator.audit()
        XCTAssertEqual(controller.appliedModes, [.blocked, .directOnly])
        XCTAssertEqual(coordinator.applied, holder.value)
    }

    func testInvalidInitialBaseIsNotRetriedEveryAudit() async throws {
        let controller = TestRoutingController(); var reads = 0
        let coordinator = RoutingCoordinator(controller: controller, loadBase: {
            reads += 1; throw RoutingConfigurationError.unsupported
        }, snapshot: { .init(decision: .init(mode: .usbHotspot, proxyInterface: "en5", directInterface: "en5"), identity: "usb") })
        await coordinator.reconcile(); await coordinator.audit(); await coordinator.audit()
        XCTAssertEqual(reads, 1)
        XCTAssertEqual(coordinator.state, .unprotected)
        XCTAssertTrue(controller.appliedModes.isEmpty)
    }

    func testNetworkChangedDuringBlockedReloadCannotOpenStaleWifiProxy() async throws {
        let controller = TestRoutingController()
        let holder = SnapshotHolder(RoutingSnapshot(decision: .init(mode: .wifiHotspot, proxyInterface: "en0", directInterface: "en0"), identity: "phone"))
        let coordinator = RoutingCoordinator(controller: controller, loadBase: { try self.base() }, snapshot: { holder.value })
        controller.afterBlock = { holder.value = .init(decision: .init(mode: .directOnly, proxyInterface: nil, directInterface: "en0"), identity: "campus") }
        await coordinator.reconcile()
        XCTAssertFalse(controller.appliedModes.contains(.wifiHotspot))
        XCTAssertEqual(coordinator.applied?.decision.mode, .directOnly)
    }

    func testNetworkChangedDuringTargetReloadClosesTargetAgain() async throws {
        let controller = TestRoutingController()
        let holder = SnapshotHolder(RoutingSnapshot(decision: .init(mode: .wifiHotspot, proxyInterface: "en0", directInterface: "en0"), identity: "phone"))
        let coordinator = RoutingCoordinator(controller: controller, loadBase: { try self.base() }, snapshot: { holder.value })
        controller.afterTarget = { holder.value = .init(decision: .init(mode: .directOnly, proxyInterface: nil, directInterface: "en0"), identity: "campus") }
        await coordinator.reconcile()
        // Cached revocation precedes the next transaction's freshly generated block.
        XCTAssertEqual(controller.appliedModes, [.blocked, .wifiHotspot, .blocked, .blocked, .directOnly])
        XCTAssertEqual(coordinator.applied?.decision.mode, .directOnly)
    }

    func testTargetReloadIdentityChangeIsBlockedBeforeNextBaseRead() async throws {
        try await assertStaleTargetRevokedBeforeNextRead(at: .targetReload)
    }

    func testSelectionRestoreIdentityChangeIsBlockedBeforeNextBaseRead() async throws {
        try await assertStaleTargetRevokedBeforeNextRead(at: .selectionRestore)
    }

    func testRuntimeVerificationIdentityChangeIsBlockedBeforeNextBaseRead() async throws {
        try await assertStaleTargetRevokedBeforeNextRead(at: .runtimeVerification)
    }

    func testFailedStaleTargetBlockStopsBeforeNextBaseRead() async throws {
        let controller = TestRoutingController()
        let holder = SnapshotHolder(.init(decision: .init(mode: .wifiHotspot, proxyInterface: "en0", directInterface: "en0"), identity: "phone"))
        var reads = 0
        let coordinator = RoutingCoordinator(controller: controller, loadBase: {
            reads += 1; return try self.base()
        }, snapshot: { holder.value })
        controller.afterTarget = {
            holder.value = .init(decision: .init(mode: .directOnly, proxyInterface: nil, directInterface: "en0"), identity: "campus")
            controller.failMode = .blocked
        }
        await coordinator.reconcile()
        XCTAssertEqual(reads, 1, "Revocation failure must stop before another potentially slow base read")
        XCTAssertEqual(coordinator.state, .unprotected)
        XCTAssertNil(coordinator.applied)
        XCTAssertFalse(controller.appliedModes.contains(.directOnly))
    }

    func testInterruptedSelectionRestoreStillBlocksWhenIdentityReturns() async throws {
        let controller = TestRoutingController()
        let phone = RoutingSnapshot(decision: .init(mode: .wifiHotspot, proxyInterface: "en0", directInterface: "en0"), identity: "phone")
        let holder = SnapshotHolder(phone)
        controller.onRestore = {
            holder.value = .init(decision: .init(mode: .directOnly, proxyInterface: nil, directInterface: "en0"), identity: "campus")
        }
        controller.onRestoreStopped = { holder.value = phone }
        var reads = 0
        let coordinator = RoutingCoordinator(controller: controller, loadBase: {
            reads += 1
            if reads == 2 {
                XCTAssertEqual(controller.appliedModes.last, .blocked)
                XCTAssertEqual(Array(controller.events.suffix(3)), ["apply:blocked", "close", "flush"])
            }
            return try self.base()
        }, snapshot: { holder.value })
        await coordinator.reconcile()
        XCTAssertEqual(reads, 2)
        XCTAssertEqual(coordinator.applied, phone)
        XCTAssertEqual(controller.appliedModes, [.blocked, .wifiHotspot, .blocked, .blocked, .wifiHotspot])
    }

    func testTunDisabledDuringSelectionRestoreStopsWithoutReload() async throws {
        let controller = TestRoutingController()
        controller.onRestore = { controller.tunEnabled = false }
        let coordinator = make(controller); await coordinator.reconcile()
        XCTAssertEqual(coordinator.state, .paused)
        XCTAssertEqual(controller.appliedModes, [.blocked, .usbHotspot])
        XCTAssertNil(coordinator.applied)
    }

    func testRuntimeAuditMismatchTriggersProtectedReload() async throws {
        let controller = TestRoutingController(); let coordinator = make(controller)
        await coordinator.reconcile(); controller.appliedModes.removeAll(); controller.auditOK = false
        await coordinator.audit()
        XCTAssertEqual(controller.appliedModes, [.blocked, .blocked, .usbHotspot])
    }

    func testActiveAuditRevokesChangedIdentityBeforeNextBaseRead() async throws {
        let controller = TestRoutingController()
        let holder = SnapshotHolder(.init(decision: .init(mode: .wifiHotspot, proxyInterface: "en0", directInterface: "en0"), identity: "phone"))
        var reads = 0
        let coordinator = RoutingCoordinator(controller: controller, loadBase: {
            reads += 1
            if reads == 2 {
                XCTAssertEqual(controller.appliedModes.last, .blocked)
                XCTAssertEqual(Array(controller.events.suffix(3)), ["apply:blocked", "close", "flush"])
            }
            return try self.base()
        }, snapshot: { holder.value })
        await coordinator.reconcile()
        controller.onVerify = {
            holder.value = .init(decision: .init(mode: .directOnly, proxyInterface: nil, directInterface: "en0"), identity: "campus")
            await coordinator.reconcile()
        }
        await coordinator.audit()
        XCTAssertEqual(reads, 2)
        XCTAssertEqual(coordinator.applied, holder.value)
    }

    func testActiveAuditRevocationFailureDoesNotStartNextBaseRead() async throws {
        let controller = TestRoutingController()
        let holder = SnapshotHolder(.init(decision: .init(mode: .wifiHotspot, proxyInterface: "en0", directInterface: "en0"), identity: "phone"))
        var reads = 0
        let coordinator = RoutingCoordinator(controller: controller, loadBase: {
            reads += 1; return try self.base()
        }, snapshot: { holder.value })
        await coordinator.reconcile()
        controller.onVerify = {
            holder.value = .init(decision: .init(mode: .directOnly, proxyInterface: nil, directInterface: "en0"), identity: "campus")
            controller.failMode = .blocked
        }
        await coordinator.audit()
        XCTAssertEqual(reads, 1)
        XCTAssertEqual(coordinator.state, .unprotected)
        XCTAssertNil(coordinator.applied)
    }

    func testSameIdentityPollDuringAuditDoesNotRevokeHealthyTarget() async throws {
        let controller = TestRoutingController(); let coordinator = make(controller)
        await coordinator.reconcile()
        let target = controller.liveConfiguration
        controller.appliedModes.removeAll(); controller.events.removeAll()
        controller.onVerify = { await coordinator.reconcile() }
        await coordinator.audit()
        XCTAssertTrue(controller.appliedModes.isEmpty)
        XCTAssertEqual(controller.liveConfiguration, target)
        XCTAssertEqual(coordinator.state, .active)
    }

    func testInterruptedAuditReopensFreshTargetWhenIdentityReturns() async throws {
        let controller = TestRoutingController()
        let phone = RoutingSnapshot(decision: .init(mode: .wifiHotspot, proxyInterface: "en0", directInterface: "en0"), identity: "phone")
        let holder = SnapshotHolder(phone)
        let coordinator = RoutingCoordinator(controller: controller, loadBase: { try self.base() }, snapshot: { holder.value })
        await coordinator.reconcile(); controller.appliedModes.removeAll()
        controller.onVerify = {
            holder.value = .init(decision: .init(mode: .directOnly, proxyInterface: nil, directInterface: "en0"), identity: "campus")
        }
        controller.onVerifyStopped = { holder.value = phone }
        await coordinator.audit()
        XCTAssertEqual(controller.appliedModes, [.blocked, .blocked, .wifiHotspot])
        XCTAssertEqual(coordinator.applied, phone)
        XCTAssertEqual(coordinator.state, .active)
    }

    func testSameInterfaceNewNetworkIdentityStillClosesOldConnections() async throws {
        let controller = TestRoutingController()
        let holder = SnapshotHolder(RoutingSnapshot(decision: .init(mode: .wifiHotspot, proxyInterface: "en0", directInterface: "en0"), identity: "phone-a"))
        let coordinator = RoutingCoordinator(controller: controller, loadBase: { try self.base() }, snapshot: { holder.value })
        await coordinator.reconcile(); controller.appliedModes.removeAll()
        holder.value = .init(decision: holder.value.decision, identity: "phone-b")
        await coordinator.reconcile()
        XCTAssertEqual(controller.appliedModes, [.blocked, .wifiHotspot])
    }

    func testInvalidNewSubscriptionStillBlocksUsingLastValidBase() async throws {
        let controller = TestRoutingController()
        let invalid = FlagHolder()
        let coordinator = RoutingCoordinator(controller: controller, loadBase: {
            if invalid.value { throw RoutingConfigurationError.unsupported }
            return try self.base()
        }, snapshot: { .init(decision: .init(mode: .usbHotspot, proxyInterface: "en5", directInterface: "en5"), identity: "usb") })
        await coordinator.reconcile(); invalid.value = true
        await coordinator.reconcile(force: true)
        XCTAssertEqual(coordinator.state, .blockedAfterFailure)
        XCTAssertEqual(controller.appliedModes.last, .blocked)
    }

    func testSameFailedNetworkDoesNotRetryReloadEveryPoll() async throws {
        let controller = TestRoutingController(); controller.failMode = .usbHotspot
        let coordinator = make(controller); await coordinator.reconcile()
        controller.appliedModes.removeAll()
        await coordinator.reconcile()
        XCTAssertTrue(controller.appliedModes.isEmpty)
        await coordinator.reconcile(force: true)
        XCTAssertFalse(controller.appliedModes.isEmpty)
    }

    func testFailureBlockAuditRestoresDriftWithoutRetryingFailedTarget() async throws {
        let controller = TestRoutingController(); controller.failMode = .usbHotspot
        let coordinator = make(controller); await coordinator.reconcile()
        XCTAssertEqual(coordinator.state, .blockedAfterFailure)
        // Simulate a core restart or external reload without a network identity change.
        controller.liveConfiguration = nil; controller.appliedModes.removeAll(); controller.events.removeAll()
        await coordinator.audit()
        XCTAssertEqual(controller.appliedModes, [.blocked])
        XCTAssertEqual(controller.events, ["apply:blocked", "close"])
        XCTAssertEqual(coordinator.state, .blockedAfterFailure)
        XCTAssertNil(coordinator.applied)
        controller.appliedModes.removeAll(); controller.events.removeAll()
        await coordinator.audit(); await coordinator.reconcile(); await coordinator.audit()
        XCTAssertTrue(controller.events.isEmpty)
    }

    func testFailureBlockAuditReportsUnavailableAndRecoversSameSnapshot() async throws {
        let controller = TestRoutingController(); controller.failMode = .usbHotspot
        let coordinator = make(controller); await coordinator.reconcile()
        controller.unavailable = true; controller.appliedModes.removeAll()
        await coordinator.audit()
        XCTAssertEqual(coordinator.state, .unprotected)
        XCTAssertNil(coordinator.applied)
        controller.unavailable = false; controller.liveConfiguration = nil
        await coordinator.audit()
        XCTAssertEqual(controller.appliedModes, [.blocked])
        XCTAssertEqual(coordinator.state, .blockedAfterFailure)
    }

    func testFailureBlockAuditDoesNotReenableTun() async throws {
        let controller = TestRoutingController(); controller.failMode = .usbHotspot
        let coordinator = make(controller); await coordinator.reconcile()
        controller.tunEnabled = false; controller.appliedModes.removeAll()
        await coordinator.audit()
        XCTAssertEqual(coordinator.state, .paused)
        XCTAssertTrue(controller.appliedModes.isEmpty)
    }

    func testFailureBlockAuditDoesNotReenableTunDisabledDuringVerification() async throws {
        let controller = TestRoutingController(); controller.failMode = .usbHotspot
        let coordinator = make(controller); await coordinator.reconcile()
        controller.appliedModes.removeAll()
        controller.onVerify = {
            controller.tunEnabled = false
            // A production runtime verification also reports mismatch for a disabled TUN.
            controller.liveConfiguration = nil
        }
        await coordinator.audit()
        XCTAssertEqual(coordinator.state, .paused)
        XCTAssertTrue(controller.appliedModes.isEmpty)
    }

    func testFailureBlockAuditDoesNotClaimProtectionWhenRepairFails() async throws {
        let controller = TestRoutingController(); controller.failMode = .usbHotspot
        let coordinator = make(controller); await coordinator.reconcile()
        controller.liveConfiguration = nil; controller.failMode = .blocked
        await coordinator.audit()
        XCTAssertEqual(coordinator.state, .unprotected)
        controller.failMode = .usbHotspot; controller.appliedModes.removeAll()
        await coordinator.audit()
        XCTAssertEqual(coordinator.applied?.decision, nil)
        XCTAssertEqual(controller.appliedModes, [.blocked])
        XCTAssertEqual(coordinator.state, .blockedAfterFailure)
    }

    func testFailureBlockAuditFinishesCleanupAfterCloseFailure() async throws {
        let controller = TestRoutingController(); controller.failMode = .usbHotspot
        let coordinator = make(controller); await coordinator.reconcile()
        controller.liveConfiguration = nil; controller.closeFails = true
        await coordinator.audit()
        XCTAssertEqual(coordinator.state, .unprotected)
        controller.closeFails = false; controller.appliedModes.removeAll(); controller.events.removeAll()
        await coordinator.audit()
        // Matching rules alone cannot confirm protection after closing old connections failed.
        XCTAssertEqual(controller.appliedModes, [.blocked])
        XCTAssertEqual(controller.events, ["apply:blocked", "close"])
        XCTAssertEqual(coordinator.state, .blockedAfterFailure)
    }

    func testFailureBlockAuditDrainsNetworkChangeQueuedDuringVerification() async throws {
        let controller = TestRoutingController(); controller.failMode = .usbHotspot
        let holder = SnapshotHolder(.init(decision: .init(mode: .usbHotspot, proxyInterface: "en5", directInterface: "en5"), identity: "usb"))
        let coordinator = RoutingCoordinator(controller: controller, loadBase: { try self.base() }, snapshot: { holder.value })
        await coordinator.reconcile(); controller.failMode = nil; controller.appliedModes.removeAll()
        controller.onVerify = {
            holder.value = .init(decision: .init(mode: .directOnly, proxyInterface: nil, directInterface: "en0"), identity: "campus")
            await coordinator.reconcile()
        }
        await coordinator.audit()
        XCTAssertEqual(controller.appliedModes, [.blocked, .directOnly])
        XCTAssertEqual(coordinator.state, .active)
        XCTAssertEqual(coordinator.applied, holder.value)
    }

    func testFailureBlockAuditDrainsForcedRetryQueuedDuringVerification() async throws {
        let controller = TestRoutingController(); controller.failMode = .usbHotspot
        let coordinator = make(controller); await coordinator.reconcile()
        controller.failMode = nil; controller.appliedModes.removeAll()
        controller.onVerify = { await coordinator.reconcile(force: true) }
        await coordinator.audit()
        XCTAssertEqual(controller.appliedModes, [.blocked, .usbHotspot])
        XCTAssertEqual(coordinator.state, .active)
    }

    func testTurningOffTunPausesInsteadOfReenablingIt() async throws {
        let controller = TestRoutingController(); let coordinator = make(controller)
        await coordinator.reconcile(); controller.appliedModes.removeAll()
        controller.tunEnabled = false; controller.auditOK = false
        await coordinator.audit()
        XCTAssertTrue(controller.appliedModes.isEmpty)
        XCTAssertEqual(coordinator.state, .paused)
    }

    func testTunDisabledDuringBaseReadDoesNotApplyBlockOrTarget() async throws {
        let controller = TestRoutingController()
        let coordinator = RoutingCoordinator(controller: controller, loadBase: {
            controller.tunEnabled = false; return try self.base()
        }, snapshot: { .init(decision: .init(mode: .usbHotspot, proxyInterface: "en5", directInterface: "en5"), identity: "usb") })
        await coordinator.reconcile()
        XCTAssertEqual(coordinator.state, .paused)
        XCTAssertTrue(controller.appliedModes.isEmpty)
    }

    func testTunDisabledDuringDnsFlushDoesNotApplyTarget() async throws {
        let controller = TestRoutingController()
        controller.onFlush = { controller.tunEnabled = false }
        let coordinator = make(controller); await coordinator.reconcile()
        XCTAssertEqual(coordinator.state, .paused)
        XCTAssertEqual(controller.appliedModes, [.blocked])
        XCTAssertNil(coordinator.applied)
    }

    func testTunDisabledDuringTargetReloadDoesNotReportActive() async throws {
        let controller = TestRoutingController()
        controller.afterTarget = { controller.tunEnabled = false }
        let coordinator = make(controller); await coordinator.reconcile()
        XCTAssertEqual(coordinator.state, .paused)
        XCTAssertNil(coordinator.applied)
    }

    func testFlappingLimitDoesNotTurnTunBackOnDuringCleanup() async throws {
        let controller = TestRoutingController()
        let counter = CounterHolder()
        controller.onEveryApply = { if controller.appliedModes.count == 8 { controller.tunEnabled = false } }
        let coordinator = RoutingCoordinator(controller: controller, loadBase: { try self.base() }, snapshot: {
            counter.value += 1
            return .init(decision: .init(mode: .usbHotspot, proxyInterface: "en5", directInterface: "en5"), identity: "flap-\(counter.value)")
        })
        await coordinator.reconcile()
        XCTAssertEqual(controller.appliedModes.count, 8)
        XCTAssertEqual(coordinator.state, .paused)
    }

    private func assertStaleTargetRevokedBeforeNextRead(at phase: IdentityChangePhase) async throws {
        let controller = TestRoutingController()
        let holder = SnapshotHolder(.init(decision: .init(mode: .wifiHotspot, proxyInterface: "en0", directInterface: "en0"), identity: "phone"))
        var reads = 0
        let coordinator = RoutingCoordinator(controller: controller, loadBase: {
            reads += 1
            if reads == 2 {
                // Inspect protection at entry to the next read, before it can yield or return.
                let data = try XCTUnwrap(controller.liveConfiguration)
                let live = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
                XCTAssertEqual(live["rules"] as? [String], ["MATCH,REJECT"])
                XCTAssertEqual((live["proxies"] as? [[String: Any]])?.count, 0)
                XCTAssertEqual(Array(controller.events.suffix(3)), ["apply:blocked", "close", "flush"])
                XCTAssertEqual(controller.lastVerifiedConfiguration, data)
            }
            return try self.base()
        }, snapshot: { holder.value })
        let changeIdentity = {
            holder.value = .init(decision: .init(mode: .directOnly, proxyInterface: nil, directInterface: "en0"), identity: "campus")
        }
        switch phase {
        case .targetReload: controller.afterTarget = changeIdentity
        case .selectionRestore: controller.onRestore = changeIdentity
        case .runtimeVerification: controller.onVerify = changeIdentity
        }
        await coordinator.reconcile()
        XCTAssertEqual(reads, 2)
        XCTAssertEqual(coordinator.state, .active)
        XCTAssertEqual(coordinator.applied, holder.value)
    }

    private func make(_ controller: TestRoutingController) -> RoutingCoordinator {
        RoutingCoordinator(controller: controller, loadBase: { try self.base() }, snapshot: {
            .init(decision: .init(mode: .usbHotspot, proxyInterface: "en5", directInterface: "en5"), identity: "usb")
        })
    }
    private func base() throws -> Data {
        try JSONSerialization.data(withJSONObject: ["interface-name": "en5", "mode": "rule", "tun": ["enable": true],
            "proxies": [["name": "Node", "type": "trojan", "server": "example.invalid", "port": 443, "password": "fixture", "interface-name": "en5"],
                        ["name": "EZ-Campus", "type": "direct"], ["name": "EZ-USB-DNS", "type": "direct"]],
            "proxy-groups": [["name": "Proxy", "type": "select", "proxies": ["Node"]]], "rules": ["MATCH,Proxy"]])
    }
}

@MainActor private final class TestRoutingController: RoutingController {
    var events: [String] = []; var appliedModes: [RoutingMode] = []
    var liveConfiguration: Data?
    var lastVerifiedConfiguration: Data?
    var tunEnabled = true
    var onTunnelCheck: (() async -> Void)?
    func tunnelEnabled() async throws -> Bool {
        if unavailable { throw MihomoClientError.unavailable }
        let callback = onTunnelCheck; onTunnelCheck = nil; await callback?()
        return tunEnabled
    }
    var failMode: RoutingMode?; var unavailable = false; var auditOK = true
    var closeFails = false
    var onVerify: (() async -> Void)?
    var onVerifyStopped: (() -> Void)?
    var onRestore: (() async -> Void)?
    var onRestoreStopped: (() -> Void)?
    var onFlush: (() -> Void)?
    var onEveryApply: (() -> Void)?
    var afterBlock: (() -> Void)?; var afterTarget: (() -> Void)?
    func apply(configuration: Data) async throws {
        if unavailable { throw MihomoClientError.unavailable }
        let json = try JSONSerialization.jsonObject(with: configuration) as! [String: Any]
        let nodes = json["proxies"] as! [[String: Any]]
        let mode: RoutingMode = nodes.isEmpty ? .blocked : json["mode"] as? String == "direct" ? .directOnly : json["interface-name"] as? String == "en0" ? .wifiHotspot : .usbHotspot
        events.append("apply:" + mode.rawValue)
        if mode == failMode { throw MihomoClientError.response(500) }
        liveConfiguration = configuration
        appliedModes.append(mode); onEveryApply?()
        if mode == .blocked { afterBlock?(); afterBlock = nil }
        else { afterTarget?(); afterTarget = nil }
    }
    func closeConnections() async throws {
        events.append("close")
        if closeFails { throw MihomoClientError.unavailable }
    }
    func flushDNS() async throws { events.append("flush"); onFlush?(); onFlush = nil }
    func selections() async throws -> [String: String] { [:] }
    func restoreSelections(_ selections: [String: String], configuration: Data,
                           shouldContinue: @escaping @MainActor () async throws -> Bool) async throws -> Bool {
        guard try await shouldContinue() else { return false }
        let callback = onRestore; onRestore = nil; await callback?()
        let allowed = try await shouldContinue()
        if !allowed { onRestoreStopped?(); onRestoreStopped = nil }
        return allowed
    }
    func verify(configuration: Data, shouldContinue: @escaping @MainActor () async throws -> Bool) async throws -> Bool {
        if unavailable { throw MihomoClientError.unavailable }
        guard try await shouldContinue() else { return false }
        let callback = onVerify; onVerify = nil; await callback?()
        guard try await shouldContinue() else {
            onVerifyStopped?(); onVerifyStopped = nil; return false
        }
        if !auditOK { auditOK = true; return false }
        let matches = liveConfiguration == configuration
        if matches { lastVerifiedConfiguration = configuration }
        return matches
    }
}

@MainActor private final class SnapshotHolder { var value: RoutingSnapshot; init(_ value: RoutingSnapshot) { self.value = value } }

@MainActor private final class FlagHolder { var value = false }

@MainActor private final class CounterHolder { var value = 0 }

private enum IdentityChangePhase { case targetReload, selectionRestore, runtimeVerification }
