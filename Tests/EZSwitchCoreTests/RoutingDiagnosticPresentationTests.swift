import XCTest
@testable import EZSwitchCore

final class RoutingDiagnosticPresentationTests: XCTestCase {
    private let split = RoutingDecision(mode: .split, proxyInterface: "en5", directInterface: "en0")
    func testCaptureReportsAuthorizationCancellationWithoutExposingRawError() {
        let result = ProcessResult(exitCode: 1, output: "execution error: User canceled. (-128)")
        XCTAssertEqual(RoutingCaptureOutcome.parse(result), .authorizationDeclined)
    }
    func testCaptureRequiresCompleteZeroDropStatistics() {
        XCTAssertEqual(RoutingCaptureOutcome.parse(nil), .unavailable)
        XCTAssertEqual(RoutingCaptureOutcome.parse(.init(exitCode: 0, output: "EZ_CAPTURE_STATUS\nlistening on pktap\n0 packets dropped by kernel\nEZ_CAPTURE_END 0 0\n")), .complete)
        XCTAssertEqual(RoutingCaptureOutcome.parse(.init(exitCode: 0, output: "EZ_CAPTURE_STATUS\nlistening on pktap\n1 packet dropped by kernel\nEZ_CAPTURE_END 0 0\n")), .packetsDropped)
        XCTAssertEqual(RoutingCaptureOutcome.parse(.init(exitCode: 0, output: "EZ_CAPTURE_STATUS\nlistening on pktap\n2048 packets captured\n0 packets dropped by kernel\nEZ_CAPTURE_END 0 0\n")), .limitReached)
        XCTAssertEqual(RoutingCaptureOutcome.parse(.init(exitCode: 0, output: "EZ_CAPTURE_STATUS\nlistening on pktap\n")), .statisticsMissing)
    }
    func testRealSingularDropIsRecognizedAsLoss() {
        let status = "EZ_CAPTURE_STATUS\nlistening on pktap\n42 packets captured\n43 packets received by filter\n1 packet dropped by kernel\nEZ_CAPTURE_END 0 0\n"
        XCTAssertEqual(RoutingCaptureOutcome.parse(.init(exitCode: 0, output: status)), .packetsDropped)
    }
    func testForcedEndCannotPassWithAnEarlierZeroDropSample() {
        let status = "EZ_CAPTURE_STATUS\nlistening on pktap\n42 packets captured\n42 packets received by filter\n0 packets dropped by kernel\nEZ_CAPTURE_END 137 1\n"
        XCTAssertNotEqual(RoutingCaptureOutcome.parse(.init(exitCode: 0, output: status)), .complete)
    }
    func testAbnormalChildExitCannotPassWithZeroDrops() {
        let status = "EZ_CAPTURE_STATUS\nlistening on pktap\n42 packets captured\n42 packets received by filter\n0 packets dropped by kernel\nEZ_CAPTURE_END 1 0\n"
        XCTAssertNotEqual(RoutingCaptureOutcome.parse(.init(exitCode: 0, output: status)), .complete)
    }
    func testMissingEndConfirmationCannotPass() {
        let status = "EZ_CAPTURE_STATUS\nlistening on pktap\n42 packets captured\n42 packets received by filter\n0 packets dropped by kernel\n"
        XCTAssertEqual(RoutingCaptureOutcome.parse(.init(exitCode: 0, output: status)), .statisticsMissing)
    }
    func testMissingPhysicalEvidenceIsNotDescribedAsMismatch() {
        let detail = RoutingDiagnosticText.physicalDetail(binding: "en5", isDirect: false, decision: split,
            interfaces: [], endpointAvailable: true, capture: .complete)
        XCTAssertTrue(detail.contains("证据不足"))
        XCTAssertFalse(detail.contains("发现不符"))
        XCTAssertFalse(detail.contains("待汇总"))
    }
    func testObservedWrongInterfaceRemainsFailureWhenCaptureIncomplete() {
        let detail = RoutingDiagnosticText.physicalDetail(binding: "en5", isDirect: false, decision: split,
            interfaces: ["en0"], endpointAvailable: true, capture: .packetsDropped)
        XCTAssertTrue(detail.contains("发现不符"))
        XCTAssertTrue(detail.contains("实际观测：en0"))
        XCTAssertTrue(detail.contains("预期出口为en5"))
    }
    func testConfigurationBindingAloneNeverDescribesPhysicalSuccess() {
        let detail = RoutingDiagnosticText.physicalDetail(binding: "en5", isDirect: false, decision: split,
            interfaces: [], endpointAvailable: true, capture: .authorizationDeclined)
        XCTAssertTrue(detail.contains("配置绑定"))
        XCTAssertTrue(detail.contains("授权已取消"))
        XCTAssertFalse(detail.contains("符合预期"))
    }
    func testPhysicalSuccessRequiresMatchingPacketsAndCompleteCapture() {
        XCTAssertTrue(RoutingDiagnosticText.physicalDetail(binding: "en0", isDirect: true, decision: split,
            interfaces: ["en0"], endpointAvailable: true, capture: .complete).contains("符合预期"))
        XCTAssertFalse(RoutingDiagnosticText.physicalDetail(binding: "en0", isDirect: true, decision: split,
            interfaces: ["en0"], endpointAvailable: true, capture: .packetsDropped).contains("符合预期"))
    }
    func testWebsiteResponseSummaryNeverClaimsRoutePass() {
        let text = RoutingDiagnosticText.connectivitySummary(received: 5, restricted: 2, total: 5, interrupted: false)
        XCTAssertTrue(text.contains("5/5")); XCTAssertTrue(text.contains("2 个"))
        XCTAssertTrue(text.contains("HTTPS 响应")); XCTAssertFalse(text.contains("符合预期"))
    }
}
