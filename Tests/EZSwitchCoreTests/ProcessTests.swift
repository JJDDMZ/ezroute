import XCTest
@testable import EZSwitchCore

final class ProcessTests: XCTestCase {
    func testArgumentsArePassedLiterallyWithoutShellExpansion() async throws {
        let result = try await ProcessRunner.run(executable: "/usr/bin/printf", arguments: ["%s", "$(touch /tmp/ezswitch-should-not-exist); 主号"], timeout: 2)
        XCTAssertEqual(result.output, "$(touch /tmp/ezswitch-should-not-exist); 主号")
        XCTAssertEqual(result.exitCode, 0)
    }
    func testLongRunningCommandTimesOut() async {
        do {
            _ = try await ProcessRunner.run(executable: "/bin/sleep", arguments: ["10"], timeout: 0.15)
            XCTFail("Expected timeout")
        } catch { XCTAssertEqual(error as? ProcessFailure, .timedOut) }
    }
    func testNonzeroExitIsPreserved() async throws {
        let result = try await ProcessRunner.run(executable: "/usr/bin/false", arguments: [], timeout: 2)
        XCTAssertNotEqual(result.exitCode, 0)
    }
}
