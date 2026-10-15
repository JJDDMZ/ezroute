import XCTest
@testable import EZSwitchCore
final class RoutingInstanceLockTests: XCTestCase {
    func testSecondCoordinatorCannotTakeOwnershipUntilFirstExits() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("owner.lock")
        var first: RoutingInstanceLock? = try RoutingInstanceLock(at: path)
        XCTAssertNotNil(first)
        XCTAssertThrowsError(try RoutingInstanceLock(at: path))
        first = nil
        XCTAssertNoThrow(try RoutingInstanceLock(at: path))
    }
    func testDoesNotFollowLockSymlink() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let target = dir.appendingPathComponent("target"); try Data("unchanged".utf8).write(to: target)
        let link = dir.appendingPathComponent("owner.lock")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        XCTAssertThrowsError(try RoutingInstanceLock(at: link))
        XCTAssertEqual(try Data(contentsOf: target), Data("unchanged".utf8))
    }
}
