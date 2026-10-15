import XCTest
@testable import EZSwitchCore

final class TrafficStoreTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("ez-traffic-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func date(_ iso: String) -> Date {
        ISO8601DateFormatter().date(from: iso)!
    }

    private func bucket(_ iso: String, _ received: UInt64, _ sent: UInt64) -> TrafficBucket {
        let minute = Int(date(iso).timeIntervalSince1970 / 60)
        return .init(minute: minute, interfaces: ["en0": .init(received: received, sent: sent)])
    }

    func testTotalsSumWithinTheRequestedRange() throws {
        let store = TrafficStore(directory: directory)
        try store.append(bucket("2026-10-12T10:00:00Z", 100, 10))
        try store.append(bucket("2026-10-12T10:01:00Z", 200, 20))
        try store.append(bucket("2026-10-12T11:00:00Z", 999, 99))
        let totals = try store.totals(since: date("2026-10-12T09:59:00Z"), now: date("2026-10-12T10:30:00Z"))
        XCTAssertEqual(totals["en0"], .init(received: 300, sent: 30))
    }

    func testTotalsSpanDayFiles() throws {
        let store = TrafficStore(directory: directory)
        try store.append(bucket("2026-10-11T23:59:00Z", 5, 5))
        try store.append(bucket("2026-10-12T00:01:00Z", 7, 7))
        let totals = try store.totals(since: date("2026-10-11T20:00:00Z"), now: date("2026-10-12T04:00:00Z"))
        XCTAssertEqual(totals["en0"], .init(received: 12, sent: 12))
    }

    func testCorruptLinesAreSkipped() throws {
        let store = TrafficStore(directory: directory)
        try store.append(bucket("2026-10-12T10:00:00Z", 100, 10))
        let file = directory.appendingPathComponent("2026-10-12.jsonl")
        let handle = try FileHandle(forWritingTo: file)
        try handle.seekToEnd()
        try handle.write(contentsOf: Data("{not json\n".utf8))
        try handle.close()
        let totals = try store.totals(since: date("2026-10-12T09:00:00Z"), now: date("2026-10-12T11:00:00Z"))
        XCTAssertEqual(totals["en0"], .init(received: 100, sent: 10))
    }

    func testPruneRemovesOnlyFilesOlderThanRetention() throws {
        let store = TrafficStore(directory: directory)
        try store.append(bucket("2026-09-01T10:00:00Z", 1, 1))
        try store.append(bucket("2026-10-12T10:00:00Z", 2, 2))
        try store.prune(now: date("2026-10-12T12:00:00Z"))
        let remaining = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
        XCTAssertEqual(remaining, ["2026-10-12.jsonl"])
    }

    func testALongRangeIsNotTruncated() throws {
        let store = TrafficStore(directory: directory)
        try store.append(bucket("2026-09-01T00:00:00Z", 1, 1))
        try store.append(bucket("2026-10-12T00:00:00Z", 2, 2))
        let totals = try store.totals(since: date("2026-09-01T00:00:00Z"),
                                      now: date("2026-10-12T01:00:00Z"))
        XCTAssertEqual(totals["en0"], .init(received: 3, sent: 3))
    }

    func testPruneKeepsTheBoundaryDayWhoseMinutesAreStillInTheWindow() throws {
        let store = TrafficStore(directory: directory)
        try store.append(bucket("2026-09-12T23:00:00Z", 5, 5))
        try store.prune(now: date("2026-10-12T12:00:00Z"))
        let remaining = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
        XCTAssertEqual(remaining, ["2026-09-12.jsonl"])
    }

    func testAppendingAfterATruncatedLineKeepsTheNextRecord() throws {
        let store = TrafficStore(directory: directory)
        try store.append(bucket("2026-10-12T10:00:00Z", 100, 10))
        let file = directory.appendingPathComponent("2026-10-12.jsonl")
        let handle = try FileHandle(forWritingTo: file)
        try handle.seekToEnd()
        try handle.write(contentsOf: Data("{partial".utf8))
        try handle.close()
        try store.append(bucket("2026-10-12T10:01:00Z", 9, 1))
        let totals = try store.totals(since: date("2026-10-12T09:00:00Z"),
                                      now: date("2026-10-12T11:00:00Z"))
        XCTAssertEqual(totals["en0"], .init(received: 109, sent: 11))
    }

    func testMissingDirectoryYieldsEmptyTotals() throws {
        let store = TrafficStore(directory: directory.appendingPathComponent("absent"))
        XCTAssertEqual(try store.totals(since: date("2026-10-12T00:00:00Z"),
                                        now: date("2026-10-12T23:59:00Z")).isEmpty, true)
    }

    func testDefaultDirectoryPointsAtTheAppTrafficFolder() {
        XCTAssertTrue(TrafficStore.defaultDirectory.path.hasSuffix("/dev.ezswitch.app/traffic"),
                      TrafficStore.defaultDirectory.path)
    }

    func testAVeryWideRangeFindsADayFileFarFromTheRangeStart() throws {
        // 区间从 1970 年起算,而文件在 1970-06-01:只有遍历真实存在的日文件才能找到它。
        // 按区间长度推算次数的实现(上限 32 个文件)会从 1970-01-01 往后走 32 天就停,读不到。
        let store = TrafficStore(directory: directory)
        try store.append(bucket("1970-06-01T00:00:00Z", 7, 7))
        let totals = try store.totals(since: Date(timeIntervalSince1970: 0), now: Date())
        XCTAssertEqual(totals["en0"], .init(received: 7, sent: 7))
    }

    func testCleanAppendsDoNotAccumulateBlankLines() throws {
        // 回归风险:无条件补换行也能让 totals 断言通过(split 会丢掉空字段),所以必须
        // 直接断言文件结构,否则无人能发现。
        let store = TrafficStore(directory: directory)
        try store.append(bucket("2026-10-12T10:00:00Z", 100, 10))
        try store.append(bucket("2026-10-12T10:01:00Z", 200, 20))
        let file = directory.appendingPathComponent("2026-10-12.jsonl")
        let text = try String(contentsOf: file, encoding: .utf8)
        XCTAssertEqual(text.filter { $0 == "\n" }.count, 2)
        XCTAssertTrue(text.hasSuffix("\n"))
        XCTAssertEqual(text.split(separator: "\n").count, 2)
    }
}
