import XCTest
@testable import EZSwitchCore

final class TrafficRecorderTests: XCTestCase {
    private let base = Date(timeIntervalSince1970: 1_760_000_000)

    func testFirstSampleOnlyEstablishesTheBaseline() {
        var recorder = TrafficRecorder()
        XCTAssertNil(recorder.capture(counters: ["en0": .init(received: 100, sent: 200)], at: base))
    }

    func testSecondSampleProducesTheDelta() {
        var recorder = TrafficRecorder()
        _ = recorder.capture(counters: ["en0": .init(received: 100, sent: 200)], at: base)
        let bucket = recorder.capture(counters: ["en0": .init(received: 150, sent: 260)],
                                      at: base.addingTimeInterval(60))
        XCTAssertEqual(bucket?.interfaces["en0"], .init(received: 50, sent: 60))
        XCTAssertEqual(bucket?.minute, Int(base.addingTimeInterval(60).timeIntervalSince1970 / 60))
    }

    func testCounterResetIsDiscardedAndRebaselined() {
        var recorder = TrafficRecorder()
        _ = recorder.capture(counters: ["en0": .init(received: 900, sent: 900)], at: base)
        XCTAssertNil(recorder.capture(counters: ["en0": .init(received: 10, sent: 10)],
                                      at: base.addingTimeInterval(60)))
        let bucket = recorder.capture(counters: ["en0": .init(received: 30, sent: 40)],
                                      at: base.addingTimeInterval(120))
        XCTAssertEqual(bucket?.interfaces["en0"], .init(received: 20, sent: 30))
    }

    func testSampleAfterALongGapIsDiscardedButStillRebaselines() {
        var recorder = TrafficRecorder()
        _ = recorder.capture(counters: ["en0": .init(received: 100, sent: 100)], at: base)
        XCTAssertNil(recorder.capture(counters: ["en0": .init(received: 9_000, sent: 9_000)],
                                      at: base.addingTimeInterval(3_600)))
        let bucket = recorder.capture(counters: ["en0": .init(received: 9_010, sent: 9_020)],
                                      at: base.addingTimeInterval(3_660))
        XCTAssertEqual(bucket?.interfaces["en0"], .init(received: 10, sent: 20))
    }

    func testUnchangedCountersProduceNoBucket() {
        var recorder = TrafficRecorder()
        _ = recorder.capture(counters: ["en0": .init(received: 100, sent: 100)], at: base)
        XCTAssertNil(recorder.capture(counters: ["en0": .init(received: 100, sent: 100)],
                                      at: base.addingTimeInterval(60)))
    }

    func testAnInterfaceThatDisappearsIsSimplyAbsent() {
        var recorder = TrafficRecorder()
        _ = recorder.capture(counters: ["en0": .init(received: 100, sent: 100),
                                        "en5": .init(received: 5, sent: 5)], at: base)
        let bucket = recorder.capture(counters: ["en0": .init(received: 140, sent: 100)],
                                      at: base.addingTimeInterval(60))
        XCTAssertEqual(bucket?.interfaces.keys.sorted(), ["en0"])
    }

    func testAGapOfExactlyTheToleranceIsStillCounted() {
        var recorder = TrafficRecorder()
        _ = recorder.capture(counters: ["en0": .init(received: 100, sent: 100)], at: base)
        let bucket = recorder.capture(counters: ["en0": .init(received: 130, sent: 120)],
                                      at: base.addingTimeInterval(TrafficRecorder.gapTolerance))
        XCTAssertEqual(bucket?.interfaces["en0"], .init(received: 30, sent: 20))
    }

    func testAnEmptyReadDoesNotWipeTheBaseline() {
        var recorder = TrafficRecorder()
        _ = recorder.capture(counters: ["en0": .init(received: 100, sent: 100)], at: base)
        XCTAssertNil(recorder.capture(counters: [:], at: base.addingTimeInterval(60)))
        let bucket = recorder.capture(counters: ["en0": .init(received: 140, sent: 130)],
                                      at: base.addingTimeInterval(120))
        XCTAssertEqual(bucket?.interfaces["en0"], .init(received: 40, sent: 30))
    }
}
