import XCTest
@testable import EZSwitchCore

final class TimedValueTests: XCTestCase {
    private let base = Date(timeIntervalSince1970: 1_760_000_000)

    func testMissingValueIsNil() {
        let cache = TimedValue<String>(ttl: 30)
        XCTAssertNil(cache.current(at: base))
    }

    func testValueIsAvailableWithinTTL() {
        var cache = TimedValue<String>(ttl: 30)
        cache.update("proxies", at: base)
        XCTAssertEqual(cache.current(at: base.addingTimeInterval(29)), "proxies")
    }

    func testValueExpiresAfterTTL() {
        var cache = TimedValue<String>(ttl: 30)
        cache.update("proxies", at: base)
        XCTAssertNil(cache.current(at: base.addingTimeInterval(31)))
    }

    func testExactlyTTLCountsAsExpired() {
        var cache = TimedValue<String>(ttl: 30)
        cache.update("proxies", at: base)
        XCTAssertNil(cache.current(at: base.addingTimeInterval(30)))
    }

    func testInvalidateClearsTheValue() {
        var cache = TimedValue<String>(ttl: 30)
        cache.update("proxies", at: base)
        cache.invalidate()
        XCTAssertNil(cache.current(at: base))
    }
}
