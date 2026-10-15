import XCTest
@testable import EZSwitchCore

final class ClashBootstrapBindingTests: XCTestCase {
    func testFirstUseCannotGuessInterfaceAndCannotReuseAnotherPhone() throws {
        XCTAssertThrowsError(try ClashBootstrapBinding.resolve(deviceID: "phone-A", currentInterface: nil,
            rememberedDeviceID: nil, rememberedInterface: nil))
        XCTAssertThrowsError(try ClashBootstrapBinding.resolve(deviceID: "phone-B", currentInterface: nil,
            rememberedDeviceID: "phone-A", rememberedInterface: "en5"))
        XCTAssertThrowsError(try ClashBootstrapBinding.resolve(deviceID: "phone-A", currentInterface: nil,
            rememberedDeviceID: nil, rememberedInterface: "en5"))
    }
    func testVerifiedCurrentInterfaceReplacesRememberedBinding() throws {
        let binding = try ClashBootstrapBinding.resolve(deviceID: "phone-B", currentInterface: "en8",
            rememberedDeviceID: "phone-A", rememberedInterface: "en5")
        XCTAssertEqual(binding.deviceID, "phone-B")
        XCTAssertEqual(binding.interface, "en8")
        XCTAssertThrowsError(try ClashBootstrapBinding.resolve(deviceID: "", currentInterface: "en5",
            rememberedDeviceID: nil, rememberedInterface: nil))
        XCTAssertThrowsError(try ClashBootstrapBinding.resolve(deviceID: "phone-A", currentInterface: "bad-interface",
            rememberedDeviceID: "phone-A", rememberedInterface: "en5"))
    }
    func testRememberedInterfaceRequiresSamePhone() throws {
        let binding = try ClashBootstrapBinding.resolve(deviceID: "phone-A", currentInterface: nil,
            rememberedDeviceID: "phone-A", rememberedInterface: "en5")
        XCTAssertEqual(binding.interface, "en5")
    }
    func testCacheInvalidatesForInterfacePhoneAndSubscriptionChanges() throws {
        func binding(_ phone: String, _ interface: String) throws -> ClashBootstrapBinding {
            try .resolve(deviceID: phone, currentInterface: interface, rememberedDeviceID: nil, rememberedInterface: nil)
        }
        var cache = ClashBootstrapSourceCache()
        let original = try binding("phone-A", "en5"), data = Data("subscription-A".utf8)
        cache.store(data, stamp: "A", binding: original)
        XCTAssertEqual(cache.lookup(stamp: "A", binding: original), data)
        XCTAssertNil(cache.lookup(stamp: "A", binding: try binding("phone-A", "en8")))
        XCTAssertNil(cache.lookup(stamp: "A", binding: try binding("phone-B", "en5")))
        XCTAssertNil(cache.lookup(stamp: "B", binding: original))
        let replacement = try binding("phone-B", "en8")
        cache.store(Data("subscription-B".utf8), stamp: "B", binding: replacement)
        XCTAssertNil(cache.lookup(stamp: "A", binding: original))
        XCTAssertEqual(cache.lookup(stamp: "B", binding: replacement), Data("subscription-B".utf8))
    }
}
