import XCTest
@testable import EZSwitchCore

final class DeviceSelectionTests: XCTestCase {
    private func defaults() -> UserDefaults {
        let name = "DeviceSelectionTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        addTeardownBlock { UserDefaults(suiteName: name)?.removePersistentDomain(forName: name) }
        return defaults
    }

    func testMigrationPersistsLegacyDeviceFromOldLineConfiguration() throws {
        let defaults = defaults()
        let original = try JSONDecoder().decode(Configuration.self, from: Data(
            #"{"deviceID":"","dailyLabel":"Daily","tetherLabel":"Shared","shortcutName":"Relay"}"#.utf8))
        defaults.set("B", forKey: "EZSwitch.routingDeviceID")
        let migrated = DeviceSelection.migrate(original, defaults: defaults)
        XCTAssertEqual(migrated.deviceID, "B")
        let saved = try JSONDecoder().decode(Configuration.self, from: XCTUnwrap(defaults.data(forKey: "EZSwitch.configuration")))
        XCTAssertEqual(saved.deviceID, "B")
        let fields = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(saved)) as? [String: Any])
        XCTAssertEqual(Set(fields.keys), ["deviceID"])
        XCTAssertNil(defaults.object(forKey: "EZSwitch.routingDeviceID"))
        XCTAssertEqual(DeviceSelection.migrate(saved, defaults: defaults).deviceID, "B")
    }

    func testOldConfigurationKeepsSelectedDeviceWithoutLineSettings() throws {
        let data = Data(#"{"deviceID":"A","dailyLabel":"商务","tetherLabel":"主号","shortcutName":"EZ Switch Relay"}"#.utf8)
        let configuration = try JSONDecoder().decode(Configuration.self, from: data)
        XCTAssertEqual(configuration.deviceID, "A")
        let fields = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(configuration)) as? [String: Any])
        XCTAssertEqual(Set(fields.keys), ["deviceID"])
    }

    func testSecondaryUSBInterfaceCannotHideActiveTetherInterface() {
        let phone = Phone(id: "phone", name: "iPhone")
        let activeFirst = phone.attaching(interface: "en5", isPrimary: true)
            .attaching(interface: "en6", isPrimary: false)
        XCTAssertEqual(activeFirst.interface, "en5")
        XCTAssertTrue(activeFirst.isPrimary)
        XCTAssertEqual(activeFirst.networkInterfaces, ["en5", "en6"])
        let inactiveFirst = phone.attaching(interface: "en6", isPrimary: false)
            .attaching(interface: "en5", isPrimary: true)
        XCTAssertEqual(inactiveFirst.interface, "en5")
        XCTAssertTrue(inactiveFirst.isPrimary)
        XCTAssertEqual(inactiveFirst.networkInterfaces, ["en6", "en5"])
    }

    func testMigrationKeepsConfiguredDeviceAndRemovesObsoleteKey() throws {
        let defaults = defaults()
        defaults.set("B", forKey: "EZSwitch.routingDeviceID")
        let result = DeviceSelection.migrate(Configuration(deviceID: "A"), defaults: defaults)
        let saved = try JSONDecoder().decode(Configuration.self, from: XCTUnwrap(defaults.data(forKey: "EZSwitch.configuration")))
        XCTAssertEqual(result.deviceID, "A")
        XCTAssertEqual(saved.deviceID, "A")
        XCTAssertNil(defaults.object(forKey: "EZSwitch.routingDeviceID"))
    }

    func testMigrationWithoutLegacyKeyLeavesPreferencesUntouched() {
        let defaults = defaults()
        let original = Configuration(deviceID: "A")
        XCTAssertEqual(DeviceSelection.migrate(original, defaults: defaults), original)
        XCTAssertNil(defaults.object(forKey: "EZSwitch.configuration"))
    }

    func testConfiguredValueWins() {
        XCTAssertEqual(DeviceSelection.resolve(configured: "A", legacy: "B", available: ["A", "C"]), "A")
    }

    func testLegacyValueIsAdoptedWhenNothingIsConfigured() {
        // 升级路径:配置为空而旧键有值时必须采纳旧值,否则用户要重选一次设备。
        XCTAssertEqual(DeviceSelection.resolve(configured: "", legacy: "B", available: []), "B")
    }

    func testSingleAvailableDeviceIsAdopted() {
        XCTAssertEqual(DeviceSelection.resolve(configured: "", legacy: nil, available: ["A"]), "A")
    }

    func testNoGuessWhenSeveralDevicesAreAvailable() {
        XCTAssertEqual(DeviceSelection.resolve(configured: "", legacy: nil, available: ["A", "B"]), "")
    }

    func testEmptyLegacyAndNoDevicesStaysEmpty() {
        XCTAssertEqual(DeviceSelection.resolve(configured: "", legacy: "", available: []), "")
    }
}
