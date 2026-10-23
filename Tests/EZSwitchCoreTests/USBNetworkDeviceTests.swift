import XCTest
@testable import EZSwitchCore

final class USBNetworkDeviceTests: XCTestCase {
    func testIPhoneKeepsLegacySelectionID() throws {
        let device = try XCTUnwrap(USBNetworkDevice.identify(vendorID: 0x05ac, productID: 1,
            name: "iPhone", serial: "existing-phone", registryPath: "port-a"))
        XCTAssertEqual(device.id, "existing-phone")
    }

    func testPortableRouterAndAndroidAreRecognizedWithoutAppleVendor() throws {
        for name in ["F50 Pro", "Android USB tethering"] {
            let device = try XCTUnwrap(USBNetworkDevice.identify(vendorID: 0x19d2, productID: 123,
                name: name, serial: "router", registryPath: "port-a"))
            XCTAssertEqual(device.name, name)
            XCTAssertFalse(device.id.isEmpty)
        }
    }

    func testDeviceWithoutSerialUsesPhysicalPathAndDoesNotCollideAcrossPorts() throws {
        let first = try XCTUnwrap(USBNetworkDevice.identify(vendorID: 1, productID: 2,
            name: "F50 Pro", serial: nil, registryPath: "port-a"))
        let again = USBNetworkDevice.identify(vendorID: 1, productID: 2,
            name: "F50 Pro", serial: "", registryPath: "port-a")
        let other = USBNetworkDevice.identify(vendorID: 1, productID: 2,
            name: "F50 Pro", serial: nil, registryPath: "port-b")
        XCTAssertEqual(first, again)
        XCTAssertNotEqual(first.id, other?.id)
        XCTAssertNil(USBNetworkDevice.identify(vendorID: 1, productID: 2,
            name: "F50 Pro", serial: nil, registryPath: nil))
    }

    func testSerialIdentitySurvivesPortChangesAndIsScopedToVendorAndProduct() throws {
        let first = try XCTUnwrap(USBNetworkDevice.identify(vendorID: 1, productID: 2,
            name: "F50 Pro", serial: "same", registryPath: "port-a"))
        let moved = USBNetworkDevice.identify(vendorID: 1, productID: 2,
            name: "F50 Pro", serial: "same", registryPath: "port-b")
        let other = USBNetworkDevice.identify(vendorID: 3, productID: 2,
            name: "F50 Pro", serial: "same", registryPath: "port-a")
        XCTAssertEqual(first, moved)
        XCTAssertNotEqual(first.id, other?.id)
    }

    func testMissingProductNameHasUsableLabel() throws {
        let device = try XCTUnwrap(USBNetworkDevice.identify(vendorID: 1, productID: 2,
            name: nil, serial: "router", registryPath: nil))
        XCTAssertEqual(device.name, "USB 网络设备")
    }

    func testPortableRouterUSBAndTrustedWirelessBindProxyAndDNS() throws {
        let trusted = RegisteredHotspot(ssid: Data("F50 Pro".utf8), security: 4, displayName: "F50 Pro")
        let usbOnly = RoutingPolicy.decide(.init(usbInterface: "en6"))
        let split = RoutingPolicy.decide(.init(usbInterface: "en6", wifiInterface: "en0"))
        let wireless = RoutingPolicy.decide(.init(wifiInterface: "en0", ssid: trusted.ssid,
            security: trusted.security, registrations: [trusted]))
        let both = RoutingPolicy.decide(.init(usbInterface: "en6", wifiInterface: "en0",
            ssid: trusted.ssid, security: trusted.security, registrations: [trusted]))
        XCTAssertEqual(usbOnly, .init(mode: .usbHotspot, proxyInterface: "en6", directInterface: "en6"))
        XCTAssertEqual(split, .init(mode: .split, proxyInterface: "en6", directInterface: "en0"))
        XCTAssertEqual(wireless, .init(mode: .wifiHotspot, proxyInterface: "en0", directInterface: "en0"))
        XCTAssertEqual(both, usbOnly)

        let base: [String: Any] = ["interface-name": "en5", "rules": ["MATCH,Proxy"],
            "proxies": [["name": "Proxy", "type": "ss", "interface-name": "en5"],
                        ["name": "EZ-Campus", "type": "direct"], ["name": "EZ-USB-DNS", "type": "direct"]],
            "proxy-groups": []]
        for decision in [usbOnly, split, wireless] {
            let data = try RoutingConfiguration.make(baseJSON: JSONSerialization.data(withJSONObject: base), decision: decision)
            let output = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
            let nodes = try XCTUnwrap(output["proxies"] as? [[String: Any]])
            XCTAssertEqual(output["interface-name"] as? String, decision.proxyInterface)
            XCTAssertEqual(nodes.first { $0["name"] as? String == "Proxy" }?["interface-name"] as? String, decision.proxyInterface)
            XCTAssertEqual(nodes.first { $0["name"] as? String == "EZ-USB-DNS" }?["interface-name"] as? String, decision.proxyInterface)
            XCTAssertEqual(nodes.first { $0["name"] as? String == "EZ-Campus" }?["interface-name"] as? String, decision.directInterface)
        }
    }
}
