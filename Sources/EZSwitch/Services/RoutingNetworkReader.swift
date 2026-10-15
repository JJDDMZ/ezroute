import Foundation
import CoreWLAN
import SystemConfiguration
import EZSwitchCore

struct RoutingNetworkReading {
    let network: RoutingNetwork
    let wifiName: String?
    let registrationAllowed: Bool
    let message: String?
    var identity: String = "unknown"
}

@MainActor enum RoutingNetworkReader {
    static func read(phones: DeviceSnapshot, deviceID: String,
                     registrations: [RegisteredHotspot], identityAuthorized: Bool) -> RoutingNetworkReading {
        guard phones.error == nil,
              let store = SCDynamicStoreCreate(nil, "EZSwitchRouting" as CFString, nil, nil),
              SCDynamicStoreCopyKeyList(store, "State:/Network/.*" as CFString) != nil else {
            return .init(network: .init(stateReadable: false), wifiName: nil,
                         registrationAllowed: false, message: "网络状态读取失败。")
        }
        func ready(_ name: String) -> Bool {
            guard RoutingPolicy.validInterface(name) else { return false }
            let link = SCDynamicStoreCopyValue(store, "State:/Network/Interface/\(name)/Link" as CFString) as? [String: Any]
            let ipv4 = SCDynamicStoreCopyValue(store, "State:/Network/Interface/\(name)/IPv4" as CFString) as? [String: Any]
            return RoutingPolicy.usableIPv4(active: link?["Active"] as? Bool == true,
                                           addresses: ipv4?["Addresses"] as? [String] ?? [])
        }
        let usbCandidates = (phones.devices.first { $0.id == deviceID }?.networkInterfaces ?? []).filter(ready)
        guard usbCandidates.count <= 1 else {
            return .init(network: .init(stateReadable: false), wifiName: nil, registrationAllowed: false,
                         message: "检测到多个 iPhone USB 出口，正在等待唯一可用出口。")
        }
        let usb = usbCandidates.first
        let available = (CWWiFiClient.shared().interfaces() ?? []).filter {
            $0.powerOn() && $0.interfaceName.map(ready) == true
        }
        guard available.count <= 1 else {
            return .init(network: .init(stateReadable: false), wifiName: nil,
                         registrationAllowed: false, message: "检测到多个 Wi-Fi 出口，正在等待唯一可用出口。")
        }
        let wifi = available.first
        let ssid = identityAuthorized ? wifi?.ssidData() : nil
        let security = identityAuthorized ? wifi.map { Int($0.security().rawValue) } : nil
        let canRegister = ssid.map { (1...32).contains($0.count) } == true &&
            security.map(RoutingPolicy.personalSecurity) == true
        func addressIdentity(_ name: String?) -> String {
            guard let name else { return "none" }
            let value = SCDynamicStoreCopyValue(store, "State:/Network/Interface/\(name)/IPv4" as CFString) as? [String: Any]
            return name + ":" + ((value?["Addresses"] as? [String] ?? []).sorted().joined(separator: ","))
        }
        let identity = [addressIdentity(usb), addressIdentity(wifi?.interfaceName),
                        ssid?.base64EncodedString() ?? "unknown", String(security ?? -1),
                        identityAuthorized ? wifi?.bssid() ?? "unknown" : "unknown"].joined(separator: "|")
        let name = ssid.flatMap { String(data: $0, encoding: .utf8) }
        return .init(network: .init(usbInterface: usb, wifiInterface: wifi?.interfaceName,
                                   ssid: ssid, security: security, registrations: registrations),
                     wifiName: name, registrationAllowed: canRegister,
                     message: wifi != nil && ssid == nil ? "Wi-Fi 名称读取失败，该网络仅用于直连。" : nil, identity: identity)
    }
}
