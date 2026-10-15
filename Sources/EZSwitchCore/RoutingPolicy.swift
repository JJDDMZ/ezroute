import Foundation
import Darwin

public struct RegisteredHotspot: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let ssid: Data
    public let security: Int
    public let displayName: String
    public init(ssid: Data, security: Int, displayName: String, id: UUID = UUID()) {
        self.id = id; self.ssid = ssid; self.security = security; self.displayName = displayName
    }
    public func matches(ssid: Data?, security: Int?) -> Bool {
        guard let ssid, (1...32).contains(ssid.count), let security,
              RoutingPolicy.personalSecurity(security) else { return false }
        return self.ssid == ssid && self.security == security
    }
}

public struct RoutingNetwork: Sendable {
    public var usbInterface: String?
    public var wifiInterface: String?
    public var ssid: Data?
    public var security: Int?
    public var registrations: [RegisteredHotspot]
    public var stateReadable: Bool
    public init(usbInterface: String? = nil, wifiInterface: String? = nil,
                ssid: Data? = nil, security: Int? = nil,
                registrations: [RegisteredHotspot] = [], stateReadable: Bool = true) {
        self.usbInterface = usbInterface; self.wifiInterface = wifiInterface
        self.ssid = ssid; self.security = security; self.registrations = registrations
        self.stateReadable = stateReadable
    }
}

public enum RoutingMode: String, Codable, Sendable {
    case usbHotspot, wifiHotspot, split, directOnly, blocked
}

public struct RoutingDecision: Codable, Equatable, Sendable {
    public let mode: RoutingMode
    public let proxyInterface: String?
    public let directInterface: String?
    public init(mode: RoutingMode, proxyInterface: String?, directInterface: String?) {
        self.mode = mode; self.proxyInterface = proxyInterface; self.directInterface = directInterface
    }
}

public enum RoutingPolicy {
    public static func personalSecurity(_ value: Int) -> Bool { [2, 3, 4, 5, 11, 13].contains(value) }
    public static func usableIPv4(active: Bool, addresses: [String]) -> Bool {
        guard active else { return false }
        return addresses.contains { address in
            var parsed = in_addr()
            guard inet_pton(AF_INET, address, &parsed) == 1,
                  let first = address.split(separator: ".").first.flatMap({ Int($0) }),
                  first > 0, first < 224, first != 127, !address.hasPrefix("169.254.") else { return false }
            return true
        }
    }
    public static func validInterface(_ name: String) -> Bool {
        name.range(of: "^en[0-9]+$", options: .regularExpression) != nil
    }
    public static func decide(_ network: RoutingNetwork) -> RoutingDecision {
        let blocked = RoutingDecision(mode: .blocked, proxyInterface: nil, directInterface: nil)
        guard network.stateReadable,
              [network.usbInterface, network.wifiInterface].compactMap({ $0 }).allSatisfy(validInterface),
              network.usbInterface == nil || network.usbInterface != network.wifiInterface else { return blocked }
        let registered = network.registrations.contains { $0.matches(ssid: network.ssid, security: network.security) }
        if let usb = network.usbInterface {
            if let wifi = network.wifiInterface, !registered {
                return .init(mode: .split, proxyInterface: usb, directInterface: wifi)
            }
            return .init(mode: .usbHotspot, proxyInterface: usb, directInterface: usb)
        }
        if let wifi = network.wifiInterface {
            return .init(mode: registered ? .wifiHotspot : .directOnly,
                         proxyInterface: registered ? wifi : nil, directInterface: wifi)
        }
        return blocked
    }
}
