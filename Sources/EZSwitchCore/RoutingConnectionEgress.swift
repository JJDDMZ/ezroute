import Foundation

/// The physical interface a connection actually leaves through, taken from the
/// connection's policy chain and the controller's adapter table. Controller
/// evidence only; it is not packet-level proof.
public struct RoutingConnectionEgress: Equatable, Sendable {
    public let interface: String
    public let isDirect: Bool
    public init(interface: String, isDirect: Bool) {
        self.interface = interface; self.isDirect = isDirect
    }

    private static let groups: Set<String> = ["Selector", "URLTest", "Fallback", "LoadBalance"]
    private static let remote: Set<String> = ["Trojan", "Vmess", "Vless", "Shadowsocks",
                                              "ShadowsocksR", "Http", "Socks5", "Snell"]

    /// - Parameters:
    ///   - chains: the connection's chains, leaf first, as the controller reports them
    ///   - adapters: the `/proxies` payload
    ///   - globalInterface: the top-level `interface-name`, used when a chain ends at
    ///     the builtin DIRECT, which carries no interface of its own
    public static func find(chains: [String], adapters: [String: [String: Any]],
                            globalInterface: String? = nil) -> RoutingConnectionEgress? {
        var leaves: [RoutingConnectionEgress] = []
        for name in chains {
            guard let adapter = adapters[name], let type = adapter["type"] as? String else { return nil }
            if groups.contains(type) { continue }
            let inherited = type == "Direct" && name == "DIRECT" ? globalInterface : nil
            guard (type == "Direct" || remote.contains(type)),
                  let interface = (adapter["interface"] as? String).flatMap({ $0.isEmpty ? nil : $0 }) ?? inherited,
                  RoutingPolicy.validInterface(interface) else { return nil }
            leaves.append(.init(interface: interface, isDirect: type == "Direct"))
        }
        guard let first = leaves.first, leaves.allSatisfy({ $0 == first }) else { return nil }
        return first
    }
}
