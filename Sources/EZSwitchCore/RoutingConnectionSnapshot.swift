import Foundation

/// One active connection, reduced to what the monitor shows. Process metadata is
/// deliberately absent: with TUN the controller records the source as 198.18.0.1
/// and cannot match it against the socket table, so `process` is always empty.
public struct RoutingConnectionRow: Equatable, Identifiable, Sendable {
    public let id: String
    public let target: String
    public let network: String
    public let rule: String
    public let chains: [String]
    public let egress: String?
    public let isDirect: Bool?
    public let received: UInt64
    public let sent: UInt64
}

public enum RoutingConnectionSnapshot {
    /// 累计字节数一律防御式读取:非有限值、负数、以及超出 `UInt64` 范围的值都记为 0,
    /// 既不崩溃也不回绕。注意 `NSNumber.uint64Value` 对负数与超大值不会崩,但会给出
    /// 18446744073709551615 或 5076964154930102272 这类垃圾值,所以范围检查不能省。
    /// 代价:理论上的 `UInt64.max` 会被当作超范围记为 0,而 2^64 字节(18 EB)不可能达到。
    /// 另两点:小数会被截断(1.5 → 1);也不要用 `(value as? Bool) != nil` 去排除布尔值 ——
    /// 实测 JSON 的 0 **与** 1 都会 bridge 成 Bool,那样会把真实的 0/1 字节计数抹成 0。
    private static func counter(_ value: Any?) -> UInt64 {
        if let number = value as? NSNumber {
            let magnitude = number.doubleValue
            guard magnitude.isFinite, magnitude >= 0,
                  magnitude < 18_446_744_073_709_551_616 else { return 0 }
            return number.uint64Value
        }
        if let text = value as? String, let parsed = UInt64(text) { return parsed }
        return 0
    }

    public static func parse(connections: Data, proxies: Data,
                             globalInterface: String?) throws -> [RoutingConnectionRow] {
        guard let root = try JSONSerialization.jsonObject(with: connections) as? [String: Any],
              let list = root["connections"] as? [[String: Any]],
              let proxyRoot = try JSONSerialization.jsonObject(with: proxies) as? [String: Any],
              let adapters = proxyRoot["proxies"] as? [String: [String: Any]] else {
            throw MihomoClientError.malformed
        }
        return list.enumerated().compactMap { index, entry in
            let metadata = entry["metadata"] as? [String: Any] ?? [:]
            let host = (metadata["host"] as? String) ?? ""
            let address = (metadata["destinationIP"] as? String) ?? ""
            let port = (metadata["destinationPort"] as? String) ?? ""
            let target = host.isEmpty ? (address.isEmpty ? "未知" : address + ":" + port) : host
            let chains = (entry["chains"] as? [String]) ?? []
            let payload = (entry["rulePayload"] as? String) ?? ""
            let rule = (entry["rule"] as? String) ?? "未知"
            let leaf = RoutingConnectionEgress.find(chains: chains, adapters: adapters,
                                                     globalInterface: globalInterface)
            return RoutingConnectionRow(
                id: (entry["id"] as? String) ?? "\(index)|\(target)|\(chains.joined(separator: ">"))",
                target: target,
                network: (metadata["network"] as? String) ?? "",
                rule: payload.isEmpty ? rule : rule + ":" + payload,
                chains: chains,
                egress: leaf?.interface,
                isDirect: leaf?.isDirect,
                received: counter(entry["download"]),
                sent: counter(entry["upload"]))
        }
    }
}
