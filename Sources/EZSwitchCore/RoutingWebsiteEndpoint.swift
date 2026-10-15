import Foundation

public struct RoutingWebsiteEndpoint: Equatable, Sendable {
    public let address: String
    public let port: Int
    public let rule: String
    public static func find(host: String, localPort: Int, previousIDs: Set<String>, observations: [Data],
                            configuration: Data) throws -> Self? {
        guard let config = try JSONSerialization.jsonObject(with: configuration) as? [String: Any],
              let nodes = config["proxies"] as? [[String: Any]] else { return nil }
        var endpoints: Set<String> = []
        var result: Self?
        for frame in observations {
            guard let root = try JSONSerialization.jsonObject(with: frame) as? [String: Any] else { return nil }
            for connection in root["connections"] as? [[String: Any]] ?? [] {
                guard let id = connection["id"] as? String, !previousIDs.contains(id),
                      let metadata = connection["metadata"] as? [String: Any],
                      metadata["sourceIP"] as? String == "127.0.0.1",
                      (metadata["host"] as? String)?.lowercased() == host.lowercased(),
                      Int(String(describing: metadata["sourcePort"] ?? "")) == localPort,
                      let raw = metadata["remoteDestination"] as? String,
                      let address = RoutingSelfCheck.canonicalIP(raw),
                      let chain = connection["chains"] as? [String] else { continue }
                let leaves = nodes.filter { node in
                    chain.contains(node["name"] as? String ?? "") && node["type"] as? String != "direct"
                }
                guard leaves.count <= 1 else { return nil }
                let port = leaves.first.flatMap { Int(String(describing: $0["port"] ?? "")) } ?? (leaves.isEmpty ? 443 : 0)
                guard (1...65535).contains(port) else { return nil }
                let rule = connection["rule"] as? String ?? ""
                endpoints.insert("\(address)|\(port)|\(rule)")
                result = .init(address: address, port: port, rule: rule)
            }
        }
        return endpoints.count == 1 ? result : nil
    }
}
