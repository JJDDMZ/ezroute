import Foundation

/// 一个出口的全部信息:该出口在所选范围内的用量,以及当前经它出去的连接。
/// 用量与连接合成一份,接口才不会在界面上出现两次。
public struct RoutingEgressSection: Equatable, Identifiable, Sendable {
    /// `nil` 表示出口未知(策略链里解析不出出口的那些连接)。
    public let egress: String?
    /// 该接口在所选范围内的合计;没有记录时为 `nil`。
    public let usage: TrafficDelta?
    public let connections: [RoutingConnectionRow]

    public var id: String { egress ?? "" }
    public var total: UInt64 { (usage?.received ?? 0) + (usage?.sent ?? 0) }

    public init(egress: String?, usage: TrafficDelta?, connections: [RoutingConnectionRow]) {
        self.egress = egress
        self.usage = usage
        self.connections = connections
    }
}

public enum RoutingEgressSections {
    /// 接口集合取「有连接的出口」与「有用量的接口」的并集:只有用量没有连接的接口也要出现,
    /// 否则它的用量就又无处安放。「出口未知」不参与并集,固定排在最后。
    public static func build(connections: [RoutingConnectionRow],
                             traffic: [String: TrafficDelta]) -> [RoutingEgressSection] {
        var known: [String: [RoutingConnectionRow]] = [:]
        var unknown: [RoutingConnectionRow] = []
        for row in connections {
            if let egress = row.egress { known[egress, default: []].append(row) }
            else { unknown.append(row) }
        }
        var sections = Set(known.keys).union(traffic.keys).map { name in
            RoutingEgressSection(egress: name, usage: traffic[name], connections: known[name] ?? [])
        }
        sections.sort { lhs, rhs in
            if lhs.connections.isEmpty != rhs.connections.isEmpty { return !lhs.connections.isEmpty }
            if lhs.total != rhs.total { return lhs.total > rhs.total }
            return (lhs.egress ?? "") < (rhs.egress ?? "")
        }
        if !unknown.isEmpty {
            sections.append(RoutingEgressSection(egress: nil, usage: nil, connections: unknown))
        }
        return sections
    }
}
