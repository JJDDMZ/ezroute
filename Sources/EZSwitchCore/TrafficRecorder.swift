import Foundation

public struct TrafficDelta: Codable, Equatable, Sendable {
    public let received: UInt64
    public let sent: UInt64
    public init(received: UInt64, sent: UInt64) { self.received = received; self.sent = sent }
}

/// One minute of per-interface byte deltas. `minute` is minutes since 1970 in UTC.
public struct TrafficBucket: Codable, Equatable, Sendable {
    public let minute: Int
    public let interfaces: [String: TrafficDelta]
    public init(minute: Int, interfaces: [String: TrafficDelta]) {
        self.minute = minute; self.interfaces = interfaces
    }
}

/// Turns cumulative interface counters into per-minute deltas.
///
/// Three samples produce no bucket. A counter that went backwards means the machine
/// restarted, and a gap longer than `gapTolerance` means the bytes cannot be attributed
/// to a single minute; both still re-baseline, so the next sample is sound. An empty read
/// is different: it means nothing was read at all, so the baseline is left untouched
/// rather than wiped.
public struct TrafficRecorder: Sendable {
    public static let gapTolerance: TimeInterval = 120
    private var previous: [String: TrafficDelta] = [:]
    private var previousAt: Date?

    public init() {}

    public mutating func capture(counters: [String: TrafficDelta], at now: Date) -> TrafficBucket? {
        // 空读数表示本轮没读到,而不是所有接口都消失了:此时不得改动基线,
        // 否则下一次真实读数会因为缺少基线而整分钟丢失。
        guard !counters.isEmpty else { return nil }
        defer { previous = counters; previousAt = now }
        guard let previousAt else { return nil }
        let elapsed = now.timeIntervalSince(previousAt)
        guard elapsed > 0, elapsed <= Self.gapTolerance else { return nil }
        var deltas: [String: TrafficDelta] = [:]
        for (name, current) in counters {
            guard let last = previous[name],
                  current.received >= last.received, current.sent >= last.sent else { continue }
            let received = current.received - last.received
            let sent = current.sent - last.sent
            if received > 0 || sent > 0 { deltas[name] = .init(received: received, sent: sent) }
        }
        guard !deltas.isEmpty else { return nil }
        return .init(minute: Int(now.timeIntervalSince1970 / 60), interfaces: deltas)
    }
}
