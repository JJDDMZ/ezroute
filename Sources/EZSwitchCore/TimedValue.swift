import Foundation

/// 带时效的缓存值。超过 `ttl` 视为没有,由调用方决定是否重取。
/// 恰好等于 `ttl` 已算过期,避免边界上的两义。
public struct TimedValue<Value: Sendable>: Sendable {
    public let ttl: TimeInterval
    private var value: Value?
    private var storedAt: Date?

    public init(ttl: TimeInterval) { self.ttl = ttl }

    public mutating func update(_ value: Value, at now: Date) {
        self.value = value
        storedAt = now
    }

    public func current(at now: Date) -> Value? {
        guard let value, let storedAt, now.timeIntervalSince(storedAt) < ttl else { return nil }
        return value
    }

    public mutating func invalidate() {
        value = nil
        storedAt = nil
    }
}
