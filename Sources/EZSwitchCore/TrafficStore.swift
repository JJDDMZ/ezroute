import Foundation

/// Append-only per-day JSONL. One line per minute; a partial trailing line after a
/// crash is skipped rather than failing the whole range.
public struct TrafficStore: Sendable {
    public static let retentionDays = 30
    public let directory: URL

    public init(directory: URL) { self.directory = directory }

    /// The one place this path is spelled out; the sampler and the settings page
    /// both read it from here rather than repeating the literal.
    public static var defaultDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/dev.ezswitch.app/traffic")
    }

    public func append(_ bucket: TrafficBucket) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        var data = try JSONEncoder().encode(bucket)
        data.append(0x0A)
        let url = directory.appendingPathComponent(Self.fileName(forMinute: bucket.minute))
        if FileManager.default.fileExists(atPath: url.path) {
            let handle = try FileHandle(forUpdating: url)
            defer { try? handle.close() }
            let end = try handle.seekToEnd()
            // 崩溃可能留下没有换行的残行;不先补一个换行,下一条记录会被拼到残行上一起丢掉。
            if end > 0 {
                try handle.seek(toOffset: end - 1)
                if try handle.read(upToCount: 1)?.first != 0x0A {
                    try handle.seek(toOffset: end)
                    try handle.write(contentsOf: Data([0x0A]))
                }
            }
            try handle.write(contentsOf: data)
        } else {
            try data.write(to: url, options: [.atomic])
        }
    }

    public func totals(since: Date, now: Date) throws -> [String: TrafficDelta] {
        guard FileManager.default.fileExists(atPath: directory.path) else { return [:] }
        let first = Int(since.timeIntervalSince1970 / 60)
        let last = Int(now.timeIntervalSince1970 / 60)
        guard first <= last else { return [:] }
        var totals: [String: TrafficDelta] = [:]
        // 遍历目录里真实存在的日文件,而不是按区间长度推算次数:后者会让一个遥远的 since
        // 尝试打开成千上万个不存在的文件(实测 since=1970 需 21,140 次、0.84 秒),而空目录
        // 现在打开 0 次。长区间也照旧读得到真正存在的那一天。
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        for name in names.sorted() {
            guard name.hasSuffix(".jsonl"),
                  let dayStart = Self.minute(fromFileName: name),
                  dayStart <= last, dayStart + 1_439 >= first else { continue }
            let url = directory.appendingPathComponent(name)
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            for line in text.split(separator: "\n") {
                guard let data = line.data(using: .utf8),
                      let bucket = try? JSONDecoder().decode(TrafficBucket.self, from: data),
                      bucket.minute >= first, bucket.minute <= last else { continue }
                for (interface, delta) in bucket.interfaces {
                    let current = totals[interface] ?? .init(received: 0, sent: 0)
                    totals[interface] = .init(received: current.received + delta.received,
                                              sent: current.sent + delta.sent)
                }
            }
        }
        return totals
    }

    public func prune(now: Date) throws {
        guard FileManager.default.fileExists(atPath: directory.path) else { return }
        let cutoffInstant = Int(now.addingTimeInterval(-Double(Self.retentionDays) * 86_400)
            .timeIntervalSince1970 / 60)
        // `day` 是天起点,cutoff 若留成时刻,边界那天在过了 UTC 零点后就会被误删,
        // 而它最新的分钟其实还在保留窗口内。
        let cutoff = Self.minute(fromFileName: Self.fileName(forMinute: cutoffInstant)) ?? cutoffInstant
        for name in (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? [] {
            guard name.hasSuffix(".jsonl"),
                  let day = Self.minute(fromFileName: name), day < cutoff else { continue }
            try FileManager.default.removeItem(at: directory.appendingPathComponent(name))
        }
    }

    private static let dayFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter
    }()

    static func fileName(forMinute minute: Int) -> String {
        dayFormatter.string(from: Date(timeIntervalSince1970: Double(minute) * 60)) + ".jsonl"
    }

    static func minute(fromFileName name: String) -> Int? {
        guard let date = dayFormatter.date(from: String(name.dropLast(6))) else { return nil }
        return Int(date.timeIntervalSince1970 / 60)
    }
}
