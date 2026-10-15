import Foundation
import Observation
import OSLog
import EZSwitchCore

@MainActor @Observable final class ConnectionMonitorModel {
    enum Range: String, CaseIterable, Identifiable {
        case halfHour, hour, day, twoDays, month
        var id: String { rawValue }
        var title: String {
            switch self {
            case .halfHour: "半小时"
            case .hour: "1 小时"
            case .day: "1 天"
            case .twoDays: "2 天"
            case .month: "30 天"
            }
        }
        var seconds: TimeInterval {
            switch self {
            case .halfHour: 1_800
            case .hour: 3_600
            case .day: 86_400
            case .twoDays: 172_800
            case .month: 2_592_000
            }
        }
    }

    static let pollInterval: Duration = .seconds(3)
    private static let adapterTTL: TimeInterval = 30
    /// 记录每次刷新的结果,便于下次「没数据」时从日志判定,而不是靠猜。
    private static let logger = Logger(subsystem: "dev.ezswitch.app", category: "Monitor")

    var range: Range = .halfHour {
        didSet { Task { await loadTraffic(force: true) } }
    }
    private(set) var rows: [RoutingConnectionRow] = []
    private(set) var traffic: [String: TrafficDelta] = [:]
    private(set) var unavailable = false
    private(set) var refreshing = false
    private(set) var refreshedAt: Date?
    private let store: TrafficStore
    @ObservationIgnored private var adapters = TimedValue<Data>(ttl: adapterTTL)
    @ObservationIgnored private var configs = TimedValue<Data>(ttl: adapterTTL)
    @ObservationIgnored private var metadataGeneration = 0
    @ObservationIgnored private var pollingID: UUID?
    @ObservationIgnored private var trafficRequestID: UUID?
    @ObservationIgnored private var trafficMinute: Int?

    init(directory: URL) { store = TrafficStore(directory: directory) }

    /// 每个出口一块:用量与连接同处一份,接口才不会在界面上出现两次。
    var sections: [RoutingEgressSection] {
        RoutingEgressSections.build(connections: rows, traffic: traffic)
    }

    /// 窗格出现就先取一次:窗口可见性通知可能还没到,不能因此一次都不取。
    /// 不可见时只取这一次、不轮询;可见性变化会让调用方的 `.task(id:)` 重建任务。
    func run(visible: Bool) async {
        let id = UUID()
        pollingID = id
        invalidateMetadata()
        defer { if pollingID == id { pollingID = nil } }
        _ = await refresh(force: true)
        guard visible else { return }
        while !Task.isCancelled, pollingID == id {
            do { try await Task.sleep(for: Self.pollInterval) } catch { return }
            _ = await refresh(force: false)
        }
    }

    func stop() {
        pollingID = nil
        trafficRequestID = nil
        invalidateMetadata()
    }

    private func invalidateMetadata() {
        metadataGeneration += 1
        adapters.invalidate()
        configs.invalidate()
    }

    private func checkGeneration(_ generation: Int) throws {
        try Task.checkCancellation()
        guard generation == metadataGeneration else { throw CancellationError() }
    }

    @discardableResult
    func refresh(force: Bool = false) async -> Bool {
        guard !refreshing, !Task.isCancelled else { return false }
        if force { invalidateMetadata() }
        let generation = metadataGeneration
        refreshing = true
        defer { refreshing = false }
        let client = MihomoClient()
        do {
            let connections = try await client.read(path: "/connections")
            try checkGeneration(generation)
            let proxies: Data
            if let cached = adapters.current(at: Date()) {
                proxies = cached
            } else {
                proxies = try await client.read(path: "/proxies")
                try checkGeneration(generation)
                adapters.update(proxies, at: Date())
            }
            let general: Data
            if let cached = configs.current(at: Date()) {
                general = cached
            } else {
                general = try await client.read(path: "/configs")
                try checkGeneration(generation)
                configs.update(general, at: Date())
            }
            let global = (try? JSONSerialization.jsonObject(with: general) as? [String: Any])?["interface-name"] as? String
            rows = try RoutingConnectionSnapshot.parse(connections: connections, proxies: proxies,
                                                       globalInterface: global)
            unavailable = false
            refreshedAt = Date()
        } catch is CancellationError {
            return false
        } catch {
            guard generation == metadataGeneration, !Task.isCancelled else { return false }
            invalidateMetadata()
            unavailable = true
        }
        await loadTraffic(force: force)
        Self.logger.notice("monitor refresh rows=\(self.rows.count) sections=\(self.sections.count) unavailable=\(self.unavailable) forced=\(force)")
        return true
    }

    func loadTraffic(force: Bool = true) async {
        let now = Date()
        let minute = Int(now.timeIntervalSince1970 / 60)
        guard force || trafficMinute != minute else { return }
        let selectedRange = range
        let request = UUID()
        trafficRequestID = request
        let store = store
        let since = now.addingTimeInterval(-selectedRange.seconds)
        // JSONL 解析不占用主执行器；连接轮询只在新分钟重算流量。
        let result = await Task.detached(priority: .utility) {
            try? store.totals(since: since, now: now)
        }.value
        guard !Task.isCancelled, trafficRequestID == request, range == selectedRange else { return }
        traffic = result ?? [:]
        trafficMinute = minute
    }

    static func bytes(_ value: UInt64) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        return formatter.string(fromByteCount: Int64(value))
    }
}
