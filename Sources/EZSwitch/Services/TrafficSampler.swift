import Foundation
import OSLog
import EZSwitchCore

/// Samples cumulative interface counters once a minute and appends one bucket per
/// minute. It lives inside the app process on purpose: the project runs no
/// background daemon, so the series has gaps whenever the app is not running.
@MainActor final class TrafficSampler {
    private static let logger = Logger(subsystem: "dev.ezswitch.app", category: "Traffic")
    private let reader: any InterfaceCounterReading
    private let store: TrafficStore
    private let interval: TimeInterval
    private var recorder = TrafficRecorder()
    private var timer: Timer?
    /// 为将来可能的设置界面保留;当前界面读的是 `TrafficStore.totals`,尚无消费方。
    private(set) var lastRecorded: Date?
    private(set) var lastError: String?

    init(directory: URL, reader: any InterfaceCounterReading = SystemInterfaceCounters(),
         interval: TimeInterval = 60) {
        self.store = TrafficStore(directory: directory)
        self.reader = reader
        self.interval = interval
    }

    func start() {
        guard timer == nil else { return }
        capture()
        let timer = Timer(timeInterval: interval, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.capture() }
        }
        // 默认模式下的定时器在菜单/滚动等 tracking 模式期间不触发,且错过的次数不会补发,
        // 每次错过的都是一整分钟的流量。挂到 .common,让追踪循环期间也照常采样。
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    func stop() { timer?.invalidate(); timer = nil }

    isolated deinit { timer?.invalidate() }

    private func capture() {
        let counters = reader.counters()
        guard let bucket = recorder.capture(counters: counters, at: Date()) else { return }
        do {
            try store.append(bucket)
            lastRecorded = Date()
            lastError = nil
        } catch {
            lastError = "流量写入失败"
            Self.logger.notice("traffic append failed")
        }
        do {
            try store.prune(now: Date())
        } catch {
            Self.logger.notice("traffic prune failed")
        }
    }
}
