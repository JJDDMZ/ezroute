import Foundation
import Darwin
import EZSwitchCore

@MainActor final class RoutingCaptureSession {
    private let id = UUID()
    private var runner: Task<ProcessResult?, Never>?
    private var finished = false
    private var stopped = false
    private var startTimedOut = false
    var available: Bool { runner != nil && !finished && !stopped }
    func start(interfaces: [String]) async throws -> Bool {
        let command = try RoutingCaptureCommand.make(interfaces: interfaces, uid: getuid(), id: id)
        let escaped = command.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\(escaped)\" with administrator privileges with prompt \"EZ Route 需要短时采集包头，以核对本轮测试出口。不会更改网络设置。\""
        runner = Task { [weak self] in
            let result = try? await ProcessRunner.run(executable: "/usr/bin/osascript", arguments: ["-e", script],
                timeout: 245, maximumOutputBytes: 1024 * 1024)
            self?.finished = true
            return result
        }
        let deadline = ContinuousClock.now + .seconds(120)
        while !finished && ContinuousClock.now < deadline {
            try Task.checkCancellation()
            if status().contains("listening on") { return true }
            try await Task.sleep(for: .milliseconds(100))
        }
        startTimedOut = !finished
        return false
    }
    func packetOffset() -> Int { read("packets").count }
    func packets(since offset: Int) -> String {
        let data = read("packets")
        return String(decoding: data.dropFirst(min(offset, data.count)), as: UTF8.self)
    }
    private func requestStop() {
        guard !stopped else { return }
        stopped = true
        _ = FileManager.default.createFile(atPath: RoutingCaptureCommand.stopFile(id), contents: Data(), attributes: [.posixPermissions: 0o600])
    }
    func cancel() { requestStop(); runner?.cancel() }
    func stop() async -> RoutingCaptureOutcome {
        requestStop()
        let result = await runner?.value
        // On cancellation, the root shell owns cleanup; keep its stop signal until it exits.
        if runner?.isCancelled != true { try? FileManager.default.removeItem(atPath: RoutingCaptureCommand.stopFile(id)) }
        if runner?.isCancelled == true { return .interrupted }
        if startTimedOut { return .startTimedOut }
        return RoutingCaptureOutcome.parse(result)
    }
    private func status() -> String { String(decoding: read("status"), as: UTF8.self) }
    private func read(_ name: String) -> Data {
        let file = URL(fileURLWithPath: RoutingCaptureCommand.directory(id)).appendingPathComponent(name)
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: file.path),
              (attributes[.size] as? NSNumber)?.intValue ?? Int.max <= 1024 * 1024 else { return Data() }
        return (try? Data(contentsOf: file)) ?? Data()
    }
}
