import Foundation
import Darwin

public struct ProcessResult: Sendable {
    public let exitCode: Int32
    public let output: String
}

public enum ProcessFailure: Error, Equatable, LocalizedError {
    case timedOut
    public var errorDescription: String? { "快捷指令运行超时，请检查是否有等待确认的动作。" }
}

public enum ProcessRunner {
    public static func run(executable: String, arguments: [String], timeout: Double = 25,
                           maximumOutputBytes: Int = 64 * 1024) async throws -> ProcessResult {
        let outputURL = FileManager.default.temporaryDirectory.appendingPathComponent("ezswitch-\(UUID().uuidString).log")
        guard FileManager.default.createFile(atPath: outputURL.path, contents: nil,
                                            attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        let handle = try FileHandle(forWritingTo: outputURL)
        defer { try? handle.close(); try? FileManager.default.removeItem(at: outputURL) }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = handle
        process.standardError = handle
        try process.run()
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(timeout))
        do {
            while process.isRunning {
                try Task.checkCancellation()
                if clock.now >= deadline { throw ProcessFailure.timedOut }
                try await Task.sleep(for: .milliseconds(50))
            }
        } catch {
            if process.isRunning {
                process.terminate()
                // Bound shutdown too: shortcuts can stall while waiting on a system service.
                for _ in 0..<10 where process.isRunning { try? await Task.sleep(for: .milliseconds(50)) }
                if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            }
            throw error
        }
        // Process has already observed termination. waitUntilExit() spins a thread-local
        // run loop and can hang when an async task resumes on a different worker.
        let data = try Data(contentsOf: outputURL)
        return ProcessResult(exitCode: process.terminationStatus,
                             output: String(decoding: data.prefix(max(0, min(maximumOutputBytes, 2 * 1024 * 1024))), as: UTF8.self))
    }
}
