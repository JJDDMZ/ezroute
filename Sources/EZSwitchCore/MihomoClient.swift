import Foundation
import Darwin

public enum MihomoClientError: Error, LocalizedError {
    case unavailable, response(Int), malformed, unsafePath
    public var errorDescription: String? {
        switch self {
        case .unavailable: "Clash 本地控制接口不可用。"
        case .response(let code): "Clash 未接受请求（HTTP \(code)）。"
        case .malformed: "Clash 配置或响应无法读取。"
        case .unsafePath: "不支持的本地控制请求。"
        }
    }
}

/// Unix sockets use filesystem access control; no token is passed to a child process.
public actor MihomoClient {
    public let socketPath: String
    private let temporaryRoot: URL
    public init(socketPath: String = "/var/run/clash-verge-service/users/\(getuid())/verge-mihomo.sock",
                temporaryRoot: URL = FileManager.default.temporaryDirectory) {
        self.socketPath = socketPath; self.temporaryRoot = temporaryRoot
    }

    public static func readGeneratedConfiguration(at source: URL) async throws -> Data {
        let directory = try PrivateRequestDirectory()
        defer { directory.remove() }
        let output = directory.url.appendingPathComponent("configuration.json")
        try directory.write(Data(), to: output)
        let script = "obj=YAML.safe_load(File.read(ARGV[0]),aliases:true); File.write(ARGV[1],JSON.generate(obj))"
        let result = try await ProcessRunner.run(executable: "/usr/bin/ruby",
            arguments: ["-ryaml", "-rjson", "-e", script, source.path, output.path], timeout: 8)
        guard result.exitCode == 0 else { throw MihomoClientError.malformed }
        let data = try directory.read(output)
        guard (try? JSONSerialization.jsonObject(with: data)) is [String: Any] else { throw MihomoClientError.malformed }
        return data
    }

    public func read(path: String) async throws -> Data {
        guard ["/configs", "/proxies", "/rules", "/connections"].contains(path) else { throw MihomoClientError.unsafePath }
        return try await request(method: "GET", path: path)
    }

    public func apply(configuration: Data) async throws {
        guard var config = try JSONSerialization.jsonObject(with: configuration) as? [String: Any] else {
            throw MihomoClientError.malformed
        }
        // A full reload must not relocate its own controller to the generated placeholder socket.
        config["external-controller-unix"] = socketPath
        let payload = try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys, .withoutEscapingSlashes])
        let body = try JSONSerialization.data(withJSONObject: ["payload": String(decoding: payload, as: UTF8.self)])
        _ = try await request(method: "PUT", path: "/configs?force=true", body: body)
    }

    public func closeConnections() async throws {
        _ = try await request(method: "DELETE", path: "/connections")
    }

    public func flushDNS() async throws {
        _ = try await request(method: "POST", path: "/cache/dns/flush")
    }
    public func selections() async throws -> [String: String] {
        let data = try await read(path: "/proxies")
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let proxies = root["proxies"] as? [String: [String: Any]] else { throw MihomoClientError.malformed }
        var result: [String: String] = [:]
        for (name, proxy) in proxies where proxy["type"] as? String == "Selector" && name != "GLOBAL" {
            if let now = proxy["now"] as? String { result[name] = now }
        }
        return result
    }
    public func diagnosticSelections() async throws -> [String: String] {
        try RoutingSelfCheck.diagnosticSelections(await read(path: "/proxies"))
    }
    public func verify(configuration: Data, shouldContinue: @escaping @Sendable () async throws -> Bool = { true }) async throws -> Bool {
        guard try await shouldContinue() else { return false }
        let general = try await read(path: "/configs")
        guard try await shouldContinue() else { return false }
        let proxies = try await read(path: "/proxies")
        guard try await shouldContinue() else { return false }
        let rules = try await read(path: "/rules")
        guard try await shouldContinue() else { return false }
        return try RoutingRuntime.matches(configuration: configuration, general: general, proxies: proxies, rules: rules)
    }
    @discardableResult
    public func restoreSelections(_ selections: [String: String], configuration: Data,
                                  shouldContinue: @escaping @Sendable () async throws -> Bool = { true }) async throws -> Bool {
        guard let config = try JSONSerialization.jsonObject(with: configuration) as? [String: Any],
              let groups = config["proxy-groups"] as? [[String: Any]] else { throw MihomoClientError.malformed }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))
        for group in groups where group["type"] as? String == "select" {
            guard let name = group["name"] as? String, let selected = selections[name],
                  (group["proxies"] as? [String])?.contains(selected) == true,
                  let escaped = name.addingPercentEncoding(withAllowedCharacters: allowed) else { continue }
            let body = try JSONSerialization.data(withJSONObject: ["name": selected])
            guard try await shouldContinue() else { return false }
            _ = try await request(method: "PUT", path: "/proxies/" + escaped, body: body)
            guard try await shouldContinue() else { return false }
        }
        return true
    }

    private func request(method: String, path: String, body: Data? = nil) async throws -> Data {
        let directory = try PrivateRequestDirectory(root: temporaryRoot)
        defer { directory.remove() }
        let response = directory.url.appendingPathComponent("response")
        try directory.write(Data(), to: response)
        var arguments = ["--silent", "--show-error", "--noproxy", "*", "--max-time", "8",
            "--unix-socket", socketPath, "--request", method, "--header", "Host: localhost",
            "--output", response.path, "--write-out", "%{http_code}", "http://localhost" + path]
        if let body {
            let input = directory.url.appendingPathComponent("payload")
            try directory.write(body, to: input)
            arguments += ["--header", "Content-Type: application/json", "--data-binary", "@" + input.path]
        }
        let result = try await ProcessRunner.run(executable: "/usr/bin/curl", arguments: arguments, timeout: 10)
        guard result.exitCode == 0 else { throw MihomoClientError.unavailable }
        guard let code = Int(result.output.trimmingCharacters(in: .whitespacesAndNewlines)) else { throw MihomoClientError.malformed }
        guard (200...299).contains(code) else { throw MihomoClientError.response(code) }
        return try directory.read(response)
    }
}

private struct PrivateRequestDirectory {
    let url: URL
    init(root: URL = FileManager.default.temporaryDirectory) throws {
        url = root.appendingPathComponent("ez-request-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
    }
    func write(_ data: Data, to file: URL) throws {
        guard FileManager.default.createFile(atPath: file.path, contents: data,
                                            attributes: [.posixPermissions: 0o600]) else { throw CocoaError(.fileWriteUnknown) }
    }
    func read(_ file: URL) throws -> Data {
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        guard (attributes[.size] as? NSNumber)?.intValue ?? Int.max <= 8 * 1024 * 1024 else {
            throw MihomoClientError.malformed
        }
        return try Data(contentsOf: file)
    }
    func remove() { try? FileManager.default.removeItem(at: url) }
}
