import Foundation

public enum RoutingWebsiteReadiness: Equatable, Sendable {
    case unavailable, checking, ready
    // Keep controls stable during read-only checks; requests still wait for ready.
    public var controlsAvailable: Bool { self != .unavailable }
    public var canProbe: Bool { self == .ready }
    @MainActor public static func waitUntilReady(timeout: Duration = .seconds(5),
                                               readiness: () -> Self) async throws -> Bool {
        let clock = ContinuousClock()
        let deadline = clock.now + timeout
        while true {
            try Task.checkCancellation()
            guard clock.now < deadline else { return false }
            let current = readiness()
            guard clock.now < deadline else { return false }
            if current.canProbe { return true }
            guard current.controlsAvailable else { return false }
            try await Task.sleep(for: min(.milliseconds(50), clock.now.duration(to: deadline)))
        }
    }
}

public struct RoutingTestSite: Identifiable, Sendable {
    public let id: String
    public let title: String
    public let host: String
    public let domestic: Bool
    public var url: String { "https://" + host + "/" }
    public static let examples = [
        RoutingTestSite(id: "bilibili", title: "哔哩哔哩", host: "www.bilibili.com", domestic: true),
        RoutingTestSite(id: "zhihu", title: "知乎", host: "www.zhihu.com", domestic: true),
        RoutingTestSite(id: "github", title: "GitHub", host: "github.com", domestic: false),
        RoutingTestSite(id: "google", title: "Google", host: "www.google.com", domestic: false),
        RoutingTestSite(id: "chatgpt", title: "ChatGPT", host: "chatgpt.com", domestic: false)]
}

public enum RoutingWebsiteError: Error, LocalizedError {
    case unavailable, failedRequest, malformed, unsupportedTarget
    public var errorDescription: String? {
        switch self {
        case .unavailable: "Clash 测试入口不可用，请检查 Clash 是否正在运行。"
        case .failedRequest: "HTTPS 请求失败或超时。"
        case .malformed: "测试响应格式无法解析。"
        case .unsupportedTarget: "请输入完整的 http:// 或 https:// 地址，且不含用户名或密码。"
        }
    }
}

/// One absolute probe target. The settings list builds these from bare hostnames;
/// the command-line probe passes a full URL so an HTTP-only internal service such
/// as the finance system can be exercised end to end.
public struct RoutingWebsiteTarget: Equatable, Sendable {
    public let url: String
    public let host: String
    /// curl `--proto` value. Pinning the scheme stops a redirect from switching it.
    public let proto: String
    public init(url: String, host: String, proto: String) {
        self.url = url; self.host = host; self.proto = proto
    }
}

public struct RoutingWebsiteProbe: Sendable {
    public let status: Int
    public let milliseconds: Int
    public let localPort: Int
    public var isSuccessfulResponse: Bool { (200..<400).contains(status) }
    public static func parse(_ output: String, exitCode: Int32) throws -> Self {
        guard exitCode == 0 else { throw RoutingWebsiteError.failedRequest }
        let fields = output.split(whereSeparator: { $0.isWhitespace })
        guard fields.count == 3, let status = Int(fields[0]), (100...599).contains(status),
              let elapsed = Double(fields[1]), elapsed.isFinite, (0...30).contains(elapsed),
              let port = Int(fields[2]), (1...65535).contains(port) else { throw RoutingWebsiteError.malformed }
        return .init(status: status, milliseconds: Int((elapsed * 1000).rounded()), localPort: port)
    }
}

/// Controller evidence of a strategy's interface binding, never physical packet evidence.
public struct RoutingWebsiteEvidence: Equatable, Sendable {
    public let interface: String
    public let isDirect: Bool
    public static func connectionIDs(_ data: Data) throws -> Set<String> {
        Set(try connections(data).compactMap { $0["id"] as? String })
    }
    public static func find(host: String, localPort: Int, previousIDs: Set<String>,
                            observations: [Data], proxies: Data, directOnlyInterface: String? = nil) throws -> Self? {
        guard localPort > 0,
              let root = try JSONSerialization.jsonObject(with: proxies) as? [String: Any],
              let adapters = root["proxies"] as? [String: [String: Any]] else { return nil }
        var matches: [Self] = []
        for observation in observations {
            for connection in try connections(observation) {
                guard let id = connection["id"] as? String, !previousIDs.contains(id),
                      let metadata = connection["metadata"] as? [String: Any],
                      metadata["sourceIP"] as? String == "127.0.0.1",
                      (metadata["host"] as? String)?.lowercased() == host.lowercased() else { continue }
                let port = (metadata["sourcePort"] as? Int) ?? Int(metadata["sourcePort"] as? String ?? "")
                guard port == localPort else { continue }
                guard let chain = connection["chains"] as? [String], !chain.isEmpty else { return nil }
                guard let leaf = RoutingConnectionEgress.find(chains: chain, adapters: adapters,
                                                              globalInterface: directOnlyInterface) else { return nil }
                matches.append(.init(interface: leaf.interface, isDirect: leaf.isDirect))
            }
        }
        guard let first = matches.first, matches.allSatisfy({ $0 == first }) else { return nil }
        return first
    }
    private static func connections(_ data: Data) throws -> [[String: Any]] {
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let connections = root["connections"] as? [[String: Any]] else { throw RoutingWebsiteError.malformed }
        return connections
    }
}

public struct RoutingWebsiteResult: Sendable {
    public let probe: RoutingWebsiteProbe
    public let evidence: RoutingWebsiteEvidence?
    public var endpoint: RoutingWebsiteEndpoint? = nil
}

public enum RoutingWebsiteTester {
    public static func target(_ raw: String) throws -> RoutingWebsiteTarget {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: trimmed),
              let scheme = components.scheme?.lowercased(), ["http", "https"].contains(scheme),
              components.user == nil, components.password == nil,
              let host = components.host, !host.isEmpty else { throw RoutingWebsiteError.unsupportedTarget }
        return .init(url: trimmed, host: host, proto: "=" + scheme)
    }

    public static func entryPort(general: Data, proxies: Data, decision: RoutingDecision) throws -> Int {
        guard let config = try JSONSerialization.jsonObject(with: general) as? [String: Any],
              let root = try JSONSerialization.jsonObject(with: proxies) as? [String: Any],
              let adapters = root["proxies"] as? [String: [String: Any]],
              (config["tun"] as? [String: Any])?["enable"] as? Bool == true,
              config["mode"] as? String == (decision.mode == .directOnly ? "direct" : "rule"),
              let port = ([config["mixed-port"], config["port"]].compactMap { $0 as? Int }).first(where: { (1...65535).contains($0) }) else {
            throw RoutingWebsiteError.unavailable
        }
        if let expected = decision.proxyInterface ?? decision.directInterface,
           config["interface-name"] as? String != expected { throw RoutingWebsiteError.unavailable }
        let builtins = Set(["DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "GLOBAL", "COMPATIBLE"])
        let groups = Set(["Selector", "URLTest", "Fallback", "LoadBalance"])
        let remote = Set(["Trojan", "Vmess", "Vless", "Shadowsocks", "ShadowsocksR", "Http", "Socks5", "Snell"])
        for (name, adapter) in adapters where !builtins.contains(name) {
            guard let type = adapter["type"] as? String else { throw RoutingWebsiteError.unavailable }
            if groups.contains(type) {
                guard decision.proxyInterface != nil else { throw RoutingWebsiteError.unavailable }
                continue
            }
            let expected: String?
            if type == "Direct", name == "EZ-Campus" { expected = decision.directInterface }
            else if type == "Direct", name == "EZ-USB-DNS" { expected = decision.proxyInterface ?? decision.directInterface }
            else if remote.contains(type) { expected = decision.proxyInterface }
            else { throw RoutingWebsiteError.unavailable }
            guard let expected, adapter["interface"] as? String == expected,
                  (adapter["dialer-proxy"] as? String ?? "").isEmpty else { throw RoutingWebsiteError.unavailable }
        }
        return port
    }

    public static func run(site: RoutingTestSite, decision: RoutingDecision, client: MihomoClient = MihomoClient(),
                           configuration: Data? = nil,
                           shouldContinue: @escaping @Sendable () async -> Bool = { true }) async throws -> RoutingWebsiteResult {
        try await run(target: .init(url: site.url, host: site.host, proto: "=https"), decision: decision,
                      client: client, configuration: configuration, shouldContinue: shouldContinue)
    }

    public static func run(target: RoutingWebsiteTarget, decision: RoutingDecision, client: MihomoClient = MihomoClient(),
                           configuration: Data? = nil,
                           shouldContinue: @escaping @Sendable () async -> Bool = { true }) async throws -> RoutingWebsiteResult {
        try Task.checkCancellation()
        let general = try await client.read(path: "/configs")
        let proxies = try await client.read(path: "/proxies")
        let port = try entryPort(general: general, proxies: proxies, decision: decision)
        let previousIDs = try RoutingWebsiteEvidence.connectionIDs(await client.read(path: "/connections"))
        // Bounded observation. A fast request may finish before sampling; that remains unknown.
        let observation = Task {
            var frames: [Data] = []
            for _ in 0..<8 {
                if Task.isCancelled { break }
                do {
                    frames.append(try await client.read(path: "/connections"))
                    try await Task.sleep(for: .milliseconds(100))
                } catch { break }
            }
            return frames
        }
        defer { observation.cancel() }
        guard await shouldContinue() else { throw RoutingWebsiteError.unavailable }
        try Task.checkCancellation()
        let request = try await ProcessRunner.run(executable: "/usr/bin/curl", arguments: [
            "--disable", "--silent", "--show-error", "--head", "--output", "/dev/null",
            "--proxy", "http://127.0.0.1:\(port)", "--noproxy", "", "--ipv4", "--retry", "0",
            "--proto", target.proto, "--connect-timeout", "4", "--max-time", "8",
            "--write-out", "%{http_code} %{time_total} %{local_port}", target.url], timeout: 10)
        observation.cancel()
        let frames = await observation.value
        let probe = try RoutingWebsiteProbe.parse(request.output, exitCode: request.exitCode)
        let evidence = try RoutingWebsiteEvidence.find(host: target.host, localPort: probe.localPort,
            previousIDs: previousIDs, observations: frames, proxies: proxies,
            directOnlyInterface: decision.mode == .directOnly ? decision.directInterface : nil)
        // Selection or binding changes during the request invalidate the observed association.
        let currentProxies = try await client.read(path: "/proxies")
        let currentGeneral = try await client.read(path: "/configs")
        let unchangedEntry = (try? entryPort(general: currentGeneral, proxies: currentProxies, decision: decision)) == port
        let currentEvidence = try RoutingWebsiteEvidence.find(host: target.host, localPort: probe.localPort,
            previousIDs: previousIDs, observations: frames, proxies: currentProxies,
            directOnlyInterface: decision.mode == .directOnly && unchangedEntry ? decision.directInterface : nil)
        let stillAuthorized = await shouldContinue()
        let valid = unchangedEntry && evidence == currentEvidence && stillAuthorized
        let endpoint = try configuration.flatMap {
            try RoutingWebsiteEndpoint.find(host: target.host, localPort: probe.localPort,
                previousIDs: previousIDs, observations: frames, configuration: $0)
        }
        return .init(probe: probe, evidence: valid ? evidence : nil, endpoint: valid ? endpoint : nil)
    }
}
