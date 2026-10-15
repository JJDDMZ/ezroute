import Foundation

public enum RoutingDiagnosticPurpose: String, CaseIterable, Sendable {
    case physical, connectivity
    public var title: String { self == .physical ? "实际出口" : "网站响应" }
    public var actionTitle: String { self == .physical ? "检查实际出口…" : "测试网站响应" }
}

/// Sanitized capture outcomes; raw packet data and authorization errors stay out of the UI.
public enum RoutingCaptureOutcome: Equatable, Sendable {
    case notRequested, complete, authorizationDeclined, startTimedOut, unavailable
    case interrupted, limitReached, packetsDropped, statisticsMissing, forcedTermination, captureFailed
    public var explanation: String {
        switch self {
        case .notRequested: "未采集包头。"
        case .complete: "包头采集完成，内核报告 0 个丢包。"
        case .authorizationDeclined: "管理员授权已取消。"
        case .startTimedOut: "等待授权或采集启动超时。"
        case .unavailable: "包头采集启动失败，请检查系统授权和采集工具。"
        case .interrupted: "包头采集已中断。"
        case .limitReached: "采集达到包数上限，请暂停其他下载后重试。"
        case .packetsDropped: "系统报告采集丢包，请暂停其他下载后重试。"
        case .statisticsMissing: "采集统计不完整，丢包数未知。"
        case .forcedTermination: "采集进程退出超时，已强制结束。"
        case .captureFailed: "采集进程异常退出。"
        }
    }
    public static func parse(_ result: ProcessResult?) -> Self {
        guard let result else { return .unavailable }
        guard result.exitCode == 0 else {
            return result.output.contains("(-128)") ? .authorizationDeclined : .unavailable
        }
        guard let range = result.output.range(of: "EZ_CAPTURE_STATUS", options: .backwards) else { return .statisticsMissing }
        let status = String(result.output[range.upperBound...])
        guard status.contains("listening on") else { return .unavailable }
        let endLines = status.components(separatedBy: .newlines).filter { $0.hasPrefix("EZ_CAPTURE_END ") }
        guard endLines.count == 1 else { return .statisticsMissing }
        let fields = endLines[0].split(separator: " ")
        guard fields.count == 3, let exitCode = Int(fields[1]), (0...255).contains(exitCode),
              let forced = Int(fields[2]), (0...1).contains(forced) else { return .statisticsMissing }
        if forced == 1 { return .forcedTermination }
        if exitCode != 0 { return .captureFailed }
        if status.range(of: #"(?m)^2048 packets captured\s*$"#, options: .regularExpression) != nil { return .limitReached }
        guard let dropped = status.range(of: #"(?m)^([0-9]+) packets? dropped by kernel\s*$"#, options: .regularExpression) else {
            return .statisticsMissing
        }
        return status[dropped].hasPrefix("0 packets") ? .complete : .packetsDropped
    }
}

public enum RoutingDiagnosticText {
    public static func physicalDetail(binding: String?, isDirect: Bool, decision: RoutingDecision,
                                      interfaces: Set<String>, endpointAvailable: Bool,
                                      capture: RoutingCaptureOutcome, interfaceNames: [String: String] = [:]) -> String {
        guard let binding else { return "证据不足：没有找到本次请求的 Clash 连接。" }
        let expected = isDirect ? decision.directInterface : decision.proxyInterface
        let strategy = isDirect ? "直连" : "代理"
        let configured = "策略：\(strategy)；配置绑定：\(binding)"
        let observed = interfaces.isEmpty ? "" : "；实际观测：\(interfaces.sorted().map { interfaceNames[$0] ?? $0 }.joined(separator: ", "))"
        let verdict = RoutingSelfCheck.assess(binding: binding, isDirect: isDirect, decision: decision,
            physicalInterfaces: interfaces, captureComplete: capture == .complete)
        if verdict == .fail {
            return configured + observed + "；发现不符：预期出口为\(expected ?? "禁止此策略")。"
        }
        if verdict == .pass { return configured + observed + "；符合预期。" }
        if capture != .complete { return configured + observed + "；证据不足：" + capture.explanation }
        if !endpointAvailable { return configured + "；证据不足：没有找到本次请求的连接端点。" }
        return configured + "；证据不足：未采集到该端点的出站包头。"
    }
    public static func connectivitySummary(received: Int, restricted: Int, total: Int, interrupted: Bool) -> String {
        let prefix = interrupted ? "本轮已停止；" : ""
        return prefix + "\(received)/\(total) 个网站收到 HTTPS 响应，其中 \(restricted) 个返回限制或错误。"
    }
}

public enum RoutingDiagnosticInterruption: Error { case stateChanged }
public enum RoutingDiagnosticVerification {
    /// Only a completed runtime comparison may return false; revoked authorization is incomplete evidence.
    public static func verify(client: MihomoClient, configuration: Data,
                              authorized: @escaping @Sendable () async -> Bool) async throws -> Bool {
        try await client.verify(configuration: configuration, shouldContinue: {
            guard await authorized() else { throw RoutingDiagnosticInterruption.stateChanged }
            return true
        })
    }
}
