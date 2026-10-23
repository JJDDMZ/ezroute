import Foundation
import Observation
import EZSwitchCore

@MainActor @Observable final class WebsiteTestModel {
    struct Row {
        var summary = "等待测试"
        var route = ""
        var attention = false
        var verdict: RoutingCheckVerdict = .unknown
    }
    struct Report {
        var rows: [String: Row] = [:]
        var summary = ""
        var expectation = ""
        var interfaceNames: [String: String] = [:]
        var completedAt: Date?
    }
    var selectedPurpose: RoutingDiagnosticPurpose = .physical
    private(set) var running = false
    private(set) var activePurpose: RoutingDiagnosticPurpose?
    private(set) var reports: [RoutingDiagnosticPurpose: Report] = [:]
    var report: Report { reports[selectedPurpose] ?? .init() }
    private(set) var sites: [RoutingTestSite]
    private(set) var listFeedback = ""
    @ObservationIgnored private let list: RoutingSiteList
    @ObservationIgnored private var task: Task<Void, Never>?
    @ObservationIgnored private var capture: RoutingCaptureSession?
    init(defaults: UserDefaults = .standard) {
        list = RoutingSiteList(defaults: defaults); sites = list.sites
    }
    func add(_ domain: String) -> Bool {
        guard !running else { return false }
        do { try list.add(domain); sites = list.sites; clear(); return true }
        catch { listFeedback = error.localizedDescription; return false }
    }
    func remove(_ host: String) {
        guard !running else { return }
        list.remove(host: host); sites = list.sites; clear()
    }
    private func clear() { reports = [:]; listFeedback = "" }
    private func setRow(_ row: Row, for id: String, purpose: RoutingDiagnosticPurpose) {
        reports[purpose, default: .init()].rows[id] = row
    }
    private func setSummary(_ text: String, purpose: RoutingDiagnosticPurpose) {
        reports[purpose, default: .init()].summary = text
    }
    func start(routing: RoutingModel) {
        guard !running, !sites.isEmpty, routing.websiteTestControlsAvailable else { return }
        let purpose = selectedPurpose
        running = true; activePurpose = purpose; reports[purpose] = .init(); listFeedback = ""
        let frozenSites = sites
        task = Task { [weak self] in
            guard let self else { return }
            await self.run(sites: frozenSites, routing: routing, purpose: purpose)
            self.reports[purpose, default: .init()].completedAt = Date()
            self.running = false; self.activePurpose = nil; self.task = nil
        }
    }
    private func run(sites: [RoutingTestSite], routing: RoutingModel, purpose: RoutingDiagnosticPurpose) async {
        let client = MihomoClient()
        var physical: [(id: String, binding: String?, direct: Bool, interfaces: Set<String>, endpoint: Bool)] = []
        var identity: RoutingSnapshot?
        var config: Data?
        var initialSelections: [String: String]?
        var stopped = false
        var configurationMismatch = false
        var stopReason = ""
        var received = 0
        var restricted = 0
        var captureOutcome: RoutingCaptureOutcome = .notRequested
        do {
            setSummary("正在核对当前网络与 Clash 配置…", purpose: purpose)
            guard try await routing.waitForWebsiteTests() else { throw RoutingWebsiteError.unavailable }
            let initial = routing.websiteTestSnapshot()
            identity = initial
            var interfaceNames: [String: String] = [:]
            if let usb = routing.reading.network.usbInterface { interfaceNames[usb] = "USB 供网（\(usb)）" }
            if let wifi = routing.reading.network.wifiInterface {
                interfaceNames[wifi] = initial.decision.mode == .wifiHotspot ? "信任的无线连接（\(wifi)）" : "Wi-Fi（\(wifi)）"
            }
            reports[purpose, default: .init()].interfaceNames = interfaceNames
            let direct = initial.decision.directInterface.map { interfaceNames[$0] ?? $0 } ?? "不可用"
            let proxy = initial.decision.proxyInterface.map { interfaceNames[$0] ?? $0 } ?? "禁止代理"
            reports[purpose, default: .init()].expectation = "本轮预期：直连 → \(direct)；代理 → \(proxy)。"
            guard let configuration = routing.websiteTestConfiguration else { throw RoutingWebsiteError.unavailable }
            config = configuration
            let authorized: @Sendable () async -> Bool = {
                await MainActor.run { routing.websiteTestControlsAvailable && routing.websiteTestSnapshot() == initial }
            }
            guard try await RoutingDiagnosticVerification.verify(client: client, configuration: configuration, authorized: authorized) else {
                configurationMismatch = true
                stopReason = "当前规则或接口绑定发生变化，检查已停止。"
                throw RoutingWebsiteError.unavailable
            }
            let selections = try await client.diagnosticSelections()
            initialSelections = selections
            var captureReady = false
            if purpose == .physical {
                setSummary("等待管理员授权，授权后开始采集测试连接的包头。", purpose: purpose)
                let session = RoutingCaptureSession(); capture = session
                captureReady = try await session.start(interfaces: routing.websiteCaptureInterfaces)
                guard captureReady else {
                    stopReason = "包头采集尚未就绪，检查已停止。"
                    throw RoutingWebsiteError.unavailable
                }
            }
            guard await authorized() else { throw RoutingWebsiteError.unavailable }
            for (index, site) in sites.enumerated() {
                try Task.checkCancellation()
                setSummary("正在\(purpose == .physical ? "检查出口" : "测试网站")：\(index + 1)/\(sites.count) · \(site.title)", purpose: purpose)
                setRow(.init(summary: "等待路由核对…"), for: site.id, purpose: purpose)
                guard try await routing.waitForWebsiteTests(), await authorized() else { throw RoutingWebsiteError.unavailable }
                if captureReady && capture?.available != true {
                    stopped = true; stopReason = "包头采集提前结束，检查已停止。"; break
                }
                guard try await client.verify(configuration: configuration, shouldContinue: { await authorized() }),
                      try await client.diagnosticSelections() == selections else {
                    stopped = true; stopReason = "配置或节点选择发生变化，已停止。"; break
                }
                let offset = capture?.packetOffset() ?? 0
                setRow(.init(summary: "测试中…"), for: site.id, purpose: purpose)
                do {
                    let result = try await RoutingWebsiteTester.run(site: site, decision: initial.decision,
                        configuration: configuration, shouldContinue: authorized)
                    guard await authorized(), try await client.verify(configuration: configuration, shouldContinue: { await authorized() }),
                          try await client.diagnosticSelections() == selections else {
                        stopped = true; stopReason = "网络、配置或节点选择发生变化，已停止。"; break
                    }
                    received += 1
                    if !result.probe.isSuccessfulResponse { restricted += 1 }
                    let requestSummary = "HTTP \(result.probe.status) · \(result.probe.milliseconds) ms"
                        + (result.probe.isSuccessfulResponse ? "" : " · 网站限制或错误")
                    let binding = result.evidence
                    let endpointAvailable = result.endpoint != nil &&
                        (initial.decision.mode == .directOnly || !(result.endpoint?.rule.isEmpty ?? true))
                    let actual: Set<String>
                    if captureReady, endpointAvailable, let endpoint = result.endpoint {
                        actual = RoutingSelfCheck.physicalInterfaces(packets: capture?.packets(since: offset) ?? "",
                                                                    address: endpoint.address, port: endpoint.port)
                    } else { actual = [] }
                    let verdict = RoutingSelfCheck.assess(binding: binding?.interface,
                        isDirect: binding?.isDirect ?? true, decision: initial.decision,
                        physicalInterfaces: actual, captureComplete: false)
                    let detail = purpose == .physical ? "正在汇总包头证据…" : ""
                    setRow(.init(summary: requestSummary, route: detail,
                        attention: purpose == .connectivity && !result.probe.isSuccessfulResponse, verdict: verdict),
                        for: site.id, purpose: purpose)
                    physical.append((site.id, binding?.interface, binding?.isDirect ?? true, actual, endpointAvailable))
                    if verdict == .fail {
                        stopped = true; stopReason = "发现策略绑定或物理出口不符，已停止后续请求。"; break
                    }
                } catch is CancellationError { throw CancellationError() }
                catch { setRow(.init(summary: "未收到 HTTPS 响应", route: purpose == .physical ? "证据不足：请求未完成。" : "", attention: true), for: site.id, purpose: purpose) }
            }
            if !(await authorized()) { stopped = true; stopReason = "当前网络或路由状态发生变化，已停止。" }
        } catch is CancellationError {
            stopReason = "检查已取消。"; stopped = true
        } catch RoutingDiagnosticInterruption.stateChanged {
            stopReason = "核对期间网络或路由状态发生变化，检查已停止。"; stopped = true
        } catch {
            if stopReason.isEmpty { stopReason = "路由尚未就绪或 Clash 控制接口不可用，检查已停止。" }
            stopped = true
        }
        if let capture {
            setSummary("正在结束包头采集并汇总结果…", purpose: purpose)
            captureOutcome = await capture.stop()
        }
        capture = nil
        if let identity, let config,
           routing.websiteTestSnapshot() == identity && routing.websiteTestControlsAvailable,
           (try? await client.verify(configuration: config)) == true,
           (try? await client.diagnosticSelections()) == initialSelections,
           routing.websiteTestSnapshot() == identity && routing.websiteTestControlsAvailable {
            for item in physical {
                guard var row = reports[purpose]?.rows[item.id] else { continue }
                if purpose == .physical {
                    let outcome: RoutingCaptureOutcome = stopped ? .interrupted : captureOutcome
                    let verdict = RoutingSelfCheck.assess(binding: item.binding, isDirect: item.direct,
                        decision: identity.decision, physicalInterfaces: item.interfaces, captureComplete: outcome == .complete)
                    if row.verdict != .fail { row.verdict = verdict }
                    row.route = RoutingDiagnosticText.physicalDetail(binding: item.binding, isDirect: item.direct,
                        decision: identity.decision, interfaces: item.interfaces, endpointAvailable: item.endpoint, capture: outcome,
                        interfaceNames: reports[purpose]?.interfaceNames ?? [:])
                    row.attention = row.verdict == .fail
                    setRow(row, for: item.id, purpose: purpose)
                }
            }
        } else {
            stopped = true
            if stopReason.isEmpty { stopReason = "结束核对时网络、配置或节点选择已变化。" }
        }
        for site in sites {
            var row = reports[purpose]?.rows[site.id] ?? .init(summary: "未执行")
            if stopped && row.verdict != .fail {
                row.verdict = .unknown
                if purpose == .physical {
                    row.route = "证据不足：" + stopReason + (captureOutcome == .notRequested ? "" : " " + captureOutcome.explanation)
                }
            }
            if ["测试中…", "等待路由核对…"].contains(row.summary) { row.summary = "已停止，未完成" }
            // Never leave a provisional message in a completed report, including observed failures.
            if purpose == .physical && row.route == "正在汇总包头证据…" {
                row.route = row.verdict == .fail ? "发现策略绑定或物理出口不符；本轮已停止。" : "证据不足：本轮未完成核对。"
            }
            setRow(row, for: site.id, purpose: purpose)
        }
        if purpose == .connectivity {
            let prefix = stopReason.isEmpty ? "" : stopReason + " "
            setSummary(prefix + RoutingDiagnosticText.connectivitySummary(received: received, restricted: restricted,
                total: sites.count, interrupted: stopped), purpose: purpose)
        } else {
            var verdicts = sites.map { reports[purpose]?.rows[$0.id]?.verdict ?? .unknown }
            if configurationMismatch { verdicts.append(.fail) }
            if stopped { verdicts.append(.unknown) }
            let overall = RoutingSelfCheck.overall(verdicts)
            let passCount = verdicts.filter { $0 == .pass }.count
            let result = overall == .fail ? "发现不符：策略绑定或实际出口与预期不一致。" :
                overall == .pass ? "符合预期：\(sites.count) 个网站的测试连接出口均匹配预期。" :
                "证据不足：已确认 \(passCount)/\(sites.count) 个网站的测试连接出口。"
            let directs = physical.filter { $0.binding != nil && $0.direct }.count
            let proxies = physical.filter { $0.binding != nil && !$0.direct }.count
            let coverage = " 覆盖：直连 \(directs) 个、代理 \(proxies) 个。"
                + (proxies == 0 && identity?.decision.proxyInterface != nil ? "代理出口尚待检查。" : "")
            setSummary(result + coverage + (stopReason.isEmpty ? "" : " " + stopReason) + " " + captureOutcome.explanation, purpose: purpose)
        }
    }
    func cancel() { capture?.cancel(); task?.cancel() }
}
