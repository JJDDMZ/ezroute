import SwiftUI
import EZSwitchCore

struct DiagnosticsPane: View {
    @Bindable var routing: RoutingModel
    @Bindable var websiteTests: WebsiteTestModel
    @Bindable var monitor: ConnectionMonitorModel
    let visible: Bool
    @State private var newDomain = ""

    private struct RefreshContext: Equatable {
        let visible: Bool
        let state: RoutingCoordinatorState
        let decision: RoutingDecision?
        let identity: String
        let configuration: Data?
        let enabled: Bool
    }

    private var refreshContext: RefreshContext {
        .init(visible: visible, state: routing.routingState, decision: routing.appliedDecision,
              identity: routing.reading.identity, configuration: routing.websiteTestConfiguration,
              enabled: routing.enabled)
    }

    var body: some View {
        Form {
            Section("连接监测") {
                Text("按 Clash 策略链显示连接目标与出口。")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button("刷新") { Task { await monitor.refresh(force: true) } }
                        .disabled(monitor.refreshing)
                    Spacer()
                    if let date = monitor.refreshedAt {
                        Text("更新于 \(date.formatted(date: .omitted, time: .standard))")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                if monitor.unavailable {
                    Text(monitor.refreshedAt == nil ? "无法连接 Clash，请检查它是否正在运行。"
                         : "Clash 暂时无法连接，当前显示上次读取的结果。")
                        .font(.caption).foregroundStyle(.orange)
                } else if monitor.refreshedAt == nil {
                    Text("正在读取连接…").font(.caption).foregroundStyle(.secondary)
                }
                if monitor.rows.isEmpty, monitor.refreshedAt != nil {
                    Text(monitor.unavailable ? "上次读取时没有活动连接。" : "当前没有活动连接。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Picker("范围", selection: $monitor.range) {
                    ForEach(ConnectionMonitorModel.Range.allCases) { range in
                        Text(range.title).tag(range)
                    }
                }.pickerStyle(.segmented)
                Text("所选时段用于汇总用量，连接列表显示当前快照。用量记录来自 EZ Route 运行期间。")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(monitor.sections) { section in
                    egressSection(section)
                }
                if monitor.sections.isEmpty {
                    Text("当前时段暂无用量记录和活动连接。")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Section("网站测试与管理") {
                Picker("检查目的", selection: $websiteTests.selectedPurpose) {
                    ForEach(RoutingDiagnosticPurpose.allCases, id: \.self) { purpose in
                        Text(purpose.title).tag(purpose)
                    }
                }.pickerStyle(.segmented).disabled(websiteTests.running)
                if websiteTests.selectedPurpose == .physical {
                    Text("采集测试连接的包头，核对流量从 USB 还是 Wi-Fi 发出。系统会请求管理员授权。")
                        .font(.callout)
                    Text("使用自己的 USB 供网设备或信任的无线连接进行测试，并暂停其他下载。")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("检查网站的 HTTPS 响应状态和耗时，无需管理员授权。")
                        .font(.callout)
                }
                HStack {
                    Button(websiteTests.running ? "正在检查…" : websiteTests.selectedPurpose.actionTitle) {
                        websiteTests.start(routing: routing)
                    }.disabled(websiteTests.running || websiteTests.sites.isEmpty || !routing.websiteTestControlsAvailable)
                    if websiteTests.running {
                        ProgressView().controlSize(.small)
                        Button("取消") { websiteTests.cancel() }
                    }
                    Spacer()
                }
                if !routing.websiteTestControlsAvailable && !websiteTests.running {
                    Text("先开启 Clash TUN 和自动路由，再开始检查。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if !websiteTests.report.summary.isEmpty {
                    Text(websiteTests.report.summary).font(.callout).textSelection(.enabled)
                }
                if websiteTests.selectedPurpose == .physical && !websiteTests.report.expectation.isEmpty {
                    Text(websiteTests.report.expectation).font(.caption).foregroundStyle(.secondary)
                }
                if let date = websiteTests.report.completedAt {
                    Text("检查于 \(date.formatted(date: .omitted, time: .standard))")
                        .font(.caption).foregroundStyle(.secondary)
                }
                WebsiteCardGrid(
                    cards: websiteTests.sites.map { site in
                        let row = websiteTests.report.rows[site.id] ?? .init()
                        let egress = row.route.isEmpty ? "" : (websiteTests.report.interfaceNames[row.route] ?? row.route)
                        return WebsiteCardPresentation.card(site: site, status: row.summary,
                                                            egress: egress, verdict: row.verdict)
                    },
                    running: websiteTests.running,
                    showVerdict: websiteTests.selectedPurpose == .physical && websiteTests.report.completedAt != nil,
                    remove: { websiteTests.remove($0) })
                HStack {
                    TextField("输入域名，例如 example.com", text: $newDomain)
                        .onSubmit { if websiteTests.add(newDomain) { newDomain = "" } }
                    Button("添加") { if websiteTests.add(newDomain) { newDomain = "" } }
                        .disabled(newDomain.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                .disabled(websiteTests.running)
                if !websiteTests.listFeedback.isEmpty {
                    Text(websiteTests.listFeedback).font(.caption).foregroundStyle(.orange)
                }
                Text("最多添加 20 个网站，两项检查共用。修改列表会重置测试结果。")
                    .font(.caption).foregroundStyle(.secondary)
                if websiteTests.selectedPurpose == .physical {
                    DisclosureGroup("检查说明") {
                        Text("检查针对本轮测试连接；HTTP 403／405 归为网站响应状态。取消授权会停止检查。")
                        Text("切换瞬间与崩溃保护属于独立检查场景。")
                    }.font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .task(id: refreshContext) {
            await monitor.run(visible: visible)
        }
        .onChange(of: visible) { _, visible in
            if !visible { monitor.stop(); websiteTests.cancel() }
        }
        .onDisappear { monitor.stop(); websiteTests.cancel() }
    }

    /// 每个出口一块:标题右侧是该出口在所选范围内的用量,下面跟它自己的连接列表。
    /// 每个出口在界面上只出现这一次。
    private func egressSection(_ section: RoutingEgressSection) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline) {
                Text(section.egress.map { "出口 · \($0)" } ?? "出口未知")
                    .font(.caption).bold()
                Spacer(minLength: 8)
                if let usage = section.usage {
                    Text("收 \(ConnectionMonitorModel.bytes(usage.received)) · 发 \(ConnectionMonitorModel.bytes(usage.sent))")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("当前时段无记录").font(.caption).foregroundStyle(.secondary)
                }
            }
            if section.connections.isEmpty {
                Text("无活动连接").font(.caption2).foregroundStyle(.secondary)
            } else {
                EgressConnectionList(rows: section.connections, row: connectionRow)
            }
        }
    }

    private func connectionRow(_ row: RoutingConnectionRow) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(row.target).font(.caption)
            Text("\(row.network) · \(row.rule) · 节点 \(row.chains.first ?? "—") · 收 \(ConnectionMonitorModel.bytes(row.received)) 发 \(ConnectionMonitorModel.bytes(row.sent))")
                .font(.caption2).foregroundStyle(.secondary)
        }
    }
}

private struct EgressConnectionList<Row: View>: View {
    let rows: [RoutingConnectionRow]
    let row: (RoutingConnectionRow) -> Row

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 2) {
                ForEach(rows) { row($0) }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(height: min(CGFloat(rows.count) * 36, 150))
    }
}
