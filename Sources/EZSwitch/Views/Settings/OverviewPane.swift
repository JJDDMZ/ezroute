import SwiftUI

struct OverviewPane: View {
    @Bindable var routing: RoutingModel

    var body: some View {
        Form {
            Section {
                Label(routing.stateTitle, systemImage: routing.isAttention ? "exclamationmark.shield" : "arrow.triangle.branch")
                    .foregroundStyle(routing.isAttention ? .orange : .primary)
                Text("网络变化时，自动选择出口并清理旧连接。")
                    .font(.callout).foregroundStyle(.secondary)
                Toggle("自动路由", isOn: Binding(get: { routing.enabled }, set: { value in
                    Task { await routing.setEnabled(value) }
                })).disabled(routing.changingEnabled)
                Text("退出时：USB 在线保留指定 USB 出口，仅 Wi-Fi 在线则直连，离线则阻断请求。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("网络与出口") {
                LabeledContent("当前网络", value: routing.modeTitle)
                LabeledContent("当前路由", value: routing.appliedDecision?.mode.displayTitle ?? "等待应用")
                LabeledContent("代理出口", value: routing.decision.proxyInterface ?? "已停用")
                LabeledContent("直连出口", value: routing.decision.directInterface ?? "不可用")
                LabeledContent("Wi-Fi", value: routing.reading.wifiName ?? (routing.reading.network.wifiInterface == nil ? "未连接" : "名称读取失败"))
                if let message = routing.reading.message { Text(message).font(.caption).foregroundStyle(.secondary) }
            }
            Section("Clash") {
                LabeledContent("订阅接入", value: routing.bootstrapStatus)
                HStack {
                    Text(routing.clashStatus).font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("检查路由") { Task { await routing.checkClash() } }.disabled(routing.checkingClash)
                }
            }
        }
        .formStyle(.grouped)
    }
}
