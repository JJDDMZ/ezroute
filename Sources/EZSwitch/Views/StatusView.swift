import SwiftUI
import AppKit

struct StatusView: View {
    @Bindable var model: AppModel
    @Bindable var routing = RoutingModel.shared
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Text("EZ Route").font(.headline)
                Spacer()
                Text("网络分流").font(.caption).foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 6) {
                Label(routing.stateTitle, systemImage: "arrow.triangle.branch")
                    .foregroundStyle(routing.isAttention ? .orange : .primary)
                Text(routing.modeTitle).foregroundStyle(.secondary)
            }.font(.callout)

            Toggle("自动路由", isOn: Binding(get: { routing.enabled }, set: { value in
                Task { await routing.setEnabled(value) }
            }))
            .toggleStyle(.switch)
            .disabled(routing.changingEnabled || model.quitting)
            .help("随 USB、Wi-Fi 和已登记热点的连接状态自动选择出口。")

            Toggle("Apple 走代理", isOn: Binding(
                get: { routing.appleViaProxy },
                set: { value in Task { await routing.setAppleViaProxy(value) } }))
                .toggleStyle(.switch)
                .disabled(routing.changingEnabled || model.quitting)
                .help("分流或无线热点模式下，关闭可让 Apple 服务直连，开启则使用订阅规则。")

            Text("手机切卡可搭配独立项目 EZ SIM。")
                .font(.caption).foregroundStyle(.secondary)

            Divider()
            HStack(spacing: 12) {
                Button { openWindow(id: "setup"); NSApp.activate() } label: {
                    Label("使用引导", systemImage: "list.bullet.clipboard")
                }
                // 菜单栏应用需主动激活，避免设置窗口出现在其他应用后方。
                Button { openSettings(); NSApp.activate() } label: {
                    Image(systemName: "gearshape").accessibilityLabel("设置")
                }
                Spacer()
                Button("退出") { NSApp.terminate(nil) }
                    .disabled(model.quitting)
            }
            .buttonStyle(.borderless)
            .font(.callout)
        }
        .padding(20)
        .frame(width: 352)
    }
}
