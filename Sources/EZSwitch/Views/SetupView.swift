import SwiftUI
import AppKit

struct SetupView: View {
    @Bindable var model: AppModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                VStack(alignment: .leading, spacing: 10) {
                    Image(systemName: "arrow.triangle.branch").font(.system(size: 36, weight: .light))
                        .frame(width: 72, height: 72)
                        .glassEffect(.regular, in: .rect(cornerRadius: 20))
                    Text("连接你的网络，\n自动选择出口。")
                        .font(.system(size: 28, weight: .semibold, design: .rounded))
                    Text("EZ Route 根据当前连接选择 Mac 的网络出口，自动管理 Clash 分流。")
                        .font(.body).foregroundStyle(.secondary)
                }
                VStack(alignment: .leading, spacing: 18) {
                    step(1, title: "选择设备与网络", text: "用 USB 连接 iPhone 或随身 Wi-Fi，在“设备与网络”中选择 USB 出口。无线连接可添加为“信任的无线连接”。")
                    step(2, title: "开启自动路由", text: "开启 Clash Verge 的 TUN 和 EZ Route 的自动路由。USB 与校园 Wi-Fi 同时在线时，直连使用 Wi-Fi，代理使用选定的 USB 出口。")
                    step(3, title: "按需搭配 EZ SIM", text: "需要手机切卡时，可使用独立项目 EZ SIM，在 iPhone 上配置双卡与 VPN 自动化。")
                }
                HStack {
                    Button("打开配置指南", systemImage: "book") { model.openGuide() }
                        .buttonStyle(.glassProminent)
                    SettingsLink { Label("打开设置", systemImage: "gearshape") }
                        .buttonStyle(.glass)
                }
                Text("完成后，在菜单栏查看当前网络和路由状态。")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button("开启状态通知") { Task { await model.allowNotifications() } }
                        .buttonStyle(.borderless)
                    Spacer()
                    Button("完成") { dismiss() }.buttonStyle(.glass)
                }
            }
            .padding(32)
        }
        .frame(width: 560, height: 610)
        .onAppear { model.hasSeenGuide = true }
    }

    private func step(_ number: Int, title: String, text: String) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Text(String(number)).font(.system(.callout, design: .rounded).weight(.semibold))
                .frame(width: 27, height: 27).background(.quaternary, in: .circle)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).fontWeight(.medium)
                Text(text).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
