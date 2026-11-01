import SwiftUI
import EZSwitchCore

struct DevicesPane: View {
    @Bindable var routing: RoutingModel
    @Bindable var model: AppModel
    @State private var candidate: RegisteredHotspot?
    @State private var confirming = false
    @State private var strictCandidate = false
    @State private var removingStrict: RegisteredHotspot?
    @State private var showingWhitelist = false

    var body: some View {
        Form {
            Section("USB 网络设备") {
                Picker("指定 USB 出口", selection: $model.configuration.deviceID) {
                    Text("连接 USB 网络设备后选择").tag("")
                    if !model.configuration.deviceID.isEmpty && !model.snapshot.devices.contains(where: { $0.id == model.configuration.deviceID }) {
                        Text("已记住的 USB 设备 · 未连接").tag(model.configuration.deviceID)
                    }
                    ForEach(model.snapshot.devices) { phone in
                        Text("\(phone.name) · \(phone.id.suffix(6))").tag(phone.id)
                    }
                }
                .disabled(routing.changingEnabled || routing.routingState == .switching || model.quitting)
                Text("支持 iPhone、随身 Wi-Fi 和其他 USB 供网设备。连接后，选择用于代理的 USB 出口。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("信任的无线连接") {
                if routing.registrations.isEmpty { Text("尚未添加信任的无线连接").foregroundStyle(.secondary) }
                ForEach(routing.registrations) { hotspot in
                    HStack {
                        Label(hotspot.displayName, systemImage: "wifi").lineLimit(1)
                        Spacer()
                        Button("移除", role: .destructive) { routing.remove(hotspot.id) }
                            .disabled(!routing.controllerOwned)
                    }
                }
                Button("信任当前无线连接…") {
                    strictCandidate = false
                    routing.refresh(); candidate = routing.pendingRegistration; confirming = candidate != nil
                }.disabled(!routing.reading.registrationAllowed || !routing.controllerOwned)
                Text("可添加手机热点或随身 Wi-Fi。按名称和安全类型匹配，改名后需重新添加；请使用独有名称。")
                    .font(.caption).foregroundStyle(.secondary)
                if !routing.feedback.isEmpty { Text(routing.feedback).font(.caption).foregroundStyle(.secondary) }
            }
            Section("严格保护的无线连接") {
                if !routing.controllerOwned {
                    Text("另一个 EZ Route 实例正在控制路由。本窗口只能查看，不能添加或移除保护。")
                        .font(.caption).foregroundStyle(.orange)
                }
                if let problem = routing.strictDataProblem {
                    Text(problem).font(.caption).foregroundStyle(.orange)
                }
                Button("查看直连白名单…") { showingWhitelist = true }
                if routing.strictRegistrations.isEmpty { Text("尚未添加严格保护的无线连接").foregroundStyle(.secondary) }
                ForEach(routing.strictRegistrations) { network in
                    HStack {
                        Label(network.displayName, systemImage: "wifi.exclamationmark").lineLimit(1)
                        Spacer()
                        Button("移除", role: .destructive) { removingStrict = network }
                            .disabled(!routing.controllerOwned)
                    }
                }
                Button("严格保护当前无线连接…") {
                    strictCandidate = true
                    routing.refresh(); candidate = routing.pendingStrictRegistration; confirming = candidate != nil
                }.disabled(!routing.reading.strictRegistrationAllowed || routing.changingEnabled
                           || model.quitting || !routing.controllerOwned)
                Text("适合校园网，支持企业认证。只有固定名单内的目标可以直连；其余目标使用 USB，USB 不可用时阻断。停用自动路由和正常退出会保留限制，需保持 Clash 的 TUN 开启。")
                    .font(.caption).foregroundStyle(.secondary)
                Text("Apple 走代理开关同样有效：开启时 Apple 使用 USB；关闭时仅 Apple 白名单主机可直连。按无线名称识别，修改名称后需重新添加。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("无线连接识别权限") {
                LabeledContent("定位权限", value: routing.locationStatus)
                Button("允许读取 Wi-Fi 名称") { routing.requestIdentityPermission() }
                Text("定位权限用于读取 Wi-Fi 名称；位置不采集、不保存。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("连接状态") {
                LabeledContent("USB 网络设备", value: "\(model.snapshot.devices.count) 台")
                if let phone = model.selectedPhone {
                    LabeledContent("USB 网络", value: phone.interface ?? "尚未建立")
                }
                if let error = model.snapshot.error {
                    Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange).font(.caption)
                }
            }
        }
        .formStyle(.grouped)
        .sheet(isPresented: $showingWhitelist) { StrictWhitelistView(appleViaProxy: routing.appleViaProxy) }
        .alert(strictCandidate ? "严格保护当前无线连接？" : "信任当前无线连接？", isPresented: $confirming) {
            Button("取消", role: .cancel) { candidate = nil }
            Button("添加") {
                if let candidate { if strictCandidate { routing.registerStrict(candidate) } else { routing.register(candidate) } }
                candidate = nil
            }
        } message: {
            Text(strictCandidate ? "将“\(candidate?.displayName ?? "")”加入严格保护。该网络只允许白名单直连，名单外目标不会在 USB 缺失时改走此网络。" :
                "信任“\(candidate?.displayName ?? "")”后，自动路由会通过该无线连接访问代理。请添加你信任的手机热点或随身 Wi-Fi。")
        }
        .alert("移除严格保护？", isPresented: Binding(get: { removingStrict != nil }, set: { if !$0 { removingStrict = nil } })) {
            Button("取消", role: .cancel) { removingStrict = nil }
            Button("移除保护", role: .destructive) { if let network = removingStrict { routing.removeStrict(network.id) }; removingStrict = nil }
        } message: { Text("移除后，该无线网络将恢复普通分流和直连回退。") }
    }
}
