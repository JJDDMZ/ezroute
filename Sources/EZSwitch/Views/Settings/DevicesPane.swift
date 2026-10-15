import SwiftUI
import EZSwitchCore

struct DevicesPane: View {
    @Bindable var routing: RoutingModel
    @Bindable var model: AppModel
    @State private var candidate: RegisteredHotspot?
    @State private var confirming = false

    var body: some View {
        Form {
            Section("USB 手机") {
                Picker("指定 iPhone", selection: $model.configuration.deviceID) {
                    Text("连接 iPhone 后选择").tag("")
                    if !model.configuration.deviceID.isEmpty && !model.snapshot.devices.contains(where: { $0.id == model.configuration.deviceID }) {
                        Text("已记住的 iPhone · 未连接").tag(model.configuration.deviceID)
                    }
                    ForEach(model.snapshot.devices) { phone in
                        Text("\(phone.name) · \(phone.id.suffix(6))").tag(phone.id)
                    }
                }
                .disabled(routing.changingEnabled || routing.routingState == .switching || model.quitting)
                Text("连接 USB 并开启 iPhone 个人热点后，EZ Route 会识别可用出口。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("已登记手机热点") {
                if routing.registrations.isEmpty { Text("尚未登记无线热点").foregroundStyle(.secondary) }
                ForEach(routing.registrations) { hotspot in
                    HStack {
                        Label(hotspot.displayName, systemImage: "personalhotspot").lineLimit(1)
                        Spacer()
                        Button("移除", role: .destructive) { routing.remove(hotspot.id) }
                    }
                }
                Button("登记当前手机热点…") {
                    routing.refresh(); candidate = routing.pendingRegistration; confirming = candidate != nil
                }.disabled(!routing.reading.registrationAllowed)
                Text("热点按名称和安全类型匹配，改名后需重新登记。请使用独有名称，避免与其他热点混淆。")
                    .font(.caption).foregroundStyle(.secondary)
                if !routing.feedback.isEmpty { Text(routing.feedback).font(.caption).foregroundStyle(.secondary) }
            }
            Section("热点识别权限") {
                LabeledContent("定位权限", value: routing.locationStatus)
                Button("允许读取热点名称") { routing.requestIdentityPermission() }
                Text("定位权限用于读取 Wi-Fi 名称；位置不采集、不保存。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("连接状态") {
                LabeledContent("USB iPhone", value: "\(model.snapshot.devices.count) 台")
                if let phone = model.selectedPhone {
                    LabeledContent("USB 网络", value: phone.interface ?? "尚未建立")
                }
                if let error = model.snapshot.error {
                    Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange).font(.caption)
                }
            }
        }
        .formStyle(.grouped)
        .alert("登记当前手机热点？", isPresented: $confirming) {
            Button("取消", role: .cancel) { candidate = nil }
            Button("登记热点") { if let candidate { routing.register(candidate) }; candidate = nil }
        } message: {
            Text("登记“\(candidate?.displayName ?? "")”后，自动路由会将它作为手机代理出口。请只登记自己的手机热点。")
        }
    }
}
