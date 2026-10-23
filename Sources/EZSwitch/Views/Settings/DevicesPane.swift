import SwiftUI
import EZSwitchCore

struct DevicesPane: View {
    @Bindable var routing: RoutingModel
    @Bindable var model: AppModel
    @State private var candidate: RegisteredHotspot?
    @State private var confirming = false

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
                    }
                }
                Button("信任当前无线连接…") {
                    routing.refresh(); candidate = routing.pendingRegistration; confirming = candidate != nil
                }.disabled(!routing.reading.registrationAllowed)
                Text("可添加手机热点或随身 Wi-Fi。按名称和安全类型匹配，改名后需重新添加；请使用独有名称。")
                    .font(.caption).foregroundStyle(.secondary)
                if !routing.feedback.isEmpty { Text(routing.feedback).font(.caption).foregroundStyle(.secondary) }
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
        .alert("信任当前无线连接？", isPresented: $confirming) {
            Button("取消", role: .cancel) { candidate = nil }
            Button("添加信任") { if let candidate { routing.register(candidate) }; candidate = nil }
        } message: {
            Text("信任“\(candidate?.displayName ?? "")”后，自动路由会通过该无线连接访问代理。请添加你信任的手机热点或随身 Wi-Fi。")
        }
    }
}
