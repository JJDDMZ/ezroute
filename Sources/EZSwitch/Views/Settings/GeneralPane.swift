import SwiftUI

struct GeneralPane: View {
    @Bindable var model: AppModel

    var body: some View {
        Form {
            Section("日常使用") {
                Toggle("登录时启动", isOn: Binding(get: { model.loginEnabled }, set: { model.setLoginEnabled($0) }))
                if !model.loginStatus.isEmpty { Text(model.loginStatus).font(.caption).foregroundStyle(.secondary) }
                LabeledContent("系统通知") {
                    Button("允许通知") { Task { await model.allowNotifications() } }
                }
                Text(model.notificationStatus).font(.caption).foregroundStyle(.secondary)
            }

        }
        .formStyle(.grouped)
    }
}
