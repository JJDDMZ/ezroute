import Foundation
import AppKit
import Observation
import ServiceManagement
import EZSwitchCore

@MainActor @Observable
final class AppModel {
    static let shared = AppModel()
    var configuration: Configuration {
        didSet {
            if let data = try? JSONEncoder().encode(configuration) {
                defaults.set(data, forKey: "EZSwitch.configuration")
            }
            if started, configuration.deviceID != oldValue.deviceID { syncDeviceID() }
        }
    }
    private(set) var snapshot = DeviceSnapshot(devices: [])
    private(set) var notificationStatus = "等待通知授权"
    private(set) var loginStatus = ""
    var hasSeenGuide: Bool {
        didSet { defaults.set(hasSeenGuide, forKey: "EZSwitch.routingGuideSeen") }
    }
    var quitting = false
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let monitor = DeviceMonitor()
    @ObservationIgnored private let notifications = NotificationService()
    @ObservationIgnored private var started = false

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        let saved = defaults.data(forKey: "EZSwitch.configuration").flatMap {
            try? JSONDecoder().decode(Configuration.self, from: $0)
        } ?? Configuration()
        let migrated = DeviceSelection.migrate(saved, defaults: defaults)
        configuration = migrated
        // 已配置设备的用户不重复看到引导。旧确认标志只用于兼容首次显示行为。
        hasSeenGuide = defaults.bool(forKey: "EZSwitch.routingGuideSeen") ||
            defaults.bool(forKey: "EZSwitch.setupAcknowledged") || !migrated.deviceID.isEmpty
        // 不读取旧 session、命令或回执；启动和退出都不再请求手机切卡。
    }

    var selectedPhone: Phone? { snapshot.devices.first { $0.id == configuration.deviceID } }
    var loginEnabled: Bool { SMAppService.mainApp.status == .enabled }

    func start() {
        guard !started else { return }
        syncDeviceID()
        started = true
        monitor.onChange = { [weak self] update in
            guard let self else { return }
            if update.error == nil {
                let selected = DeviceSelection.resolve(configured: self.configuration.deviceID,
                    legacy: nil, available: update.devices.map(\.id))
                if selected != self.configuration.deviceID { self.configuration.deviceID = selected }
                self.snapshot = update
            } else {
                // 保留最后一次物理设备快照，路由仍接收错误快照并执行原有保护。
                self.snapshot.error = update.error
            }
            self.syncDeviceID()
            RoutingModel.shared.receive(update)
        }
        monitor.start()
        RoutingModel.shared.start()
        Task { notificationStatus = await notifications.authorizationDescription() }
    }

    private func syncDeviceID() {
        RoutingModel.shared.setDeviceID(configuration.deviceID)
    }

    func allowNotifications() async {
        _ = await notifications.requestPermission()
        notificationStatus = await notifications.authorizationDescription()
    }

    func setLoginEnabled(_ value: Bool) {
        do {
            if value { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
            loginStatus = SMAppService.mainApp.status == .requiresApproval ? "请在系统设置中批准登录项。" : ""
        } catch { loginStatus = error.localizedDescription }
    }

    func openGuide() {
        if let path = Bundle.main.url(forResource: "setup", withExtension: "md", subdirectory: "docs") {
            NSWorkspace.shared.open(path)
        }
    }
}
