import Foundation

public enum DeviceSelection {
    /// 保存设备选择后才移除旧路由键。
    public static func migrate(_ configuration: Configuration, defaults: UserDefaults) -> Configuration {
        guard defaults.object(forKey: "EZSwitch.routingDeviceID") != nil else { return configuration }
        var migrated = configuration
        migrated.deviceID = resolve(configured: configuration.deviceID,
                                    legacy: defaults.string(forKey: "EZSwitch.routingDeviceID"), available: [])
        guard let data = try? JSONEncoder().encode(migrated) else { return configuration }
        defaults.set(data, forKey: "EZSwitch.configuration")
        defaults.removeObject(forKey: "EZSwitch.routingDeviceID")
        return migrated
    }

    /// 取舍顺序:已有配置 > 升级前的旧键 > 快照里唯一的一台设备。
    /// 有多台且没有配置时返回空,不猜。
    public static func resolve(configured: String, legacy: String?, available: [String]) -> String {
        if !configured.isEmpty { return configured }
        if let legacy, !legacy.isEmpty { return legacy }
        if available.count == 1 { return available[0] }
        return ""
    }
}
