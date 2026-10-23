import EZSwitchCore

extension RoutingMode {
    var displayTitle: String {
        switch self {
        case .usbHotspot: "USB 供网"
        case .wifiHotspot: "信任的无线连接"
        case .split: "USB 与 Wi-Fi 分流"
        case .directOnly: "Wi-Fi 直连"
        case .blocked: "等待可用网络"
        }
    }
}
