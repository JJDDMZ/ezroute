import EZSwitchCore

extension RoutingMode {
    var displayTitle: String {
        switch self {
        case .usbHotspot: "手机 USB 热点"
        case .wifiHotspot: "手机无线热点"
        case .split: "USB 与 Wi-Fi 分流"
        case .directOnly: "Wi-Fi 直连"
        case .blocked: "等待可用网络"
        }
    }
}
