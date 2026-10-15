import SwiftUI

enum SettingsPane: String, CaseIterable, Identifiable {
    case overview, devices, diagnostics, general

    var id: String { rawValue }

    var title: String {
        switch self {
        case .overview: "概览"
        case .devices: "设备与热点"
        case .diagnostics: "诊断与监测"
        case .general: "通用"
        }
    }

    var symbol: String {
        switch self {
        case .overview: "arrow.triangle.branch"
        case .devices: "iphone.gen3"
        case .diagnostics: "waveform.path.ecg"
        case .general: "gearshape"
        }
    }
}
