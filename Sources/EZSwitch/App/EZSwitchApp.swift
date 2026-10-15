import SwiftUI
import AppKit
import EZSwitchCore

@main
struct EZSwitchApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var model = AppModel.shared

    init() {
        if CommandLine.arguments.contains("--enable-routing") {
            UserDefaults.standard.set(true, forKey: "EZSwitch.automaticRouting")
        }
        if CommandLine.arguments.contains("--diagnose") || CommandLine.arguments.contains("--routing-state") {
            let monitor = DeviceMonitor()
            monitor.onChange = { value in
                if CommandLine.arguments.contains("--routing-state") {
                    let selected = DeviceSelection.resolve(configured: AppModel.shared.configuration.deviceID,
                        legacy: nil, available: value.error == nil ? value.devices.map(\.id) : [])
                    let reading = RoutingNetworkReader.read(phones: value, deviceID: selected, registrations: [], identityAuthorized: false)
                    let decision = RoutingPolicy.decide(reading.network)
                    let result: [String: Any] = ["mode": decision.mode.rawValue, "usb": reading.network.usbInterface ?? "none", "wifi": reading.network.wifiInterface ?? "none", "state_readable": reading.network.stateReadable]
                    print(String(decoding: try! JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]), as: UTF8.self))
                    exit(value.error == nil ? 0 : 1)
                }
                if let error = value.error { print("Monitor error: \(error)") }
                for phone in value.devices {
                    print("\(phone.name) · \(phone.id.suffix(6)) · USB network: \(phone.interface ?? "none") · primary: \(phone.isPrimary)")
                    let reading = RoutingNetworkReader.read(phones: value, deviceID: phone.id,
                                                            registrations: [], identityAuthorized: false)
                    let decision = RoutingPolicy.decide(reading.network)
                    print("Routing preview: \(decision.mode.rawValue) · usable USB: \(reading.network.usbInterface ?? "none") · usable Wi-Fi: \(reading.network.wifiInterface ?? "none") · applied: false")
                }
                print("USB iPhones: \(value.devices.count)")
                exit(value.error == nil ? 0 : 1)
            }
            monitor.start()
        }
    }

    var body: some Scene {
        MenuBarExtra {
            StatusView(model: model)
                .onAppear { delegate.model = model; model.start() }
        } label: {
            SettingsLaunchLabel(model: model)
        }
        .menuBarExtraStyle(.window)

        Window("EZ Route 使用引导", id: "setup") {
            SetupView(model: model)
                .onAppear { delegate.model = model; model.start() }
        }
        .windowResizability(.contentSize)
        .defaultPosition(.center)
        .defaultLaunchBehavior(model.hasSeenGuide ? .suppressed : .presented)

        Settings {
            SettingsView(model: model)
                .onAppear { delegate.model = model; model.start(); NSApp.activate() }
        }
    }
}

/// 菜单栏标签在启动时就存在；不依赖用户先打开菜单来呈现设置。
private struct SettingsLaunchLabel: View {
    @Bindable var model: AppModel
    @Environment(\.openSettings) private var openSettings
    @State private var presented = false

    var body: some View {
        Label("EZ Route", systemImage: RoutingModel.shared.isAttention ? "exclamationmark.shield" : "arrow.triangle.branch")
            .task {
                guard !presented, CommandLine.arguments.contains("--enable-routing") else { return }
                presented = true
                openSettings()
                NSApp.activate()
            }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    var model: AppModel? = .shared
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        model?.start()
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let model else { return .terminateNow }
        let routing = RoutingModel.shared
        guard routing.enabled || routing.routingState != .idle else { return .terminateNow }
        model.quitting = true
        Task {
            guard await routing.prepareQuit() else {
                model.quitting = false
                let alert = NSAlert()
                alert.messageText = "退出前的路由调整未完成"
                alert.informativeText = "应用将继续运行。请先断开校园 Wi-Fi，恢复 Clash 控制接口后再退出。"
                alert.runModal()
                sender.reply(toApplicationShouldTerminate: false); return
            }
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}
