import Foundation
import CoreWLAN
import SystemConfiguration
import AppKit

/// Event-driven invalidation plus polling in RoutingModel. Events are not a packet filter.
@MainActor final class RoutingNetworkEvents: NSObject, CWEventDelegate {
    var changed: (() -> Void)?
    var sleeping: (() -> Void)?
    var waking: (() -> Void)?
    private var store: SCDynamicStore?
    private var source: CFRunLoopSource?
    private var observers: [NSObjectProtocol] = []
    private let wifi = CWWiFiClient()
    func start() {
        guard store == nil else { return }
        var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil, copyDescription: nil)
        store = SCDynamicStoreCreate(nil, "EZSwitchRoutingEvents" as CFString, { _, _, context in
            guard let context else { return }
            let object = Unmanaged<RoutingNetworkEvents>.fromOpaque(context).takeUnretainedValue()
            Task { @MainActor in object.changed?() }
        }, &context)
        if let store {
            SCDynamicStoreSetNotificationKeys(store, nil, ["State:/Network/Interface/en[0-9]+/Link", "State:/Network/Interface/en[0-9]+/IPv4"] as CFArray)
            source = SCDynamicStoreCreateRunLoopSource(nil, store, 0)
            if let source { CFRunLoopAddSource(CFRunLoopGetMain(), source, .commonModes) }
        }
        wifi.delegate = self
        for event in [CWEventType.ssidDidChange, .bssidDidChange, .linkDidChange, .powerDidChange] {
            try? wifi.startMonitoringEvent(with: event)
        }
        let center = NSWorkspace.shared.notificationCenter
        observers.append(center.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.sleeping?() }
        })
        observers.append(center.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.waking?() }
        })
    }
    nonisolated func ssidDidChangeForWiFiInterface(withName interfaceName: String) { notify() }
    nonisolated func bssidDidChangeForWiFiInterface(withName interfaceName: String) { notify() }
    nonisolated func linkDidChangeForWiFiInterface(withName interfaceName: String) { notify() }
    nonisolated func powerStateDidChangeForWiFiInterface(withName interfaceName: String) { notify() }
    nonisolated private func notify() { Task { @MainActor [weak self] in self?.changed?() } }
}
