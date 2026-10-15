import Foundation
import AppKit
import IOKit
import SystemConfiguration
import EZSwitchCore

private func usbChanged(_ context: UnsafeMutableRawPointer?, _ iterator: io_iterator_t) {
    while case let service = IOIteratorNext(iterator), service != 0 { IOObjectRelease(service) }
    guard let context else { return }
    let monitor = Unmanaged<DeviceMonitor>.fromOpaque(context).takeUnretainedValue()
    Task { @MainActor in monitor.scheduleRefresh() }
}

private func networkChanged(_ store: SCDynamicStore, _ keys: CFArray, _ context: UnsafeMutableRawPointer?) {
    guard let context else { return }
    let monitor = Unmanaged<DeviceMonitor>.fromOpaque(context).takeUnretainedValue()
    Task { @MainActor in monitor.scheduleRefresh() }
}

@MainActor
final class DeviceMonitor {
    var onChange: ((DeviceSnapshot) -> Void)?
    private var port: IONotificationPortRef?
    private var added: io_iterator_t = 0
    private var removed: io_iterator_t = 0
    private var store: SCDynamicStore?
    private var source: CFRunLoopSource?
    private var refreshTask: Task<Void, Never>?
    private var fallback: Timer?
    private var wakeObserver: NSObjectProtocol?
    private var setupError: String?

    func start() {
        let pointer = Unmanaged.passUnretained(self).toOpaque()
        port = IONotificationPortCreate(kIOMainPortDefault)
        if let port, let loopSource = IONotificationPortGetRunLoopSource(port)?.takeUnretainedValue() {
            CFRunLoopAddSource(CFRunLoopGetMain(), loopSource, .commonModes)
            let a = IOServiceAddMatchingNotification(port, kIOFirstMatchNotification,
                IOServiceMatching("IOUSBHostDevice"), usbChanged, pointer, &added)
            let b = IOServiceAddMatchingNotification(port, kIOTerminatedNotification,
                IOServiceMatching("IOUSBHostDevice"), usbChanged, pointer, &removed)
            if a == KERN_SUCCESS && b == KERN_SUCCESS {
                usbChanged(pointer, added); usbChanged(pointer, removed)
            } else { setupError = "无法订阅 USB 事件（\(a), \(b)）。" }
        } else { setupError = "无法初始化 USB 监测。" }

        var context = SCDynamicStoreContext(version: 0, info: pointer, retain: nil, release: nil, copyDescription: nil)
        store = SCDynamicStoreCreate(nil, "EZSwitch" as CFString, networkChanged, &context)
        if let store {
            let patterns = ["State:/Network/Global/.*", "State:/Network/Interface/.*/.*", "State:/Network/Service/.*/.*"]
            guard SCDynamicStoreSetNotificationKeys(store, nil, patterns as CFArray),
                  let source = SCDynamicStoreCreateRunLoopSource(nil, store, 0) else {
                setupError = "无法订阅网络状态。"; refresh(); return
            }
            self.source = source
            CFRunLoopAddSource(CFRunLoopGetMain(), source, .commonModes)
        } else { setupError = "无法读取系统网络状态。" }
        wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { [weak self] _ in Task { @MainActor in self?.scheduleRefresh() } }
        fallback = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
        refresh()
    }

    func scheduleRefresh() {
        refreshTask?.cancel()
        refreshTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(650))
            guard !Task.isCancelled else { return }
            self?.refresh()
        }
    }

    func refresh() {
        guard setupError == nil, let store else {
            onChange?(.init(devices: [], error: setupError ?? "网络监测不可用。")); return
        }
        do {
            // An unreadable snapshot is not evidence of physical disconnection.
            guard SCDynamicStoreCopyKeyList(store, "State:/Network/.*" as CFString) != nil else {
                throw MonitorError.unavailable("无法读取系统网络状态（\(SCError())）。")
            }
            var phones = try enumeratePhones()
            let primary = Set(["IPv4", "IPv6"].compactMap {
                (SCDynamicStoreCopyValue(store, "State:/Network/Global/\($0)" as CFString)
                    as? [String: Any])?["PrimaryInterface"] as? String
            })
            for (deviceID, interface) in try usbNetworkInterfaces() {
                guard let index = phones.firstIndex(where: { $0.id == deviceID }) else { continue }
                let link = SCDynamicStoreCopyValue(store, "State:/Network/Interface/\(interface)/Link" as CFString) as? [String: Any]
                let ipv4 = SCDynamicStoreCopyValue(store, "State:/Network/Interface/\(interface)/IPv4" as CFString) as? [String: Any]
                let ipv6 = SCDynamicStoreCopyValue(store, "State:/Network/Interface/\(interface)/IPv6" as CFString) as? [String: Any]
                let addresses = (ipv4?["Addresses"] as? [String] ?? []) + (ipv6?["Addresses"] as? [String] ?? [])
                let hasAddress = addresses.contains { !$0.hasPrefix("169.254.") && !$0.hasPrefix("fe80:") && $0 != "0.0.0.0" }
                let isPrimary = (link?["Active"] as? Bool == true) && hasAddress && primary.contains(interface)
                phones[index] = phones[index].attaching(interface: interface, isPrimary: isPrimary)
            }
            onChange?(.init(devices: phones.sorted { $0.id < $1.id }))
        } catch { onChange?(.init(devices: [], error: error.localizedDescription)) }
    }

    private func enumeratePhones() throws -> [Phone] {
        var iterator: io_iterator_t = 0
        guard IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOUSBHostDevice"), &iterator) == KERN_SUCCESS
        else { throw MonitorError.unavailable("无法读取 USB 设备。") }
        defer { IOObjectRelease(iterator) }
        var phones: [Phone] = []
        while case let service = IOIteratorNext(iterator), service != 0 {
            defer { IOObjectRelease(service) }
            if let phone = phone(service) { phones.append(phone) }
        }
        return phones
    }

    private func phone(_ service: io_registry_entry_t) -> Phone? {
        guard (property(service, "idVendor") as? NSNumber)?.intValue == 0x05ac,
              let name = property(service, "USB Product Name") as? String, name.hasPrefix("iPhone"),
              let serial = property(service, "USB Serial Number") as? String, !serial.isEmpty else { return nil }
        return Phone(id: serial, name: name)
    }

    private func usbNetworkInterfaces() throws -> [(String, String)] {
        var iterator: io_iterator_t = 0
        guard IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("IOEthernetInterface"), &iterator) == KERN_SUCCESS
        else { throw MonitorError.unavailable("无法读取网络设备关联。") }
        defer { IOObjectRelease(iterator) }
        var matches: [(String, String)] = []
        while case let interface = IOIteratorNext(iterator), interface != 0 {
            defer { IOObjectRelease(interface) }
            guard let bsd = property(interface, "BSD Name") as? String else { continue }
            // Follow registry ancestry to the actual iPhone, not a localized service name.
            var current = interface
            IOObjectRetain(current)
            for _ in 0..<32 {
                if let found = phone(current) {
                    matches.append((found.id, bsd)); break
                }
                var parent: io_registry_entry_t = 0
                guard IORegistryEntryGetParentEntry(current, kIOServicePlane, &parent) == KERN_SUCCESS else { break }
                IOObjectRelease(current); current = parent
            }
            IOObjectRelease(current)
        }
        return matches
    }

    private func property(_ service: io_registry_entry_t, _ key: String) -> Any? {
        IORegistryEntryCreateCFProperty(service, key as CFString, nil, 0)?.takeRetainedValue()
    }
}

private enum MonitorError: LocalizedError {
    case unavailable(String)
    var errorDescription: String? { if case .unavailable(let message) = self { return message }; return nil }
}
