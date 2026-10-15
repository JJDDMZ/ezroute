import Foundation
import CoreLocation
import Observation
import OSLog
import EZSwitchCore

@MainActor @Observable final class RoutingModel: NSObject, CLLocationManagerDelegate {
    private static let logger = Logger(subsystem: "dev.ezswitch.app", category: "Routing")
    static let shared = RoutingModel()
    private(set) var usbDeviceID: String = "" {
        didSet { if timer != nil { refresh() } }
    }
    private(set) var registrations: [RegisteredHotspot]
    private(set) var reading = RoutingNetworkReading(network: .init(stateReadable: false), wifiName: nil,
                                                    registrationAllowed: false, message: nil)
    private(set) var locationStatus = "等待授权"
    private(set) var feedback = ""
    private(set) var clashStatus = "等待检查"
    private(set) var bootstrapStatus = "等待接入"
    private(set) var checkingClash = false
    private(set) var enabled = false
    /// 苹果服务是否改走代理。默认否:平时用国区账号,直连更快;处理外区账号时打开。
    private(set) var appleViaProxy = false
    private(set) var routingState: RoutingCoordinatorState = .idle
    private(set) var appliedDecision: RoutingDecision?
    private(set) var changingEnabled = false
    private var sleeping = false
    private var shuttingDown = false
    @ObservationIgnored private var instanceLock: RoutingInstanceLock?
    @ObservationIgnored private var coordinator: RoutingCoordinator!
    @ObservationIgnored private let networkEvents = RoutingNetworkEvents()
    @ObservationIgnored private let notifications = NotificationService()
    @ObservationIgnored private var lastAudit = Date.distantPast
    @ObservationIgnored private var baseCache = ClashBootstrapSourceCache()
    @ObservationIgnored private var settleTask: Task<Void, Never>?
    @ObservationIgnored private var settling = false
    @ObservationIgnored private var lastAnnouncement: RoutingDecision?
    @ObservationIgnored private var lastFailure = Date.distantPast
    @ObservationIgnored private var coupling: RoutingTunnelCoupling
    @ObservationIgnored private var probingTunnel = false
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let location = CLLocationManager()
    @ObservationIgnored private var phones = DeviceSnapshot(devices: [], error: "等待读取")
    @ObservationIgnored private var timer: Timer?
    @ObservationIgnored private var traffic: TrafficSampler?

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        coupling = RoutingTunnelCoupling(suspended: defaults.bool(forKey: "EZSwitch.automaticRoutingSuspendedByTunnel"))
        registrations = defaults.data(forKey: "EZSwitch.registeredHotspots").flatMap {
            try? JSONDecoder().decode([RegisteredHotspot].self, from: $0)
        } ?? []
        super.init()
        location.delegate = self
        enabled = defaults.bool(forKey: "EZSwitch.automaticRouting")
        appleViaProxy = defaults.bool(forKey: "EZSwitch.appleViaProxy")
        coordinator = RoutingCoordinator(controller: RoutingControllerAdapter(), loadBase: { [weak self] in
            guard let self else { throw MihomoClientError.unavailable }
            return try await self.loadBase()
        }, snapshot: { [weak self] in
            guard let self else { return .init(decision: .init(mode: .blocked, proxyInterface: nil, directInterface: nil), identity: "unavailable") }
            return self.currentSnapshot()
        }, appleViaProxy: { [weak self] in self?.appleViaProxy ?? false })
        coordinator.onChange = { [weak self] state, snapshot in self?.didApply(state, snapshot) }
        networkEvents.changed = { [weak self] in self?.networkChanged() }
        networkEvents.sleeping = { [weak self] in
            guard let self else { return }; self.sleeping = true
            self.refresh(); Task { await self.coordinator.reconcile(force: true) }
        }
        networkEvents.waking = { [weak self] in self?.sleeping = false; self?.networkChanged() }
    }

    var decision: RoutingDecision { RoutingPolicy.decide(reading.network) }
    var phonesForPicker: [Phone] { phones.devices }
    var modeTitle: String { decision.mode.displayTitle }
    var pendingRegistration: RegisteredHotspot? {
        guard reading.registrationAllowed, let ssid = reading.network.ssid,
              let security = reading.network.security else { return nil }
        return .init(ssid: ssid, security: security,
                     displayName: reading.wifiName ?? "热点 · " + ssid.base64EncodedString())
    }
    func receive(_ snapshot: DeviceSnapshot) {
        phones = snapshot
        refresh()
    }
    func setDeviceID(_ value: String) {
        guard usbDeviceID != value else { return }
        usbDeviceID = value
    }
    func start() {
        guard timer == nil else { return }
        do {
            let directory = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/dev.ezswitch.app")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            instanceLock = try RoutingInstanceLock(at: directory.appendingPathComponent("routing.lock"))
        } catch {
            enabled = false; routingState = .unprotected
            clashStatus = "无法取得路由控制权。请检查是否已有其他 EZ Route 实例正在运行。"
            return
        }
        networkEvents.start()
        let sampler = TrafficSampler(directory: TrafficStore.defaultDirectory)
        sampler.start()
        traffic = sampler
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }; self.refresh()
                if self.enabled && !self.shuttingDown && Date().timeIntervalSince(self.lastAudit) >= 5 {
                    self.lastAudit = Date(); await self.coordinator.audit()
                }
                // Only a suspension is worth probing; a switch the user turned off stays off.
                else if !self.enabled && !self.shuttingDown { await self.probeTunnelForRestore() }
            }
        }
    }
    func refresh() {
        let status = location.authorizationStatus
        let authorized = status == .authorizedAlways
        switch status {
        case .authorizedAlways: locationStatus = "已允许读取热点名称"
        case .denied, .restricted: locationStatus = "未授权，请在系统设置中允许读取热点名称"
        default: locationStatus = "等待授权"
        }
        reading = RoutingNetworkReader.read(phones: phones, deviceID: usbDeviceID,
                                           registrations: registrations, identityAuthorized: authorized)
        if enabled && !shuttingDown { Task { await coordinator.reconcile() } }
    }
    func requestIdentityPermission() { location.requestWhenInUseAuthorization() }
    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        Task { @MainActor [weak self] in self?.refresh() }
    }
    func register(_ candidate: RegisteredHotspot) {
        refresh()
        guard reading.registrationAllowed,
              candidate.matches(ssid: reading.network.ssid, security: reading.network.security) else {
            feedback = "网络已变化，请重新选择当前热点。"; return
        }
        guard !registrations.contains(where: { $0.matches(ssid: candidate.ssid, security: candidate.security) }) else {
            feedback = "该热点已在列表中。"; return
        }
        registrations.append(candidate); persist()
        feedback = "热点已登记。开启自动路由后，连接它即可使用手机出口。"; refresh()
    }
    func remove(_ id: UUID) { registrations.removeAll { $0.id == id }; persist(); refresh() }
    private func persist() {
        if let data = try? JSONEncoder().encode(registrations) { defaults.set(data, forKey: "EZSwitch.registeredHotspots") }
    }
    var stateTitle: String {
        switch routingState {
        case .idle: "自动路由已关闭"
        case .paused: "TUN 已关闭 · 自动路由已暂停"
        case .switching: "正在切换网络出口"
        case .active: enabled ? "自动路由运行中" : "自动路由已关闭 · 退出配置已生效"
        case .blockedAfterFailure: "切换失败 · 请求已阻断"
        case .unprotected: "出口状态待确认 · 请断开校园 Wi-Fi"
        }
    }
    var isAttention: Bool { routingState == .unprotected || routingState == .blockedAfterFailure }
    var websiteTestControlsAvailable: Bool {
        enabled && !shuttingDown && !sleeping && !settling &&
            routingState == .active && coordinator.websiteTestReadiness.controlsAvailable
    }
    func waitForWebsiteTests() async throws -> Bool {
        try await RoutingWebsiteReadiness.waitUntilReady {
            self.websiteTestControlsAvailable ? self.coordinator.websiteTestReadiness : .unavailable
        }
    }
    func websiteTestSnapshot() -> RoutingSnapshot { currentSnapshot() }
    var websiteTestConfiguration: Data? { coordinator.diagnosticConfiguration }
    var websiteCaptureInterfaces: [String] {
        [reading.network.usbInterface, reading.network.wifiInterface].compactMap { $0 }
    }
    private var generatedURL: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(
            "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml")
    }
    private func currentStamp() -> String {
        [generatedURL, generatedURL.deletingLastPathComponent().appendingPathComponent("profiles.yaml")].map { url in
            guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path) else { return "missing" }
            return "\((attributes[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0)|\(attributes[.size] ?? "")"
        }.joined(separator: "|")
    }
    private func loadBase() async throws -> Data {
        reading = RoutingNetworkReader.read(phones: phones, deviceID: usbDeviceID,
            registrations: registrations, identityAuthorized: location.authorizationStatus == .authorizedAlways)
        let binding = try ClashBootstrapBinding.resolve(deviceID: usbDeviceID,
            currentInterface: reading.network.usbInterface,
            rememberedDeviceID: defaults.string(forKey: "EZSwitch.bootstrapDeviceID"),
            rememberedInterface: defaults.string(forKey: "EZSwitch.bootstrapUSBInterface"))
        let stamp = currentStamp()
        if let cachedBase = baseCache.lookup(stamp: stamp, binding: binding) { return cachedBase }
        let directory = generatedURL.deletingLastPathComponent()
        let registry = try await MihomoClient.readGeneratedConfiguration(at: directory.appendingPathComponent("profiles.yaml"))
        guard let scriptURL = Bundle.main.url(forResource: "routing-bootstrap", withExtension: "js"),
              let legacyURL = Bundle.main.url(forResource: "legacy-routing", withExtension: "js") else {
            throw ClashBootstrapError.invalidRegistry
        }
        let usb = binding.interface
        let script = try String(contentsOf: scriptURL, encoding: .utf8)
            .replacingOccurrences(of: "const USB_INTERFACE = 'en5';", with: "const USB_INTERFACE = '\(usb)';")
            .replacingOccurrences(of: "const EZ_BOOTSTRAP_USB = 'en5';", with: "const EZ_BOOTSTRAP_USB = '\(usb)';")
        let backup = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/dev.ezswitch.app/ClashBridge")
        _ = try ClashBootstrap.install(directory: directory, registry: registry, backupDirectory: backup,
            script: script, ownedLegacy: String(contentsOf: legacyURL, encoding: .utf8))
        defaults.set(usb, forKey: "EZSwitch.bootstrapUSBInterface")
        defaults.set(binding.deviceID, forKey: "EZSwitch.bootstrapDeviceID")
        bootstrapStatus = "订阅接入已完成"
        let data = try await MihomoClient.readGeneratedConfiguration(at: generatedURL)
        guard currentStamp() == stamp else { throw MihomoClientError.malformed }
        _ = try RoutingConfiguration.make(baseJSON: data, decision: .init(mode: .blocked, proxyInterface: nil, directInterface: nil))
        guard let config = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              (config["tun"] as? [String: Any])?["enable"] as? Bool == true else { throw MihomoClientError.malformed }
        if config["ez-switch-bootstrap-version"] as? Int == 1 {
            let profiles = try JSONSerialization.jsonObject(with: registry) as? [String: Any]
            let selected = (profiles?["items"] as? [[String: Any]])?.first { $0["uid"] as? String == profiles?["current"] as? String }
            guard config["ez-switch-profile-name"] as? String == (selected?["name"] as? String ?? "") else { throw MihomoClientError.malformed }
        }
        baseCache.store(data, stamp: stamp, binding: binding)
        return data
    }
    private func currentSnapshot() -> RoutingSnapshot {
        // Read again at every asynchronous boundary, not just when the timer fired.
        reading = RoutingNetworkReader.read(phones: phones, deviceID: usbDeviceID,
            registrations: registrations, identityAuthorized: location.authorizationStatus == .authorizedAlways)
        let target: RoutingDecision
        if sleeping || settling { target = .init(mode: .blocked, proxyInterface: nil, directInterface: nil) }
        else if !enabled || shuttingDown {
            if let usb = reading.network.usbInterface { target = .init(mode: .usbHotspot, proxyInterface: usb, directInterface: usb) }
            else if let wifi = reading.network.wifiInterface { target = .init(mode: .directOnly, proxyInterface: nil, directInterface: wifi) }
            else { target = .init(mode: .blocked, proxyInterface: nil, directInterface: nil) }
        } else { target = decision }
        return .init(decision: target, identity: reading.identity + "|" + usbDeviceID + "|" + currentStamp() + "|\(enabled)|\(shuttingDown)|\(sleeping)|\(settling)")
    }
    private func networkChanged() {
        guard enabled && !shuttingDown else { refresh(); return }
        settling = true; refresh()
        settleTask?.cancel()
        settleTask = Task { [weak self] in
            do { try await Task.sleep(for: .milliseconds(600)) } catch { return }
            guard let self else { return }; self.settling = false; self.refresh()
        }
    }
    func setEnabled(_ value: Bool) async {
        await applyEnabled(value)
        // A deliberate off retires any tunnel-driven restore. A failed on keeps it, so
        // switching the tunnel back on still restores what the tunnel suspended.
        if !value || enabled { coupling.userSetEnabled(); persistCoupling() }
    }

    /// Switches automatic routing without touching the coupling. Used by the switch
    /// itself and by the restore path when the tunnel comes back.
    private func applyEnabled(_ value: Bool) async {
        guard !changingEnabled, instanceLock != nil else { return }
        changingEnabled = true; defer { changingEnabled = false }
        if value {
            do {
                guard try await RoutingControllerAdapter().tunnelEnabled() else {
                    clashStatus = "请先在 Clash 开启 TUN，再启用自动路由。"; return
                }
                _ = try await loadBase()
            }
            catch { clashStatus = error.localizedDescription; bootstrapStatus = "接入失败 · 已保留原扩展"; return }
            _ = await notifications.requestPermission()
        }
        enabled = value; defaults.set(value, forKey: "EZSwitch.automaticRouting")
        refresh(); await coordinator.reconcile(force: true)
    }

    /// 只改苹果服务的走向,不动其余分流。重算一次配置即可生效。
    func setAppleViaProxy(_ value: Bool) async {
        guard value != appleViaProxy else { return }
        appleViaProxy = value; defaults.set(value, forKey: "EZSwitch.appleViaProxy")
        refresh(); await coordinator.reconcile(force: true)
    }

    /// Runs only while automatic routing is off, so the tunnel coming back can restore
    /// what it suspended. A switch the user turned off is never probed.
    private func probeTunnelForRestore() async {
        guard coupling.suspended, !probingTunnel, instanceLock != nil else { return }
        probingTunnel = true; defer { probingTunnel = false }
        let tunneled = (try? await RoutingControllerAdapter().tunnelEnabled()) ?? false
        guard coupling.observeTunnel(enabled: tunneled) else { return }
        await applyEnabled(true)
        if enabled {
            coupling.restoreSucceeded(); persistCoupling()
            notifications.post("TUN 已开启", body: "自动路由已恢复。", id: "ez-routing-tunnel")
        } else {
            coupling.restoreFailed(); persistCoupling()
        }
    }

    private func persistCoupling() {
        defaults.set(coupling.suspended, forKey: "EZSwitch.automaticRoutingSuspendedByTunnel")
    }
    func prepareQuit() async -> Bool {
        guard instanceLock != nil else { return true }
        shuttingDown = true; settleTask?.cancel(); settling = false
        await coordinator.reconcile(force: true)
        // A busy transaction will observe shuttingDown in its snapshot and drain before exit.
        let limit = Date().addingTimeInterval(25)
        while (coordinator.isBusy || routingState == .switching) && Date() < limit { try? await Task.sleep(for: .milliseconds(100)) }
        let safe = !coordinator.isBusy && (routingState == .active || routingState == .blockedAfterFailure || routingState == .paused)
        if !safe { shuttingDown = false }
        return safe
    }
    private func didApply(_ state: RoutingCoordinatorState, _ snapshot: RoutingSnapshot?) {
        let reason = coordinator.failureDescription ?? "none"
        Self.logger.notice("state=\(String(describing: state), privacy: .public) mode=\(snapshot?.decision.mode.rawValue ?? "none", privacy: .public) reason=\(reason, privacy: .public)")
        routingState = state; appliedDecision = snapshot?.decision
        if state == .paused {
            let wasEnabled = enabled
            coupling.tunnelWentOff(wasEnabled: wasEnabled); persistCoupling()
            enabled = false; defaults.set(false, forKey: "EZSwitch.automaticRouting")
            if wasEnabled {
                notifications.post("TUN 已关闭",
                    body: "自动路由已暂停，重新开启 TUN 后自动恢复。", id: "ez-routing-tunnel")
            }
        }
        clashStatus = coordinator.failureDescription.map { stateTitle + "；" + $0 } ?? stateTitle
        if state == .active, enabled, let snapshot, lastAnnouncement != snapshot.decision {
            lastAnnouncement = snapshot.decision
            let body: String
            switch snapshot.decision.mode {
            case .usbHotspot: body = "当前使用 iPhone USB 热点。"
            case .wifiHotspot: body = "当前使用已登记的手机无线热点。"
            case .split: body = "代理与公共 DNS 使用手机 USB，直连使用 Wi-Fi。"
            case .directOnly: body = "当前使用 Wi-Fi 直连，代理已停用。"
            case .blocked: body = "正在等待可用网络，Clash 请求已阻断。"
            }
            notifications.post("网络出口已切换", body: body, id: "ez-routing-status")
        }
        if isAttention && Date().timeIntervalSince(lastFailure) > 30 {
            lastFailure = Date(); notifications.post("请检查网络出口", body: stateTitle, id: "ez-routing-error")
        }
    }
    func checkClash() async {
        guard !checkingClash else { return }
        checkingClash = true; defer { checkingClash = false }
        do {
            _ = try await loadBase()
            _ = try await MihomoClient().read(path: "/configs")
            if enabled {
                if routingState == .blockedAfterFailure || routingState == .unprotected { await coordinator.reconcile(force: true) }
                else { await coordinator.audit() }
                clashStatus = coordinator.failureDescription.map { stateTitle + "；" + $0 } ?? stateTitle }
            else { clashStatus = "Clash 控制接口与配置读取正常，自动路由已关闭。" }
        } catch { clashStatus = "无法读取 Clash 配置或控制接口，请检查 Clash 是否正在运行。" }
    }
}
