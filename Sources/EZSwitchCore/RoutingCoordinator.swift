import Foundation

public struct RoutingSnapshot: Equatable, Sendable {
    public let decision: RoutingDecision
    public let identity: String
    public init(decision: RoutingDecision, identity: String) { self.decision = decision; self.identity = identity }
}
public enum RoutingCoordinatorState: Equatable, Sendable {
    case idle, paused, switching, active, blockedAfterFailure, unprotected
}
@MainActor public protocol RoutingController: AnyObject {
    func tunnelEnabled() async throws -> Bool
    func apply(configuration: Data) async throws
    func closeConnections() async throws
    func flushDNS() async throws
    func selections() async throws -> [String: String]
    func restoreSelections(_ selections: [String: String], configuration: Data,
                           shouldContinue: @escaping @MainActor () async throws -> Bool) async throws -> Bool
    func verify(configuration: Data, shouldContinue: @escaping @MainActor () async throws -> Bool) async throws -> Bool
}
public extension RoutingController {
    func verify(configuration: Data) async throws -> Bool {
        try await verify(configuration: configuration, shouldContinue: { true })
    }
}
/// Serializes complete config transactions. It cannot guard packets before a network event arrives.
@MainActor public final class RoutingCoordinator {
    public private(set) var failureDescription: String?
    public private(set) var applied: RoutingSnapshot?
    public private(set) var state: RoutingCoordinatorState = .idle {
        didSet { onChange?(state, applied) }
    }
    public var onChange: (@MainActor (RoutingCoordinatorState, RoutingSnapshot?) -> Void)?
    private let controller: any RoutingController
    private let loadBase: @MainActor () async throws -> Data
    private let snapshot: @MainActor () -> RoutingSnapshot
    private let appleViaProxy: @MainActor () -> Bool
    public var isBusy: Bool { running }
    public var websiteTestReadiness: RoutingWebsiteReadiness {
        guard state == .active, applied != nil else { return .unavailable }
        return running ? .checking : .ready
    }
    public var diagnosticConfiguration: Data? { state == .active && applied != nil ? configuration : nil }
    private var running = false
    private var requested = false
    private var forceRequested = false
    private var configuration: Data?
    private var lastBlock: Data?
    private var failedSnapshot: RoutingSnapshot?
    private var awaitingInitialController = false
    private var savedSelections: [String: String] = [:]
    public init(controller: any RoutingController, loadBase: @escaping @MainActor () async throws -> Data,
                snapshot: @escaping @MainActor () -> RoutingSnapshot,
                appleViaProxy: @escaping @MainActor () -> Bool = { false }) {
        self.controller = controller; self.loadBase = loadBase; self.snapshot = snapshot
        self.appleViaProxy = appleViaProxy
    }
    public func reconcile(force: Bool = false) async {
        requested = true; forceRequested = forceRequested || force
        guard !running else { return }
        running = true; defer { running = false }
        var attempts = 0
        while requested && attempts < 8 {
            requested = false; attempts += 1
            let target = snapshot()
            let forced = forceRequested; forceRequested = false
            if (target == applied || target == failedSnapshot) && !forced { continue }
            applied = nil; state = .switching
            var blocked: Data? = lastBlock
            var stage = "检查虚拟网卡"
            var controllerChecked = false
            do {
                guard try await controller.tunnelEnabled() else {
                    awaitingInitialController = false
                    configuration = nil; failureDescription = nil; state = .paused; continue
                }
                controllerChecked = true; awaitingInitialController = false
                stage = "读取配置"
                let base = try await loadBase()
                blocked = try RoutingConfiguration.make(baseJSON: base, decision: .init(mode: .blocked, proxyInterface: nil, directInterface: nil))
                lastBlock = blocked
                // Retain selections before removing their groups. Failure is not allowed to skip blocking.
                if let selections = try? await controller.selections() { savedSelections.merge(selections) { _, new in new } }
                stage = "应用阻断配置"
                guard try await retainTunnel() else { continue }
                try await controller.apply(configuration: blocked!)
                stage = "关闭旧连接"
                try await controller.closeConnections()
                stage = "清理 DNS 缓存"
                try await controller.flushDNS()
                guard snapshot() == target else { requested = true; continue }
                let output = try RoutingConfiguration.make(baseJSON: base, decision: target.decision,
                                                          appleViaProxy: appleViaProxy())
                stage = "应用目标配置"
                guard try await retainTunnel() else { continue }
                guard snapshot() == target else { requested = true; continue }
                try await controller.apply(configuration: output)
                // A reload can yield while SSID/IP/interface identity changes.
                stage = "复查身份并撤销失效出口"
                guard try await retainTargetOrBlock(target, blocked: blocked!) else { continue }
                stage = "恢复节点选择"
                var interrupted = false
                let authorization: @MainActor () async throws -> Bool = {
                    let allowed = try await self.retainTunnel() && self.snapshot() == target
                    if !allowed { interrupted = true }
                    return allowed
                }
                let restored = try await controller.restoreSelections(savedSelections, configuration: output,
                    shouldContinue: authorization)
                stage = "复查身份并撤销失效出口"
                guard try await retainTargetOrBlock(target, blocked: blocked!, forceBlock: !restored || interrupted) else { continue }
                stage = "核对运行配置"
                let verified = try await controller.verify(configuration: output, shouldContinue: authorization)
                stage = "复查身份并撤销失效出口"
                guard try await retainTargetOrBlock(target, blocked: blocked!, forceBlock: interrupted) else { continue }
                guard verified else { throw MihomoClientError.malformed }
                failureDescription = nil; failedSnapshot = nil
                configuration = output; applied = target; state = .active
            } catch {
                let detail = (error is MihomoClientError || error is RoutingConfigurationError || error is ClashBootstrapError || error is ManagedDNSError) ? error.localizedDescription : "本地程序或控制请求失败。"
                failureDescription = stage + "：" + detail
                configuration = nil; applied = nil; failedSnapshot = snapshot()
                // Only an initial API failure is automatically retried. An invalid base still needs
                // a changed identity/configuration or explicit retry, not a reload on every audit.
                awaitingInitialController = !controllerChecked && lastBlock == nil
                do {
                    guard try await controller.tunnelEnabled() else { state = .paused; continue }
                    guard let blocked else { throw MihomoClientError.malformed }
                    try await controller.apply(configuration: blocked)
                    try await controller.closeConnections()
                    guard try await controller.verify(configuration: blocked) else { throw MihomoClientError.malformed }
                    state = .blockedAfterFailure
                } catch { state = .unprotected }
                // No busy retry loop when the API or subscription is invalid.
                requested = false; forceRequested = false
            }
        }
        if requested {
            // Network flapping must not leave the last attempted wireless mode active.
            applied = nil; configuration = nil
            do {
                guard try await controller.tunnelEnabled() else {
                    state = .paused; requested = false; forceRequested = false; return
                }
                let base = try await loadBase()
                let blocked = try RoutingConfiguration.make(baseJSON: base, decision: .init(mode: .blocked, proxyInterface: nil, directInterface: nil))
                guard try await retainTunnel() else { return }
                lastBlock = blocked
                try await controller.apply(configuration: blocked); try await controller.closeConnections()
                guard try await controller.verify(configuration: blocked) else { throw MihomoClientError.malformed }
                state = .blockedAfterFailure
            } catch { state = .unprotected }
            failedSnapshot = snapshot()
            requested = false; forceRequested = false
        }
    }

    private func retainTargetOrBlock(_ target: RoutingSnapshot, blocked: Data, forceBlock: Bool = false) async throws -> Bool {
        guard try await retainTunnel() else { return false }
        guard forceBlock || snapshot() != target else { return true }
        // Revoke the just-opened target before another base read or selection query can delay blocking.
        applied = nil; configuration = nil; state = .switching
        try await controller.apply(configuration: blocked)
        try await controller.closeConnections()
        try await controller.flushDNS()
        guard try await controller.verify(configuration: blocked) else { throw MihomoClientError.malformed }
        requested = true
        return false
    }

    private func retainTunnel() async throws -> Bool {
        guard try await controller.tunnelEnabled() else {
            configuration = nil; applied = nil; awaitingInitialController = false
            failureDescription = nil; state = .paused
            requested = false; forceRequested = false
            return false
        }
        return true
    }

    public func audit() async {
        guard !running else { return }
        if state == .unprotected && awaitingInitialController && lastBlock == nil {
            // Probe without reading subscriptions or writing a configuration while the core is down.
            running = true
            do {
                let enabled = try await controller.tunnelEnabled()
                awaitingInitialController = false
                if !enabled { state = .paused }
                running = false
                if enabled { await reconcile(force: true) }
            } catch {
                running = false
                // Keep the recovery probe armed; unconfirmed initial state remains unprotected.
            }
            return
        }
        if (state == .blockedAfterFailure || state == .unprotected), let blocked = lastBlock {
            // A failed target remains paused, but its protective block must not go unaudited.
            // Keep the same lock as an active audit and drain requests received while awaiting the API.
            running = true
            await auditFailureBlock(blocked)
            running = false
            if state != .paused && (requested || snapshot() != failedSnapshot) {
                await reconcile(force: forceRequested)
            }
            return
        }
        guard let configuration else { return }
        // Verification owns the transaction lock too; otherwise an old audit could overwrite a new decision.
        running = true
        let audited = applied
        var interrupted = false
        let authorization: @MainActor () async throws -> Bool = {
            let allowed = try await self.retainTunnel() && self.snapshot() == audited
            if !allowed { interrupted = true }
            return allowed
        }
        let verified = (try? await controller.verify(configuration: configuration, shouldContinue: authorization)) == true
        if state == .paused { running = false; return }
        if verified && !interrupted && !requested && snapshot() == audited,
           let selections = try? await controller.selections() { savedSelections.merge(selections) { _, new in new } }
        if let audited, let blocked = lastBlock,
           !verified || interrupted || snapshot() != audited {
            do {
                // Revoke under the audit lock, before another transaction can enter loadBase.
                _ = try await retainTargetOrBlock(audited, blocked: blocked, forceBlock: true)
            } catch {
                self.configuration = nil; applied = nil; failedSnapshot = snapshot()
                failureDescription = "审计撤销失效出口：" + (error is MihomoClientError ? error.localizedDescription : "本地程序或控制请求失败。")
                state = .unprotected
                requested = false; forceRequested = false
                running = false
                return
            }
        }
        running = false
        if state == .paused { return }
        if !verified || requested || snapshot() != applied { await reconcile(force: !verified || forceRequested) }
    }

    private func auditFailureBlock(_ blocked: Data) async {
        do {
            guard try await controller.tunnelEnabled() else { state = .paused; return }
            // After an unconfirmed repair, matching rules alone do not prove old connections were closed.
            let verified = state == .blockedAfterFailure ? try await controller.verify(configuration: blocked) : false
            if !verified {
                // Verification yields; a user may have disabled TUN while it was in flight.
                guard try await controller.tunnelEnabled() else { state = .paused; return }
                state = .switching
                try await controller.apply(configuration: blocked)
                try await controller.closeConnections()
                guard try await controller.verify(configuration: blocked) else { throw MihomoClientError.malformed }
            }
            if state != .blockedAfterFailure { state = .blockedAfterFailure }
        } catch {
            // The cached block describes intent; only a successful live check confirms protection.
            let detail = error is MihomoClientError ? error.localizedDescription : "本地程序或控制请求失败。"
            failureDescription = "维护阻断配置：" + detail
            state = .unprotected
        }
    }
}
