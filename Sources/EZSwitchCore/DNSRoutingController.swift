import Foundation

/// Adds system DNS only after the routing transaction's live verification.
/// The coordinator still owns blocking, connection cleanup and stale snapshots.
@MainActor public final class DNSRoutingController: RoutingController {
    private let controller: any RoutingController
    private let dns: ManagedDNS
    private let runtime: @MainActor () async throws -> Data
    private let selectedUSB: @MainActor () -> String?
    private let protectedDNS: ManagedDNS?
    private let protectedInterface: @MainActor () -> String?
    private let protectedStateReadable: @MainActor () -> Bool
    public init(controller: any RoutingController, dns: ManagedDNS,
                runtime: @escaping @MainActor () async throws -> Data,
                selectedUSB: @escaping @MainActor () -> String?, protectedDNS: ManagedDNS? = nil,
                protectedInterface: @escaping @MainActor () -> String? = { nil },
                protectedStateReadable: @escaping @MainActor () -> Bool = { true }) {
        self.controller = controller; self.dns = dns; self.runtime = runtime; self.selectedUSB = selectedUSB
        self.protectedDNS = protectedDNS; self.protectedInterface = protectedInterface
        self.protectedStateReadable = protectedStateReadable
    }
    public func tunnelEnabled() async throws -> Bool {
        let enabled: Bool
        do {
            enabled = try await controller.tunnelEnabled()
        } catch {
            try dns.restore()
            // A controller timeout must not restore campus DHCP DNS behind the strict rules.
            // Release protected DNS only after an explicit TUN-off or non-protected verification.
            throw error
        }
        if !enabled {
            var failure: Error?
            do { try dns.restore() } catch { failure = error }
            do { try protectedDNS?.restore() } catch { if failure == nil { failure = error } }
            if let failure { throw failure }
        }
        return enabled
    }
    public func apply(configuration: Data) async throws { try await controller.apply(configuration: configuration) }
    public func closeConnections() async throws { try await controller.closeConnections() }
    public func flushDNS() async throws { try await controller.flushDNS() }
    public func selections() async throws -> [String: String] { try await controller.selections() }
    public func restoreSelections(_ selections: [String: String], configuration: Data,
                                 shouldContinue: @escaping @MainActor () async throws -> Bool) async throws -> Bool {
        try await controller.restoreSelections(selections, configuration: configuration, shouldContinue: shouldContinue)
    }
    public func verify(configuration: Data, shouldContinue: @escaping @MainActor () async throws -> Bool) async throws -> Bool {
        guard try await controller.verify(configuration: configuration, shouldContinue: shouldContinue),
              try await shouldContinue() else { return false }
        let config = try JSONSerialization.jsonObject(with: configuration) as? [String: Any]
        if let usb = selectedUSB(), config?["interface-name"] as? String == usb,
           config?["mode"] as? String == "rule",
           (config?["proxies"] as? [[String: Any]])?.contains(where: {
               !["direct", "reject"].contains(($0["type"] as? String ?? "").lowercased())
           }) == true {
            let address = try TunnelDNSAddress.resolve(await runtime())
            // Runtime read yields: authorization must be checked again before
            // touching a service that may no longer be the selected USB outlet.
            guard try await shouldContinue(), selectedUSB() == usb else { return false }
            try dns.synchronize(interface: usb, address: address)
        } else { try dns.restore() }
        if let protectedDNS {
            if let interface = protectedInterface(), config?["mode"] as? String == "rule" {
                let address = try TunnelDNSAddress.resolve(await runtime())
                guard try await shouldContinue(), protectedInterface() == interface else { return false }
                try protectedDNS.synchronize(interface: interface, address: address)
            } else if protectedStateReadable() { try protectedDNS.restore() }
        }
        return try await shouldContinue()
    }
}
