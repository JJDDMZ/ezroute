import Foundation

/// Adds system DNS only after the routing transaction's live verification.
/// The coordinator still owns blocking, connection cleanup and stale snapshots.
@MainActor public final class DNSRoutingController: RoutingController {
    private let controller: any RoutingController
    private let dns: ManagedDNS
    private let runtime: @MainActor () async throws -> Data
    private let selectedUSB: @MainActor () -> String?
    public init(controller: any RoutingController, dns: ManagedDNS,
                runtime: @escaping @MainActor () async throws -> Data,
                selectedUSB: @escaping @MainActor () -> String?) {
        self.controller = controller; self.dns = dns; self.runtime = runtime; self.selectedUSB = selectedUSB
    }
    public func tunnelEnabled() async throws -> Bool {
        do {
            let enabled = try await controller.tunnelEnabled()
            if !enabled { try dns.restore() }
            return enabled
        } catch {
            try dns.restore()
            throw error
        }
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
        return try await shouldContinue()
    }
}
