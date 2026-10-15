import Foundation
import EZSwitchCore

@MainActor final class RoutingControllerAdapter: RoutingController {
    private let client = MihomoClient()
    func tunnelEnabled() async throws -> Bool {
        let data = try await client.read(path: "/configs")
        let config = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        return (config?["tun"] as? [String: Any])?["enable"] as? Bool == true
    }
    func apply(configuration: Data) async throws { try await client.apply(configuration: configuration) }
    func closeConnections() async throws { try await client.closeConnections() }
    func flushDNS() async throws { try await client.flushDNS() }
    func selections() async throws -> [String: String] { try await client.selections() }
    func restoreSelections(_ selections: [String: String], configuration: Data,
                           shouldContinue: @escaping @MainActor () async throws -> Bool) async throws -> Bool {
        try await client.restoreSelections(selections, configuration: configuration,
            shouldContinue: { try await shouldContinue() })
    }
    func verify(configuration: Data, shouldContinue: @escaping @MainActor () async throws -> Bool) async throws -> Bool {
        try await client.verify(configuration: configuration, shouldContinue: { try await shouldContinue() })
    }
}
