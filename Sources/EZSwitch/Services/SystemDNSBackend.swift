import Foundation
import Security
import SystemConfiguration
import EZSwitchCore

/// Uses network-service UUIDs, never localized service names or shell commands.
@MainActor final class SystemDNSBackend: ManagedDNSBackend {
    private let authorization = NetworkDNSAuthorization()
    func allowAuthorizationRetry() { authorization.denied = false }
    func service(for interface: String) throws -> DNSService {
        let preferences = try preferences()
        let matches = (SCNetworkServiceCopyAll(preferences) as? [SCNetworkService] ?? []).filter {
            SCNetworkServiceGetEnabled($0) && bsdName($0) == interface
        }
        guard matches.count == 1, let service = matches.first else { throw ManagedDNSError.serviceUnavailable }
        return try read(service, in: preferences)
    }
    func service(id: String) throws -> DNSService? {
        let preferences = try preferences()
        guard let service = SCNetworkServiceCopy(preferences, id as CFString) else { return nil }
        return try read(service, in: preferences)
    }
    func replace(_ service: DNSService, with configuration: Data?) throws {
        try authorization.acquire()
        let preferences = try preferences(authorized: true)
        guard SCPreferencesLock(preferences, false) else { throw ManagedDNSError.writeFailed }
        defer { SCPreferencesUnlock(preferences) }
        // Re-read after authorization and taking the lock; a system dialog may
        // remain open while the user changes network settings elsewhere.
        guard let live = SCNetworkServiceCopy(preferences, service.id as CFString), bsdName(live) == service.interface else {
            throw ManagedDNSError.serviceUnavailable
        }
        let current = try read(live, in: preferences)
        guard ManagedDNS.equivalent(current.configuration, service.configuration) else { throw ManagedDNSError.changedExternally }
        let path = "/NetworkServices/\(service.id)/DNS" as CFString
        if let configuration {
            guard let value = try PropertyListSerialization.propertyList(from: configuration, format: nil) as? [String: Any],
                  SCPreferencesPathSetValue(preferences, path, value as CFDictionary) else { throw ManagedDNSError.writeFailed }
        } else if SCPreferencesPathGetValue(preferences, path) != nil {
            guard SCPreferencesPathRemoveValue(preferences, path) else { throw ManagedDNSError.writeFailed }
        }
        guard SCPreferencesCommitChanges(preferences) else { throw ManagedDNSError.writeFailed }
        guard SCPreferencesApplyChanges(preferences) else {
            // A commit can succeed while notification fails. Keep the caller's
            // recovery journal; the next restore re-applies the original settings.
            throw ManagedDNSError.writeFailed
        }
    }
    private func preferences(authorized: Bool = false) throws -> SCPreferences {
        let value = authorized
            ? SCPreferencesCreateWithAuthorization(nil, "EZ Route USB DNS" as CFString, nil, authorization.reference)
            : SCPreferencesCreate(nil, "EZ Route USB DNS" as CFString, nil)
        guard let value else { throw ManagedDNSError.serviceUnavailable }
        return value
    }
    private func bsdName(_ service: SCNetworkService) -> String? {
        guard let interface = SCNetworkServiceGetInterface(service),
              let name = SCNetworkInterfaceGetBSDName(interface) else { return nil }
        return name as String
    }
    private func read(_ service: SCNetworkService, in preferences: SCPreferences) throws -> DNSService {
        guard let identifier = SCNetworkServiceGetServiceID(service), let interface = bsdName(service) else {
            throw ManagedDNSError.serviceUnavailable
        }
        let id = identifier as String
        guard UUID(uuidString: id) != nil else { throw ManagedDNSError.serviceUnavailable }
        let value = SCPreferencesPathGetValue(preferences, "/NetworkServices/\(id)/DNS" as CFString)
        let data = try value.map { try PropertyListSerialization.data(fromPropertyList: $0, format: .binary, options: 0) }
        return .init(id: id, interface: interface, configuration: data)
    }
}

private final class NetworkDNSAuthorization {
    var reference: AuthorizationRef?
    var denied = false
    func acquire() throws {
        guard !denied else { throw ManagedDNSError.authorizationDenied }
        if reference == nil {
            guard AuthorizationCreate(nil, nil, [], &reference) == errAuthorizationSuccess else {
                denied = true; throw ManagedDNSError.authorizationDenied
            }
        }
        guard let reference else { throw ManagedDNSError.writeFailed }
        let status = "system.preferences.network".withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { pointer in
                var rights = AuthorizationRights(count: 1, items: pointer)
                return AuthorizationCopyRights(reference, &rights, nil, [.interactionAllowed, .extendRights, .preAuthorize], nil)
            }
        }
        guard status == errAuthorizationSuccess else {
            denied = true; throw ManagedDNSError.authorizationDenied
        }
    }
    deinit { if let reference { AuthorizationFree(reference, []) } }
}
