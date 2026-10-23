import Foundation

public struct DNSService {
    public let id: String
    public let interface: String
    public let configuration: Data?
    public init(id: String, interface: String, configuration: Data?) {
        self.id = id; self.interface = interface; self.configuration = configuration
    }
}

@MainActor public protocol ManagedDNSBackend: AnyObject {
    func service(for interface: String) throws -> DNSService
    func service(id: String) throws -> DNSService?
    /// Compare the entire configuration under a preferences lock before writing.
    func replace(_ service: DNSService, with configuration: Data?) throws
}

public enum ManagedDNSError: Error, LocalizedError {
    case serviceUnavailable, changedExternally, writeFailed, invalidTunnel, invalidJournal, authorizationDenied
    public var errorDescription: String? {
        switch self {
        case .serviceUnavailable: "无法唯一确定 USB 网络服务，未修改 DNS。"
        case .changedExternally: "DNS 已被其他程序或用户修改，已保留该设置。请检查网络 DNS 后重试。"
        case .writeFailed: "无法应用或恢复 USB DNS。请允许网络设置授权后重试。"
        case .invalidTunnel: "无法确定 Clash 的 TUN DNS 地址，未修改系统 DNS。"
        case .invalidJournal: "USB DNS 恢复记录无法读取，已保留记录和当前设置。"
        case .authorizationDenied: "未获得 USB DNS 网络设置授权。请允许授权后重新开启自动路由或点击检查路由。"
        }
    }
}

/// Owns only the selected USB service's DNS. The durable record precedes every
/// first write and survives a failed write or an abnormal application exit.
@MainActor public final class ManagedDNS {
    private struct Record: Codable {
        let version: Int
        let serviceID: String
        let interface: String
        let original: Data?
        let installed: Data
    }
    private let backend: any ManagedDNSBackend
    private let journalURL: URL
    public var hasPendingChanges: Bool { FileManager.default.fileExists(atPath: journalURL.path) }
    public init(backend: any ManagedDNSBackend, journalURL: URL) {
        self.backend = backend; self.journalURL = journalURL
    }
    public func synchronize(interface: String?, address: String?) throws {
        guard let interface, let address else { try restore(); return }
        guard RoutingPolicy.validInterface(interface), TunnelDNSAddress.validIPv4(address) else { throw ManagedDNSError.invalidTunnel }
        if let record = try load() {
            if record.interface != interface {
                try restore()
            } else {
                guard let current = try backend.service(id: record.serviceID), current.interface == interface else {
                    throw ManagedDNSError.serviceUnavailable
                }
                guard Self.equivalent(current.configuration, record.installed) else { throw ManagedDNSError.changedExternally }
                let wanted = try Self.replacingServers(in: record.original, with: address)
                if Self.equivalent(record.installed, wanted) { return }
                // A changed TUN subnet must preserve the very first original settings.
                try restore()
            }
        }
        let service = try backend.service(for: interface)
        let installed = try Self.replacingServers(in: service.configuration, with: address)
        let record = Record(version: 1, serviceID: service.id, interface: service.interface,
                            original: service.configuration, installed: installed)
        try save(record)
        do { try backend.replace(service, with: installed) }
        catch ManagedDNSError.authorizationDenied {
            // This error is reserved for a rejected authorization *before* any
            // system write. There is no DNS change to restore in this case.
            try FileManager.default.removeItem(at: journalURL)
            throw ManagedDNSError.authorizationDenied
        }
        guard let actual = try backend.service(id: service.id), actual.interface == service.interface,
              Self.equivalent(actual.configuration, installed) else { throw ManagedDNSError.writeFailed }
    }
    public func restore() throws {
        guard let record = try load() else { return }
        if let current = try backend.service(id: record.serviceID) {
            guard current.interface == record.interface else { throw ManagedDNSError.serviceUnavailable }
            if Self.equivalent(current.configuration, record.installed) || Self.equivalent(current.configuration, record.original) {
                // Commit and ApplyChanges are separate macOS operations. Even
                // when saved preferences are already original, re-apply them:
                // an earlier restore may have committed but failed to notify.
                try backend.replace(current, with: record.original)
                guard let actual = try backend.service(id: record.serviceID), actual.interface == record.interface,
                      Self.equivalent(actual.configuration, record.original) else { throw ManagedDNSError.writeFailed }
            }
            // An independent edit releases ownership without overwriting it.
        }
        try FileManager.default.removeItem(at: journalURL)
    }
    public static func equivalent(_ first: Data?, _ second: Data?) -> Bool {
        guard let first, let second else { return first == second }
        guard let a = try? PropertyListSerialization.propertyList(from: first, format: nil) as? NSDictionary,
              let b = try? PropertyListSerialization.propertyList(from: second, format: nil) as? NSDictionary else { return false }
        return a.isEqual(b)
    }
    private static func replacingServers(in data: Data?, with address: String) throws -> Data {
        var dictionary: [String: Any] = [:]
        if let data {
            guard let value = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
                throw ManagedDNSError.invalidJournal
            }
            dictionary = value
        }
        dictionary["ServerAddresses"] = [address]
        return try PropertyListSerialization.data(fromPropertyList: dictionary, format: .binary, options: 0)
    }
    private func load() throws -> Record? {
        guard hasPendingChanges else { return nil }
        do {
            let record = try JSONDecoder().decode(Record.self, from: Data(contentsOf: journalURL))
            guard record.version == 1, !record.serviceID.isEmpty, RoutingPolicy.validInterface(record.interface),
                  (try PropertyListSerialization.propertyList(from: record.installed, format: nil)) is [String: Any] else {
                throw ManagedDNSError.invalidJournal
            }
            return record
        } catch { throw ManagedDNSError.invalidJournal }
    }
    private func save(_ record: Record) throws {
        try FileManager.default.createDirectory(at: journalURL.deletingLastPathComponent(), withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        try JSONEncoder().encode(record).write(to: journalURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: journalURL.path)
    }
}

public enum TunnelDNSAddress {
    /// Mihomo v1.19.32 uses the next IPv4 address on its actual TUN subnet as DNS.
    /// Never derive this from the fake-IP pool or a hard-coded utun interface name.
    public static func resolve(_ runtime: Data) throws -> String {
        guard let root = try JSONSerialization.jsonObject(with: runtime) as? [String: Any],
              let tun = root["tun"] as? [String: Any], tun["enable"] as? Bool == true,
              tun["auto-route"] as? Bool == true,
              (tun["dns-hijack"] as? [String])?.contains("any:53") == true,
              let cidr = (tun["inet4-address"] as? [String])?.first else { throw ManagedDNSError.invalidTunnel }
        let parts = cidr.split(separator: "/")
        guard parts.count == 2, let prefix = Int(parts[1]), (1...30).contains(prefix),
              let ip = ipv4(String(parts[0])), ip < UInt32.max else { throw ManagedDNSError.invalidTunnel }
        let next = ip + 1
        let mask = UInt32.max << (32 - prefix)
        guard ip & mask == next & mask, next & ~mask != ~mask else { throw ManagedDNSError.invalidTunnel }
        return [24, 16, 8, 0].map { String((next >> $0) & 255) }.joined(separator: ".")
    }
    public static func validIPv4(_ address: String) -> Bool { ipv4(address) != nil }
    private static func ipv4(_ address: String) -> UInt32? {
        let parts = address.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var value: UInt32 = 0
        for part in parts {
            guard !part.isEmpty, part.allSatisfy({ $0.isASCII && $0.isNumber }), let byte = UInt8(part) else { return nil }
            value = (value << 8) | UInt32(byte)
        }
        return value
    }
}
