import Foundation

/// 设备选择沿用旧配置格式；解码时忽略已经停用的 SIM 标签与 Relay 字段。
public struct Configuration: Codable, Equatable, Sendable {
    public var deviceID: String

    public init(deviceID: String = "") {
        self.deviceID = deviceID
    }
}

public struct Phone: Identifiable, Equatable, Sendable {
    public let id: String
    public let name: String
    public var interface: String?
    public var isPrimary: Bool
    public var networkInterfaces: [String]
    public init(id: String, name: String, interface: String? = nil, isPrimary: Bool = false) {
        self.id = id; self.name = name; self.interface = interface; self.isPrimary = isPrimary
        self.networkInterfaces = interface.map { [$0] } ?? []
    }
    public func attaching(interface: String, isPrimary: Bool) -> Phone {
        var updated = self
        if !updated.networkInterfaces.contains(interface) { updated.networkInterfaces.append(interface) }
        guard !self.isPrimary || isPrimary else { return updated }
        updated.interface = interface; updated.isPrimary = isPrimary
        return updated
    }
}

public struct DeviceSnapshot: Equatable, Sendable {
    public var devices: [Phone]
    public var error: String?
    public init(devices: [Phone], error: String? = nil) { self.devices = devices; self.error = error }
}
