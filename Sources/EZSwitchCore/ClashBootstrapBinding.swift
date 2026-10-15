import Foundation

public struct ClashBootstrapBinding: Equatable, Sendable {
    public let deviceID: String
    public let interface: String
    private init(deviceID: String, interface: String) {
        self.deviceID = deviceID; self.interface = interface
    }
    public static func resolve(deviceID: String, currentInterface: String?,
                               rememberedDeviceID: String?, rememberedInterface: String?) throws -> Self {
        guard !deviceID.isEmpty else { throw ClashBootstrapError.usbNotIdentified }
        let candidate: String?
        if let currentInterface { candidate = currentInterface }
        else { candidate = rememberedDeviceID == deviceID ? rememberedInterface : nil }
        guard let candidate, RoutingPolicy.validInterface(candidate) else {
            throw ClashBootstrapError.usbNotIdentified
        }
        return .init(deviceID: deviceID, interface: candidate)
    }
}

public struct ClashBootstrapSourceCache: Sendable {
    private var data: Data?
    private var stamp: String?
    private var binding: ClashBootstrapBinding?
    public init() {}
    public func lookup(stamp: String, binding: ClashBootstrapBinding) -> Data? {
        self.stamp == stamp && self.binding == binding ? data : nil
    }
    public mutating func store(_ data: Data, stamp: String, binding: ClashBootstrapBinding) {
        self.data = data; self.stamp = stamp; self.binding = binding
    }
}
