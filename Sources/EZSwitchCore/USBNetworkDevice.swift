import Foundation

public enum USBNetworkDevice {
    public static func identify(vendorID: Int, productID: Int, name: String?,
                                serial: String?, registryPath: String?) -> Phone? {
        let label = name.flatMap { $0.isEmpty ? nil : $0 } ?? "USB 网络设备"
        // Keep existing iPhone selections and bootstrap bindings valid after upgrading.
        if vendorID == 0x05ac, label.hasPrefix("iPhone"), let serial, !serial.isEmpty {
            return Phone(id: serial, name: label)
        }
        let identity: String
        if let serial, !serial.isEmpty {
            identity = "serial:" + Data(serial.utf8).base64EncodedString()
        } else if let registryPath, !registryPath.isEmpty {
            // Serial-less adapters are remembered at their physical USB port.
            identity = "path:" + Data(registryPath.utf8).base64EncodedString()
        } else { return nil }
        return Phone(id: "usb:\(vendorID):\(productID):\(identity)", name: label)
    }
}
