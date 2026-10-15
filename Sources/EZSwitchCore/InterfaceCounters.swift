import Foundation
import Darwin

/// Cumulative per-interface byte counters, read in-process without privilege and
/// without a child process.
public protocol InterfaceCounterReading: Sendable {
    func counters() -> [String: TrafficDelta]
}

public struct SystemInterfaceCounters: InterfaceCounterReading {
    public init() {}

    /// `getifaddrs` must not be used here. Its `AF_LINK` payload is `if_data`, whose
    /// `ifi_ibytes`/`ifi_obytes` are 32-bit and therefore wrap every 4 GiB; the recorder
    /// would read each wrap as a counter reset and silently drop that minute. The route
    /// socket's `NET_RT_IFLIST2` messages carry `if_data64` instead.
    public func counters() -> [String: TrafficDelta] {
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0]
        var length = 0
        guard sysctl(&mib, 6, nil, &length, nil, 0) == 0, length > 0 else { return [:] }
        var buffer = [UInt8](repeating: 0, count: length)
        guard sysctl(&mib, 6, &buffer, &length, nil, 0) == 0 else { return [:] }
        return Self.parse(buffer, length: length)
    }

    /// 遍历 `NET_RT_IFLIST2` 报文流。从 `counters()` 里拆出来,是为了让「字段是 64 位」
    /// 这件事能被一条不依赖实时流量的测试钉住。
    static func parse(_ buffer: [UInt8], length: Int) -> [String: TrafficDelta] {
        var result: [String: TrafficDelta] = [:]
        var offset = 0
        buffer.withUnsafeBytes { raw in
            while offset + MemoryLayout<if_msghdr>.size <= length {
                let header = raw.loadUnaligned(fromByteOffset: offset, as: if_msghdr.self)
                let messageLength = Int(header.ifm_msglen)
                guard messageLength > 0, offset + messageLength <= length else { break }
                if header.ifm_type == RTM_IFINFO2 {
                    let info = raw.loadUnaligned(fromByteOffset: offset, as: if_msghdr2.self)
                    var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
                    if if_indextoname(UInt32(info.ifm_index), &name) != nil {
                        // `String(cString:)` 在本 SDK 已废弃;直接解码 NUL 结尾缓冲,避免新增警告。
                        let interface = String(decoding: name.prefix { $0 != 0 }
                            .map { UInt8(bitPattern: $0) }, as: UTF8.self)
                        if RoutingPolicy.validInterface(interface) {
                            result[interface] = .init(received: info.ifm_data.ifi_ibytes,
                                                      sent: info.ifm_data.ifi_obytes)
                        }
                    }
                }
                offset += messageLength
            }
        }
        return result
    }
}
