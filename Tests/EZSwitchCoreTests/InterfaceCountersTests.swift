import XCTest
import Darwin
@testable import EZSwitchCore

final class InterfaceCountersTests: XCTestCase {
    func testOnlyPhysicalEthernetInterfacesAreReported() {
        let counters = SystemInterfaceCounters().counters()
        XCTAssertFalse(counters.isEmpty)
        for name in counters.keys {
            XCTAssertNotNil(name.range(of: "^en[0-9]+$", options: .regularExpression), name)
        }
    }

    func testCountersAreReadableAndStableAcrossCalls() {
        let first = SystemInterfaceCounters().counters()
        let second = SystemInterfaceCounters().counters()
        XCTAssertEqual(first.keys.sorted(), second.keys.sorted())
    }

    func testACounterLargerThanThirtyTwoBitsIsNotTruncated() throws {
        // 另外两个测试都在读活系统,无法钉住「64 位」这件事本身:计数器要超过 4 GiB 才会
        // 暴露 32 位截断。这里直接喂一条合成的 RTM_IFINFO2 记录。
        let live = SystemInterfaceCounters().counters()
        guard let name = live.keys.sorted().first else { throw XCTSkip("no enN interface") }
        let index = if_nametoindex(name)
        guard index != 0 else { throw XCTSkip("no interface index") }
        let huge: UInt64 = 4_294_967_296 + 1_234   // 若按 32 位读会变成 1234
        var message = if_msghdr2()
        message.ifm_msglen = UInt16(MemoryLayout<if_msghdr2>.size)
        message.ifm_type = UInt8(RTM_IFINFO2)
        message.ifm_index = UInt16(index)
        message.ifm_data.ifi_ibytes = huge
        message.ifm_data.ifi_obytes = huge + 1
        let buffer = withUnsafeBytes(of: message) { Array($0) }
        let parsed = SystemInterfaceCounters.parse(buffer, length: buffer.count)
        XCTAssertEqual(parsed[name]?.received, huge)
        XCTAssertEqual(parsed[name]?.sent, huge + 1)
    }
}
