import XCTest
@testable import EZSwitchCore

final class RoutingDirectDomainsTests: XCTestCase {
    private let campus = "EZ-Campus"

    func testBuiltInListsAreSane() {
        let domains = RoutingDirectDomains.domains
        XCTAssertFalse(domains.isEmpty)
        XCTAssertEqual(domains.count, Set(domains).count, "清单里有重复项")
        XCTAssertFalse(RoutingDirectDomains.apple.isEmpty)
        for domain in domains {
            XCTAssertFalse(domain.isEmpty)
            XCTAssertEqual(domain, domain.lowercased())
            XCTAssertFalse(domain.contains("/"), "不应带 scheme 或路径: \(domain)")
            XCTAssertFalse(domain.hasPrefix("."), "不应以点开头: \(domain)")
        }
    }

    func testDomesticListCoversTheReportedCases() {
        let domains = Set(RoutingDirectDomains.domestic)
        for expected in ["xiaohongshu.com", "xhscdn.com", "deepseek.com", "cn.bing.com",
                         "weixinbridge.com", "hypergryph.com", "kuaishou.com", "douyin.com"] {
            XCTAssertTrue(domains.contains(expected), "缺少 \(expected)")
        }
    }

    func testAppleListCoversEveryAppleRuleTheSubscriptionProxies() {
        let domains = Set(RoutingDirectDomains.apple)
        // 订阅把 apple.com / mzstatic.com / icloud.com / me.com 等指向苹果服务代理组。
        for expected in ["apple.com", "apple.co", "apple-cloudkit.com", "cdn-apple.com",
                         "icloud.com", "icloud-content.com", "me.com", "mzstatic.com",
                         "www-cdn.icloud.com.akadns.net"] {
            XCTAssertTrue(domains.contains(expected), "缺少 \(expected)")
        }
    }

    func testBuiltInRulesPrependAndKeepTheCatchAllLast() {
        let existing = ["DOMAIN-SUFFIX,qq.com,EZ-Campus", "MATCH,⚓️其他流量"]
        let result = RoutingDirectDomains.prepending(to: existing, campus: campus)
        XCTAssertEqual(result.last, "MATCH,⚓️其他流量")
        XCTAssertEqual(Array(result.suffix(2)), existing)
        XCTAssertEqual(result.count, RoutingDirectDomains.domains.count + existing.count)
        XCTAssertEqual(result.first, "DOMAIN-SUFFIX,\(RoutingDirectDomains.domains[0]),\(campus)")
    }

    func testEveryInjectedRuleTargetsTheCampusOutlet() {
        let result = RoutingDirectDomains.prepending(to: ["MATCH,⚓️其他流量"], campus: campus)
        for rule in result.dropLast() {
            let fields = rule.components(separatedBy: ",")
            XCTAssertEqual(fields.count, 3)
            XCTAssertEqual(fields[0], "DOMAIN-SUFFIX")
            XCTAssertEqual(fields[2], campus)
        }
    }

    func testDomainAlreadyDirectInTheSubscriptionIsNotDuplicated() {
        let existing = ["DOMAIN-SUFFIX,deepseek.com,EZ-Campus", "MATCH,⚓️其他流量"]
        let result = RoutingDirectDomains.prepending(to: existing, campus: campus)
        XCTAssertEqual(result.count, RoutingDirectDomains.domains.count + existing.count - 1)
        XCTAssertEqual(result.filter { $0 == "DOMAIN-SUFFIX,deepseek.com,EZ-Campus" }.count, 1)
    }

    func testDomainProxiedByTheSubscriptionIsStillOverridden() {
        // 订阅把某个域名指向了代理时,我们的规则更靠前,必须仍然生效。
        let existing = ["DOMAIN-SUFFIX,apple.com,🍎苹果服务", "MATCH,⚓️其他流量"]
        let result = RoutingDirectDomains.prepending(to: existing, campus: campus)
        XCTAssertEqual(result.filter { $0 == "DOMAIN-SUFFIX,apple.com,\(campus)" }.count, 1)
        XCTAssertTrue(result.firstIndex(of: "DOMAIN-SUFFIX,apple.com,\(campus)")!
                      < result.firstIndex(of: "DOMAIN-SUFFIX,apple.com,🍎苹果服务")!)
    }

    func testAppleGroupIsLeftToTheSubscriptionWhenTheSwitchIsOn() {
        let existing = ["DOMAIN-SUFFIX,apple.com,🍎苹果服务", "MATCH,⚓️其他流量"]
        let result = RoutingDirectDomains.prepending(to: existing, campus: campus, includeApple: false)
        XCTAssertFalse(result.contains { $0.hasPrefix("DOMAIN-SUFFIX,apple.com,") && $0.hasSuffix(campus) },
                       "开启开关后苹果域名不能再被我们改成直连")
        XCTAssertEqual(result.count, RoutingDirectDomains.domestic.count + existing.count)
        // 国内清单不受开关影响。
        XCTAssertTrue(result.contains("DOMAIN-SUFFIX,xiaohongshu.com,\(campus)"))
    }
}
