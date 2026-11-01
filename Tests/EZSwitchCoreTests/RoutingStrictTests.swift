import XCTest
@testable import EZSwitchCore

final class RoutingStrictTests: XCTestCase {
    private let campus = RegisteredHotspot(ssid: Data("Campus".utf8), security: 7, displayName: "Campus")

    func testStrictCampusTakesPriorityAndDoesNotBecomeDirectOnUsbLoss() {
        var network = RoutingNetwork(usbInterface: "en5", wifiInterface: "en0", ssid: campus.ssid,
                                     security: 7, registrations: [campus])
        network.strictRegistrations = [campus]
        XCTAssertTrue(RoutingPolicy.decide(network).strictProtection)
        network.usbInterface = nil
        let decision = RoutingPolicy.decide(network)
        XCTAssertTrue(decision.strictProtection)
        XCTAssertNil(decision.proxyInterface)
        // A changed security type must not turn an enrolled campus SSID into unprotected Wi-Fi.
        network.security = 0
        XCTAssertTrue(RoutingPolicy.decide(network).strictProtection)
        XCTAssertTrue(RoutingPolicy.sessionDecision(network, active: false).strictProtection)
        XCTAssertEqual(RoutingPolicy.sessionDecision(network, active: false, suspended: true).mode, .blocked)
    }

    func testUnreadableWirelessIdentityNeverAuthorizesCampusWhenStrictRegistrationsExist() {
        var network = RoutingNetwork(wifiInterface: "en0")
        network.strictRegistrations = [campus]
        XCTAssertEqual(RoutingPolicy.decide(network).mode, .blocked)
        XCTAssertEqual(RoutingPolicy.sessionDecision(network, active: false).mode, .blocked)
        network.usbInterface = "en5"
        let decision = RoutingPolicy.decide(network)
        XCTAssertEqual(decision.directInterface, "en5")
        XCTAssertEqual(decision.proxyInterface, "en5")
    }

    func testStrictOfflineWhitelistAndDnsCannotFallBackForUnknownDomains() throws {
        let config = try output(usb: nil)
        XCTAssertEqual(config["mode"] as? String, "rule")
        let rules = try XCTUnwrap(config["rules"] as? [String])
        XCTAssertEqual(target("www.bilibili.com", rules), "EZ-Campus")
        XCTAssertEqual(target("chatgpt.com", rules), "REJECT")
        XCTAssertEqual(target("api.github.com", rules), "REJECT")
        XCTAssertEqual(target("unknown.example.cn", rules), "REJECT")
        XCTAssertEqual(target("mask.icloud.com", rules), "REJECT")
        XCTAssertFalse(rules.contains("DOMAIN-SUFFIX,cn,EZ-Campus"))
        XCTAssertFalse(rules.contains("DOMAIN-KEYWORD,officecdn,EZ-Campus"))
        let dns = try XCTUnwrap(config["dns"] as? [String: Any])
        XCTAssertEqual(dns["nameserver"] as? [String], ["223.5.5.5#REJECT"])
        let policy = try XCTUnwrap(dns["nameserver-policy"] as? [String: [String]])
        XCTAssertEqual(policy["campus.example"], ["192.0.2.53#EZ-Campus"])
        XCTAssertEqual(policy["+.campus.example"], ["192.0.2.53#EZ-Campus"])
        XCTAssertEqual(target("jw.campus.example", rules), "EZ-Campus")
        XCTAssertTrue(rules.contains("DOMAIN-SUFFIX,campus.example,EZ-Campus"))
        XCTAssertNil(policy["+.cn"])
        XCTAssertNil(policy["chatgpt.com"])
        XCTAssertEqual((config["proxy-groups"] as? [[String: Any]])?.count, 0)
    }

    func testStrictAppleToggleOverridesDirectSubscriptionAndDoesNotChangeDomesticPolicy() throws {
        for usb in ["en5", nil] as [String?] {
            let direct = try output(usb: usb)
            let proxy = try output(usb: usb, appleViaProxy: true)
            let directRules = try XCTUnwrap(direct["rules"] as? [String])
            let proxyRules = try XCTUnwrap(proxy["rules"] as? [String])
            XCTAssertEqual(target("gateway.icloud.com.cn", directRules), "EZ-Campus")
            XCTAssertEqual(target("bag.itunes.apple.com", directRules), "EZ-Campus")
            XCTAssertEqual(target("bag.itunes.apple.com", proxyRules), usb == nil ? "REJECT" : "Proxy")
            XCTAssertEqual(target("gateway.icloud.com.cn", proxyRules), usb == nil ? "REJECT" : "Proxy")
            XCTAssertEqual(target("www.bilibili.com", proxyRules), "EZ-Campus")
            XCTAssertEqual(target("mask.icloud.com", directRules), usb == nil ? "REJECT" : "Proxy")
            let dns = proxy["dns"] as! [String: Any]
            let policy = dns["nameserver-policy"] as! [String: [String]]
            XCTAssertNil(policy["gateway.icloud.com.cn"])
        }
    }

    func testStrictRulesPreserveRejectAndProxyExceptionsAndIgnoreNewSubscriptionDirectItems() throws {
        let config = try output(usb: "en5")
        let rules = config["rules"] as! [String]
        XCTAssertEqual(target("denied.bilibili.com", rules), "REJECT")
        XCTAssertEqual(target("special.bilibili.com", rules), "Proxy")
        XCTAssertEqual(target("new-subscription.example", rules), "Proxy")
        XCTAssertEqual(target("www.bilibili.com.evil.example", rules), "Proxy")
        XCTAssertEqual(target("chatgpt.com", rules), "Proxy")
        XCTAssertEqual(target("unknown.example.cn", rules), "Proxy")
        let nodes = config["proxies"] as! [[String: Any]]
        XCTAssertEqual(nodes.first(where: { $0["name"] as? String == "Node" })?["interface-name"] as? String, "en5")
    }

    func testNormalSessionExitKeepsItsOriginalPolicyAndInvalidNetworksStayBlocked() {
        XCTAssertEqual(RoutingPolicy.sessionDecision(.init(usbInterface: "en5", wifiInterface: "en0"), active: false),
            .init(mode: .usbHotspot, proxyInterface: "en5", directInterface: "en5"))
        XCTAssertEqual(RoutingPolicy.sessionDecision(.init(wifiInterface: "en0"), active: false),
            .init(mode: .directOnly, proxyInterface: nil, directInterface: "en0"))
        XCTAssertEqual(RoutingPolicy.sessionDecision(.init(usbInterface: "utun3"), active: false).mode, .blocked)
    }

    func testStrictOnlineDnsKeepsPublicQueriesOnUsbAndOfflineDnsUsesFiniteExactNames() throws {
        let online = try output(usb: "en5")
        let offline = try output(usb: nil)
        let onlineDNS = online["dns"] as! [String: Any]
        let offlineDNS = offline["dns"] as! [String: Any]
        XCTAssertEqual(onlineDNS["nameserver"] as? [String], ["223.5.5.5#EZ-USB-DNS", "119.29.29.29#EZ-USB-DNS"])
        let onlinePolicy = onlineDNS["nameserver-policy"] as! [String: [String]]
        let offlinePolicy = offlineDNS["nameserver-policy"] as! [String: [String]]
        XCTAssertNil(onlinePolicy["www.bilibili.com"])
        XCTAssertEqual(offlinePolicy["www.bilibili.com"], ["223.5.5.5#EZ-Campus", "119.29.29.29#EZ-Campus"])
        // Only the school zone may use a wildcard resolver; every other name stays finite.
        XCTAssertTrue(offlinePolicy.keys.allSatisfy {
            $0 == "+.campus.example" || (!$0.contains("*") && !$0.hasPrefix("+."))
        })
        XCTAssertNil(offlinePolicy["mask.icloud.com"])
        if let directory = ProcessInfo.processInfo.environment["EZROUTE_STRICT_FIXTURES_DIR"] {
            let path = URL(fileURLWithPath: directory, isDirectory: true)
            try FileManager.default.createDirectory(at: path, withIntermediateDirectories: true)
            for (name, config) in [("online", online), ("offline", offline), ("apple-proxy", try output(usb: "en5", appleViaProxy: true))] {
                try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes])
                    .write(to: path.appendingPathComponent(name + ".json"))
            }
        }
    }


    func testStrictWhitelistInvariants() {
        let suffixes = RoutingStrictDomains.suffixes
        let exact = RoutingStrictDomains.exact
        let apple = RoutingStrictDomains.apple
        XCTAssertFalse(suffixes.isEmpty)
        XCTAssertFalse(exact.isEmpty)
        XCTAssertFalse(apple.isEmpty)
        XCTAssertEqual(Set(suffixes).count, suffixes.count, "后缀重复")
        XCTAssertEqual(Set(exact).count, exact.count, "精确主机重复")
        XCTAssertEqual(Set(apple).count, apple.count, "Apple 主机重复")
        XCTAssertTrue(exact.allSatisfy { host in
            !suffixes.contains { host == $0 || host.hasSuffix("." + $0) }
        }, "精确主机已被后缀覆盖")
        XCTAssertTrue(Set(exact).isDisjoint(with: Set(apple)), "Apple 与非 Apple 重叠")
        XCTAssertTrue(suffixes.contains("campus.example"), "校内域名必须整域放行")
        XCTAssertFalse(suffixes.contains(where: { $0.split(separator: ".").count < 2 }), "裸顶级域不得放行")

        let dns = RoutingStrictDomains.knownDNSHosts
        XCTAssertEqual(Set(dns).count, dns.count, "解析主机重复")
        XCTAssertTrue(dns.allSatisfy { host in
            exact.contains(host) || suffixes.contains { host == $0 || host.hasSuffix("." + $0) }
        }, "解析主机没有对应的许可条目")
        XCTAssertTrue(suffixes.allSatisfy { dns.contains($0) && dns.contains("www." + $0) })

        let allowed = Set(exact)
        XCTAssertTrue(RoutingStrictDomains.excludedHosts.allSatisfy { !allowed.contains($0) })
        XCTAssertFalse(RoutingStrictDomains.excludedSuffixes.contains("apple.com"))
    }

    func testTelemetryAndForeignSensitiveHostsNeverUseCampus() throws {
        for usb in ["en5", nil] as [String?] {
            let config = try output(usb: usb)
            let rules = config["rules"] as! [String]
            let fallback = usb == nil ? "REJECT" : "Proxy"
            XCTAssertEqual(target("data.bilibili.com", rules), fallback)
            XCTAssertEqual(target("hm.baidu.com", rules), fallback)
            XCTAssertEqual(target("www.youtube.com", rules), fallback)
            XCTAssertEqual(target("www.bilibili.com", rules), "EZ-Campus")
            // Apple keeps its existing switch behaviour; telemetry exclusions do not apply to it.
            XCTAssertEqual(target("metrics.icloud.com", rules), "EZ-Campus")
        }
    }


    func testStrictDisablesPureIPSpoofingAndStripsTunBypass() throws {
        let config = try output(usb: "en5", tunExtras: [
            "route-exclude-address": ["10.0.0.0/8"], "include-uid": [501], "exclude-uid": [0],
            "include-package": ["com.example"], "route-exclude-address-set": "bypass",
        ])
        let sniffer = try XCTUnwrap(config["sniffer"] as? [String: Any])
        XCTAssertEqual(sniffer["parse-pure-ip"] as? Bool, false)
        let tun = try XCTUnwrap(config["tun"] as? [String: Any])
        for key in ["route-exclude-address", "route-exclude-address-set", "include-uid",
                    "include-uid-range", "exclude-uid", "exclude-uid-range", "include-package",
                    "exclude-package", "include-android-user"] {
            XCTAssertNil(tun[key], key)
        }
        XCTAssertEqual(tun["enable"] as? Bool, true)
    }

    func testExclusionsPrecedeAppleAllowlist() throws {
        let rules = try XCTUnwrap((try output(usb: "en5"))["rules"] as? [String])
        let telemetry = try XCTUnwrap(rules.firstIndex(of: "DOMAIN,data.bilibili.com,Proxy"))
        let apple = try XCTUnwrap(rules.firstIndex(of: "DOMAIN,metrics.icloud.com,EZ-Campus"))
        XCTAssertLessThan(telemetry, apple)
    }

    func testCorruptedStrictDataFailsClosed() {
        var network = RoutingNetwork(usbInterface: "en5", wifiInterface: "en0", ssid: campus.ssid,
                                    security: 7, registrations: [], strictDataUnreadable: true)
        network.strictRegistrations = [campus]
        let withUSB = RoutingPolicy.decide(network)
        XCTAssertEqual(withUSB.mode, .usbHotspot)
        XCTAssertFalse(withUSB.strictProtection)
        network.usbInterface = nil
        XCTAssertEqual(RoutingPolicy.decide(network).mode, .blocked)
        let decision = RoutingPolicy.sessionDecision(network, active: false)
        XCTAssertEqual(decision.mode, .blocked)
        XCTAssertNil(decision.directInterface)
    }

    private func output(usb: String?, appleViaProxy: Bool = false,
                        tunExtras: [String: Any] = [:]) throws -> [String: Any] {
        let tun = ["enable": true].merging(tunExtras) { _, new in new }
        let base: [String: Any] = ["mode": "rule", "interface-name": "en5", "tun": tun,
            "proxies": [["name": "Node", "type": "trojan", "server": "example.invalid", "port": 443,
                         "password": "fixture", "interface-name": "en5"],
                        ["name": "EZ-Campus", "type": "direct", "interface-name": "en0"],
                        ["name": "EZ-USB-DNS", "type": "direct", "interface-name": "en5"]],
            "proxy-groups": [["name": "Proxy", "type": "select", "proxies": ["Node"]]],
            "rules": ["DOMAIN,denied.bilibili.com,REJECT", "DOMAIN,special.bilibili.com,Proxy",
                      "DOMAIN-SUFFIX,apple.com,Proxy",
                      "DOMAIN-SUFFIX,cn,EZ-Campus", "DOMAIN-SUFFIX,icloud.com.cn,EZ-Campus",
                      "DOMAIN-SUFFIX,bilibili.com,EZ-Campus", "DOMAIN-KEYWORD,officecdn,EZ-Campus",
                      "DOMAIN,new-subscription.example,EZ-Campus", "MATCH,Proxy"]]
        let decision = RoutingDecision(mode: usb == nil ? .directOnly : .split,
            proxyInterface: usb, directInterface: "en0", strictProtection: true)
        return try JSONSerialization.jsonObject(with: RoutingConfiguration.make(
            baseJSON: JSONSerialization.data(withJSONObject: base), decision: decision,
            appleViaProxy: appleViaProxy)) as! [String: Any]
    }

    private func target(_ host: String, _ rules: [String]) -> String? {
        for rule in rules {
            let f = rule.components(separatedBy: ",")
            if f[0] == "MATCH" { return f[1] }
            if f[0] == "DOMAIN" && host == f[1] || f[0] == "DOMAIN-SUFFIX" && (host == f[1] || host.hasSuffix("." + f[1])) {
                return f[2]
            }
        }
        return nil
    }
}
