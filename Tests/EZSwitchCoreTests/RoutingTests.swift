import XCTest
@testable import EZSwitchCore

final class RoutingTests: XCTestCase {
    func testUnsupportedBootstrapCannotOpenAnyRoutingMode() throws {
        let blockedBase = try JSONSerialization.data(withJSONObject: [
            "interface-name": "en5", "tun": ["enable": true], "ez-switch-bootstrap-error": "unsupported-subscription",
            "proxies": [["name": "EZ-Campus", "type": "direct"], ["name": "EZ-USB-DNS", "type": "direct"]],
            "proxy-groups": [[String: Any]](), "rules": ["MATCH,REJECT"]])
        XCTAssertNoThrow(try RoutingConfiguration.make(baseJSON: blockedBase,
            decision: .init(mode: .blocked, proxyInterface: nil, directInterface: nil)))
        for decision in [RoutingDecision(mode: .usbHotspot, proxyInterface: "en5", directInterface: "en5"),
                         RoutingDecision(mode: .directOnly, proxyInterface: nil, directInterface: "en0")] {
            XCTAssertThrowsError(try RoutingConfiguration.make(baseJSON: blockedBase, decision: decision))
        }
    }
    let hotspot = RegisteredHotspot(ssid: Data("My Phone".utf8), security: 4, displayName: "My Phone")

    func testTunCannotLetSecondaryLinkLocalInterfaceHideUsbHotspot() {
        for first in ["en5", "en6"] {
            let second = first == "en5" ? "en6" : "en5"
            let phone = Phone(id: "phone", name: "iPhone").attaching(interface: first, isPrimary: false)
                .attaching(interface: second, isPrimary: false)
            let ready = phone.networkInterfaces.filter {
                RoutingPolicy.usableIPv4(active: true, addresses: $0 == "en5" ? ["172.20.10.5"] : ["169.254.3.4"])
            }
            XCTAssertEqual(ready, ["en5"])
        }
    }

    func testCampusAloneCannotAuthorizeProxy() {
        XCTAssertEqual(RoutingPolicy.decide(.init(wifiInterface: "en0")),
                       .init(mode: .directOnly, proxyInterface: nil, directInterface: "en0"))
    }

    func testRegisteredWifiUsesOnePhoneOutlet() {
        let network = RoutingNetwork(wifiInterface: "en0", ssid: hotspot.ssid,
                                     security: 4, registrations: [hotspot])
        XCTAssertEqual(RoutingPolicy.decide(network),
                       .init(mode: .wifiHotspot, proxyInterface: "en0", directInterface: "en0"))
    }

    func testUsbAloneAndRegisteredWifiPreferUsb() {
        for wifi in [nil, "en0"] {
            XCTAssertEqual(RoutingPolicy.decide(.init(usbInterface: "en5", wifiInterface: wifi,
                ssid: hotspot.ssid, security: 4, registrations: [hotspot])),
                .init(mode: .usbHotspot, proxyInterface: "en5", directInterface: "en5"))
        }
    }

    func testUsbAndCampusSplitWithoutWifiProxy() {
        XCTAssertEqual(RoutingPolicy.decide(.init(usbInterface: "en5", wifiInterface: "en0")),
                       .init(mode: .split, proxyInterface: "en5", directInterface: "en0"))
    }

    func testDeniedPermissionEmptyIdentityAndDifferentSecurityAreDirect() {
        for (ssid, security) in [(nil, nil), (Data(), 4), (hotspot.ssid, 3), (Data("My Phone ".utf8), 4)] as [(Data?, Int?)] {
            XCTAssertEqual(RoutingPolicy.decide(.init(wifiInterface: "en0", ssid: ssid,
                security: security, registrations: [hotspot])).mode, .directOnly)
        }
    }

    func testUnknownStateAndNoUsableInterfaceBlock() {
        XCTAssertEqual(RoutingPolicy.decide(.init()).mode, .blocked)
        XCTAssertEqual(RoutingPolicy.decide(.init(usbInterface: "en5", wifiInterface: "en0", stateReadable: false)).mode, .blocked)
        XCTAssertEqual(RoutingPolicy.decide(.init(usbInterface: "utun8")).mode, .blocked)
        XCTAssertEqual(RoutingPolicy.decide(.init(usbInterface: "en0", wifiInterface: "en0")).mode, .blocked)
    }

    func testEnterpriseOrUnknownSecurityCannotBeRegisteredPhonePermission() {
        for security in [0, 9, Int.max] {
            let stored = RegisteredHotspot(ssid: hotspot.ssid, security: security, displayName: "My Phone")
            XCTAssertEqual(RoutingPolicy.decide(.init(wifiInterface: "en0", ssid: stored.ssid,
                security: security, registrations: [stored])).mode, .directOnly)
        }
    }

    func testUsbChargingLinkLocalAndIpv6AloneAreNotReady() {
        XCTAssertFalse(RoutingPolicy.usableIPv4(active: false, addresses: ["172.20.10.5"]))
        for address in ["169.254.3.4", "0.0.0.0", "127.0.0.1", "fe80::1", "999.1.1.1"] {
            XCTAssertFalse(RoutingPolicy.usableIPv4(active: true, addresses: [address]))
        }
        XCTAssertTrue(RoutingPolicy.usableIPv4(active: true, addresses: ["172.20.10.5"]))
    }

    func testCampusConfigurationRemovesRemoteNodesAndBackgroundGroups() throws {
        let output = try transformed(.init(mode: .directOnly, proxyInterface: nil, directInterface: "en0"))
        XCTAssertEqual(output["mode"] as? String, "direct")
        XCTAssertEqual(output["interface-name"] as? String, "en0")
        XCTAssertEqual(output["rules"] as? [String], ["MATCH,EZ-Campus"])
        XCTAssertEqual((output["proxy-groups"] as? [[String: Any]])?.count, 0)
        let nodes = try XCTUnwrap(output["proxies"] as? [[String: Any]])
        XCTAssertEqual(nodes.count, 2)
        XCTAssertTrue(nodes.allSatisfy { $0["type"] as? String == "direct" && $0["interface-name"] as? String == "en0" })
        let dns = try XCTUnwrap(output["dns"] as? [String: Any])
        XCTAssertEqual(dns["proxy-server-nameserver"] as? [String], ["223.5.5.5#EZ-USB-DNS", "119.29.29.29#EZ-USB-DNS"])
    }

    func testSplitBindsRemoteAndDnsToUsbAndDomesticRulesToWifi() throws {
        let output = try transformed(.init(mode: .split, proxyInterface: "en5", directInterface: "en0"))
        let nodes = output["proxies"] as! [[String: Any]]
        XCTAssertEqual(nodes.first?["interface-name"] as? String, "en5")
        XCTAssertEqual(nodes.first?["ip-version"] as? String, "ipv4")
        XCTAssertEqual(nodes.first?["mptcp"] as? Bool, false)
        XCTAssertEqual(nodes.first(where: { $0["name"] as? String == "EZ-Campus" })?["interface-name"] as? String, "en0")
        let rules = try XCTUnwrap(output["rules"] as? [String])
        XCTAssertEqual(rules.first, "IP-CIDR,192.0.2.10/32,EZ-Campus,no-resolve")
        XCTAssertEqual(rules.last, "MATCH,Proxy")
        XCTAssertTrue(rules.contains("DOMAIN-SUFFIX,bilibili.com,EZ-Campus"), "订阅自带的直连规则不能丢")
        XCTAssertEqual(rules.filter { $0.hasPrefix("DOMAIN-SUFFIX,bilibili.com,") }.count, 1, "不能重复注入")
        XCTAssertEqual(output["mode"] as? String, "rule")
        XCTAssertEqual((output["tun"] as? [String: Any])?["enable"] as? Bool, true)
    }

    func testSinglePhoneModesBindEveryOutboundToTheSameOutlet() throws {
        for decision in [RoutingDecision(mode: .usbHotspot, proxyInterface: "en5", directInterface: "en5"),
                         RoutingDecision(mode: .wifiHotspot, proxyInterface: "en0", directInterface: "en0")] {
            let output = try transformed(decision)
            XCTAssertTrue((output["proxies"] as! [[String: Any]]).allSatisfy {
                $0["interface-name"] as? String == decision.proxyInterface
            })
        }
    }

    func testOfflineDoesNotKeepRemoteNodesOrDnsRequests() throws {
        let output = try transformed(.init(mode: .blocked, proxyInterface: nil, directInterface: nil))
        XCTAssertEqual(output["rules"] as? [String], ["MATCH,REJECT"])
        XCTAssertEqual((output["proxies"] as? [[String: Any]])?.count, 0)
        // Keep the mapper alive across blocked -> active reloads, while every
        // real DNS lookup is rejected before it can reach a physical outlet.
        let dns = try XCTUnwrap(output["dns"] as? [String: Any])
        XCTAssertEqual(dns["enable"] as? Bool, true)
        XCTAssertEqual(dns["enhanced-mode"] as? String, "fake-ip")
        for key in ["nameserver", "default-nameserver", "proxy-server-nameserver", "direct-nameserver"] {
            XCTAssertEqual(dns[key] as? [String], ["223.5.5.5#REJECT"])
        }
        XCTAssertEqual(dns["respect-rules"] as? Bool, false)
        XCTAssertEqual(output["mode"] as? String, "rule")
    }

    func testRejectsProviderChainWifiFallbackAndMalformedDecisions() throws {
        for addition in [["proxy-providers": ["subscription": ["type": "http"]]],
                         ["proxy-groups": [["name": "Proxy", "type": "select", "proxies": ["Node", "EZ-Campus"]]]]] as [[String: Any]] {
            var base = fixture; base.merge(addition) { _, value in value }
            XCTAssertThrowsError(try RoutingConfiguration.make(baseJSON: JSONSerialization.data(withJSONObject: base), decision: split))
        }
        var chained = fixture
        var nodes = chained["proxies"] as! [[String: Any]]; nodes[0]["dialer-proxy"] = "EZ-Campus"; chained["proxies"] = nodes
        XCTAssertThrowsError(try RoutingConfiguration.make(baseJSON: JSONSerialization.data(withJSONObject: chained), decision: split))
        XCTAssertThrowsError(try transformed(.init(mode: .split, proxyInterface: "en0", directInterface: "en0")))
    }

    func testBaseCanRestoreAfterDirectWithoutMutatingSubscription() throws {
        let input = try JSONSerialization.data(withJSONObject: fixture)
        _ = try RoutingConfiguration.make(baseJSON: input, decision: .init(mode: .directOnly, proxyInterface: nil, directInterface: "en0"))
        let restored = try JSONSerialization.jsonObject(with: RoutingConfiguration.make(baseJSON: input, decision: split)) as! [String: Any]
        XCTAssertEqual((restored["proxies"] as! [[String: Any]]).first?["name"] as? String, "Node")
        XCTAssertEqual(try JSONSerialization.jsonObject(with: input) as? NSDictionary, fixture as NSDictionary)
    }

    func testSplitCannotUseIpOrProcessOnlyRulesToAuthorizeCampus() throws {
        var base = fixture
        base["rules"] = ["GEOIP,CN,EZ-Campus", "PROCESS-NAME,browser,EZ-Campus",
                         "DOMAIN-SUFFIX,bilibili.com,EZ-Campus", "MATCH,Proxy"]
        base["sniffer"] = ["enable": false, "skip-domain": ["+.gstatic.com"]]
        let data = try RoutingConfiguration.make(baseJSON: JSONSerialization.data(withJSONObject: base), decision: split)
        let output = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let rules = try XCTUnwrap(output["rules"] as? [String])
        XCTAssertEqual(rules.first, "IP-CIDR,192.0.2.10/32,EZ-Campus,no-resolve")
        XCTAssertEqual(rules.last, "MATCH,Proxy")
        XCTAssertFalse(rules.contains { $0.hasPrefix("GEOIP,") }, "IP 归属类规则不能用来授权直连")
        XCTAssertFalse(rules.contains { $0.hasPrefix("PROCESS-NAME,") })
        XCTAssertTrue(rules.contains("DOMAIN-SUFFIX,bilibili.com,EZ-Campus"))
        let sniffer = try XCTUnwrap(output["sniffer"] as? [String: Any])
        XCTAssertEqual(sniffer["enable"] as? Bool, true)
        XCTAssertEqual(sniffer["parse-pure-ip"] as? Bool, true)
        XCTAssertNil(sniffer["skip-domain"])
    }

    func testKnownLabAddressHasPriorityOverSubscriptionProxyRules() throws {
        let output = try transformed(split)
        let rules = try XCTUnwrap(output["rules"] as? [String])
        XCTAssertEqual(rules.first, "IP-CIDR,192.0.2.10/32,EZ-Campus,no-resolve")
        XCTAssertEqual(rules.last, "MATCH,Proxy")
        let campus = (output["proxies"] as? [[String: Any]])?.first { $0["name"] as? String == "EZ-Campus" }
        XCTAssertEqual(campus?["interface-name"] as? String, "en0")
    }

    func testKnownLabAddressCannotFallBackToAirportOnPhoneNetworks() throws {
        for decision in [RoutingDecision(mode: .usbHotspot, proxyInterface: "en5", directInterface: "en5"),
                         RoutingDecision(mode: .wifiHotspot, proxyInterface: "en0", directInterface: "en0")] {
            let output = try transformed(decision)
            XCTAssertEqual((output["rules"] as? [String])?.first, "IP-CIDR,192.0.2.10/32,REJECT,no-resolve")
        }
    }

    func testSchoolDomainsResolveThroughTheCampusOutletOnlyWhenOneExists() throws {
        for decision in [split, RoutingDecision(mode: .directOnly, proxyInterface: nil, directInterface: "en0")] {
            let output = try transformed(decision)
            let dns = try XCTUnwrap(output["dns"] as? [String: Any])
            let policy = try XCTUnwrap(dns["nameserver-policy"] as? [String: [String]])
            XCTAssertEqual(policy["+.campus.example"], ["192.0.2.53#EZ-Campus"])
            XCTAssertEqual(policy["campus.example"], ["192.0.2.53#EZ-Campus"])
            XCTAssertEqual(Set(policy.keys), ["+.campus.example", "campus.example"])
            // Under fake-ip the client never sees a real address: the direct outbound
            // resolves the name again at dial time, and that lookup only honours
            // nameserver-policy when this flag is set.
            XCTAssertEqual(dns["direct-nameserver-follow-policy"] as? Bool, true)
        }
    }

    func testPhoneOnlyAndOfflineModesCarryNoCampusResolver() throws {
        for decision in [RoutingDecision(mode: .usbHotspot, proxyInterface: "en5", directInterface: "en5"),
                         RoutingDecision(mode: .wifiHotspot, proxyInterface: "en0", directInterface: "en0"),
                         RoutingDecision(mode: .blocked, proxyInterface: nil, directInterface: nil)] {
            let output = try transformed(decision)
            let dns = try XCTUnwrap(output["dns"] as? [String: Any])
            XCTAssertNil(dns["nameserver-policy"])
            XCTAssertEqual(dns["direct-nameserver-follow-policy"] as? Bool, false)
        }
    }

    func testDomesticDomainsAreMadeDirectAheadOfTheSubscriptionFallback() throws {
        let wifiHotspot = RoutingDecision(mode: .wifiHotspot, proxyInterface: "en0", directInterface: "en0")
        for decision in [split, wifiHotspot] {
            let output = try transformed(decision)
            let rules = try XCTUnwrap(output["rules"] as? [String])
            XCTAssertTrue(rules.first?.hasPrefix("IP-CIDR,192.0.2.10/32,") == true, "实验地址那条必须仍在最前")
            let catchAll = try XCTUnwrap(rules.firstIndex { $0.hasPrefix("MATCH,") })
            XCTAssertEqual(catchAll, rules.count - 1)
            for domain in ["xiaohongshu.com", "xhscdn.com", "deepseek.com", "weixinbridge.com", "cn.bing.com"] {
                let index = try XCTUnwrap(rules.firstIndex(of: "DOMAIN-SUFFIX,\(domain),EZ-Campus"),
                                          "\(domain) 没有被注入")
                XCTAssertGreaterThan(index, 0, "\(domain) 必须排在实验地址之后")
                XCTAssertLessThan(index, catchAll, "\(domain) 必须排在兜底之前")
            }
        }
    }

    func testDomesticDomainsOverrideASubscriptionRuleThatProxiesThem() throws {
        var base = fixture
        base["rules"] = ["DOMAIN-SUFFIX,bing.com,Proxy", "MATCH,Proxy"]
        let data = try RoutingConfiguration.make(baseJSON: JSONSerialization.data(withJSONObject: base),
                                                 decision: split)
        let output = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let rules = try XCTUnwrap(output["rules"] as? [String])
        let ours = try XCTUnwrap(rules.firstIndex(of: "DOMAIN-SUFFIX,cn.bing.com,EZ-Campus"))
        let theirs = try XCTUnwrap(rules.firstIndex(of: "DOMAIN-SUFFIX,bing.com,Proxy"))
        XCTAssertLessThan(ours, theirs)
    }

    func testUsbOnlyModeDoesNotSendDomesticDomainsToCampus() throws {
        let output = try transformed(.init(mode: .usbHotspot, proxyInterface: "en5", directInterface: "en5"))
        let rules = try XCTUnwrap(output["rules"] as? [String])
        XCTAssertFalse(rules.contains { $0.contains("xiaohongshu.com") },
                       "手机 USB 模式可能没有 Wi-Fi，不应把国内域名指到 campus")
    }

    func testAppleDomainsAreDirectByDefaultAndLeftToTheSubscriptionWhenSwitched() throws {
        let base = try JSONSerialization.data(withJSONObject: fixture)
        let direct = try JSONSerialization.jsonObject(with: RoutingConfiguration.make(baseJSON: base,
                                                                                      decision: split)) as! [String: Any]
        let directRules = try XCTUnwrap(direct["rules"] as? [String])
        XCTAssertTrue(directRules.contains("DOMAIN-SUFFIX,apple.com,EZ-Campus"))
        XCTAssertTrue(directRules.contains("DOMAIN-SUFFIX,mzstatic.com,EZ-Campus"))

        let throughProxy = try JSONSerialization.jsonObject(
            with: try RoutingConfiguration.make(baseJSON: base, decision: split,
                                                appleViaProxy: true)) as! [String: Any]
        let proxiedRules = try XCTUnwrap(throughProxy["rules"] as? [String])
        XCTAssertFalse(proxiedRules.contains("DOMAIN-SUFFIX,apple.com,EZ-Campus"),
                       "开关打开后苹果域名要交回订阅的代理规则")
        XCTAssertFalse(proxiedRules.contains("DOMAIN-SUFFIX,mzstatic.com,EZ-Campus"))
        XCTAssertTrue(proxiedRules.contains("DOMAIN-SUFFIX,xiaohongshu.com,EZ-Campus"),
                      "开关只影响苹果那一组")
    }

    private let split = RoutingDecision(mode: .split, proxyInterface: "en5", directInterface: "en0")
    private func transformed(_ decision: RoutingDecision) throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: RoutingConfiguration.make(
            baseJSON: JSONSerialization.data(withJSONObject: fixture), decision: decision)) as! [String: Any]
    }
    private var fixture: [String: Any] {
        ["mode": "rule", "interface-name": "en5", "tun": ["enable": true],
         "proxies": [
            ["name": "Node", "type": "trojan", "server": "example.invalid", "port": 443, "password": "fixture", "interface-name": "en5"],
            ["name": "EZ-Campus", "type": "direct", "interface-name": "en0"],
            ["name": "EZ-USB-DNS", "type": "direct", "interface-name": "en5"]],
         "proxy-groups": [["name": "Proxy", "type": "select", "proxies": ["Node"]]],
         "rules": ["DOMAIN-SUFFIX,bilibili.com,EZ-Campus", "MATCH,Proxy"]]
    }
}
