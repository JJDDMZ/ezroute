import Foundation

public enum RoutingConfigurationError: Error, LocalizedError {
    case unsupported, invalidDecision
    public var errorDescription: String? {
        switch self {
        case .unsupported: "当前订阅结构暂不支持自动分流。"
        case .invalidDecision: "网络出口尚未确定。"
        }
    }
}

public enum RoutingConfiguration {
    private static let campus = "EZ-Campus"
    private static let dnsNode = "EZ-USB-DNS"
    /// Example campus resolver and domain. Replace these documentation values
    /// for a campus deployment; see docs/campus-profile.md.
    private static let campusDNS = "192.0.2.53"
    private static let schoolDomain = "campus.example"
    private static let supported = Set(["trojan", "vmess", "vless", "ss", "ssr", "http", "socks5", "snell"])

    /// `appleViaProxy` 为真时放弃注入苹果直连规则,让订阅的苹果服务代理规则接管——
    /// 处理外区 Apple 账号时需要。默认假:本机平时用国区账号,苹果服务直连更快。
    public static func make(baseJSON: Data, decision: RoutingDecision,
                            appleViaProxy: Bool = false) throws -> Data {
        try validate(decision)
        guard var out = try JSONSerialization.jsonObject(with: baseJSON) as? [String: Any],
              var nodes = out["proxies"] as? [[String: Any]],
              let groups = out["proxy-groups"] as? [[String: Any]],
              let rules = out["rules"] as? [String], !rules.isEmpty else { throw RoutingConfigurationError.unsupported }
        if decision.mode != .blocked, out["ez-switch-bootstrap-error"] != nil {
            throw RoutingConfigurationError.unsupported
        }
        for key in ["proxy-providers", "rule-providers", "sub-rules", "listeners", "tunnels"] {
            if let value = out[key], !(value as? [String: Any] ?? [:]).isEmpty ||
                (out[key] as? [Any])?.isEmpty == false { throw RoutingConfigurationError.unsupported }
            if let value = out[key], !(value is [String: Any]), !(value is [Any]) { throw RoutingConfigurationError.unsupported }
        }
        guard let originalUSB = out["interface-name"] as? String, RoutingPolicy.validInterface(originalUSB),
              nodes.filter({ $0["name"] as? String == campus && $0["type"] as? String == "direct" }).count == 1,
              nodes.filter({ $0["name"] as? String == dnsNode && $0["type"] as? String == "direct" }).count == 1 else {
            throw RoutingConfigurationError.unsupported
        }
        var names = Set(["DIRECT", "REJECT", "REJECT-DROP", "PASS", "GLOBAL", "PASS-RULE", "COMPATIBLE"])
        for item in nodes + groups {
            guard let name = item["name"] as? String, !name.isEmpty, names.insert(name).inserted else {
                throw RoutingConfigurationError.unsupported
            }
        }
        let remoteNames = Set(nodes.compactMap { node -> String? in
            let name = node["name"] as? String
            return name == campus || name == dnsNode ? nil : name
        }).union(groups.compactMap { $0["name"] as? String })
        for node in nodes {
            let name = node["name"] as? String ?? ""
            if name == campus || name == dnsNode { continue }
            guard let type = node["type"] as? String, supported.contains(type),
                  node["interface-name"] as? String == originalUSB, node["dialer-proxy"] == nil else {
                throw RoutingConfigurationError.unsupported
            }
        }
        for group in groups {
            guard let type = group["type"] as? String,
                  ["select", "url-test", "fallback", "load-balance"].contains(type),
                  let members = group["proxies"] as? [String], !members.isEmpty,
                  members.allSatisfy({ remoteNames.contains($0) || ["REJECT", "REJECT-DROP"].contains($0) }),
                  (group["use"] as? [String] ?? []).isEmpty,
                  !["include-all", "include-all-proxies", "include-all-providers"].contains(where: { group[$0] as? Bool == true }) else {
                throw RoutingConfigurationError.unsupported
            }
        }
        let ruleTypes = Set(["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "GEOSITE", "GEOIP", "IP-CIDR", "IP-CIDR6", "IP-ASN", "SRC-IP-CIDR", "DST-PORT", "SRC-PORT", "PROCESS-NAME", "PROCESS-PATH", "NETWORK"])
        for rule in rules {
            let fields = rule.components(separatedBy: ",")
            let index = fields.count - (fields.last == "no-resolve" ? 2 : 1)
            guard (fields.first == "MATCH" && fields.count == 2) ||
                (ruleTypes.contains(fields[0]) && index == 2), index > 0,
                remoteNames.contains(fields[index]) || [campus, "REJECT", "REJECT-DROP"].contains(fields[index]) else {
                throw RoutingConfigurationError.unsupported
            }
        }
        guard rules.last?.hasPrefix("MATCH,") == true else { throw RoutingConfigurationError.unsupported }

        if decision.mode == .split {
            guard rules.last?.components(separatedBy: ",").last != campus else { throw RoutingConfigurationError.unsupported }
            let namedDirectRules = Set(["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "GEOSITE"])
            out["rules"] = rules.filter { rule in
                let fields = rule.components(separatedBy: ",")
                let index = fields.count - (fields.last == "no-resolve" ? 2 : 1)
                return fields[index] != campus || namedDirectRules.contains(fields[0])
            }
        }

        out["sniffer"] = ["enable": decision.mode != .blocked && decision.mode != .directOnly,
            "force-dns-mapping": true, "parse-pure-ip": true, "override-destination": false,
            "sniff": ["HTTP": ["ports": [80, 8080]], "TLS": ["ports": [443, 8443]], "QUIC": ["ports": [443, 8443]]]] as [String: Any]

        if decision.mode == .blocked {
            out["mode"] = "rule"; out["rules"] = ["MATCH,REJECT"]
            out["proxies"] = [[String: Any]](); out["proxy-groups"] = [[String: Any]]()
            // Disabling DNS destroys Mihomo's host mapper. macOS can still hold
            // its fake IPs, so the next direct-only mode cannot resolve them.
            // Preserve the mapper while rejecting every upstream DNS dial.
            let rejectedResolvers = ["223.5.5.5#REJECT"]
            out["dns"] = ["enable": true, "listen": "127.0.0.1:1053", "ipv6": false,
                "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
                "fake-ip-filter": ["*.lan", "*.local"], "respect-rules": false, "prefer-h3": false,
                "default-nameserver": rejectedResolvers, "nameserver": rejectedResolvers,
                "proxy-server-nameserver": rejectedResolvers, "direct-nameserver": rejectedResolvers,
                "direct-nameserver-follow-policy": false]
            out["interface-name"] = originalUSB
        } else {
            let direct = decision.directInterface!
            let upstream = decision.proxyInterface ?? direct
            if decision.mode == .directOnly {
                nodes = nodes.filter { [campus, dnsNode].contains($0["name"] as? String ?? "") }
                out["proxy-groups"] = [[String: Any]]()
                out["rules"] = ["MATCH," + campus]
                out["mode"] = "direct"
            } else { out["mode"] = "rule" }
            for i in nodes.indices {
                nodes[i]["interface-name"] = nodes[i]["name"] as? String == campus ? direct : upstream
                nodes[i]["ip-version"] = "ipv4"; nodes[i]["mptcp"] = false
            }
            out["proxies"] = nodes; out["interface-name"] = upstream
            let resolvers = ["223.5.5.5#" + dnsNode, "119.29.29.29#" + dnsNode]
            var dns: [String: Any] = ["enable": true, "listen": "127.0.0.1:1053", "ipv6": false,
                "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
                "fake-ip-filter": ["*.lan", "*.local"], "respect-rules": false, "prefer-h3": false,
                "default-nameserver": resolvers, "nameserver": resolvers,
                "proxy-server-nameserver": resolvers, "direct-nameserver": resolvers,
                "direct-nameserver-follow-policy": false]
            // School-internal names exist only in the campus resolver, which the phone
            // side cannot reach; without this exception they never resolve while TUN is
            // up. Only a mode that holds a campus outlet may ask it, and the query still
            // leaves through the campus-bound policy, never the phone. Both the apex and
            // its subdomains are listed so matching does not depend on `+.` semantics.
            // Only the explicitly configured campus resolver is used here.
            if decision.mode == .split || decision.mode == .directOnly {
                let campusResolvers = [campusDNS + "#" + campus]
                dns["nameserver-policy"] = [schoolDomain: campusResolvers,
                                            "+." + schoolDomain: campusResolvers]
                // fake-ip hands the client a synthetic address, so the direct outbound
                // resolves the real name again when it dials. Without this flag that
                // second lookup ignores nameserver-policy and falls back to the public
                // resolvers, which cannot answer a school-internal name.
                dns["direct-nameserver-follow-policy"] = true
            }
            out["dns"] = dns
        }
        // 订阅自带的直连清单有缺口:小红书、DeepSeek、微信的部分域名不在其中,于是落到
        // 最后的 MATCH 兜底、经手机出口绕到境外节点。这里补上应用自带的国内清单。
        // 只在存在 Wi-Fi 直连出口的模式里补:手机 USB 模式可能根本没有 Wi-Fi,把域名指到
        // campus 会新增一种连不上的失败面。注入发生在下面那条实验规则之前,所以实验地址
        // 仍然排在最前面。
        if decision.mode == .split || decision.mode == .wifiHotspot {
            let current = out["rules"] as? [String] ?? []
            out["rules"] = RoutingDirectDomains.prepending(to: current, campus: campus,
                                                           includeApple: !appleViaProxy)
        }
        // Explicit local exception: never send this lab address to an airport node.
        // Split mode has a Wi-Fi outlet; phone-only modes must reject it.
        if decision.mode == .split || decision.mode == .usbHotspot || decision.mode == .wifiHotspot {
            let target = decision.mode == .split ? campus : "REJECT"
            let labRule = "IP-CIDR,192.0.2.10/32," + target + ",no-resolve"
            let current = out["rules"] as? [String] ?? []
            out["rules"] = [labRule] + current.filter { !$0.hasPrefix("IP-CIDR,192.0.2.10/32,") }
        }
        return try JSONSerialization.data(withJSONObject: out, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    private static func validate(_ decision: RoutingDecision) throws {
        let interfaces = [decision.proxyInterface, decision.directInterface].compactMap { $0 }
        guard interfaces.allSatisfy(RoutingPolicy.validInterface) else { throw RoutingConfigurationError.invalidDecision }
        let valid: Bool
        switch decision.mode {
        case .blocked: valid = interfaces.isEmpty
        case .directOnly: valid = decision.proxyInterface == nil && decision.directInterface != nil
        case .split: valid = interfaces.count == 2 && decision.proxyInterface != decision.directInterface
        case .usbHotspot, .wifiHotspot: valid = interfaces.count == 2 && decision.proxyInterface == decision.directInterface
        }
        guard valid else { throw RoutingConfigurationError.invalidDecision }
    }
}
