import Foundation

public enum RoutingRuntime {
    public static func matches(configuration: Data, general: Data, proxies: Data, rules: Data) throws -> Bool {
        guard let expected = try JSONSerialization.jsonObject(with: configuration) as? [String: Any],
              let actual = try JSONSerialization.jsonObject(with: general) as? [String: Any],
              let proxyEnvelope = try JSONSerialization.jsonObject(with: proxies) as? [String: Any],
              let adapters = proxyEnvelope["proxies"] as? [String: [String: Any]],
              let ruleEnvelope = try JSONSerialization.jsonObject(with: rules) as? [String: Any],
              let actualRules = ruleEnvelope["rules"] as? [[String: Any]],
              let nodes = expected["proxies"] as? [[String: Any]],
              let groups = expected["proxy-groups"] as? [[String: Any]],
              let expectedRules = expected["rules"] as? [String],
              actual["mode"] as? String == expected["mode"] as? String,
              actual["interface-name"] as? String == expected["interface-name"] as? String,
              let expectedTunnel = (expected["tun"] as? [String: Any])?["enable"] as? Bool,
              (actual["tun"] as? [String: Any])?["enable"] as? Bool == expectedTunnel else { return false }
        let typeMap = ["select": "Selector", "url-test": "URLTest", "fallback": "Fallback", "load-balance": "LoadBalance",
                       "direct": "Direct", "trojan": "Trojan", "vmess": "Vmess", "vless": "Vless", "ss": "Shadowsocks",
                       "ssr": "ShadowsocksR", "http": "Http", "socks5": "Socks5", "snell": "Snell"]
        for node in nodes {
            guard let name = node["name"] as? String, let actualNode = adapters[name],
                  actualNode["interface"] as? String == node["interface-name"] as? String,
                  actualNode["type"] as? String == typeMap[node["type"] as? String ?? ""],
                  (actualNode["dialer-proxy"] as? String ?? "").isEmpty else { return false }
        }
        for group in groups {
            guard let name = group["name"] as? String, let actualGroup = adapters[name],
                  actualGroup["type"] as? String == typeMap[group["type"] as? String ?? ""],
                  actualGroup["all"] as? [String] == group["proxies"] as? [String] else { return false }
        }
        let expectedNames = Set((nodes + groups).compactMap { $0["name"] as? String })
        let builtins = Set(["DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "GLOBAL", "COMPATIBLE"])
        guard Set(adapters.keys).subtracting(builtins) == expectedNames,
              actualRules.count == expectedRules.count else { return false }
        let ruleTypes = ["DOMAIN": "Domain", "DOMAIN-SUFFIX": "DomainSuffix", "DOMAIN-KEYWORD": "DomainKeyword", "DOMAIN-REGEX": "DomainRegex",
                         "GEOSITE": "GeoSite", "GEOIP": "GeoIP", "IP-CIDR": "IPCIDR", "IP-CIDR6": "IPCIDR",
                         "IP-ASN": "IP-ASN", "SRC-IP-CIDR": "SrcIPCIDR", "DST-PORT": "DstPort", "SRC-PORT": "SrcPort",
                         "PROCESS-NAME": "Process", "PROCESS-PATH": "ProcessPath", "NETWORK": "Network", "MATCH": "Match"]
        for (rule, actualRule) in zip(expectedRules, actualRules) {
            let fields = rule.components(separatedBy: ",")
            let index = fields.count - (fields.last == "no-resolve" ? 2 : 1)
            guard index > 0, actualRule["type"] as? String == ruleTypes[fields[0]],
                  actualRule["proxy"] as? String == fields[index],
                  actualRule["payload"] as? String == (fields[0] == "MATCH" ? "" : fields[1]) else { return false }
        }
        return true
    }
}
