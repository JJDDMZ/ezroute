import Foundation

/// Restricts the existing transaction output. It never treats a subscription DIRECT as permission.
enum RoutingStrictConfiguration {
    static let relayHosts = ["mask.icloud.com", "mask-h2.icloud.com", "mask-api.icloud.com",
        "apple-relay.cloudflare.com", "apple-relay.fastly-edge.com", "apple-relay.apple.com", "cp4.cloudflare.com"]

    static func make(_ input: [String: Any], originalRules: [String], decision: RoutingDecision,
                     appleViaProxy: Bool) throws -> [String: Any] {
        guard decision.mode == .split || decision.mode == .directOnly else {
            throw RoutingConfigurationError.invalidDecision
        }
        var out = input
        let campus = "EZ-Campus"
        let online = decision.proxyInterface != nil
        let fallbackFields = originalRules.last?.components(separatedBy: ",") ?? []
        let fallback = online ? (fallbackFields.last ?? "REJECT") : "REJECT"
        guard fallback != campus else { throw RoutingConfigurationError.unsupported }
        var rejects: [String] = []
        var proxies: [String] = []
        for rule in originalRules where !rule.hasPrefix("MATCH,") {
            var fields = rule.components(separatedBy: ",")
            let index = fields.count - (fields.last == "no-resolve" ? 2 : 1)
            if ["REJECT", "REJECT-DROP"].contains(fields[index]) { rejects.append(rule) }
            else if fields[index] != campus {
                if !online { fields[index] = "REJECT" }
                // An address-based proxy exception must not cause an unlisted offline DNS lookup.
                if !online, ["GEOIP", "IP-CIDR", "IP-CIDR6", "IP-ASN"].contains(fields[0]), fields.last != "no-resolve" {
                    fields.append("no-resolve")
                }
                proxies.append(fields.joined(separator: ","))
            }
        }
        let relayRules = relayHosts.map { "DOMAIN,\($0),\(fallback)" }
        let appleFamilies = RoutingDirectDomains.apple + ["icloud.com.cn", "apple.com.cn", "apple.cn", "apzones.com"]
        let forcedApple = appleViaProxy ? appleFamilies.map { "DOMAIN-SUFFIX,\($0),\(fallback)" } : []
        let allow = RoutingStrictDomains.rules(campus: campus)
        let directApple = appleViaProxy ? [] : RoutingStrictDomains.apple.map { "DOMAIN,\($0),\(campus)" }
        // Telemetry and foreign-sensitive hosts fall back to USB even when a parent suffix is allowed.
        // They are emitted before every allowance, including the Apple exact list.
        let exclusions = RoutingStrictDomains.excludedSuffixes.map { "DOMAIN-SUFFIX,\($0),\(fallback)" } +
            RoutingStrictDomains.excludedHosts.map { "DOMAIN,\($0),\(fallback)" }
        // The existing Apple preference overrides subscription Apple proxies only for these exact hosts.
        // Rejects, relay exclusions and explicit exclusions always win.
        let effective = rejects + relayRules + exclusions + directApple + proxies + forcedApple + allow + ["MATCH,\(fallback)"]
        out["rules"] = effective
        out["mode"] = "rule"
        // A pure-IP TLS connection must not borrow a whitelisted SNI to reach an arbitrary address.
        if var sniffer = out["sniffer"] as? [String: Any] {
            sniffer["parse-pure-ip"] = false
            out["sniffer"] = sniffer
        }
        // Strip TUN fields that would let selected traffic bypass the tunnel entirely.
        if var tun = out["tun"] as? [String: Any] {
            for key in ["route-exclude-address", "route-exclude-address-set",
                        "include-uid", "include-uid-range", "exclude-uid", "exclude-uid-range",
                        "include-package", "exclude-package", "include-android-user"] {
                tun.removeValue(forKey: key)
            }
            out["tun"] = tun
        }

        let upstream = online ? ["223.5.5.5#EZ-USB-DNS", "119.29.29.29#EZ-USB-DNS"] : ["223.5.5.5#REJECT"]
        var dns = out["dns"] as? [String: Any] ?? [:]
        for key in ["nameserver", "default-nameserver", "proxy-server-nameserver", "direct-nameserver"] { dns[key] = upstream }
        var policy: [String: [String]] = [:]
        // The school zone is resolved by the campus resolver for every host, not only the
        // hosts observed so far. A new `jw.` or `lib.` service would otherwise be unresolvable
        // while TUN is up, because public resolvers cannot answer an internal name.
        let school: [String] = ["192.0.2.53#EZ-Campus"]
        policy["campus.example"] = school
        policy["+.campus.example"] = school
        // Online public DNS stays on USB. Offline campus DNS has finite exact names only:
        // domain-keyword and child proxy exceptions can therefore be evaluated before granting DNS.
        let hosts = RoutingStrictDomains.knownDNSHosts + (appleViaProxy ? [] : RoutingStrictDomains.apple)
        for host in hosts where literalTarget(host, rules: effective) == campus {
            if host == "campus.example" || host.hasSuffix(".campus.example") { continue }
            if !online { policy[host] = ["223.5.5.5#EZ-Campus", "119.29.29.29#EZ-Campus"] }
        }
        dns["nameserver-policy"] = policy
        dns["direct-nameserver-follow-policy"] = true
        out["dns"] = dns
        return out
    }

    private static func literalTarget(_ host: String, rules: [String]) -> String? {
        for rule in rules {
            let f = rule.components(separatedBy: ",")
            if f[0] == "MATCH" { return f[1] }
            if f[0] == "DOMAIN" && host == f[1] ||
                f[0] == "DOMAIN-SUFFIX" && (host == f[1] || host.hasSuffix("." + f[1])) ||
                f[0] == "DOMAIN-KEYWORD" && host.contains(f[1]) {
                return f[2]
            }
        }
        return nil
    }
}
