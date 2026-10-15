import Foundation
import Darwin

public enum RoutingCheckVerdict: String, Sendable { case pass, fail, unknown }
public enum RoutingSiteError: Error, LocalizedError {
    case invalid, duplicate, limit
    public var errorDescription: String? {
        switch self {
        case .invalid: "请输入纯域名，如 example.com；国际化域名请使用 Punycode。"
        case .duplicate: "这个域名已在列表中。"
        case .limit: "最多保存 20 个测试域名。"
        }
    }
}
public final class RoutingSiteList {
    private let defaults: UserDefaults
    private static let key = "EZSwitch.websiteTestHosts"
    public private(set) var sites: [RoutingTestSite]
    public init(defaults: UserDefaults) {
        self.defaults = defaults
        let hosts = defaults.stringArray(forKey: Self.key) ?? RoutingTestSite.examples.map(\.host)
        sites = []
        for value in hosts.prefix(20) {
            guard let host = try? Self.normalize(value), !sites.contains(where: { $0.host == host }) else { continue }
            sites.append(Self.site(host))
        }
    }
    public static func normalize(_ value: String) throws -> String {
        var host = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if host.hasSuffix(".") { host.removeLast() }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard host.utf8.count <= 253, labels.count >= 2,
              labels.allSatisfy({ $0.range(of: "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", options: .regularExpression) != nil }),
              let suffix = labels.last, suffix.contains(where: { $0.isLetter }),
              !["local", "localhost", "internal", "invalid", "test", "onion"].contains(String(suffix)) else { throw RoutingSiteError.invalid }
        return host
    }
    public func add(_ value: String) throws {
        let host = try Self.normalize(value)
        guard !sites.contains(where: { $0.host == host }) else { throw RoutingSiteError.duplicate }
        guard sites.count < 20 else { throw RoutingSiteError.limit }
        sites.append(Self.site(host)); save()
    }
    public func remove(host: String) { sites.removeAll { $0.host == host }; save() }
    private func save() { defaults.set(sites.map(\.host), forKey: Self.key) }
    private static func site(_ host: String) -> RoutingTestSite {
        RoutingTestSite.examples.first { $0.host == host } ?? .init(id: host, title: host, host: host, domestic: false)
    }
}
public enum RoutingSelfCheck {
    public static func diagnosticSelections(_ data: Data) throws -> [String: String] {
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let proxies = root["proxies"] as? [String: [String: Any]] else { throw MihomoClientError.malformed }
        var result: [String: String] = [:]
        for (name, proxy) in proxies where name != "GLOBAL" {
            guard ["Selector", "URLTest", "Fallback"].contains(proxy["type"] as? String ?? "") else { continue }
            guard let selected = proxy["now"] as? String, !selected.isEmpty else { throw MihomoClientError.malformed }
            result[name] = selected
        }
        return result
    }
    public static func assess(binding: String?, isDirect: Bool, decision: RoutingDecision,
                              physicalInterfaces: Set<String>, captureComplete: Bool) -> RoutingCheckVerdict {
        let expected = isDirect ? decision.directInterface : decision.proxyInterface
        guard let binding else { return .unknown }
        guard let expected else { return .fail }
        guard binding == expected, physicalInterfaces.allSatisfy({ $0 == expected }) else { return .fail }
        return captureComplete && physicalInterfaces.contains(expected) ? .pass : .unknown
    }
    public static func overall(_ verdicts: [RoutingCheckVerdict]) -> RoutingCheckVerdict {
        if verdicts.contains(.fail) { return .fail }
        return !verdicts.isEmpty && verdicts.allSatisfy({ $0 == .pass }) ? .pass : .unknown
    }
    public static func physicalInterfaces(packets: String, address: String, port: Int) -> Set<String> {
        guard let target = canonicalIP(address), (1...65535).contains(port) else { return [] }
        let regex = try! NSRegularExpression(pattern: #"\((en[0-9]+), ([^)]*)\).*\bIP6? \S+ > (\S+): "#)
        var interfaces: Set<String> = []
        for line in packets.split(separator: "\n") {
            let value = String(line)
            guard let match = regex.firstMatch(in: value, range: NSRange(value.startIndex..., in: value)),
                  let interfaceRange = Range(match.range(at: 1), in: value),
                  let metadataRange = Range(match.range(at: 2), in: value),
                  let endpointRange = Range(match.range(at: 3), in: value) else { continue }
            let metadata = String(value[metadataRange])
            guard metadata.range(of: #"(?:^|, )out(?:,|$)"#, options: [.regularExpression, .caseInsensitive]) != nil,
                  metadata.range(of: #"(?:^|, )proc (?:verge-mihomo|mihomo):[0-9]+(?:,|$)"#, options: .regularExpression) != nil else { continue }
            let endpoint = value[endpointRange]
            guard let dot = endpoint.lastIndex(of: "."), Int(endpoint[endpoint.index(after: dot)...]) == port,
                  canonicalIP(String(endpoint[..<dot])) == target else { continue }
            interfaces.insert(String(value[interfaceRange]))
        }
        return interfaces
    }
    public static func canonicalIP(_ address: String) -> String? {
        for family in [AF_INET, AF_INET6] {
            var bytes = [UInt8](repeating: 0, count: 16)
            guard inet_pton(family, address, &bytes) == 1 else { continue }
            var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(family, &bytes, &output, socklen_t(output.count)) != nil else { continue }
            return String(cString: output)
        }
        return nil
    }
}

/// Only system executables, numeric interfaces and a validated local account name reach the root shell.
public enum RoutingCaptureCommand {
    public static func directory(_ id: UUID) -> String { "/private/tmp/ezswitch-capture-" + id.uuidString }
    public static func stopFile(_ id: UUID) -> String { "/private/tmp/ezswitch-capture-stop-" + id.uuidString }
    public static func make(interfaces: [String], uid: UInt32, id: UUID) throws -> String {
        guard uid > 0, (1...2).contains(interfaces.count), Set(interfaces).count == interfaces.count,
              interfaces.allSatisfy(RoutingPolicy.validInterface) else { throw RoutingSiteError.invalid }
        // macOS chmod ACL entries need an account name or UUID, not a numeric UID.
        guard let account = getpwuid(uid), let rawName = account.pointee.pw_name else { throw RoutingSiteError.invalid }
        let accountName = String(cString: rawName)
        guard accountName.range(of: "^[A-Za-z_][A-Za-z0-9_.-]{0,254}$", options: .regularExpression) != nil else {
            throw RoutingSiteError.invalid
        }
        let directory = directory(id), stop = stopFile(id)
        // Administrator AppleScript children can inherit blocked and ignored signals.
        // Reset both in the system interpreter before the shell installs its traps.
        return """
        /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/perl -T -MPOSIX -e '$ENV{PATH}="/usr/bin:/bin:/usr/sbin:/sbin"; $SIG{INT}="DEFAULT"; $SIG{TERM}="DEFAULT"; $SIG{HUP}="DEFAULT"; $SIG{CHLD}="DEFAULT"; POSIX::sigprocmask(POSIX::SIG_SETMASK(), POSIX::SigSet->new()) or die "signal mask: $!"; exec "/bin/sh" or die "exec: $!";' <<'EZ_CAPTURE_SCRIPT'
        set -eu
        umask 077
        [ ! -e '\(stop)' ] || exit 1
        /bin/mkdir -m 700 '\(directory)'
        c=''
        cleanup() { if [ -n "$c" ]; then /bin/kill -KILL "$c" 2>/dev/null || :; fi; /bin/rm -f '\(directory)/packets' '\(directory)/status' '\(stop)'; /bin/rmdir '\(directory)' 2>/dev/null || :; }
        trap cleanup EXIT HUP INT TERM
        : > '\(directory)/packets'
        : > '\(directory)/status'
        /bin/chmod +a 'user:\(accountName) allow read,search' '\(directory)'
        /bin/chmod +a 'user:\(accountName) allow read' '\(directory)/packets' '\(directory)/status'
        /usr/sbin/tcpdump -i 'pktap,\(interfaces.joined(separator: ","))' -k INPD -n -q -l -p -s 256 -c 2048 '(ip or ip6) and (tcp or udp)' > '\(directory)/packets' 2> '\(directory)/status' &
        c=$!
        end=$(( $(/bin/date +%s) + 120 ))
        while /bin/kill -0 "$c" 2>/dev/null && [ "$(/bin/date +%s)" -lt "$end" ] && [ ! -e '\(stop)' ]; do /bin/sleep 0.1; done
        /bin/kill -INT "$c" 2>/dev/null || :
        n=0
        while /bin/kill -0 "$c" 2>/dev/null && [ "$n" -lt 20 ]; do /bin/sleep 0.1; n=$((n+1)); done
        # tcpdump supports TERM for a clean exit too; try it before discarding statistics with KILL.
        if /bin/kill -0 "$c" 2>/dev/null; then
            /bin/kill -TERM "$c" 2>/dev/null || :
            n=0
            while /bin/kill -0 "$c" 2>/dev/null && [ "$n" -lt 20 ]; do /bin/sleep 0.1; n=$((n+1)); done
        fi
        forced=0
        if /bin/kill -0 "$c" 2>/dev/null && /bin/kill -KILL "$c" 2>/dev/null; then forced=1; fi
        if wait "$c" 2>/dev/null; then capture_exit=0; else capture_exit=$?; fi
        c=''
        /bin/echo 'EZ_CAPTURE_STATUS'
        /bin/cat '\(directory)/status'
        /bin/echo
        /bin/echo "EZ_CAPTURE_END $capture_exit $forced"
        EZ_CAPTURE_SCRIPT
        """
    }
}
