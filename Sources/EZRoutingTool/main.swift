import Foundation
import Darwin
import EZSwitchCore

// Reuse the settings-page tester; this command never applies configuration.
@MainActor func currentDecision() async throws -> RoutingDecision {
    let client = MihomoClient()
    let general = try await client.read(path: "/configs")
    let proxies = try await client.read(path: "/proxies")
    guard let config = try JSONSerialization.jsonObject(with: general) as? [String: Any],
          let root = try JSONSerialization.jsonObject(with: proxies) as? [String: Any],
          let adapters = root["proxies"] as? [String: [String: Any]],
          let mode = config["mode"] as? String, ["rule", "direct"].contains(mode),
          let core = config["interface-name"] as? String, RoutingPolicy.validInterface(core),
          let direct = adapters["EZ-Campus"]?["interface"] as? String, RoutingPolicy.validInterface(direct),
          adapters["EZ-Campus"]?["type"] as? String == "Direct",
          adapters["EZ-USB-DNS"]?["type"] as? String == "Direct",
          adapters["EZ-USB-DNS"]?["interface"] as? String == core else {
        throw RoutingWebsiteError.unavailable
    }
    let remoteTypes = Set(["Trojan", "Vmess", "Vless", "Shadowsocks", "ShadowsocksR", "Http", "Socks5", "Snell"])
    guard mode == "direct" || adapters.values.contains(where: { remoteTypes.contains($0["type"] as? String ?? "") }) else {
        throw RoutingWebsiteError.unavailable
    }
    let decision = RoutingDecision(mode: mode == "direct" ? .directOnly : (core == direct ? .usbHotspot : .split),
                                   proxyInterface: mode == "direct" ? nil : core, directInterface: direct)
    _ = try RoutingWebsiteTester.entryPort(general: general, proxies: proxies, decision: decision)
    return decision
}

/// One end-to-end request through the current Clash entry. This is the only check
/// that can show whether a mode actually resolves and reaches a given address:
/// the controller API exposes no runtime DNS configuration at all.
@MainActor func probeSite(_ raw: String) async throws -> Int32 {
    let target = try RoutingWebsiteTester.target(raw)
    let client = MihomoClient()
    let decision = try await currentDecision()
    var row: [String: Any] = ["url": target.url, "host": target.host,
                              "physical_egress_verified": false, "live_configuration_modified": false]
    func emit(_ row: [String: Any]) throws {
        let data = try JSONSerialization.data(withJSONObject: ["event": "site-probe", "result": row],
                                              options: [.sortedKeys])
        print(String(decoding: data, as: UTF8.self))
    }
    let result: RoutingWebsiteResult
    do {
        result = try await RoutingWebsiteTester.run(target: target, decision: decision, client: client)
    } catch {
        row["status"] = "REQUEST_FAILED"
        row["reason"] = (error as? LocalizedError)?.errorDescription ?? "request-or-controller-unavailable"
        try emit(row)
        return 1
    }
    let expected = result.evidence.map { $0.isDirect ? decision.directInterface : decision.proxyInterface }
    let matches = result.evidence != nil && expected != nil && result.evidence?.interface == expected
    row["http_status"] = result.probe.status
    row["milliseconds"] = result.probe.milliseconds
    row["content_response_success"] = result.probe.isSuccessfulResponse
    row["configuration_binding_confirmed"] = matches
    if let evidence = result.evidence {
        row["interface"] = evidence.interface
        row["strategy"] = evidence.isDirect ? "direct" : "proxy"
    }
    // A fast request can finish before the read-only sampling, so an unconfirmed
    // binding is reported as unknown rather than as a failure.
    row["status"] = result.probe.isSuccessfulResponse ? (matches ? "BINDING_CONFIRMED" : "RESPONSE_ONLY")
                                                      : "NON_SUCCESS_RESPONSE"
    try emit(row)
    return result.probe.isSuccessfulResponse ? 0 : 1
}

@MainActor func testCurrentWebsites() async throws -> Bool {
    let client = MihomoClient()
    let decision = try await currentDecision()
    var rows: [[String: Any]] = []
    func record(_ row: [String: Any]) throws {
        rows.append(row)
        let data = try JSONSerialization.data(withJSONObject: ["event": "site-result", "result": row], options: [.sortedKeys])
        print(String(decoding: data, as: UTF8.self))
        fflush(stdout)
    }
    var confirmed = true
    var stopped = false
    for site in RoutingTestSite.examples {
        if stopped {
            try record(["site": site.id, "status": "SKIPPED", "reason": "previous-binding-mismatch"])
            continue
        }
        if decision.proxyInterface == nil && !site.domestic {
            try record(["site": site.id, "status": "SKIPPED", "reason": "no-proxy-outlet"])
            continue
        }
        do {
            let result = try await RoutingWebsiteTester.run(site: site, decision: decision, client: client)
            let expected = result.evidence.map { $0.isDirect ? decision.directInterface : decision.proxyInterface }
            let matches = result.evidence != nil && result.evidence?.interface == expected
            var row: [String: Any] = ["site": site.id, "http_status": result.probe.status,
                "milliseconds": result.probe.milliseconds, "content_response_success": result.probe.isSuccessfulResponse,
                "configuration_binding_confirmed": matches, "physical_egress_verified": false]
            if let evidence = result.evidence {
                row["interface"] = evidence.interface
                row["strategy"] = evidence.isDirect ? "direct" : "proxy"
            }
            row["status"] = matches ? "BINDING_CONFIRMED" : "UNKNOWN"
            try record(row)
            confirmed = confirmed && matches && result.probe.isSuccessfulResponse
            if result.evidence != nil && !matches { stopped = true }
        } catch {
            try record(["site": site.id, "status": "UNKNOWN", "reason": "request-or-controller-unavailable"])
            confirmed = false
        }
    }
    let output: [String: Any] = ["scope": "current-controller-binding-and-fixed-website-diagnostics",
        "network_identity_verified": false, "physical_egress_verified": false,
        "live_configuration_modified": false, "all_requests_and_bindings_confirmed": confirmed,
        "sites": rows]
    let data = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
    print(String(decoding: data, as: UTF8.self))
    return confirmed
}

if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--site-probe" {
    do { exit(try await probeSite(CommandLine.arguments[2])) }
    catch {
        fputs("site probe unavailable: \(error.localizedDescription)\n", stderr)
        exit(2)
    }
}

if CommandLine.arguments == [CommandLine.arguments[0], "--website-tests"] {
    do { exit(try await testCurrentWebsites() ? 0 : 1) }
    catch {
        print("{\"scope\":\"current-website-diagnostics\",\"status\":\"UNAVAILABLE\",\"physical_egress_verified\":false}")
        exit(2)
    }
}

// Conversion and read-only local controller auditing. No reload operation.
let args = CommandLine.arguments
let auditing = args.count == 4 && args[1] == "--audit-routing"
guard auditing || (args.count == 5 && args[1] == "--routing-fixture") else {
    fputs("usage: EZRoutingTool --routing-fixture base.json decision.json output.json | --audit-routing base.json decision.json | --website-tests | --site-probe <http-or-https-url>\n", stderr)
    exit(2)
}
do {
    let base = try Data(contentsOf: URL(fileURLWithPath: args[2]))
    let decision = try JSONDecoder().decode(RoutingDecision.self, from: Data(contentsOf: URL(fileURLWithPath: args[3])))
    let output = try RoutingConfiguration.make(baseJSON: base, decision: decision)
    if auditing {
        let verified = try await MihomoClient().verify(configuration: output)
        print("{\"runtime_configuration_verified\":\(verified)}")
        exit(verified ? 0 : 1)
    }
    let fd = open(args[4], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
    guard fd >= 0 else { throw CocoaError(.fileWriteUnknown) }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    do { try handle.write(contentsOf: output); try handle.close() }
    catch { try? handle.close(); try? FileManager.default.removeItem(atPath: args[4]); throw error }
    print("configuration_converted")
} catch {
    // Parsing errors may contain subscription text, so do not print their diagnostic payloads.
    fputs("configuration_conversion_failed\n", stderr)
    exit(1)
}
