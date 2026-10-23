import Foundation
import Darwin

public enum ClashBootstrapError: Error, LocalizedError {
    case unsupportedScript, invalidRegistry, unsafeFile, usbNotIdentified
    public var errorDescription: String? {
        switch self {
        case .unsupportedScript: "Clash 存在自定义扩展脚本，已保留原文件；自动订阅接入需要先检查该脚本。"
        case .invalidRegistry: "Clash 订阅关联无法读取，未安装全局路由保护。"
        case .unsafeFile: "Clash 扩展文件路径或权限异常，未安装全局路由保护。"
        case .usbNotIdentified: "尚未确认指定设备的 USB 网络接口。请连接 iPhone 或随身 Wi-Fi，开启 USB 供网并选择 USB 出口，再接入自动路由。"
        }
    }
}

public enum ClashBootstrap {
    public static let identityScript = "function main(config, profileName) { return config; }\n"
    public static func install(directory: URL, registry: Data, backupDirectory: URL,
                               script: String, ownedLegacy: String) throws -> Bool {
        guard let config = try JSONSerialization.jsonObject(with: registry) as? [String: Any],
              let items = config["items"] as? [[String: Any]],
              let current = config["current"] as? String,
              let profile = items.first(where: { $0["uid"] as? String == current }),
              let global = items.first(where: { $0["uid"] as? String == "Script" }),
              global["type"] as? String == "script", global["file"] as? String == "Script.js" else {
            throw ClashBootstrapError.invalidRegistry
        }
        let profiles = directory.appendingPathComponent("profiles")
        try rejectSymlink(profiles); try rejectSymlink(backupDirectory, allowMissing: true)
        let globalURL = profiles.appendingPathComponent("Script.js")
        let oldGlobal = try read(globalURL)
        let savedManaged = backupDirectory.appendingPathComponent("global-managed.js")
        let previousManaged = try optionalRead(savedManaged)
        guard oldGlobal == previousManaged || identity(String(decoding: oldGlobal, as: UTF8.self)) else {
            throw ClashBootstrapError.unsupportedScript
        }
        var legacyURL: URL?, oldLegacy: Data?, legacyID: String?
        let selected = (profile["option"] as? [String: Any])?["script"] as? String ?? "Script"
        if selected != "Script" {
            guard let local = items.first(where: { $0["uid"] as? String == selected }),
                  local["type"] as? String == "script", let file = local["file"] as? String,
                  file == URL(fileURLWithPath: file).lastPathComponent, !file.hasPrefix("."),
                  selected.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil else {
                throw ClashBootstrapError.invalidRegistry
            }
            let url = profiles.appendingPathComponent(file), data = try read(url)
            if String(decoding: data, as: UTF8.self) == ownedLegacy {
                legacyURL = url; oldLegacy = data; legacyID = selected
            } else if !identity(String(decoding: data, as: UTF8.self)) {
                throw ClashBootstrapError.unsupportedScript
            }
        }
        let payload = Data(script.utf8)
        guard payload != oldGlobal || legacyURL != nil else { return false }
        try FileManager.default.createDirectory(at: backupDirectory, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: backupDirectory.path)
        let original = backupDirectory.appendingPathComponent("global-original.js")
        if try optionalRead(original) == nil { try replace(oldGlobal, at: original) }
        if let oldLegacy, let legacyID {
            let backup = backupDirectory.appendingPathComponent("legacy-\(legacyID).js")
            if try optionalRead(backup) == nil { try replace(oldLegacy, at: backup) }
        }
        do {
            try replace(payload, at: globalURL)
            try replace(payload, at: savedManaged)
            if let legacyURL { try replace(Data(identityScript.utf8), at: legacyURL) }
        } catch {
            try? replace(oldGlobal, at: globalURL)
            if let oldLegacy, let legacyURL { try? replace(oldLegacy, at: legacyURL) }
            if let previousManaged { try? replace(previousManaged, at: savedManaged) }
            else { try? FileManager.default.removeItem(at: savedManaged) }
            throw error
        }
        return true
    }
    private static func identity(_ script: String) -> Bool {
        let commentsRemoved = script.replacingOccurrences(of: "(?m)//[^\\n]*", with: "", options: .regularExpression)
        return commentsRemoved.range(of: "^\\s*function\\s+main\\s*\\(\\s*config\\s*(?:,\\s*profileName\\s*)?\\)\\s*\\{\\s*return\\s+config\\s*;?\\s*\\}\\s*$", options: .regularExpression) != nil
    }
    private static func rejectSymlink(_ url: URL, allowMissing: Bool = false) throws {
        do {
            let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
            guard attrs[.type] as? FileAttributeType != .typeSymbolicLink else { throw ClashBootstrapError.unsafeFile }
        } catch let error as NSError where allowMissing && error.domain == NSCocoaErrorDomain && error.code == NSFileReadNoSuchFileError { return }
    }
    private static func optionalRead(_ url: URL) throws -> Data? {
        try rejectSymlink(url, allowMissing: true)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try read(url)
    }
    private static func read(_ url: URL) throws -> Data {
        try rejectSymlink(url)
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        guard attrs[.type] as? FileAttributeType == .typeRegular,
              (attrs[.size] as? NSNumber)?.intValue ?? Int.max < 1_048_576 else { throw ClashBootstrapError.unsafeFile }
        return try Data(contentsOf: url)
    }
    private static func replace(_ data: Data, at url: URL) throws {
        try rejectSymlink(url, allowMissing: true)
        let temporary = url.deletingLastPathComponent().appendingPathComponent(".ez-" + UUID().uuidString)
        let fd = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw ClashBootstrapError.unsafeFile }
        defer { try? FileManager.default.removeItem(at: temporary) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do { try handle.write(contentsOf: data); try handle.close() }
        catch { try? handle.close(); throw error }
        guard rename(temporary.path, url.path) == 0 else { throw ClashBootstrapError.unsafeFile }
    }
}
