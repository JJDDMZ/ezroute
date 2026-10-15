import Foundation

/// 卡片网格里的一张卡。`alias` 只在别名与域名不同时才非空:用户自加的域名
/// `title` 等于 `host`,不去重就会把同一个字符串显示两行。
public struct WebsiteCard: Equatable, Identifiable, Sendable {
    public let id: String
    public let host: String
    public let alias: String?
    public let egress: String
    public let status: String
    public let verdict: RoutingCheckVerdict

    public init(id: String, host: String, alias: String?, egress: String,
                status: String, verdict: RoutingCheckVerdict) {
        self.id = id; self.host = host; self.alias = alias
        self.egress = egress; self.status = status; self.verdict = verdict
    }
}

public enum WebsiteCardPresentation {
    public static func card(site: RoutingTestSite, status: String, egress: String,
                            verdict: RoutingCheckVerdict) -> WebsiteCard {
        WebsiteCard(id: site.host,
                    host: site.host,
                    alias: site.title == site.host ? nil : site.title,
                    egress: egress,
                    status: status,
                    verdict: verdict)
    }
}
