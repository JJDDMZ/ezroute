import XCTest
@testable import EZSwitchCore

final class WebsiteCardPresentationTests: XCTestCase {
    private func site(_ host: String, title: String) -> RoutingTestSite {
        .init(id: host, title: title, host: host, domestic: false)
    }

    func testAliasIsDroppedWhenItEqualsTheHost() {
        // 用户自加的域名 title 等于 host,卡片不能把同一个字符串显示两行。
        let card = WebsiteCardPresentation.card(site: site("czwcx.campus.example", title: "czwcx.campus.example"),
                                                status: "HTTP 200 · 84 ms",
                                                egress: "手机 USB",
                                                verdict: .pass)
        XCTAssertNil(card.alias)
        XCTAssertEqual(card.host, "czwcx.campus.example")
    }

    func testAliasIsKeptWhenItDiffers() {
        let card = WebsiteCardPresentation.card(site: site("github.com", title: "GitHub"),
                                                status: "HTTP 200 · 152 ms",
                                                egress: "手机 USB",
                                                verdict: .pass)
        XCTAssertEqual(card.alias, "GitHub")
    }

    func testCardCarriesStatusEgressAndVerdict() {
        let card = WebsiteCardPresentation.card(site: site("api.deepseek.com", title: "api.deepseek.com"),
                                                status: "HTTP 401 · 21 ms",
                                                egress: "未知",
                                                verdict: .unknown)
        XCTAssertEqual(card.status, "HTTP 401 · 21 ms")
        XCTAssertEqual(card.egress, "未知")
        XCTAssertEqual(card.verdict, .unknown)
    }

    func testIdentityIsTheHost() {
        let card = WebsiteCardPresentation.card(site: site("github.com", title: "GitHub"),
                                                status: "", egress: "", verdict: .unknown)
        XCTAssertEqual(card.id, "github.com")
    }
}
