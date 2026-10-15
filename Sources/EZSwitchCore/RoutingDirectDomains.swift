import Foundation

/// 应用自带的直连域名清单:订阅清单没覆盖、或订阅的走向与本机偏好不同的域名。
///
/// `domestic` 是订阅清单的缺口:小红书、DeepSeek、微信的部分域名不在其中,于是落到最后的
/// `MATCH` 兜底、经手机出口绕到境外节点。清单里每个域名都实测解析到国内地址,直连可达。
///
/// `apple` 是本机偏好:这台机器平时只用国区 Apple 账号,Apple 服务直连更快(音乐与商店的
/// 端点在国内都有节点,走代理反而是 CN → 境外 → CN)。偶尔要处理外区账号时,由
/// `appleViaProxy` 开关放弃注入这一组,让订阅的苹果服务代理规则接管。
///
/// 只放域名。IP 类规则刻意不在这里:`routing/clash-usb-wifi.js` 会丢弃目标为直连的非域名
/// 规则,目的是让未知域名的请求保留手机兜底,不把国内 IP 之外的流量推上校园链路。
public enum RoutingDirectDomains {
    /// 订阅清单没有、但国内直连可达的域名。每一项都实测解析到国内地址。
    public static let domestic: [String] = [
        // 社交与微信
        "weixinbridge.com",
        // AI 与开发者
        "deepseek.com", "deepseeksvc.com", "volcengine.com", "baichuan-ai.com", "minimaxi.com",
        "stepfun.com", "iflytek.com", "sensetime.com", "huaweicloud.com", "gitee.com",
        "apifox.com", "csdn.net", "oschina.net", "segmentfault.com", "cnblogs.com",
        "yuque.com", "51cto.com", "nowcoder.com", "imooc.com", "dcloud.io", "gamesci.cn",
        // 数码硬件
        "huawei.com", "xiaomi.com", "mi.com", "oppo.com", "realme.com", "ithome.com",
        "chiphell.com", "expreview.com", "tgbus.com",
        // 视频音乐直播
        "douyin.com", "ixigua.com", "kuaishou.com", "kwimgs.com", "xiaohongshu.com",
        "xhscdn.com", "kugou.com", "pptv.com", "1905.com", "ximalaya.com", "qingting.fm",
        "yy.com", "zhanqi.tv",
        // 动漫小说
        "dmzj.com", "qidian.com", "jjwxc.net", "zongheng.com", "17k.com", "ciweimao.com",
        "fanqienovel.com",
        // 游戏
        "mihoyo.com", "miyoushe.com", "bh3.com", "hypergryph.com", "kurogame.com",
        "lilith.com", "sunborngame.com", "papegames.com", "xoyo.com", "wanmei.com", "sdo.com",
        "ztgame.com", "xishanju.com", "heishenhua.com", "4399.com", "7k7k.com", "3839.com",
        "taptap.cn", "xiaoheihe.cn", "wegame.com.cn", "gamersky.com", "3dmgame.com",
        "ali213.net", "ngabbs.com", "17173.com",
        // 电商生活
        "pinduoduo.com", "pddpic.com", "tmall.com", "1688.com", "vip.com", "suning.com",
        "mogujie.com", "dianping.com", "mtyun.com", "ele.me", "qunar.com", "58.com",
        "anjuke.com", "ganji.com", "sf-express.com",
        // 汽车房产出行
        "dongchedi.com", "yiche.com", "bitauto.com", "lianjia.com", "ke.com",
        // 招聘教育
        "zhipin.com", "lagou.com", "51job.com", "zhaopin.com", "cnki.net", "koolearn.com",
        "chaoxing.com", "icourse163.org", "youdao.com", "hujiang.com", "zhihuishu.com",
        // 金融医疗
        "cmbchina.com", "ccb.com", "unionpay.com", "eastmoney.com", "xueqiu.com", "pingan.com",
        "haodf.com", "chunyuyisheng.com", "guahao.com",
        // 其他
        "10010.com", "cn.bing.com", "chuapp.com",

    ]

    /// 订阅把 Apple 服务指向了代理组;本机平时用国区账号,直连更快。这一组覆盖订阅里
    /// 所有苹果相关的代理规则:`apple.com` 一条就罩住 `itunes.apple.com`、`apps.apple.com`、
    /// `testflight.apple.com`、`hls.itunes.apple.com` 等子域。
    public static let apple: [String] = [
        "apple.com", "apple.co", "apple-cloudkit.com", "cdn-apple.com",
        "icloud.com", "icloud-content.com", "me.com", "mzstatic.com",
        // 不在 apple.com 之下(落在 akadns.net),订阅单独给了代理规则。
        "www-cdn.icloud.com.akadns.net",
    ]

    public static var domains: [String] { domestic + apple }

    /// 把内置清单前置到订阅规则之前。已经指向直连出口的同名规则不再重复插入;
    /// 指向代理的同名规则不阻止插入——更靠前的那一条才会生效。
    /// `includeApple` 为假时不注入苹果那一组,订阅的苹果服务代理规则得以生效。
    public static func prepending(to existing: [String], campus: String,
                                  includeApple: Bool = true) -> [String] {
        var alreadyDirect = Set<String>()
        for rule in existing {
            let fields = rule.components(separatedBy: ",")
            guard fields.count >= 3 else { continue }
            let target = fields[2].trimmingCharacters(in: .whitespaces)
            guard target == campus || target.uppercased() == "DIRECT" else { continue }
            alreadyDirect.insert(fields[1].lowercased())
        }
        let wanted = includeApple ? domains : domestic
        let injected = wanted
            .filter { !alreadyDirect.contains($0) }
            .map { "DOMAIN-SUFFIX,\($0),\(campus)" }
        return injected + existing
    }
}
