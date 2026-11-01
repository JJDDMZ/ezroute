import SwiftUI
import EZSwitchCore

struct StrictWhitelistView: View {
    let appleViaProxy: Bool
    @Environment(\.dismiss) private var dismiss
    @State private var search = ""

    private func visible(_ host: String) -> Bool { search.isEmpty || host.localizedCaseInsensitiveContains(search) }
    private var campusSuffixes: [String] {
        RoutingStrictDomains.suffixes.filter { $0 == "campus.example" || $0.hasSuffix(".campus.example") }
    }
    private var domesticSuffixes: [String] {
        RoutingStrictDomains.suffixes.filter { !($0 == "campus.example" || $0.hasSuffix(".campus.example")) }
    }

    var body: some View {
        VStack(alignment: .leading) {
            Text("严格保护直连白名单").font(.title2).padding([.top, .horizontal])
            Text("已有拒绝和代理例外优先。上报/统计端点与境外站点不授予校园直连；Apple 中继不直连；名单不会随订阅扩大。")
                .font(.caption).foregroundStyle(.secondary).padding(.horizontal)
            List {
                if !campusSuffixes.isEmpty {
                    Section("校内域名（整域）") {
                        ForEach(campusSuffixes, id: \.self) { Text($0).textSelection(.enabled) }
                    }
                }
                Section("非 Apple · 服务域名及子域（\(domesticSuffixes.count)）") {
                    ForEach(domesticSuffixes.filter(visible), id: \.self) { Text($0).textSelection(.enabled) }
                }
                Section("非 Apple · 精确主机（\(RoutingStrictDomains.exact.count)）") {
                    ForEach(RoutingStrictDomains.exact.filter(visible), id: \.self) { Text($0).textSelection(.enabled) }
                }
                Section(appleViaProxy ? "Apple · 已设为 USB 代理（\(RoutingStrictDomains.apple.count)）" : "Apple · 精确直连主机（\(RoutingStrictDomains.apple.count)）") {
                    ForEach(RoutingStrictDomains.apple.filter(visible), id: \.self) { Text($0).textSelection(.enabled) }
                }
            }
            .searchable(text: $search, prompt: "查找域名")
            Text("另有 \(RoutingStrictDomains.excludedHosts.count + RoutingStrictDomains.excludedSuffixes.count) 条显式排除（上报/统计与境外站点）不在此列表内。")
                .font(.caption).foregroundStyle(.secondary).padding(.horizontal)
            HStack { Spacer(); Button("完成") { dismiss() }.keyboardShortcut(.defaultAction) }.padding()
        }
        .frame(minWidth: 520, minHeight: 500)
    }
}
