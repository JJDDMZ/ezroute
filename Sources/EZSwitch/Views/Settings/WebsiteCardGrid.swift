import SwiftUI
import EZSwitchCore

struct WebsiteCardGrid: View {
    let cards: [WebsiteCard]
    let running: Bool
    let showVerdict: Bool
    let remove: (String) -> Void

    private let columns = Array(repeating: GridItem(.flexible(), spacing: 8), count: 3)

    var body: some View {
        LazyVGrid(columns: columns, alignment: .leading, spacing: 8) {
            ForEach(cards) { card in
                VStack(alignment: .leading, spacing: 5) {
                    HStack(alignment: .top, spacing: 4) {
                        Text(card.host).font(.caption).bold().lineLimit(2).textSelection(.enabled)
                        Spacer(minLength: 0)
                        Button { remove(card.host) } label: {
                            Image(systemName: "xmark.circle.fill").font(.caption)
                        }
                        .buttonStyle(.plain)
                        .disabled(running)
                        .accessibilityLabel("移除 \(card.host)")
                    }
                    if let alias = card.alias {
                        Text(alias).font(.caption2).foregroundStyle(.secondary)
                    }
                    if !card.egress.isEmpty {
                        Text(card.egress).font(.caption2)
                            .fixedSize(horizontal: false, vertical: true)
                            .textSelection(.enabled)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(.quaternary, in: .rect(cornerRadius: 4))
                    }
                    if !card.status.isEmpty {
                        Text(card.status).font(.caption2).foregroundStyle(.secondary)
                    }
                    if showVerdict {
                        Label(title(card.verdict), systemImage: symbol(card.verdict))
                            .font(.caption2).foregroundStyle(color(card.verdict))
                    }
                    Spacer(minLength: 0)
                }
                .padding(8)
                .frame(maxWidth: .infinity, minHeight: 110, alignment: .topLeading)
                .background(.quaternary.opacity(0.35), in: .rect(cornerRadius: 7))
                .overlay {
                    RoundedRectangle(cornerRadius: 7)
                        .strokeBorder(color(card.verdict).opacity(showVerdict ? 0.65 : 0.15), lineWidth: 1)
                }
            }
        }
    }

    private func title(_ verdict: RoutingCheckVerdict) -> String {
        switch verdict {
        case .pass: "符合预期"
        case .fail: "发现不符"
        case .unknown: "证据不足"
        }
    }

    private func symbol(_ verdict: RoutingCheckVerdict) -> String {
        switch verdict {
        case .pass: "checkmark.circle"
        case .fail: "exclamationmark.triangle"
        case .unknown: "questionmark.circle"
        }
    }

    private func color(_ verdict: RoutingCheckVerdict) -> Color {
        switch verdict {
        case .pass: .green
        case .fail: .orange
        case .unknown: .secondary
        }
    }
}
