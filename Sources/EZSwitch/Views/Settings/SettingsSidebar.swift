import SwiftUI
import EZSwitchCore

struct SettingsSidebar: View {
    @Bindable var model: AppModel
    @State private var selected: SettingsPane = .overview
    @State private var monitor = ConnectionMonitorModel(directory: TrafficStore.defaultDirectory)
    @State private var websiteTests = WebsiteTestModel()
    @State private var windowVisible = false

    var body: some View {
        NavigationSplitView {
            List(SettingsPane.allCases, selection: $selected) { pane in
                Label(pane.title, systemImage: pane.symbol).tag(pane)
            }
            .listStyle(.sidebar)
            .navigationSplitViewColumnWidth(min: 170, ideal: 180, max: 200)
        } detail: {
            detail
        }
        .frame(width: 760, height: 560)
        .background(SettingsWindowVisibility(isVisible: $windowVisible).frame(width: 0, height: 0))
    }

    @ViewBuilder private var detail: some View {
        switch selected {
        case .overview:    OverviewPane(routing: .shared)
        case .devices:     DevicesPane(routing: .shared, model: model)
        case .diagnostics: DiagnosticsPane(routing: .shared, websiteTests: websiteTests,
                                          monitor: monitor, visible: windowVisible)
        case .general:     GeneralPane(model: model)
        }
    }
}
