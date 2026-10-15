import SwiftUI

struct SettingsView: View {
    @Bindable var model: AppModel

    var body: some View {
        SettingsSidebar(model: model)
    }
}
