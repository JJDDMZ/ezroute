import AppKit
import SwiftUI

/// Settings 场景可能保留视图，窗口关闭或最小化时也必须停止轮询。
struct SettingsWindowVisibility: NSViewRepresentable {
    @Binding var isVisible: Bool

    func makeNSView(context: Context) -> VisibilityView {
        let view = VisibilityView()
        view.changed = update
        return view
    }

    func updateNSView(_ view: VisibilityView, context: Context) {
        view.changed = update
        view.publish()
    }

    private func update(_ visible: Bool) {
        if isVisible != visible { isVisible = visible }
    }

    final class VisibilityView: NSView {
        var changed: (Bool) -> Void = { _ in }
        private var observers: [NSObjectProtocol] = []
        private var revision = 0

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            revision += 1
            for observer in observers { NotificationCenter.default.removeObserver(observer) }
            observers = []
            if let window {
                for name in [NSWindow.didChangeOcclusionStateNotification, NSWindow.didMiniaturizeNotification,
                             NSWindow.didDeminiaturizeNotification, NSWindow.willCloseNotification] {
                    let closing = name == NSWindow.willCloseNotification
                    observers.append(NotificationCenter.default.addObserver(forName: name, object: window,
                                                                            queue: .main) { [weak self] _ in
                        Task { @MainActor in self?.publish(closing: closing) }
                    })
                }
            }
            publish()
        }

        func publish(closing: Bool = false) {
            let visible = !closing && (window.map { $0.isVisible && !$0.isMiniaturized } ?? false)
            let revision = revision
            // 视图更新与窗口附着期间不直接修改 SwiftUI 状态。
            Task { @MainActor [weak self] in
                guard let self, self.revision == revision else { return }
                self.changed(visible)
            }
        }

        isolated deinit {
            for observer in observers { NotificationCenter.default.removeObserver(observer) }
        }
    }
}
