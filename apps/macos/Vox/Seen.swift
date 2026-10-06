// What the person can see now (ADR-028 R-6: read means shown to a person): whether the window is
// in front of them, and which timeline rows lie inside the visible part of the timeline. A row a
// lazy list prepares off screen, or one drawn while the window is hidden, minimized, covered or
// not the key window, or while the app is not active, is not seen.

import AppKit
import SwiftUI

/// Whether the window holding a view is in front of the person: the app active and not hidden,
/// the window key, not minimized and not covered.
@MainActor
final class WindowSeen: ObservableObject {
    @Published private(set) var seen = false
    private weak var window: NSWindow?
    private var watching: [NSObjectProtocol] = []

    func attach(_ window: NSWindow?) {
        guard let window, window !== self.window else { return }
        self.window = window
        watching.forEach(NotificationCenter.default.removeObserver)
        let names: [(Notification.Name, AnyObject?)] = [
            (NSWindow.didBecomeKeyNotification, window),
            (NSWindow.didResignKeyNotification, window),
            (NSWindow.didMiniaturizeNotification, window),
            (NSWindow.didDeminiaturizeNotification, window),
            (NSWindow.didChangeOcclusionStateNotification, window),
            (NSApplication.didHideNotification, nil),
            (NSApplication.didUnhideNotification, nil),
            (NSApplication.didBecomeActiveNotification, nil),
            (NSApplication.didResignActiveNotification, nil),
        ]
        watching = names.map { name, object in
            NotificationCenter.default.addObserver(forName: name, object: object, queue: .main) {
                [weak self] _ in
                MainActor.assumeIsolated { self?.update() }
            }
        }
        update()
    }

    private func update() {
        guard let window else {
            seen = false
            return
        }
        seen = NSApp.isActive && !NSApp.isHidden && window.isKeyWindow && !window.isMiniaturized
            && window.occlusionState.contains(.visible)
    }
}

/// Hands the view's window to `seen` when the view joins it. Asked once, a beat after the view was
/// made, a view not yet in its window gave nil and was never asked again: a room opened that way
/// never counted as seen, and nothing in it was read (seen in the QE pass's read log).
struct WindowReader: NSViewRepresentable {
    let seen: WindowSeen

    func makeNSView(context: Context) -> NSView {
        let view = WindowWatcher()
        view.joined = { [weak seen] window in seen?.attach(window) }
        return view
    }

    func updateNSView(_ view: NSView, context: Context) {
        if let window = view.window { seen.attach(window) }
    }

    /// Says when it joins a window.
    final class WindowWatcher: NSView {
        var joined: ((NSWindow?) -> Void)?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            let window = window
            MainActor.assumeIsolated { joined?(window) }
        }
    }
}

/// Each timeline row's frame in the timeline's own coordinates, by message id.
struct RowFrames: PreferenceKey {
    static var defaultValue: [String: CGRect] = [:]

    static func reduce(value: inout [String: CGRect], nextValue: () -> [String: CGRect]) {
        value.merge(nextValue()) { $1 }
    }
}

extension View {
    /// Report this row's frame in the timeline's coordinates, for what is visible.
    func reportsFrame(of id: String) -> some View {
        background(GeometryReader { geo in
            Color.clear.preference(key: RowFrames.self,
                                   value: [id: geo.frame(in: .named("timeline"))])
        })
    }
}
