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
    /// Publish only outside representable updates. The live identity/visibility guard also
    /// makes a detached or replaced attachment ineligible before that publication runs.
    @Published private var visibleAttachment: UUID?
    var seen: Bool { visibleAttachment == attachment && isVisible }

    private weak var window: NSWindow?
    private var owner: UUID?
    private var attachment = UUID()
    private var watching: [NSObjectProtocol] = []
    private var updateTask: Task<Void, Never>?
    private var updateToken: UUID?

    func attach(_ window: NSWindow?, owner: UUID) {
        guard owner != self.owner || window !== self.window else { return }
        retireAttachment()
        self.owner = owner
        self.window = window
        guard let window else { scheduleUpdate(); return }
        let attachment = attachment
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
                MainActor.assumeIsolated {
                    guard let self, self.attachment == attachment else { return }
                    self.scheduleUpdate()
                }
            }
        }
        scheduleUpdate()
    }

    /// An old represented view must not detach or move its replacement's attachment.
    func moved(to window: NSWindow?, owner: UUID) {
        guard self.owner == owner else { return }
        attach(window, owner: owner)
    }

    func detach(owner: UUID) {
        guard self.owner == owner else { return }
        retireAttachment()
        self.owner = nil
        window = nil
        scheduleUpdate()
    }

    private func retireAttachment() {
        attachment = UUID()
        updateTask?.cancel()
        updateTask = nil
        updateToken = nil
        watching.forEach(NotificationCenter.default.removeObserver)
        watching = []
    }

    private var isVisible: Bool {
        guard owner != nil, let window else { return false }
        return NSApp.isActive && !NSApp.isHidden && window.isKeyWindow && !window.isMiniaturized
            && window.occlusionState.contains(.visible)
    }

    private func scheduleUpdate() {
        guard updateTask == nil else { return }
        let token = UUID(), attachment = attachment
        updateToken = token
        updateTask = Task { @MainActor [weak self] in
            guard let self, !Task.isCancelled, self.updateToken == token,
                  self.attachment == attachment else { return }
            self.updateTask = nil
            self.updateToken = nil
            // Never replay a Bool captured during attachment or a window notification.
            let visible = self.isVisible ? attachment : nil
            // A view may have sampled live visibility while it was false and then true again
            // before this coalesced update. Publish even when the attachment is unchanged.
            self.visibleAttachment = visible
        }
    }

    deinit {
        updateTask?.cancel()
        watching.forEach(NotificationCenter.default.removeObserver)
    }
}

/// Hands the view's window to `seen` when the view joins it. Asked once, a beat after the view was
/// made, a view not yet in its window gave nil and was never asked again: a room opened that way
/// never counted as seen, and nothing in it was read (seen in the QE pass's read log).
struct WindowReader: NSViewRepresentable {
    let seen: WindowSeen

    func makeNSView(context: Context) -> WindowWatcher {
        let view = WindowWatcher()
        view.use(seen)
        return view
    }

    func updateNSView(_ view: WindowWatcher, context: Context) {
        view.use(seen)
    }

    static func dismantleNSView(_ view: WindowWatcher, coordinator: ()) {
        view.detach()
    }

    /// Says when it joins a window.
    final class WindowWatcher: NSView {
        private let owner = UUID()
        private weak var seen: WindowSeen?

        func use(_ seen: WindowSeen) {
            if self.seen !== seen {
                self.seen?.detach(owner: owner)
                self.seen = seen
            }
            seen.attach(window, owner: owner)
        }

        func detach() {
            seen?.detach(owner: owner)
            seen = nil
        }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            let window = window
            MainActor.assumeIsolated { seen?.moved(to: window, owner: owner) }
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
