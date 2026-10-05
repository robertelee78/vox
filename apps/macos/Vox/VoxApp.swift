// Vox.app: the native macOS client of the account's vox daemon (ADR-014, ADR-028).
//
// The app hosts no node (M-2). It acts as one node, chosen at first run (E-4, M-6), attached on
// launch and let go of on quit (A-4): the daemon then detaches it, unless it is kept or another
// client holds it.

import AppKit
import SwiftUI

@main
struct VoxApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        Window("Vox", id: "main") {
            RootView(model: delegate.model)
                .frame(minWidth: 520, minHeight: 360)
        }
    }
}

/// The app's lifecycle: start on launch, let go of the node on quit.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = AppModel()

    func applicationDidFinishLaunching(_ notification: Notification) {
        Task { await model.start() }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    /// Quitting lets go of the node before the app exits (A-4), so the daemon has detached it
    /// when the app is gone.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard model.holdsNode else { return .terminateNow }
        Task {
            await model.quit()
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}
