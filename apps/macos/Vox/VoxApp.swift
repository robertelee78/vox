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
    /// The app's model, the one the delegate starts and quits, observed here: the menu bar
    /// extra's `isInserted` is read again when the person turns it on or off.
    @StateObject private var model = AppModel.shared

    init() {
        // `vox uninstall`: unregister the background items and exit, before any window or daemon.
        if CommandLine.arguments.contains(Uninstall.flag) {
            Uninstall.unregisterAndExit()
        }
    }

    var body: some Scene {
        Window("Vox", id: "main") {
            RootView(model: model)
                // A vox:// room link opened anywhere (Mail, Messages, a browser) opens the Join
                // sheet with it filled in; joining still takes the room's passphrase and a click.
                .onOpenURL { model.openLink($0) }
                // Every view's text in the app's face and size; drawn again when the size
                // changes (View > Bigger, Smaller, Actual Size).
                .font(Theme.text)
                .controlSize(Theme.controls)
                .buttonStyle(VoxButtonStyle())
                .id(model.textScale)
                // The sidebar (260) and the inspector (240) leave the room 400 or more: room
                // for the composer's field beside its To: and Urgent controls.
                .frame(minWidth: 900, minHeight: 360)
                // Dark is the one theme (ADR-028 L-2).
                .preferredColorScheme(.dark)
        }
        .commands { VoxCommands(app: model) }
        // Vox > Settings… (⌘,): Keep Running, the menu bar item and the text size, where a person
        // looks for them after first run.
        Settings {
            SettingsView(app: model)
                .font(Theme.text)
                .controlSize(Theme.controls)
                .buttonStyle(VoxButtonStyle())
                .id(model.textScale)
                .preferredColorScheme(.dark)
        }
        // Off until the person turns it on (M-22). Its image is the Vox mark as a template
        // (assets/brand/vox-menubar.svg, made into MenuBarIcon by scripts/brand-icon.sh), which
        // macOS draws in the menu bar's own colour.
        MenuBarExtra("Vox", image: "MenuBarIcon",
                     isInserted: Binding(get: { model.menuBar },
                                         set: { model.showMenuBar($0) })) {
            MenuBarContent(app: model)
                .font(Theme.text)
                .controlSize(Theme.controls)
                .buttonStyle(VoxButtonStyle())
                .id(model.textScale)
                .preferredColorScheme(.dark)
        }
        .menuBarExtraStyle(.window)
    }
}

/// The app's lifecycle: start on launch, let go of the node on quit.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    var model: AppModel { AppModel.shared }
    /// SIGTERM, SIGHUP and SIGINT, each a clean quit (ADR-026 S-4).
    private var stops: [DispatchSourceSignal] = []

    func applicationDidFinishLaunching(_ notification: Notification) {
        // **A stop signal quits the app as ⌘Q does** (ADR-026 S-4): the node is let go of by the
        // same rule, rather than the process ending under it.
        for sig in [SIGTERM, SIGHUP, SIGINT] {
            signal(sig, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            // Out of the queue's callout: terminating runs a nested event loop until the node is
            // let go of, and that work is on the main queue, which a callout would hold. A run-loop
            // timer, not RunLoop.perform: that queues the block without waking the loop, and an
            // idle app then never quit.
            source.setEventHandler {
                NSApp.perform(#selector(NSApplication.terminate(_:)), with: nil, afterDelay: 0)
            }
            source.resume()
            stops.append(source)
        }
        // The Finder Services item (M-24).
        services = ServicesProvider(app: model)
        NSApp.servicesProvider = services
        Task { await model.start() }
    }

    private var services: ServicesProvider?

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
