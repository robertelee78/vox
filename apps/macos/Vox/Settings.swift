// The Settings window (Vox > Settings…, ⌘,): the choices that shape how Vox runs, each kept where
// a person looks for it afterwards. Keep Running and the menu bar item were asked once, at first
// run, and the menu bar item could be hidden with nothing to bring it back; the text size was only
// in the View menu. Each is one control whose words say what it does.

import ServiceManagement
import SwiftUI

struct SettingsView: View {
    @ObservedObject var app: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            setting {
                // The one Keep Running switch: the same call as Vox > Keep Running While Logged In
                // (#571), so the two always agree.
                Toggle("Keep Vox running while you're logged in", isOn: Binding(
                    get: { app.keepRunning },
                    set: { on in Task { await app.setKeepRunning(on) } }))
                    .accessibilityIdentifier("settings-keep-running")
            } said: {
                Text("Your rooms stay reachable with this window closed. Vox adds itself to Login "
                    + "Items, and macOS may ask you to allow it in System Settings.")
                if app.keepRunning, let state = KeepRunningState.now() {
                    Text(state.words)
                        .accessibilityIdentifier("settings-keep-running-state")
                    if state == .waiting {
                        Button("Open Login Items") { KeepRunningState.openLoginItems() }
                    }
                }
            }
            setting {
                Toggle("Show Vox in the menu bar", isOn: Binding(
                    get: { app.menuBar },
                    set: { app.showMenuBar($0) }))
                    .accessibilityIdentifier("settings-menu-bar")
            } said: {
                Text("What needs you, your shares and your live tunnels, one click away.")
            }
            setting {
                Picker("Text size", selection: Binding(
                    get: { app.textScale },
                    set: { app.setTextSize($0) })) {
                    ForEach(Theme.scales, id: \.self) { scale in
                        Text(TextSize.words(scale)).tag(scale)
                    }
                }
                .fixedSize()
                .accessibilityIdentifier("settings-text-size")
            } said: {
                Text("View > Bigger (⌘+) and Smaller (⌘−) step through the same sizes.")
            }
        }
        .padding(24)
        .frame(width: Theme.scaled(460), alignment: .topLeading)
        .contentSurface()
    }

    /// One setting: its control, then what it does in secondary text.
    private func setting(@ViewBuilder _ control: () -> some View,
                         @ViewBuilder said: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            control()
            VStack(alignment: .leading, spacing: 4) { said() }
                .secondaryText()
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// A text size, in words: a percentage of Actual Size.
enum TextSize {
    static func words(_ scale: Double) -> String {
        let percent = Int((scale * 100).rounded())
        return scale == 1 ? "\(percent)% (Actual Size)" : "\(percent)%"
    }
}

/// Where the login item stands, said under Keep Running while it is on.
enum KeepRunningState: Equatable {
    case approved, waiting

    /// Its state now, or nil when there is nothing to say.
    static func now() -> KeepRunningState? {
        switch Daemon.loginItem.status {
        case .enabled: return .approved
        case .requiresApproval: return .waiting
        default: return nil
        }
    }

    var words: String {
        switch self {
        case .approved: return "On, and allowed in Login Items."
        case .waiting: return "Waiting for you to allow Vox in System Settings, General, Login Items. "
            + "Until then Vox runs while it is open."
        }
    }

    /// System Settings' Login Items, through the one Keep Running implementation (#571): a proof
    /// build only records the request.
    static func openLoginItems() { Daemon.openLoginItems() }
}
