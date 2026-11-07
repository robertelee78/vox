// The Settings window (Vox > Settings…, ⌘,): the choices that shape how Vox runs, each kept where
// a person looks for it afterwards. Keep Running and the menu bar item were asked once, at first
// run, and the menu bar item could be hidden with nothing to bring it back; the text size was only
// in the View menu. Each is one control whose words say what it does.

import AppKit
import ServiceManagement
import SwiftUI

private enum SettingsFocus: Hashable {
    case setup(String), keepRunning, loginItems, menuBar, update, restart
    case computers, network, daemonLog, textSize
}

struct SettingsView: View {
    @ObservedObject var app: AppModel
    @State private var showingComputers = false
    @State private var showingNetwork = false
    @State private var repoDirectory: URL?
    @State private var showingRepoDecision = false
    @FocusState private var focused: SettingsFocus?

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView { settings }
                .frame(idealHeight: 605)
                .frame(width: Theme.scaled(460), alignment: .topLeading)
                .contentSurface()
                .onChange(of: focused) { target in
                    if let target { proxy.scrollTo(target) }
                }
                .sheet(isPresented: $showingComputers) { ComputerTrustView() }
                .sheet(isPresented: $showingNetwork) { NetworkSettingsView() }
                .sheet(isPresented: $showingRepoDecision) {
                    if let node = app.node, let directory = repoDirectory {
                        RepoDecisionView(model: node, directory: directory.path, decline: false) {
                            showingRepoDecision = false
                        }
                    }
                }
        }
    }

    private var settings: some View {
        VStack(alignment: .leading, spacing: Space.s20) {
            setting {
                Button("Rebind Repository…") {
                    let panel = NSOpenPanel()
                    panel.canChooseFiles = false
                    panel.canChooseDirectories = true
                    panel.allowsMultipleSelection = false
                    if panel.runModal() == .OK, let url = panel.url {
                        repoDirectory = url
                        showingRepoDecision = true
                    }
                }
                .accessibilityIdentifier("settings-rebind-repository")
                .disabled(app.node == nil)
            } said: {
                Text("Choose a repository and review its current room decision before changing it.")
            }
            if !app.agentSetups.isEmpty {
                setting {
                    ForEach(app.agentSetups) { request in
                        HStack {
                            Text(request.name)
                            Spacer()
                            Button("Set Up") { app.offerAgentSetup(request) }
                                .accessibilityIdentifier("settings-agent-setup-\(request.harness)")
                                .focused($focused, equals: .setup(request.id))
                                .id(SettingsFocus.setup(request.id))
                        }
                    }
                } said: {
                    Text("Set up a harness for Vox here, including one you chose Not Now for.")
                }
            }
            setting {
                // The one Keep Running switch: the same call as Vox > Keep Running While Logged In
                // (#571), so the two always agree.
                Toggle("Keep Vox running while you're logged in", isOn: Binding(
                    get: { app.keepRunning },
                    set: { on in Task { await app.setKeepRunning(on) } }))
                    .accessibilityIdentifier("settings-keep-running")
                    .focused($focused, equals: .keepRunning)
                    .id(SettingsFocus.keepRunning)
            } said: {
                Text("Your rooms stay reachable with this window closed. Vox adds itself to Login "
                    + "Items, and macOS may ask you to allow it in System Settings.")
                if app.keepRunning, let state = KeepRunningState.now() {
                    Text(state.words)
                        .accessibilityIdentifier("settings-keep-running-state")
                    if state == .waiting {
                        Button("Open Login Items") { KeepRunningState.openLoginItems() }
                            .focused($focused, equals: .loginItems)
                            .id(SettingsFocus.loginItems)
                    }
                }
            }
            setting {
                Toggle("Show Vox in the menu bar", isOn: Binding(
                    get: { app.menuBar },
                    set: { app.showMenuBar($0) }))
                    .accessibilityIdentifier("settings-menu-bar")
                    .focused($focused, equals: .menuBar)
                    .id(SettingsFocus.menuBar)
            } said: {
                Text("What needs you, your shares and your live tunnels, one click away.")
            }
            setting {
                HStack {
                    Button("Update Vox") { Task { await app.updateVox() } }
                        .disabled(app.updating)
                        .accessibilityIdentifier("settings-update")
                        .focused($focused, equals: .update)
                        .id(SettingsFocus.update)
                    if app.updating { ProgressView("Updating Vox…") }
                    if app.updated {
                        Button("Restart Vox") { app.reopenUpdatedApp() }
                            .accessibilityIdentifier("settings-update-restart")
                            .focused($focused, equals: .restart)
                            .id(SettingsFocus.restart)
                    }
                }
            } said: {
                Text("Installs the latest release and restarts its daemon. Remembered nodes return automatically; held sessions end.")
                if let said = app.updateSaid {
                    Text(said).textSelection(.enabled)
                        .accessibilityIdentifier("settings-update-said")
                }
            }
            setting {
                Button("Add Computer…") { showingComputers = true }
                    .accessibilityIdentifier("settings-add-computer")
                    .focused($focused, equals: .computers)
                    .id(SettingsFocus.computers)
            } said: {
                Text("Trust the nodes on your computers together, or keep choosing individual nodes.")
            }
            setting {
                Button("Network…") { showingNetwork = true }
                    .accessibilityIdentifier("settings-network")
                    .focused($focused, equals: .network)
                    .id(SettingsFocus.network)
            } said: {
                Text("Add or remove this machine's anchors, and see each anchor's source and reach.")
            }
            if let node = app.node { DaemonLogSetting(node: node, focused: $focused) }
            setting {
                Picker("Conversation text size", selection: Binding(
                    get: { app.textScale },
                    set: { app.setTextSize($0) })) {
                    ForEach(Theme.scales, id: \.self) { scale in
                        Text(TextSize.words(scale)).tag(scale)
                    }
                }
                .fixedSize()
                .accessibilityIdentifier("settings-text-size")
                .focused($focused, equals: .textSize)
                .id(SettingsFocus.textSize)
            } said: {
                Text("The messages and the composer, as View > Bigger (⌘+) and Smaller (⌘−) set it. The "
                    + "sidebar keeps macOS's sidebar size.")
            }
        }
        .padding(Space.s24)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .focusSection()
    }

    /// One setting: its control, then what it does in secondary text.
    private func setting(@ViewBuilder _ control: () -> some View,
                         @ViewBuilder said: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: Space.s8) {
            control()
            VStack(alignment: .leading, spacing: Space.s4) { said() }
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

/// Observe the node directly: the first status report may arrive while Settings is open.
private struct DaemonLogSetting: View {
    @ObservedObject var node: NodeModel
    var focused: FocusState<SettingsFocus?>.Binding
    var body: some View {
        if let path = node.logPath {
            VStack(alignment: .leading, spacing: Space.s8) {
                Button("Show Daemon Log in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
                }
                .accessibilityIdentifier("settings-daemon-log")
                .focused(focused, equals: .daemonLog)
                .id(SettingsFocus.daemonLog)
                Text("Daemon log: \(path)").secondaryText().textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("settings-daemon-log-path")
            }
        }
    }
}
