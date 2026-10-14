// What the app is doing, and the one node it acts as (ADR-014 M-6, ADR-028 E-4).

import AppKit
import Foundation
import Combine
import ServiceManagement
@MainActor
final class AppModel: ObservableObject {
    /// The one model: the app observes it, and its delegate starts it and quits it.
    static let shared = AppModel()

    /// Where the app is, from launch to an attached node.
    enum Phase: Equatable {
        /// First run: whether to keep the daemon running while the person is logged in (M-8).
        case askingLoginItem
        /// The login item waits for the person's approval in System Settings; the system's
        /// sentence when registering it failed.
        case loginItemApproval(said: String?)
        /// Reaching the daemon.
        case starting
        /// The daemon could not be reached, or the node not attached for a reason no passphrase
        /// fixes: what kind of failure, and the sentence said (P4).
        case unreachable(StartFailure)
        /// The data root holds an earlier release's node directories, which this version does not
        /// read (the daemon refuses it): offered to be moved aside (#576). Their paths; the
        /// sentence after a failed move.
        case oldLayout(dirs: [String], said: String?)
        /// First run on a Mac with no node yet: make one here; the sentence after a failed try.
        case welcome(said: String?)
        /// Making node `node`, then attaching it.
        case creating(node: String)
        /// First run: several nodes on this Mac, none chosen yet. Their names.
        case choosing([String])
        /// The node needs its identity passphrase to attach; the daemon's sentence after a
        /// failed try.
        case passphrase(node: String, said: String?)
        /// Attaching, with the passphrase given.
        case attaching(node: String)
        /// Acting as `node`, whose fingerprint is `fingerprint`.
        case attached(node: String, fingerprint: String)
        /// `node` was detached from this window (Node > Detach): it may be attached again, and
        /// nothing else (E-4). Acting as another node is a fresh first run, not a menu action.
        case detached(node: String)
    }

    @Published private(set) var phase: Phase = .starting {
        didSet {
            // Read once, as the daemon is found unreachable, not each time a view draws.
            if case .unreachable = phase {
                loginItemSaid = keepRunning ? Daemon.loginItemSaid() : nil
            } else if loginItemSaid != nil {
                loginItemSaid = nil
            }
        }
    }
    /// Whether the menu bar extra is shown: off until the person turns it on (M-22).
    @Published private(set) var menuBar = MenuBarChoice.on()
    /// The app's text size (Theme.scale): the window is drawn again when it changes.
    @Published private(set) var textScale = Theme.scale

    /// Step the app's text size `by` sizes (+1 Bigger, -1 Smaller), or back to Actual Size (0).
    func stepTextSize(_ by: Int) {
        let i = Theme.scales.firstIndex(of: Theme.scale) ?? 1
        let next = by == 0 ? 1 : Theme.scales[max(0, min(Theme.scales.count - 1, i + by))]
        UserDefaults.standard.set(next, forKey: Theme.scaleKey)
        textScale = next
    }

    /// Set the app's text size to one of `Theme.scales` (Settings), as Bigger and Smaller step it.
    func setTextSize(_ scale: Double) {
        guard Theme.scales.contains(scale), scale != textScale else { return }
        UserDefaults.standard.set(scale, forKey: Theme.scaleKey)
        textScale = scale
    }

    /// Show or hide the menu bar extra, and keep the choice. Setting the value it already has does
    /// nothing: SwiftUI sets a MenuBarExtra's `isInserted` on its updates, and a change notice for
    /// each of those started another update, so the main thread never went idle.
    func showMenuBar(_ on: Bool) {
        guard on != menuBar else { return }
        menuBar = on
        MenuBarChoice.set(on)
    }
    /// The node acted as, once attached: what the main window shows.
    private var nodeChanges: AnyCancellable?
    @Published private(set) var node: NodeModel? {
        didSet {
            nodeChanges = node?.objectWillChange.sink { [weak self] _ in
                self?.objectWillChange.send()
            }
        }
    }
    private var client: VoxClient?
    /// Changed harness configuration files, reported by the launch's light-hook installation.
    @Published var agentSetupSaid: String?
    @Published private(set) var agentSetups: [AgentSetupRequest] = []
    @Published private(set) var agentSetupOffers: [AgentSetupRequest] = []
    @Published var agentSetupAsk: AgentSetupRequest?
    @Published private(set) var agentSetupBusy = false
    @Published private(set) var agentSetupFailed: String?
    private var agentSetupTimer: Timer?

    /// Whether the person chose Keep Running at first run: then a node is kept attached when the
    /// app quits, once its passphrase is in the Keychain or it needs none (ADR-014 M-6, M-8).
    /// Read once, then kept as the person answers: views read it as they draw, and the answer is
    /// a file.
    @Published private(set) var keepRunning = Daemon.kept() == true

    /// Whether the app holds a node the daemon is to let go of when it quits.
    var holdsNode: Bool {
        if case .attached = phase { return true }
        return false
    }

    /// Ask about the login item at first run; then reach the daemon, and attach the node chosen at
    /// first run, or ask which.
    func start() async {
        AgentSetupStore.registerApp()
        refreshAgentSetups()
        if agentSetupTimer == nil {
            agentSetupTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
                Task { @MainActor in self?.refreshAgentSetups() }
            }
        }
        Daemon.refreshSkillPack { [weak self] said in self?.agentSetupSaid = said }
        if Daemon.kept() == nil {
            phase = .askingLoginItem
            return
        }
        await reach()
    }

    /// The person's answer at first run: keep the daemon running while logged in, or not now.
    func answerLoginItem(keep: Bool) async {
        guard keep else {
            Daemon.remember(kept: false)
            keepRunning = false
            await reach()
            return
        }
        let status: SMAppService.Status
        do {
            status = try Daemon.startKeeping()
        } catch {
            keepRunning = false
            phase = .loginItemApproval(said: error.localizedDescription)
            return
        }
        keepRunning = true
        if status == .requiresApproval {
            phase = .loginItemApproval(said: nil)
            return
        }
        await reach()
    }

    /// Reach the daemon (the login item's, else one started as `vox` does), then attach the node
    /// chosen at first run, or ask which.
    func reach() async {
        let generation = beginNodeRequest()
        phase = .starting
        do {
            let client = try await Daemon.reach()
            guard nodeRequestGeneration == generation else { return }
            self.client = client
            let nodes = try await client.nodes()
            guard ownsNodeRequest(client, generation) else { return }
            let chosen = try await client.computerStatus().selectedName
            guard ownsNodeRequest(client, generation) else { return }
            if let chosen, let node = nodes.first(where: { $0.name == chosen }) {
                await use(node)
            } else {
                await offerNodes(nodes)
            }
        } catch {
            guard nodeRequestGeneration == generation else { return }
            // Refused for an earlier release's node directories: said plainly, with a way on.
            if let dirs = try? oldLayout(dataRoot: ""), !dirs.isEmpty {
                phase = .oldLayout(dirs: dirs, said: nil)
            } else {
                phase = .unreachable(StartFailure(error))
            }
        }
    }

    @Published private(set) var updating = false
    @Published private(set) var updateSaid: String?
    @Published private(set) var updated = false

    /// The app uses the same verified bundle replacement and daemon restart as `vox update`.
    func updateVox() async {
        guard !updating else { return }
        updating = true
        updateSaid = nil
        updated = false
        defer { updating = false }
        do {
            updateSaid = try await Daemon.command(["update"], patience: 300)
            updated = true
        } catch {
            updateSaid = sentence(error)
        }
    }

    /// Open the installed bundle after updating; the current process keeps its old code until quit.
    func reopenUpdatedApp() {
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.createsNewApplicationInstance = true
        NSWorkspace.shared.openApplication(at: Bundle.main.bundleURL, configuration: configuration) { _, error in
            Task { @MainActor in
                if let error { self.updateSaid = sentence(error) }
                else { NSApp.terminate(nil) }
            }
        }
    }

    /// Restart the same account's daemon using this app's bundled version (ADR-034 UP-2).
    func restartDaemon() async {
        let generation = beginNodeRequest()
        phase = .starting
        do {
            _ = try await Daemon.command(["daemon", "--restart"], patience: 45)
            guard nodeRequestGeneration == generation else { return }
            await reach()
        } catch {
            guard nodeRequestGeneration == generation else { return }
            phase = .unreachable(StartFailure(error))
        }
    }

    /// What was moved aside, from and to, said on the welcome that follows.
    @Published private(set) var movedAside: [MovedAside] = []

    /// Move the earlier release's node directories aside, whole and unread (#576), then start as on
    /// a Mac with no node: the welcome.
    func moveAside() async {
        let day = DateFormatter()
        day.locale = Locale(identifier: "en_US_POSIX")
        day.dateFormat = "yyyy-MM-dd"
        do {
            movedAside = try moveOldLayoutAside(dataRoot: "", date: day.string(from: Date()))
        } catch {
            let dirs = (try? oldLayout(dataRoot: "")) ?? []
            phase = .oldLayout(dirs: dirs, said: sentence(error))
            return
        }
        await reach()
    }

    /// No node chosen yet: none on this Mac, so make one here; one, so act as it without asking
    /// which; several, so ask which.
    private func offerNodes(_ nodes: [NodeSummary]) async {
        switch nodes.count {
        case 0: phase = .welcome(said: nil)
        case 1 where !AgentSetupStore.madeNode(nodes[0].name): await use(nodes[0])
        default:
            nodeList = nodes
            phase = .choosing(nodes.map(\.name))
        }
    }

    /// First run with no node: make node `name` here, as `vox node create` does, under the
    /// identity passphrase typed twice, then attach it with that passphrase. The bytes go into a
    /// `Passphrase` at once and are wiped (M-5).
    private var nodeActionInProgress = false
    var canChooseAppNode: Bool { node != nil && !nodeActionInProgress }
    /// Explicit CT-13 selection keeps the current window and its drafts until authenticated.
    @Published var appNodeChooser = false
    @Published private(set) var appNodeChoices: [NodeSummary] = []
    @Published private(set) var appNodeChoiceSaid: String?
    @Published private(set) var appNodeChoiceBusy = false

    func askAppNodeChoice() async {
        guard let client, node != nil, !nodeActionInProgress else { return }
        let generation = beginNodeRequest()
        appNodeChoiceSaid = nil
        do {
            let choices = try await client.nodes()
            guard ownsNodeRequest(client, generation) else { return }
            appNodeChoices = choices
            appNodeChooser = true
        } catch {
            guard ownsNodeRequest(client, generation) else { return }
            appNodeChoiceSaid = sentence(error)
            appNodeChooser = true
        }
    }

    func selectAppNode(_ name: String, fingerprint expected: String, passphrase secret: Secret) async {
        guard let original = client, let old = node, appNodeChooser,
              !nodeActionInProgress, appNodeChoices.contains(where: {
                  $0.name == name && $0.fingerprint == expected
              }) else { secret.wipe(); return }
        if old.me == expected { secret.wipe(); appNodeChooser = false; return }
        let generation = beginNodeRequest()
        nodeActionInProgress = true
        appNodeChoiceBusy = true
        defer { nodeActionInProgress = false; appNodeChoiceBusy = false }
        var prospective: VoxClient?
        var committed = false
        do {
            let passphrase = try secret.passphrase()
            defer { passphrase.wipe() }
            let connection = try await VoxClient.open(dataRoot: "")
            prospective = connection
            guard ownsNodeRequest(original, generation), self.node === old,
                  connection.configDir() == original.configDir() else {
                await connection.close(); return
            }
            let choices = try await connection.nodes()
            guard ownsNodeRequest(original, generation), self.node === old,
                  choices.contains(where: { $0.name == name && $0.fingerprint == expected }) else {
                await connection.close(); return
            }
            let actual = try await connection.attach(node: name, passphrase: passphrase)
            guard ownsNodeRequest(original, generation), self.node === old, actual == expected else {
                await connection.close(); return
            }
            // Only an authenticated, still-selected request changes the daemon's personal role.
            let selected = try await connection.selectPersonalNode(node: name)
            committed = true
            guard ownsNodeRequest(original, generation), self.node === old else {
                // The role committed while another request superseded this one. Capture that
                // request's generation: never revive this choice or write its local mirror.
                let reconciliationGeneration = nodeRequestGeneration
                await connection.close()
                guard !Task.isCancelled, nodeRequestGeneration == reconciliationGeneration,
                      self.client === original, self.node === old else { return }
                // Some superseding requests leave the old actor on screen. Start a new
                // authoritative reach so it cannot indefinitely contradict the saved role.
                await reach()
                return
            }
            guard selected.selectedNode == expected, selected.selectedName == name else {
                await connection.close()
                guard ownsNodeRequest(original, generation), self.node === old else { return }
                appNodeChooser = false
                appNodeChoiceSaid = "The daemon selected a different node. Reconnecting to its saved selection."
                await reach()
                return
            }
            self.client = connection
            enter(name, actual, connection)
            appNodeChooser = false
            do {
                let file = choiceFile(connection)
                try FileManager.default.createDirectory(at: file.deletingLastPathComponent(),
                    withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                try Data((name + "\n").utf8).write(to: file, options: .atomic)
            } catch {
                // The daemon already committed the role. Report the local mirror failure
                // without pretending the old node still acts in this window.
                let mirrorFailure = sentence(error)
                do {
                    let fresh = try await connection.nodes()
                    guard ownsNodeRequest(connection, generation), self.node?.me == expected else {
                        await original.close(); return
                    }
                    appNodeChoices = fresh
                    appNodeChoiceSaid = mirrorFailure
                } catch {
                    guard ownsNodeRequest(connection, generation), self.node?.me == expected else {
                        await original.close(); return
                    }
                    appNodeChoices = []
                    appNodeChoiceSaid = mirrorFailure + " " + sentence(error)
                }
                appNodeChooser = true
            }
            await original.close()
        } catch {
            secret.wipe()
            if let prospective { await prospective.close() }
            guard ownsNodeRequest(original, generation), self.node === old else { return }
            appNodeChoiceSaid = sentence(error)
            if committed { await reach() }
        }
    }

    private var nodeRequestGeneration: UInt64 = 0

    private func beginNodeRequest() -> UInt64 {
        nodeRequestGeneration &+= 1
        return nodeRequestGeneration
    }

    private func ownsNodeRequest(_ client: VoxClient, _ generation: UInt64) -> Bool {
        self.client === client && nodeRequestGeneration == generation
    }

    private func refreshNodeState(_ client: VoxClient, generation: UInt64) async throws {
        let shown = node
        let fresh = try await client.nodes()
        guard ownsNodeRequest(client, generation) else { return }
        nodeList = fresh
        await shown?.refreshMachineState()
    }

    func createNode(_ name: String, passphrase secret: Secret, again: Secret) async {
        guard let client, !nodeActionInProgress else { secret.wipe(); again.wipe(); return }
        let generation = beginNodeRequest()
        nodeActionInProgress = true
        defer { nodeActionInProgress = false }
        let same = secret.matches(again)
        again.wipe()
        guard same else {
            secret.wipe()
            phase = .welcome(said: asSentence("the two passphrases differ; nothing was created"))
            return
        }
        phase = .creating(node: name)
        let passphrase: Passphrase
        do {
            passphrase = try secret.passphrase()
        } catch {
            guard ownsNodeRequest(client, generation) else { return }
            phase = .welcome(said: sentence(error))
            return
        }
        defer { passphrase.wipe() }
        do {
            _ = try await client.createNode(node: name, passphrase: passphrase)
            guard ownsNodeRequest(client, generation) else { return }
        } catch {
            guard ownsNodeRequest(client, generation) else { return }
            phase = .welcome(said: sentence(error))
            return
        }
        do {
            try await client.keep(node: name, passphrase: passphrase)
            guard ownsNodeRequest(client, generation) else { return }
            let fingerprint = try await client.attach(node: name, passphrase: passphrase)
            guard ownsNodeRequest(client, generation) else { return }
            try await refreshNodeState(client, generation: generation)
            guard ownsNodeRequest(client, generation) else { return }
            try await remember(name, client, generation: generation)
            guard ownsNodeRequest(client, generation) else { return }
            enter(name, fingerprint, client)
        } catch {
            guard ownsNodeRequest(client, generation) else { return }
            // Made, but not attached: it is asked for as any node is.
            phase = .passphrase(node: name, said: sentence(error))
        }
    }

    /// First-run selection. Later CT-13 changes use the explicit, authenticated modal.
    func choose(_ name: String) async {
        guard let client, case .choosing = phase else { return }
        let generation = beginNodeRequest()
        do {
            let nodes = try await client.nodes()
            guard ownsNodeRequest(client, generation) else { return }
            guard let node = nodes.first(where: { $0.name == name }) else {
                await offerNodes(nodes)
                return
            }
            guard ownsNodeRequest(client, generation) else { return }
            await use(node)
        } catch {
            guard nodeRequestGeneration == generation else { return }
            phase = .unreachable(StartFailure(error))
        }
    }

    /// Attach `node` with the passphrase typed for it; the bytes go into a `Passphrase` at once
    /// and are not kept here (M-5).
    func attach(_ node: String, passphrase secret: Secret) async {
        guard let client, !nodeActionInProgress else { secret.wipe(); return }
        let generation = beginNodeRequest()
        nodeActionInProgress = true
        defer { nodeActionInProgress = false }
        phase = .attaching(node: node)
        let passphrase: Passphrase
        do {
            passphrase = try secret.passphrase()
        } catch {
            guard ownsNodeRequest(client, generation) else { return }
            phase = .passphrase(node: node, said: sentence(error))
            return
        }
        defer { passphrase.wipe() }
        do {
            // Unlock always remembers credentials, independently of Keep Running.
            try await client.keep(node: node, passphrase: passphrase)
            guard ownsNodeRequest(client, generation) else { return }
            let fingerprint = try await client.attach(node: node, passphrase: passphrase)
            guard ownsNodeRequest(client, generation) else { return }
            try await refreshNodeState(client, generation: generation)
            guard ownsNodeRequest(client, generation) else { return }
            try await remember(node, client, generation: generation)
            guard ownsNodeRequest(client, generation) else { return }
            enter(node, fingerprint, client)
        } catch VoxError.WrongPassphrase(let reason) {
            guard ownsNodeRequest(client, generation) else { return }
            phase = .passphrase(node: node, said: reason)
        } catch {
            guard ownsNodeRequest(client, generation) else { return }
            // No passphrase fixes it (busy, gone, not answering): said as what it is (P4).
            phase = .unreachable(StartFailure(error))
        }
    }

    /// Forget the window's node credentials and release its live keys, preserving its data.
    func detachNode() async {
        guard let name = signedInAs else { return }
        await lockNode(name)
    }

    func lockNode(_ name: String) async {
        guard let client, !nodeActionInProgress else { return }
        let shown = self.node
        let generation = beginNodeRequest()
        nodeActionInProgress = true
        defer { nodeActionInProgress = false }
        do {
            let current = try await client.nodes()
            guard ownsNodeRequest(client, generation) else { return }
            guard current.first(where: { $0.name == name })?.status == "Ready" else {
                try await refreshNodeState(client, generation: generation)
                return
            }
            try await client.unkeep(node: name)
            guard ownsNodeRequest(client, generation) else { return }
            try await client.detach(node: name)
            guard ownsNodeRequest(client, generation) else { return }
            let fresh = try await client.nodes()
            guard ownsNodeRequest(client, generation) else { return }
            nodeList = fresh
            if signedInAs == name {
                guard self.node === shown else { return }
                if fresh.first(where: { $0.name == name })?.status == "Ready", let shown {
                    // Requested detach leaves a passphraseless node Ready, but FFI detach
                    // releases this client's Held connection. Restore only this same identity,
                    // without remembering credentials again or replacing its window/drafts.
                    let fingerprint = try await client.attach(node: name, passphrase: nil)
                    guard ownsNodeRequest(client, generation), self.node === shown,
                          signedInAs == name else { return }
                    guard fingerprint == shown.me else {
                        throw VoxError.Detached(reason: "The node's identity changed while forgetting it. Reopen its window.")
                    }
                    let resumed = try await shown.resumeAfterUnlock { [weak self, weak shown] in
                        guard let self, let shown else { return false }
                        return self.ownsNodeRequest(client, generation) && self.node === shown
                            && self.signedInAs == name
                    }
                    guard ownsNodeRequest(client, generation), self.node === shown,
                          signedInAs == name else { return }
                    guard resumed else {
                        throw VoxError.Detached(reason: "The node is unavailable after forgetting it. Try Again.")
                    }
                    phase = .attached(node: name, fingerprint: fingerprint)
                } else {
                    await shown?.refreshMachineState()
                    guard ownsNodeRequest(client, generation), self.node === shown else { return }
                    phase = .detached(node: name)
                }
            }
        } catch {
            guard ownsNodeRequest(client, generation) else { return }
            forgotSaid = sentence(error)
            try? await refreshNodeState(client, generation: generation)
        }
    }

    /// The nodes on this Mac, with their fingerprints, as the sign-in choice lists them (P8).
    @Published private(set) var nodeList: [NodeSummary] = []

    /// The node signed in as now, attached or detached: what Sign Out acts on.
    var signedInAs: String? {
        switch phase {
        case let .attached(node, _), let .detached(node): return node
        default: return nil
        }
    }

    var selectedNodeStatus: String? {
        guard let name = signedInAs else { return nil }
        if let shown = node {
            guard shown.node == name else { return nil }
            return shown.nodeStatus
        }
        return nodeList.first(where: { $0.name == name })?.status
    }

    /// The sign-in's New Node…: make one here, as at first run.
    func newNode() {
        guard case .choosing = phase else { return }
        _ = beginNodeRequest()
        phase = .welcome(said: nil)
    }

    /// Attach again the node this window was opened with, after Detach (E-4): at once if it needs
    /// no passphrase, else its passphrase is asked for.
    func attachAgain() async {
        guard let client, let name = signedInAs else { return }
        let generation = beginNodeRequest()
        do {
            let nodes = try await client.nodes()
            guard ownsNodeRequest(client, generation) else { return }
            guard let node = nodes.first(where: { $0.name == name }) else {
                phase = .unreachable(StartFailure(kind: .other, said: "node \(name) is no longer on this Mac"))
                return
            }
            guard ownsNodeRequest(client, generation) else { return }
            nodeList = nodes
            if node.status == "Locked" {
                attachNodeAsk = name
            } else if let shown = self.node, shown.node == name {
                await shown.refreshMachineState()
                guard ownsNodeRequest(client, generation), self.node === shown else { return }
                if shown.nodeStatus == "Ready" {
                    phase = .attached(node: name, fingerprint: shown.me)
                }
            } else {
                await use(node)
            }
        } catch {
            guard nodeRequestGeneration == generation else { return }
            phase = .unreachable(StartFailure(error))
        }
    }

    /// What the login item last said of why it would not start, when Keep Running is chosen and
    /// the daemon is unreachable: its daemon ends quietly on a refusal no retry can change
    /// (`vox daemon --login-item`).
    @Published private(set) var loginItemSaid: String?

    /// Keep Running off: the login item is unregistered, the answer kept as Not Now, and the
    /// daemon reached as `vox` starts it.
    func stopKeepingRunning() async {
        do {
            try await Daemon.stopKeeping()
        } catch {
            phase = .unreachable(StartFailure(error))
            return
        }
        keepRunning = false
        await reach()

    }

    /// A vox:// room link the system opened the app with, held until a node is attached: it fills
    /// in the Join sheet, and never joins by itself.
    private var pendingLink: String?

    /// The system opened `url`: a room link goes to the Join sheet, now or once a node is attached.
    func openLink(_ url: URL) {
        guard url.scheme?.lowercased() == "vox" else { return }
        if url.host?.lowercased() == "agent-setup" {
            let harness = URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems?.first { $0.name == "harness" }?.value
            refreshAgentSetups()
            if let request = agentSetups.first(where: { $0.harness == harness }),
               !AgentSetupStore.declined(request) { offerAgentSetup(request) }
            return
        }
        // **A node on this Mac waits for its passphrase** (#666): `vox` opens
        // vox://attach-node?node=N where it would have printed "run in a terminal"; the person
        // gets a notification with Attach…, which opens the Attach sheet for it.
        if ["unlock-node", "attach-node"].contains(url.host?.lowercased() ?? "") {
            let named = URLComponents(url: url, resolvingAgainstBaseURL: false)?
                .queryItems?.first { $0.name == "node" }?.value
            if let named, !named.isEmpty {
                // In front: the Attach sheet at once. Behind: a notification, whose Attach…
                // brings Vox forward with it.
                if NSApp.isActive {
                    attachNodeAsk = named
                } else {
                    Notifier.shared.attachNode = { [weak self] n in
                        self?.attachNodeAsk = n
                        NSApp.activate(ignoringOtherApps: true)
                    }
                    Notifier.shared.ask()
                    Notifier.shared.postAttach(node: named)
                }
            }
            return
        }
        let link = url.absoluteString
        if let node {
            node.offerJoin(link)
        } else {
            pendingLink = link
        }
    }

    /// Keep Running changes the login item only. Remembered node credentials are independent.
    func setKeepRunning(_ on: Bool) async {
        guard on != keepRunning else { return }
        if on {
            do {
                let status = try Daemon.startKeeping()
                keepRunning = true
                if status == .requiresApproval { Daemon.openLoginItems() }
            } catch {
                keepRunning = false
                keepRunningSaid = sentence(error)
                return
            }
            return
        }
        do {
            try await Daemon.stopKeeping()
        } catch {
            keepRunningSaid = sentence(error)
            return
        }
        keepRunning = false
        var answers = false
        if let client { answers = (try? await client.nodes()) != nil }
        if !answers { await reach() }

    }

    /// Why unlocking a saved node failed.
    @Published private(set) var keepNodeSaid: (node: String, message: String)?

    func dismissKeepNodeError(_ node: String) {
        guard keepNodeSaid?.node == node else { return }
        keepNodeSaid = nil
    }

    /// A node on this Mac whose Attach… was chosen under ON THIS MACHINE (#666), its passphrase
    /// asked for; nil when none is asked.
    @Published var attachNodeAsk: String? {
        didSet {
            if attachNodeAsk != oldValue { _ = beginNodeRequest() }
        }
    }
    /// Why Forget could not finish; nil once read.
    @Published var forgotSaid: String?

    /// Forget node `node` credentials and release its live keys without removing data.
    func forgetPassphrase(_ node: String) async {
        await lockNode(node)
    }

    /// Keep `node` with its passphrase in the Keychain (M-6, ADR-028 K-10): the daemon attaches
    /// it, checks the passphrase against the node's vault and stores it, so the node stays
    /// attached after quit and is attached again when the daemon starts. An empty passphrase, for
    /// a node made with none, stores nothing.
    func keepNode(_ node: String, passphrase secret: Secret) async {
        guard let client, !nodeActionInProgress else { secret.wipe(); return }
        let generation = beginNodeRequest()
        keepNodeSaid = nil
        nodeActionInProgress = true
        defer { nodeActionInProgress = false }
        do {
            let passphrase = try secret.passphrase()
            defer { passphrase.wipe() }
            try await client.keep(node: node, passphrase: passphrase)
            guard ownsNodeRequest(client, generation) else { return }
            let fresh = try await client.nodes()
            guard ownsNodeRequest(client, generation), attachNodeAsk == node || signedInAs == node else { return }
            nodeList = fresh
            if signedInAs == node, let shown = self.node {
                let fingerprint = try await client.attach(node: node, passphrase: nil)
                guard ownsNodeRequest(client, generation), self.node === shown else { return }
                guard fingerprint == shown.me else {
                    enter(node, fingerprint, client)
                    attachNodeAsk = nil
                    keepNodeSaid = nil
                    return
                }
                let resumed = try await shown.resumeAfterUnlock { [weak self, weak shown] in
                    guard let self, let shown else { return false }
                    return self.ownsNodeRequest(client, generation) && self.node === shown
                }
                guard ownsNodeRequest(client, generation), self.node === shown else { return }
                guard resumed else { throw VoxError.Detached(reason: "The node is not Ready yet. Try Unlock again.") }
                phase = .attached(node: node, fingerprint: fingerprint)
            }
            if signedInAs == node, self.node == nil {
                let fingerprint = try await client.attach(node: node, passphrase: nil)
                guard ownsNodeRequest(client, generation), signedInAs == node else { return }
                enter(node, fingerprint, client)
            }
            attachNodeAsk = nil
            keepNodeSaid = nil
        } catch {
            guard ownsNodeRequest(client, generation) else { return }
            keepNodeSaid = (node, sentence(error))
            try? await refreshNodeState(client, generation: generation)
        }
    }

    /// Why turning Keep Running on or off failed, in macOS's or the daemon's words; nil once read.
    @Published var keepRunningSaid: String?

    /// Let go of the node and end the client (A-4).
    func quit() async {
        let generation = beginNodeRequest()
        guard let original = client else { return }
        await original.close()
        guard ownsNodeRequest(original, generation) else { return }
        client = nil
    }

    /// Attach the node: one already attached, or one that needs no passphrase, at once; else ask
    /// for its passphrase. With Keep Running chosen, a node that needs no passphrase is kept as it
    /// attaches (M-6).
    private func use(_ node: NodeSummary) async {
        guard let client else { return }
        let generation = beginNodeRequest()
        if !node.keep {
            // Refused for a node that has a passphrase, which is then asked for; but a daemon that
            // no longer answers is said as that, not as a passphrase to type.
            if (try? await client.keep(node: node.name, passphrase: nil)) == nil {
                guard ownsNodeRequest(client, generation) else { return }
                do {
                    _ = try await client.nodes()
                    guard ownsNodeRequest(client, generation) else { return }
                    phase = .passphrase(node: node.name, said: nil)
                } catch {
                    guard ownsNodeRequest(client, generation) else { return }
                    phase = .unreachable(StartFailure(error))
                }
                return
            }
        }
        guard ownsNodeRequest(client, generation) else { return }
        phase = .attaching(node: node.name)
        do {
            let fingerprint = try await client.attach(node: node.name, passphrase: nil)
            guard ownsNodeRequest(client, generation) else { return }
            try await refreshNodeState(client, generation: generation)
            guard ownsNodeRequest(client, generation) else { return }
            try await remember(node.name, client, generation: generation)
            guard ownsNodeRequest(client, generation) else { return }
            enter(node.name, fingerprint, client)
        } catch VoxError.Busy(let reason) {
            guard ownsNodeRequest(client, generation) else { return }
            // Another process holds the node: no passphrase fixes that (P4).
            phase = .unreachable(StartFailure(kind: .busy, said: reason))
        } catch {
            guard ownsNodeRequest(client, generation) else { return }
            // A node not attached that wants its passphrase: asked for, with nothing said yet.
            phase = .passphrase(node: node.name,
                                said: node.state == "attached" ? sentence(error) : nil)
        }
    }

    /// Act as `node`: the main window takes over, and follows the node's events.
    private func enter(_ node: String, _ fingerprint: String, _ client: VoxClient) {
        let model = NodeModel(client: client, node: node, me: fingerprint)
        self.node = model
        phase = .attached(node: node, fingerprint: fingerprint)
        if let link = pendingLink {
            pendingLink = nil
            model.offerJoin(link)
        }
        Task { await model.start() }
    }

    // The node chosen at first run, kept in the account's config directory beside vox's own
    // settings, so a scratch VOX_CONFIG_DIR keeps it with everything else.

    private func choiceFile(_ client: VoxClient) -> URL {
        URL(fileURLWithPath: client.configDir()).appendingPathComponent("app/node")
    }

    private func remember(_ node: String, _ client: VoxClient, generation: UInt64) async throws {
        // The daemon owns the saved identity and signed personal-role update. Saving a name
        // in the app alone must never leave the old node's automatic drive authority active.
        _ = try await client.selectPersonalNode(node: node)
        guard ownsNodeRequest(client, generation) else { return }
        let file = choiceFile(client)
        try FileManager.default.createDirectory(
            at: file.deletingLastPathComponent(), withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try Data((node + "\n").utf8).write(to: file, options: .atomic)
    }

    func refreshAgentSetups() {
        let requests = AgentSetupStore.requests()
        if agentSetups != requests { agentSetups = requests }
        let offers = requests.filter { !AgentSetupStore.declined($0) && !AgentSetupStore.answered($0) }
        if agentSetupOffers != offers { agentSetupOffers = offers }
    }

    func offerAgentSetup(_ request: AgentSetupRequest) {
        guard !agentSetupBusy else { return }
        agentSetupFailed = nil
        agentSetupAsk = request
        NSApp.activate(ignoringOtherApps: true)
        NSApp.windows.first(where: { $0.identifier?.rawValue == "main" || $0.title == "Vox" })?
            .makeKeyAndOrderFront(nil)
    }

    func declineAgentSetup(_ request: AgentSetupRequest) {
        guard !agentSetupBusy else { return }
        do {
            let held = try AgentSetupStore.lock(request)
            defer { try? held.close() }
            guard currentAgentSetup(request) else { return }
            try AgentSetupStore.answer(request, outcome: "declined", node: request.node)
            agentSetupAsk = nil
            agentSetupSaid = "\(request.name) setup is declined. You can choose Set Up in Vox Settings later."
            refreshAgentSetups()
        } catch {
            agentSetupFailed = sentence(error)
            agentSetupSaid = sentence(error)
        }
    }

    /// An open sheet can outlive an unsolicited offer being replaced by an agent's request.
    /// Show that new request for a fresh click; never answer a window the person has not read.
    private func currentAgentSetup(_ shown: AgentSetupRequest) -> Bool {
        guard let current = AgentSetupStore.requests().first(where: { $0.harness == shown.harness })
        else {
            agentSetupFailed = "This setup request is no longer available. Open Set Up again."
            return false
        }
        guard current.request == shown.request && current.dir == shown.dir && current.node == shown.node
        else {
            offerAgentSetup(current)
            agentSetupFailed = "A newer setup request arrived. Review it before choosing Set Up or Not Now."
            return false
        }
        return true
    }

    /// Only the app creates and remembers the node. It never selects the agent's node as the
    /// person's node, and its passphrase never enters a command, environment, file or reply.
    func setUpAgent(_ request: AgentSetupRequest, name: String, passphrase secret: Secret,
                    again: Secret) async {
        guard !agentSetupBusy else { secret.wipe(); again.wipe(); return }
        let held: FileHandle
        do { held = try AgentSetupStore.lock(request) }
        catch {
            secret.wipe(); again.wipe()
            agentSetupFailed = sentence(error)
            return
        }
        defer { try? held.close() }
        guard currentAgentSetup(request) else { secret.wipe(); again.wipe(); return }
        let same = secret.matches(again)
        again.wipe()
        guard same else {
            secret.wipe()
            agentSetupFailed = "The two passphrases differ; nothing was created."
            return
        }
        agentSetupBusy = true
        agentSetupFailed = nil
        defer { agentSetupBusy = false }
        do {
            let passphrase = try secret.passphrase()
            defer { passphrase.wipe() }
            _ = try await Daemon.command(["agent", "setup", request.harness, "--node", name,
                                          "--finish", "--check"],
                                         patience: 30, environment: Daemon.harnessEnvironment())
            let client: VoxClient
            if let existing = self.client { client = existing }
            else { client = try await Daemon.reach() }
            let nodes = try await client.nodes()
            if !nodes.contains(where: { $0.name == name }) {
                _ = try await client.createNode(node: name, passphrase: passphrase)
            }
            try await client.keep(node: name, passphrase: passphrase)
            _ = try await Daemon.command(["agent", "setup", request.harness, "--node", name, "--finish"],
                                         patience: 30, environment: Daemon.harnessEnvironment())
            try AgentSetupStore.answer(request, outcome: "ready", node: name)
            refreshAgentSetups()
            agentSetupAsk = nil
            agentSetupSaid = "\(request.name) is set up as node \(name), Ready and remembered."
        } catch { agentSetupFailed = sentence(error) }
    }
}

/// A failure as the daemon said it (M-7): the sentence alone, never a type's name, begun with a
/// capital and ended with a full stop (P6).
func sentence(_ error: Error) -> String {
    switch error {
    case let VoxError.Failed(reason): return asSentence(reason)
    case let VoxError.Detached(reason): return asSentence(reason)
    case let VoxError.Unknown(reason): return asSentence(reason)
    case let VoxError.WrongPassphrase(reason): return asSentence(reason)
    case let VoxError.Busy(reason): return asSentence(reason)
    default: return asSentence(error.localizedDescription)
    }
}

/// `text` begun with a capital and ended with a full stop, its words otherwise as they came.
func asSentence(_ text: String) -> String {
    var said = text.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let first = said.first else { return said }
    said = first.uppercased() + said.dropFirst()
    if let last = said.last, !".!?".contains(last) { said += "." }
    return said
}

/// Why Vox could not start acting as a node, by kind, with the sentence said (P4): the card says
/// what happened and what can help, and keeps the sentence under Details.
struct StartFailure: Error, Equatable {
    enum Kind: Equatable {
        /// The daemon Vox started stopped as it started (`vox daemon` exited).
        case exited
        /// The startup command refused, including preparation before a process could start.
        case startRefused
        /// No daemon answered within Vox's patience.
        case notAnswering
        /// Another process holds the node (an older `vox` still running as it).
        case busy
        /// The local client and its daemon have different release versions.
        case versionMismatch
        /// Anything else.
        case other
    }

    let kind: Kind
    let said: String

    init(kind: Kind, said: String) {
        self.kind = kind
        self.said = said
    }

    /// `error`, by kind: one Vox threw itself as such, the daemon's typed refusals, else other.
    init(_ error: Error) {
        switch error {
        case let failure as StartFailure: self = failure
        case let VoxError.Busy(reason): self.init(kind: .busy, said: reason)
        default:
            let words = sentence(error).replacingOccurrences(of: "this vox is", with: "this app is")
            self.init(kind: Daemon.versionMismatch(words) ? .versionMismatch : .other, said: words)
        }
    }

    /// The card's headline.
    var headline: String {
        switch kind {
        case .exited, .startRefused: return "Vox can't start its background service"
        case .notAnswering: return "Vox's background service isn't answering"
        case .busy: return "Another copy of Vox is using this node"
        case .versionMismatch: return said
        case .other: return "Vox can't reach its background service"
        }
    }

    /// One line of likely cause.
    var cause: String {
        switch kind {
        case .exited: return "It stopped as it started. Your rooms are unreachable until it runs."
        case .startRefused: return "Its start was refused. Your rooms are unreachable until it runs."
        case .notAnswering: return "It may still be starting, or be stuck. Your rooms are unreachable until it answers."
        case .busy: return "Only one copy may act as a node at a time: a command that has not finished, or another copy of Vox, holds it."
        case .versionMismatch: return "Restart the daemon to use this app's version. Remembered nodes return automatically."
        case .other: return "Your rooms are unreachable until it answers."
        }
    }
}
