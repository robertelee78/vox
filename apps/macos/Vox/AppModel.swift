// What the app is doing, and the one node it acts as (ADR-014 M-6, ADR-028 E-4).

import Foundation
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
        /// The daemon did not answer; its sentence.
        case unreachable(String)
        /// First run: no node chosen yet. The nodes on this Mac.
        case choosing([String])
        /// The node needs its identity passphrase to attach; the daemon's sentence after a
        /// failed try.
        case passphrase(node: String, said: String?)
        /// Attaching, with the passphrase given.
        case attaching(node: String)
        /// Acting as `node`, whose fingerprint is `fingerprint`.
        case attached(node: String, fingerprint: String)
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

    /// Show or hide the menu bar extra, and keep the choice. Setting the value it already has does
    /// nothing: SwiftUI sets a MenuBarExtra's `isInserted` on its updates, and a change notice for
    /// each of those started another update, so the main thread never went idle.
    func showMenuBar(_ on: Bool) {
        guard on != menuBar else { return }
        menuBar = on
        MenuBarChoice.set(on)
    }
    /// The node acted as, once attached: what the main window shows.
    @Published private(set) var node: NodeModel?
    private var client: VoxClient?

    /// Whether the person chose Keep Running at first run: then a node is kept attached when the
    /// app quits, once its passphrase is in the Keychain or it needs none (ADR-014 M-6, M-8).
    /// Read once, then kept as the person answers: views read it as they draw, and the answer is
    /// a file.
    private(set) var keepRunning = Daemon.kept() == true

    /// Whether the app holds a node the daemon is to let go of when it quits.
    var holdsNode: Bool {
        if case .attached = phase { return true }
        return false
    }

    /// Ask about the login item at first run; then reach the daemon, and attach the node chosen at
    /// first run, or ask which.
    func start() async {
        if Daemon.kept() == nil {
            phase = .askingLoginItem
            return
        }
        await reach()
    }

    /// The person's answer at first run: keep the daemon running while logged in, or not now.
    func answerLoginItem(keep: Bool) async {
        Daemon.remember(kept: keep)
        keepRunning = keep
        guard keep else {
            await reach()
            return
        }
        do {
            try Daemon.loginItem.register()
        } catch {
            phase = .loginItemApproval(said: error.localizedDescription)
            return
        }
        if Daemon.loginItem.status == .requiresApproval {
            phase = .loginItemApproval(said: nil)
            return
        }
        await reach()
    }

    /// Reach the daemon (the login item's, else one started as `vox` does), then attach the node
    /// chosen at first run, or ask which.
    func reach() async {
        phase = .starting
        do {
            let client = try await Daemon.reach()
            self.client = client
            let nodes = try await client.nodes()
            if let chosen = chosenNode(client), let node = nodes.first(where: { $0.name == chosen }) {
                await use(node)
            } else {
                phase = .choosing(nodes.map(\.name))
            }
        } catch {
            phase = .unreachable(sentence(error))
        }
    }

    /// The person picked `name` at first run.
    func choose(_ name: String) async {
        guard let client else { return }
        do {
            let nodes = try await client.nodes()
            guard let node = nodes.first(where: { $0.name == name }) else {
                phase = .choosing(nodes.map(\.name))
                return
            }
            await use(node)
        } catch {
            phase = .unreachable(sentence(error))
        }
    }

    /// Attach `node` with the passphrase typed for it; the bytes go into a `Passphrase` at once
    /// and are not kept here (M-5).
    func attach(_ node: String, passphrase secret: Secret, keepInKeychain: Bool = false) async {
        guard let client else { return }
        phase = .attaching(node: node)
        let passphrase: Passphrase
        do {
            passphrase = try secret.passphrase()
        } catch {
            phase = .passphrase(node: node, said: sentence(error))
            return
        }
        defer { passphrase.wipe() }
        do {
            // Kept (K-10, opt-in): the daemon attaches it with the passphrase, stores that in the
            // login keychain, and keeps it attached past this app's quit.
            if keepRunning && keepInKeychain {
                try await client.keep(node: node, passphrase: passphrase)
            }
            let fingerprint = try await client.attach(node: node, passphrase: passphrase)
            remember(node, client)
            enter(node, fingerprint, client)
        } catch {
            phase = .passphrase(node: node, said: sentence(error))
        }
    }

    /// Detach the node from the daemon now (Node > Detach): its connections close and its keys
    /// are wiped; the app then asks which node to act as.
    func detachNode() async {
        guard let client, case let .attached(node, _) = phase else { return }
        do {
            try await client.detach(node: node)
            self.node = nil
            phase = .choosing(try await client.nodes().map(\.name))
        } catch {
            phase = .unreachable(sentence(error))
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
            try Daemon.stopKeeping()
        } catch {
            phase = .unreachable(sentence(error))
            return
        }
        keepRunning = false
        await reach()
    }

    /// Let go of the node and end the client (A-4).
    func quit() async {
        await client?.close()
        client = nil
    }

    /// Attach the node: one already attached, or one that needs no passphrase, at once; else ask
    /// for its passphrase. With Keep Running chosen, a node that needs no passphrase is kept as it
    /// attaches (M-6).
    private func use(_ node: NodeSummary) async {
        guard let client else { return }
        if node.state != "attached" && keepRunning {
            // Refused for a node that has a passphrase, which is then asked for; but a daemon that
            // no longer answers is said as that, not as a passphrase to type.
            if (try? await client.keep(node: node.name, passphrase: nil)) == nil {
                do {
                    _ = try await client.nodes()
                    phase = .passphrase(node: node.name, said: nil)
                } catch {
                    phase = .unreachable(sentence(error))
                }
                return
            }
        }
        phase = .attaching(node: node.name)
        do {
            let fingerprint = try await client.attach(node: node.name, passphrase: nil)
            remember(node.name, client)
            enter(node.name, fingerprint, client)
        } catch {
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
        Task { await model.start() }
    }

    // The node chosen at first run, kept in the account's config directory beside vox's own
    // settings, so a scratch VOX_CONFIG_DIR keeps it with everything else.

    private func choiceFile(_ client: VoxClient) -> URL {
        URL(fileURLWithPath: client.configDir()).appendingPathComponent("app/node")
    }

    private func chosenNode(_ client: VoxClient) -> String? {
        guard let text = try? String(contentsOf: choiceFile(client), encoding: .utf8) else {
            return nil
        }
        let name = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return name.isEmpty ? nil : name
    }

    private func remember(_ node: String, _ client: VoxClient) {
        let file = choiceFile(client)
        try? FileManager.default.createDirectory(
            at: file.deletingLastPathComponent(), withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try? Data((node + "\n").utf8).write(to: file, options: .atomic)
    }
}

/// A failure as the daemon said it (M-7): the sentence alone, never a type's name.
func sentence(_ error: Error) -> String {
    switch error {
    case let VoxError.Failed(reason): return reason
    case let VoxError.Detached(reason): return reason
    default: return error.localizedDescription
    }
}
