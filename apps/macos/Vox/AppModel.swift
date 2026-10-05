// What the app is doing, and the one node it acts as (ADR-014 M-6, ADR-028 E-4).

import Foundation
@MainActor
final class AppModel: ObservableObject {
    /// Where the app is, from launch to an attached node.
    enum Phase: Equatable {
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

    @Published private(set) var phase: Phase = .starting
    private var client: VoxClient?

    /// Whether the app holds a node the daemon is to let go of when it quits.
    var holdsNode: Bool {
        if case .attached = phase { return true }
        return false
    }

    /// Reach the daemon, and attach the node chosen at first run, or ask which.
    func start() async {
        phase = .starting
        do {
            let client = try await VoxClient.open(dataRoot: "")
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
    func attach(_ node: String, passphrase typed: Data) async {
        var bytes = typed
        guard let client else { return }
        phase = .attaching(node: node)
        let passphrase: Passphrase
        do {
            passphrase = try Passphrase(bytes: bytes)
        } catch {
            bytes.resetBytes(in: 0..<bytes.count)
            phase = .passphrase(node: node, said: sentence(error))
            return
        }
        bytes.resetBytes(in: 0..<bytes.count)
        defer { passphrase.wipe() }
        do {
            let fingerprint = try await client.attach(node: node, passphrase: passphrase)
            remember(node, client)
            phase = .attached(node: node, fingerprint: fingerprint)
        } catch {
            phase = .passphrase(node: node, said: sentence(error))
        }
    }

    /// Let go of the node and end the client (A-4).
    func quit() async {
        await client?.close()
        client = nil
    }

    /// Attach a node already attached (no passphrase needed), else ask for its passphrase.
    private func use(_ node: NodeSummary) async {
        guard let client else { return }
        guard node.state == "attached" else {
            phase = .passphrase(node: node.name, said: nil)
            return
        }
        phase = .attaching(node: node.name)
        do {
            let fingerprint = try await client.attach(node: node.name, passphrase: nil)
            remember(node.name, client)
            phase = .attached(node: node.name, fingerprint: fingerprint)
        } catch {
            phase = .passphrase(node: node.name, said: sentence(error))
        }
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
