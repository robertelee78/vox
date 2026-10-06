// The Share extension (ADR-014 M-23, #449): a file or folder shared from Finder or any app goes
// to a room, through the vox daemon, as `vox share` sends it. The app need not be running: the
// extension is a client of the daemon itself, acting as the node the app chose at first run, and
// only while that node is attached. It never asks for a passphrase (M-7: what failed is said in
// the daemon's own words).

import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// The extension's principal class, named in its Info.plist.
final class ShareViewController: NSViewController {
    private var model: ShareModel?

    override func loadView() {
        let model = ShareModel(context: extensionContext)
        self.model = model
        let host = NSHostingView(rootView: ShareView(model: model))
        host.frame = NSRect(x: 0, y: 0, width: 440, height: 380)
        view = host
        Task { await model.load() }
    }
}

/// What the sheet shows, and the one client of the daemon it holds while it is open.
@MainActor
final class ShareModel: ObservableObject {
    enum Phase: Equatable {
        case loading
        /// Nothing can be sent: why, in words.
        case refused(String)
        case ready
        case sending
        /// Sent: what the daemon answered.
        case done(String)
    }

    @Published var phase: Phase = .loading
    @Published var rooms: [RoomSummary] = []
    @Published var room = "" {
        didSet { Task { await loadMembers() } }
    }
    @Published var members: [Member] = []
    @Published var to: Set<String> = []
    @Published var note = ""
    @Published var file: URL?
    /// The daemon's refusal of the last send, said under the form.
    @Published var failure = ""

    private weak var context: NSExtensionContext?
    private var client: VoxClient?

    init(context: NSExtensionContext?) {
        self.context = context
    }

    /// The person's real home: inside the sandbox HOME is the extension's container, and the
    /// daemon's data root is in the real one.
    private static var home: String {
        if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir {
            return String(cString: dir)
        }
        return NSHomeDirectory()
    }

    /// The account's data root, and its config directory beside it (vox's macOS defaults).
    private static var dataRoot: String { home + "/Library/Application Support/vox" }

    func load() async {
        file = await sharedFile()
        guard file != nil else {
            phase = .refused("Nothing to share: Vox shares one file or folder at a time.")
            return
        }
        let client: VoxClient
        do {
            client = try await VoxClient.open(dataRoot: Self.dataRoot)
        } catch {
            phase = .refused("Open Vox first: \(sentence(error))")
            return
        }
        self.client = client
        let choice = URL(fileURLWithPath: Self.dataRoot).appendingPathComponent("app/node")
        guard
            let node = (try? String(contentsOf: choice, encoding: .utf8))?
                .trimmingCharacters(in: .whitespacesAndNewlines),
            !node.isEmpty
        else {
            phase = .refused("Open Vox to choose your node first.")
            return
        }
        do {
            let nodes = try await client.nodes()
            guard nodes.contains(where: { $0.name == node && $0.state == "attached" }) else {
                phase = .refused("Open Vox to attach node \(node) first.")
                return
            }
            // Joins the attachment the app holds; attaches nothing new, and asks for nothing.
            _ = try await client.attach(node: node, passphrase: nil)
            rooms = try await client.rooms().filter { $0.open && $0.over.isEmpty }
        } catch {
            phase = .refused(sentence(error))
            return
        }
        guard let first = rooms.first else {
            phase = .refused("Node \(node) holds no open room to share into.")
            return
        }
        room = first.id
        phase = .ready
    }

    func loadMembers() async {
        guard let client, !room.isEmpty else { return }
        to = []
        members = (try? await client.roster(room: room)) ?? []
    }

    func send() async {
        guard let client, let file else { return }
        phase = .sending
        failure = ""
        do {
            let shared = try await client.share(
                room: room, path: file.path, to: Array(to), note: note, re: "",
                urgent: false, count: 0, forSecs: 0)
            phase = .done("Shared \(shared.name) (SHA-256 \(shared.sha256.prefix(16))…)")
        } catch {
            failure = sentence(error)
            phase = .ready
        }
    }

    func finish() {
        let client = self.client
        self.client = nil
        Task { await client?.close() }
        if case .done = phase {
            context?.completeRequest(returningItems: nil)
        } else {
            context?.cancelRequest(withError: NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError))
        }
    }

    /// The file or folder the share sheet was given: its first attachment's file URL.
    private func sharedFile() async -> URL? {
        let items = (context?.inputItems as? [NSExtensionItem]) ?? []
        guard let provider = items.flatMap({ $0.attachments ?? [] })
            .first(where: { $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) })
        else { return nil }
        return await withCheckedContinuation { done in
            provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier) { item, _ in
                switch item {
                case let url as URL: done.resume(returning: url)
                case let data as Data: done.resume(returning: URL(dataRepresentation: data, relativeTo: nil))
                default: done.resume(returning: nil)
                }
            }
        }
    }
}

/// The sheet: the file, the room, who it is for, a note, and Send.
struct ShareView: View {
    @ObservedObject var model: ShareModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Share to a Vox room").font(.headline)
            if let file = model.file {
                Text(file.lastPathComponent).font(.body.monospaced()).lineLimit(1)
            }
            switch model.phase {
            case .loading:
                ProgressView().frame(maxWidth: .infinity)
            case let .refused(why):
                Text(why).fixedSize(horizontal: false, vertical: true)
            case let .done(said):
                Text(said).fixedSize(horizontal: false, vertical: true)
            case .ready, .sending:
                form
            }
            Spacer(minLength: 0)
            HStack {
                Spacer()
                if case .done = model.phase {
                    Button("Done") { model.finish() }.keyboardShortcut(.defaultAction)
                } else {
                    Button("Cancel") { model.finish() }.keyboardShortcut(.cancelAction)
                    if model.phase == .ready || model.phase == .sending {
                        Button("Send") { Task { await model.send() } }
                            .keyboardShortcut(.defaultAction)
                            .disabled(model.phase == .sending || model.room.isEmpty)
                    }
                }
            }
        }
        .padding(16)
        .frame(width: 440, height: 380)
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 8) {
            Picker("Room", selection: $model.room) {
                ForEach(model.rooms, id: \.id) { room in
                    Text(room.name.isEmpty ? String(room.id.prefix(12)) : room.name).tag(room.id)
                }
            }
            Text("To (none: the whole room)").font(.caption)
            List(model.members, id: \.fingerprint) { member in
                Toggle(isOn: Binding(
                    get: { model.to.contains(member.fingerprint) },
                    set: { on in
                        if on { model.to.insert(member.fingerprint) } else { model.to.remove(member.fingerprint) }
                    }
                )) {
                    Text(member.name.isEmpty ? String(member.fingerprint.prefix(12)) : member.name)
                }
            }
            .frame(minHeight: 90)
            TextField("Note", text: $model.note)
            if !model.failure.isEmpty {
                Text(model.failure).foregroundColor(.red).fixedSize(horizontal: false, vertical: true)
            }
        }
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
