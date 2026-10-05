// The node the app acts as, once attached: its rooms grouped by what they need from the person
// (ADR-028 W-2), the room on screen, its members and their trust (L-4), and the status bar's facts
// (W-1).

import Foundation

@MainActor
final class NodeModel: ObservableObject {
    /// What the window shows in its middle.
    enum Selection: Hashable {
        case room(String)
        case keyring
    }

    /// A room as the sidebar shows it.
    struct Room: Identifiable, Equatable {
        let id: String
        let name: String
        let open: Bool
        /// Unread messages addressed to this node; of them, urgent.
        var addressed = 0
        var urgent = 0
        /// Other unread messages: new to the room, and coordination traffic.
        var new = 0
        var coordination = 0

        /// What it needs from the person, by the rule the TUI groups by (W-2).
        var need: RoomGroup {
            roomGroup(toYou: UInt32(addressed), new: UInt32(new), coordination: UInt32(coordination))
        }

        /// The room's unread in words, as its row says it.
        var words: String {
            var parts: [String] = []
            if addressed > 0 { parts.append("\(addressed) to you") }
            if urgent > 0 { parts.append("\(urgent) urgent") }
            if new > 0 { parts.append("\(new) new") }
            if coordination > 0 { parts.append("\(coordination) coordination") }
            return parts.isEmpty ? "nothing unread" : parts.joined(separator: ", ")
        }
    }

    /// A member of the room on screen.
    struct MemberRow: Identifiable, Equatable {
        let id: String
        let name: String
        let trust: Trust
    }

    let node: String
    let me: String
    private let client: VoxClient

    @Published private(set) var rooms: [Room] = []
    @Published var selection: Selection?
    @Published private(set) var messages: [RoomMessage] = []
    @Published private(set) var members: [MemberRow] = []
    @Published private(set) var trusted: [TrustedNode] = []
    @Published private(set) var nodes: [NodeSummary] = []
    @Published private(set) var peers = 0
    /// The keyring window, as the TUI's status bar says it (K-9).
    @Published private(set) var keyring = ""
    /// The last thing that failed, in the daemon's words (M-7), or the node's last notice.
    @Published private(set) var said: String?
    /// The node ended: detached, or the daemon stopped.
    @Published private(set) var ended: String?

    init(client: VoxClient, node: String, me: String) {
        self.client = client
        self.node = node
        self.me = me
    }

    /// The rooms in `need`, urgent first, then by name.
    func group(_ need: RoomGroup) -> [Room] {
        rooms.filter { $0.need == need }.sorted {
            if $0.urgent != $1.urgent { return $0.urgent > $1.urgent }
            return $0.name.localizedStandardCompare($1.name) == .orderedAscending
        }
    }

    /// Load everything and follow the node's events.
    func start() async {
        await refresh()
        do {
            try await client.subscribe(listener: Listener(model: self))
        } catch {
            said = sentence(error)
        }
    }

    /// The rooms, the keyring, the nodes on this Mac and the peers, read again.
    func refresh() async {
        do {
            let fresh = try await client.rooms()
            rooms = fresh.map { r in
                var room = Room(id: r.id, name: name(of: r), open: r.open)
                if let held = rooms.first(where: { $0.id == r.id }) {
                    room.addressed = held.addressed
                    room.urgent = held.urgent
                    room.new = held.new
                    room.coordination = held.coordination
                }
                return room
            }
            trusted = try await client.trustList()
            nodes = try await client.nodes()
            let view = try await client.view()
            peers = Int(view.peers)
            keyring = view.keyring
        } catch {
            said = sentence(error)
        }
    }

    /// Show `selection`; a room shown is read, so its unread counts end.
    func show(_ selection: Selection?) async {
        self.selection = selection
        guard case let .room(id) = selection else { return }
        if let i = rooms.firstIndex(where: { $0.id == id }) {
            rooms[i].addressed = 0
            rooms[i].urgent = 0
            rooms[i].new = 0
            rooms[i].coordination = 0
        }
        do {
            messages = try await client.read(room: id, after: "", limit: 0)
            let roster = try await client.roster(room: id)
            let consents = try await client.consents(room: id)
            let keyring = Set(trusted.map(\.fingerprint))
            let back = Set(consents.inbound)
            members = roster.filter { $0.fingerprint != me }.map { m in
                let trust: Trust = keyring.contains(m.fingerprint)
                    ? (back.contains(m.fingerprint) ? .mutual : .oneWay) : .none
                return MemberRow(id: m.fingerprint,
                                 name: m.name.isEmpty ? String(m.fingerprint.prefix(12)) : m.name,
                                 trust: trust)
            }
        } catch {
            said = sentence(error)
        }
    }

    /// The next room that needs the person, if any (W-2).
    func nextNeedingYou() async {
        guard let room = group(.needsYou).first else { return }
        await show(.room(room.id))
    }

    /// Post `text` to the room on screen.
    func post(_ text: String) async {
        guard case let .room(id) = selection else { return }
        do {
            try await client.post(room: id, text: text, to: [], re: "", urgent: false)
        } catch {
            said = sentence(error)
        }
    }

    // ---- what the node says -------------------------------------------------------------------

    fileprivate func arrived(_ message: RoomMessage, in room: String) {
        if case .room(room) = selection {
            if !messages.contains(where: { $0.id == message.id }) {
                messages.append(message)
            }
            return
        }
        // This node's own posts are never unread.
        guard message.author != me else { return }
        guard let i = rooms.firstIndex(where: { $0.id == room }) else {
            // A room joined or made since the rooms were read (by `vox room join`, say): read
            // them again, then count it.
            Task {
                await refresh()
                if rooms.contains(where: { $0.id == room }) { arrived(message, in: room) }
            }
            return
        }
        switch message.level {
        case .toYou:
            rooms[i].addressed += 1
            if message.urgent { rooms[i].urgent += 1 }
        case .new:
            rooms[i].new += 1
        case .coordination:
            rooms[i].coordination += 1
        }
    }

    fileprivate func noticed(_ text: String) {
        Task { await refresh() }
    }

    fileprivate func stopped(_ text: String) {
        ended = text
    }

    private func name(of room: RoomSummary) -> String {
        room.name.isEmpty ? String(room.id.prefix(12)) : room.name
    }
}

/// The node's events, handed to the model on the main actor.
private final class Listener: ClientListener, @unchecked Sendable {
    private weak var model: NodeModel?

    init(model: NodeModel) { self.model = model }

    func onMessage(room: String, message: RoomMessage) {
        Task { @MainActor [weak model] in model?.arrived(message, in: room) }
    }

    func onNotice(text: String) {
        Task { @MainActor [weak model] in model?.noticed(text) }
    }

    func onEnded(text: String) {
        Task { @MainActor [weak model] in model?.stopped(text) }
    }
}
