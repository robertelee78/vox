// The node the app acts as, once attached: its rooms grouped by what they need from the person
// (ADR-028 W-2), the room on screen, its members and their trust (L-4), and the status bar's facts
// (W-1).

import Foundation
import ServiceManagement

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
    /// Who has read each of this node's own messages in the room on screen, by message id (R-6).
    @Published private(set) var readBy: [String: [String]] = [:]
    /// The services members share in the room on screen, as cards above its timeline.
    @Published private(set) var roomServices: [SharedService] = []
    /// Follows who has read what while a room is on screen.
    private var watching: Task<Void, Never>?
    @Published private(set) var members: [MemberRow] = []
    @Published private(set) var trusted: [TrustedNode] = []
    @Published private(set) var nodes: [NodeSummary] = []
    @Published private(set) var peers = 0
    /// The keyring window, as the TUI's status bar says it (K-9).
    @Published private(set) var keyring = ""
    /// Whether the LAN helper is approved, so the family LAN may be offered (ADR-014 M-12).
    @Published private(set) var lanHelperReady = false
    /// The rooms whose family LAN this app runs; each one's latest line, and why one failed.
    @Published private(set) var lanOn: Set<String> = []
    @Published private(set) var lanSaid: [String: String] = [:]
    @Published private(set) var lanFailed: [String: String] = [:]

    /// The family LAN's root helper: the bundle's launchd daemon (ADR-014 M-10).
    private var lanHelper: SMAppService { .daemon(plistName: "us.vox.lanhelper.plist") }
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
            lanHelperReady = lanHelper.status == .enabled
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
            roomServices = (try? await client.services(room: id).shared) ?? []
            watchReads(id)
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

    /// Register the LAN helper; macOS asks the person to approve it in System Settings, which
    /// the app opens and never clicks through (M-10, M-33).
    func allowLanHelper() async {
        do {
            try lanHelper.register()
        } catch {
            said = error.localizedDescription
        }
        if lanHelper.status == .requiresApproval {
            SMAppService.openSystemSettingsLoginItems()
        }
        lanHelperReady = lanHelper.status == .enabled
    }

    /// Bring this Mac onto `room`'s family LAN, or take it down; a failure is the daemon's
    /// sentence, shown where it was asked (M-7).
    func setLan(_ room: String, on: Bool) async {
        lanFailed[room] = nil
        do {
            if on {
                lanSaid[room] = try await client.lanUp(room: room, allow: [], helperSocket: "")
                lanOn.insert(room)
            } else {
                try await client.lanDown(room: room)
                lanOn.remove(room)
                lanSaid[room] = nil
            }
        } catch {
            lanFailed[room] = sentence(error)
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

    /// The messages drawn on screen are read (R-6): the node is told, as the TUI tells it what it
    /// draws, once each, in batches. This node's own, and those not received yet, are not.
    func drawn(_ message: RoomMessage) {
        guard case let .room(room) = selection, message.author != me, !message.owed,
              !marked.contains(message.id) else { return }
        marked.insert(message.id)
        unmarked.append(message.id)
        guard flushing == nil else { return }
        flushing = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 300_000_000)
            guard let self else { return }
            let ids = self.unmarked
            self.unmarked = []
            self.flushing = nil
            do {
                try await self.client.markRead(room: room, ids: ids)
            } catch {
                // Not recorded: drawn again, it is told again.
                ids.forEach { self.marked.remove($0) }
                self.said = sentence(error)
            }
        }
    }

    private var marked: Set<String> = []
    private var unmarked: [String] = []
    private var flushing: Task<Void, Never>?

    /// Who has read this node's messages in `room`, read again every few seconds while it is on
    /// screen: read records arrive with the room's syncs and draw nothing of their own.
    private func watchReads(_ room: String) {
        watching?.cancel()
        watching = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, case .room(room) = self.selection else { return }
                if let reads = try? await self.client.readBy(room: room) {
                    self.readBy = Dictionary(uniqueKeysWithValues: reads.map { ($0.id, $0.names) })
                }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

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
