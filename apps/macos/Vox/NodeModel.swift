// The node the app acts as, once attached: its rooms grouped by what they need from the person
// (ADR-028 W-2), the room on screen, its members and their trust (L-4), and the status bar's facts
// (W-1).

import AppKit
import Foundation
import ServiceManagement

@MainActor
final class NodeModel: ObservableObject {
    /// What the window shows in its middle.
    enum Selection: Hashable {
        case room(String)
        case keyring
        case decisions
        case services
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
    @Published private(set) var messages: [RoomMessage] = [] {
        didSet {
            byID = Dictionary(messages.map { ($0.id, $0) }) { $1 }
            helloSeen = messages.contains { $0.kind == "hello" && $0.author != me }
        }
    }
    /// The room on screen's messages by id, for what is in view.
    private(set) var byID: [String: RoomMessage] = [:]
    /// Whether another member of the room on screen announced an agent session.
    private(set) var helloSeen = false
    /// Who has read each of this node's own messages in the room on screen, by message id (R-6).
    @Published private(set) var readBy: [String: [String]] = [:]
    /// Where this node's verified copy of each share it pulled in the room on screen is, by the
    /// share's message id (ADR-028 F-3, F-4): what its card opens with Quick Look.
    @Published private(set) var pulled: [String: String] = [:]
    /// A file handed to Vox from elsewhere (the Finder Services item, M-24), waiting for the room
    /// on screen to take it: its To: and note are asked there.
    @Published var incoming: URL?
    // ---- what the menus, keys and palette ask for (M-19–M-21) ---------------------------------

    /// The sheet a menu, key or palette action opened.
    @Published var sheet: NodeSheet?
    /// The lanes view in place of the room's timeline (W-3).
    @Published var showLanes = false
    /// Asks the room on screen to choose a file to attach (⌘O); each ask counts one up.
    @Published var attachAsked = 0
    /// Asks the room on screen to send its draft urgent (⌘↩).
    @Published var urgentAsked = 0
    /// The message selected in the timeline, and the one the composer replies to (⌘R).
    @Published var selectedMessage: String?
    @Published var replyTo: RoomMessage?
    /// The service card selected above the timeline, whose command ⌘⇧C copies.
    @Published var selectedService: SharedService?
    /// What a menu action last did, said where the person is (E-5).
    @Published var did: String?

    /// Each other member's lane in the room on screen (ADR-028 W-3), as the node derives it.
    @Published private(set) var lanes: [Lane] = []
    /// The newest message of each member's lane when the person last looked at the lanes, by
    /// fingerprint: what changed since is what came after (W-3).
    @Published var laneLooked: [String: String] = [:]
    /// The services members share in the room on screen, as cards above its timeline.
    @Published private(set) var roomServices: [SharedService] = []
    /// What the last keyring change did, or why it failed, in the daemon's words (E-5, M-7).
    @Published private(set) var keyringDid: String?
    @Published private(set) var keyringFailed: String?
    /// The keyring window has closed: the change waiting is made once the passphrase is given.
    @Published private(set) var keyringNeedsPassphrase = false
    private var keyringWaiting: ((Passphrase?) async throws -> String)?

    /// Follows who has read what while a room is on screen.
    private var watching: Task<Void, Never>?
    /// Follows the node's facts (keyring, nodes, peers) while the model lives.
    private var following: Task<Void, Never>?
    @Published private(set) var members: [MemberRow] = []
    @Published private(set) var trusted: [TrustedNode] = []
    /// The trusted nodes that trust this node back, as the rooms shared with them record it (L-4).
    @Published private(set) var trustsBack: Set<String> = []
    /// The keyring row selected, by fingerprint: what Keyring > Compare, Rename and Remove act on.
    @Published var keyringSelected: String?
    /// What a Keyring menu action asks the keyring view to open; each ask counts one up.
    @Published var keyringAsk: KeyringAsk?
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

    /// Whether macOS lets Vox notify; nil until it says.
    @Published private(set) var notifying: Bool?
    /// Whether this model posts notifications at all.
    private let notifies: Bool
    /// Local notifications for messages in rooms the person is not looking at (M-23).
    private let notifier = Notifier()

    /// `notify`: whether this model posts notifications; the app's does, and the screenshot
    /// renderer's (apps/macos/Screenshots, never shipped) does not, so it asks nobody anything.
    init(client: VoxClient, node: String, me: String, notify: Bool = true) {
        self.client = client
        self.node = node
        self.me = me
        notifies = notify
        guard notify else { return }
        notifier.open = { [weak self] room in Task { await self?.show(.room(room)) } }
        notifier.allowed = { [weak self] granted in self?.notifying = granted }
        notifier.ask()
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
        await seedUnread()
        do {
            try await client.subscribe(listener: Listener(model: self))
        } catch {
            said = sentence(error)
        }
        follow()
    }

    /// Read the node's facts again every few seconds, each published only when it changed: the
    /// keyring and its window, the nodes on this Mac, the peers. A change made elsewhere (the
    /// CLI, another client) shows without a notice.
    private func follow() {
        following?.cancel()
        following = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                guard let self else { return }
                await self.readFacts()
            }
        }
    }

    /// The keyring, the nodes on this Mac, the peers and the keyring window, assigned only when
    /// they changed; and who trusts back, while the keyring is on screen.
    private func readFacts() async {
        if let keyring = try? await client.trustList(), keyring != trusted { trusted = keyring }
        if let fresh = try? await client.nodes(), fresh != nodes { nodes = fresh }
        if let view = try? await client.view() {
            if Int(view.peers) != peers { peers = Int(view.peers) }
            if view.keyring != keyring { keyring = view.keyring }
        }
        let ready = lanHelper.status == .enabled
        if ready != lanHelperReady { lanHelperReady = ready }
        if selection == .keyring {
            let back = await readTrustsBack()
            if back != trustsBack { trustsBack = back }
        }
    }

    /// The nodes that trust this one back, from each open room's consents.
    private func readTrustsBack() async -> Set<String> {
        var back: Set<String> = []
        for room in rooms where room.open {
            if let consents = try? await client.consents(room: room.id) {
                back.formUnion(consents.inbound)
            }
        }
        return back
    }

    /// Rooms whose unread was counted from what the node recorded as read.
    private var seeded: Set<String> = []

    /// Each open room's unread, the first time it is seen, from what the node recorded as read
    /// (ADR-028 R-8): what came while the app was closed. The node's events count from there.
    func seedUnread() async {
        for room in rooms where room.open && !seeded.contains(room.id) {
            if case .room(room.id) = selection { continue }
            guard let rows = try? await client.unread(room: room.id),
                  let i = rooms.firstIndex(where: { $0.id == room.id }) else { continue }
            seeded.insert(room.id)
            for message in rows where message.author != me {
                switch message.level {
                case .toYou:
                    rooms[i].addressed += 1
                    if message.urgent { rooms[i].urgent += 1 }
                case .new: rooms[i].new += 1
                case .coordination: rooms[i].coordination += 1
                }
            }
        }
    }

    /// The rooms, the keyring, the nodes on this Mac and the peers, read again.
    func refresh() async {
        do {
            let fresh = try await client.rooms()
            let now = fresh.map { r in
                var room = Room(id: r.id, name: name(of: r), open: r.open)
                if let held = rooms.first(where: { $0.id == r.id }) {
                    room.addressed = held.addressed
                    room.urgent = held.urgent
                    room.new = held.new
                    room.coordination = held.coordination
                }
                return room
            }
            if now != rooms { rooms = now }
            await readFacts()
            let back = await readTrustsBack()
            if back != trustsBack { trustsBack = back }
        } catch {
            said = sentence(error)
        }
    }

    /// Put `selection` on screen at once: a room switched to shows nothing of the last one while
    /// its own is read (show reads it).
    func select(_ selection: Selection?) {
        guard selection != self.selection else { return }
        self.selection = selection
        guard case .room = selection else { return }
        messages = []
        readBy = [:]
        pulled = [:]
        members = []
        lanes = []
        roomServices = []
        selectedMessage = nil
        selectedService = nil
        replyTo = nil
    }

    /// Show `selection`; a room shown is read, so its unread counts end.
    func show(_ selection: Selection?) async {
        select(selection)
        if case .decisions = selection {
            decisionEvents = await decisions()
        }
        guard case let .room(id) = selection else { return }
        if let i = rooms.firstIndex(where: { $0.id == id }) {
            rooms[i].addressed = 0
            rooms[i].urgent = 0
            rooms[i].new = 0
            rooms[i].coordination = 0
        }
        do {
            // Each read lands only if the room is still the one on screen: a quick switch must not
            // draw one room's messages under another.
            let read = try await client.read(room: id, after: "", limit: 0)
            guard case .room(id) = self.selection else { return }
            messages = read
            let services = (try? await client.services(room: id).shared) ?? []
            let laneRows = (try? await client.lanes(room: id)) ?? []
            let rows = try await memberRows(id)
            guard case .room(id) = self.selection else { return }
            roomServices = services
            lanes = laneRows
            members = rows
            watchReads(id)
        } catch {
            said = sentence(error)
        }
    }

    // ---- the keyring (M-16) ----------------------------------------------------------------

    /// Trust `fingerprint` as `alias`. Whether it was done.
    func trust(_ fingerprint: String, as alias: String) async -> Bool {
        let fp = fingerprint.filter { !$0.isWhitespace && $0 != "-" && $0 != "·" }.lowercased()
        return await keyringChange { [client] pass in
            try await client.trustAdd(fingerprint: fp, name: alias, identityPassphrase: pass)
            return "Trusting \(fp.prefix(12)) as \(alias)."
        }
    }

    /// Show `fingerprint` as `alias` from now on.
    func rename(_ fingerprint: String, to alias: String) async -> Bool {
        await keyringChange { [client] pass in
            try await client.trustRename(fingerprint: fingerprint, name: alias,
                                         identityPassphrase: pass)
            return "\(fingerprint.prefix(12)) is now \(alias)."
        }
    }

    /// Untrust `node`.
    func untrust(_ node: TrustedNode) async {
        _ = await keyringChange { [client] pass in
            try await client.trustRemove(fingerprint: node.fingerprint, identityPassphrase: pass)
            return "No longer trusting \(node.name). Your sender key is rotated, and everyone you "
                + "still trust is re-keyed."
        }
    }

    /// The change waiting for the passphrase, made with it; its bytes are wiped at once.
    func retryKeyring(with secret: Secret) async {
        defer { secret.wipe() }
        guard let waiting = keyringWaiting else { return }
        do {
            let passphrase = try secret.passphrase()
            defer { passphrase.wipe() }
            keyringDid = try await waiting(passphrase)
            keyringFailed = nil
            keyringNeedsPassphrase = false
            keyringWaiting = nil
            await refresh()
        } catch {
            keyringFailed = sentence(error)
        }
    }

    /// Make a keyring change, asking for the passphrase when the node says the keyring window has
    /// closed (ADR-026 N-2), and say what it did.
    private func keyringChange(_ change: @escaping (Passphrase?) async throws -> String) async -> Bool {
        keyringDid = nil
        keyringFailed = nil
        do {
            keyringDid = try await change(nil)
            keyringNeedsPassphrase = false
            await refresh()
            return true
        } catch {
            let why = sentence(error)
            if why.contains("needs your identity passphrase") {
                keyringWaiting = change
                keyringNeedsPassphrase = true
            } else {
                keyringFailed = why
            }
            return false
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

    /// The room at sidebar position `n` (1-based): needs you, then active, then quiet (⌘1–⌘9).
    func showRoom(at n: Int) async {
        let ordered = group(.needsYou) + group(.active) + group(.quiet)
        guard n >= 1 && n <= ordered.count else { return }
        await show(.room(ordered[n - 1].id))
    }

    /// Open the keyring view and ask it for `kind`: the add form, or the selected row's compare,
    /// rename or remove (M-21).
    func askKeyring(_ kind: KeyringAsk.Kind) {
        let row = kind == .add ? nil : keyringSelected
        guard kind == .add || row != nil else { return }
        select(.keyring)
        Task {
            await show(.keyring)
            keyringAsk = KeyringAsk(kind: kind, fingerprint: row)
        }
    }

    /// The room on screen's id, if a room is on screen.
    var roomOnScreen: String? {
        if case let .room(id) = selection { return id }
        return nil
    }

    /// Create a room named `name` under `passphrase`, and show it.
    func createRoom(_ name: String, passphrase secret: Secret) async -> Bool {
        await withPassphrase(secret) { [client] p in try await client.createRoom(name: name, passphrase: p) }
    }

    /// Join a room by its link and passphrase, and show it. It keeps the name its members gave it.
    func joinRoom(_ link: String, passphrase secret: Secret) async -> Bool {
        await withPassphrase(secret) { [client] p in
            try await client.joinRoom(link: link, passphrase: p)
        }
    }

    private func withPassphrase(_ secret: Secret,
                                _ act: (Passphrase) async throws -> String) async -> Bool {
        do {
            let passphrase = try secret.passphrase()
            defer { passphrase.wipe() }
            let room = try await act(passphrase)
            await refresh()
            await show(.room(room))
            return true
        } catch {
            said = sentence(error)
            return false
        }
    }

    /// Copy the room on screen's link (⌘L), saying what it carries.
    func copyRoomLink() async {
        guard let id = roomOnScreen else { return }
        do {
            let link = try await client.link(room: id)
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(link.url, forType: .string)
            did = link.note.isEmpty ? "Room link copied." : "Room link copied. \(link.note)"
        } catch {
            said = sentence(error)
        }
    }

    /// Leave the room on screen, or end it for everyone.
    func leaveRoom(endingIt: Bool) async {
        guard let id = roomOnScreen else { return }
        do {
            if endingIt { try await client.end(room: id) } else { try await client.leave(room: id) }
            did = endingIt ? "The room is ended for everyone." : "You left the room."
            selection = nil
            await refresh()
        } catch {
            said = sentence(error)
        }
    }

    /// Set the room on screen's retention.
    func setRetention(_ seconds: UInt64, passphrase secret: Secret) async -> Bool {
        defer { secret.wipe() }
        guard let id = roomOnScreen else { return false }
        do {
            let passphrase = try secret.passphrase()
            defer { passphrase.wipe() }
            try await client.setRetention(room: id, ttlSecs: seconds, identityPassphrase: passphrase)
            did = seconds == 0 ? "Messages here are kept for good."
                : "Messages here are kept for \(Retention.words(seconds)), then deleted everywhere."
            return true
        } catch {
            said = sentence(error)
            return false
        }
    }

    /// The decision record as last read, newest first (M-18).
    @Published var decisionEvents: [DecisionEvent] = []

    /// This node's decision record, newest first (M-18).
    func decisions() async -> [DecisionEvent] {
        do {
            return try await client.decisions()
        } catch {
            said = sentence(error)
            return []
        }
    }

    /// The room on screen's admins, creator first.
    func admins() async -> [String] {
        guard let id = roomOnScreen else { return [] }
        return (try? await client.admins(room: id)) ?? []
    }

    /// Make a member an admin of the room on screen, or take it back.
    func setAdmin(_ member: String, _ admin: Bool) async {
        guard let id = roomOnScreen else { return }
        do {
            try await client.setAdmin(room: id, member: member, admin: admin)
        } catch {
            said = sentence(error)
        }
    }

    /// Copy the selected service's address (⌘⇧C): its canonical form, which works pasted on any
    /// member's machine (ADR-028 S-1, S-3), said by its readable one.
    func copyServiceCommand() {
        guard let service = selectedService else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(service.canonical, forType: .string)
        did = "Copied the address of \(service.address)."
    }

    /// Copy a service's command, as given: with the canonical address (S-3).
    func copyCommand(_ command: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(command, forType: .string)
        did = "Copied: \(command)"
    }

    /// A room's services, as the daemon lists them.
    func services(of room: String) async throws -> RoomServices {
        try await client.services(room: room)
    }

    /// A room's members.
    func rosterOf(_ room: String) async throws -> [Member] {
        try await client.roster(room: room)
    }

    /// What listens on this Mac, as one-step sharing lists it (S-4).
    func listeningHere() async -> ListeningServices {
        await client.listening()
    }

    /// What sharing the service on `port` would do, said before it is shared (S-4).
    func previewShare(port: UInt16, udp: Bool) async throws -> ServicePreview {
        try await client.servicePreview(port: port, udp: udp)
    }

    /// Share `local` in `room` as `tag`; nil when shared, else the daemon's sentence.
    func shareService(room: String, tag: String, local: String) async -> String? {
        do {
            try await client.serviceAdd(room: room, tag: tag, local: local)
            did = "Shared \(tag) (\(local))."
            return nil
        } catch {
            return sentence(error)
        }
    }

    /// Stop sharing `tag` in `room`.
    func stopService(room: String, tag: String) async {
        do {
            try await client.serviceRemove(room: room, tag: tag)
            did = "Stopped sharing \(tag)."
        } catch {
            said = sentence(error)
        }
    }

    /// The next room that needs the person, if any (W-2).
    func nextNeedingYou() async {
        guard let room = group(.needsYou).first else { return }
        await show(.room(room.id))
    }

    /// Share the file or folder at `url` in the room on screen, addressed to `to` (members'
    /// fingerprints; none: the room) with `note`, in one message (ADR-028 F-1). Whether it was.
    func attach(_ url: URL, to: [String], note: String) async -> Bool {
        guard case let .room(id) = selection else { return false }
        do {
            _ = try await client.share(room: id, path: url.path, to: to, note: note, re: "",
                                       urgent: false, count: 0, forSecs: 0)
            return true
        } catch {
            said = sentence(error)
            return false
        }
    }

    /// Post `text` to the room on screen.
    func post(_ text: String, to: [String] = [], urgent: Bool = false, re: String = "") async {
        guard case let .room(id) = selection else { return }
        do {
            try await client.post(room: id, text: text, to: to, re: re, urgent: urgent)
        } catch {
            said = sentence(error)
        }
    }

    // ---- what the node says -------------------------------------------------------------------

    /// The messages drawn on screen are read (R-6): the node is told, as the TUI tells it what it
    /// draws, once each, in batches. This node's own, and those not received yet, are not.
    func drawn(_ message: RoomMessage, in room: String) {
        guard case .room(room) = selection, byID[message.id] != nil, message.author != me,
              !message.owed, !marked.contains(message.id) else { return }
        marked.insert(message.id)
        unmarked[room, default: []].append(message.id)
        guard flushing == nil else { return }
        flushing = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 300_000_000)
            guard let self else { return }
            // Batched by room: a switch inside the batch tells each room only its own.
            let batches = self.unmarked
            self.unmarked = [:]
            self.flushing = nil
            for (room, ids) in batches {
                do {
                    try await self.client.markRead(room: room, ids: ids)
                } catch {
                    // Not recorded: drawn again, it is told again.
                    ids.forEach { self.marked.remove($0) }
                    self.said = sentence(error)
                }
            }
        }
    }

    private var marked: Set<String> = []
    private var unmarked: [String: [String]] = [:]
    private var flushing: Task<Void, Never>?

    /// The members of `room` other than this node, with the trust each has here.
    private func memberRows(_ room: String) async throws -> [MemberRow] {
        let roster = try await client.roster(room: room)
        let consents = try await client.consents(room: room)
        let keyring = Set(trusted.map(\.fingerprint))
        let back = Set(consents.inbound)
        return roster.filter { $0.fingerprint != me }.map { m in
            let trust: Trust = keyring.contains(m.fingerprint)
                ? (back.contains(m.fingerprint) ? .mutual : .oneWay) : .none
            return MemberRow(id: m.fingerprint,
                             name: m.name.isEmpty ? String(m.fingerprint.prefix(12)) : m.name,
                             trust: trust)
        }
    }

    /// The room on screen, read again every few seconds while it is there, each part published
    /// only when it changed: who has read this node's messages (read records arrive with the
    /// room's syncs and draw nothing of their own), the lanes, the pulled copies, the services
    /// shared, and the members with their trust (one who joins while the room is on screen).
    private func watchReads(_ room: String) {
        watching?.cancel()
        watching = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                guard let self, case .room(room) = self.selection else { return }
                let reads = try? await self.client.readBy(room: room)
                let laneRows = try? await self.client.lanes(room: room)
                let copies = try? await self.client.pulled(room: room)
                let services = try? await self.client.services(room: room).shared
                let rows = try? await self.memberRows(room)
                guard case .room(room) = self.selection else { return }
                if let reads {
                    let now = Dictionary(uniqueKeysWithValues: reads.map { ($0.id, $0.names) })
                    if now != self.readBy { self.readBy = now }
                }
                if let laneRows, laneRows != self.lanes { self.lanes = laneRows }
                if let copies {
                    let now = Dictionary(copies.map { ($0.entry, $0.path) }) { $1 }
                    if now != self.pulled { self.pulled = now }
                }
                if let services, services != self.roomServices { self.roomServices = services }
                if let rows, rows != self.members { self.members = rows }
            }
        }
    }

    fileprivate func arrived(_ message: RoomMessage, in room: String) {
        let focused: Bool = {
            if case .room(room) = selection { return NSApp.isActive }
            return false
        }()
        // A message the person is not looking at is notified: never this node's own, nor
        // coordination traffic, nor one whose body has not arrived.
        if notifies && !focused && message.author != me && message.level != .coordination
            && !message.owed {
            let name = rooms.first { $0.id == room }?.name ?? String(room.prefix(12))
            notifier.post(message, room: room, roomName: name, me: me)
        }
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

// The menu bar extra's facts (M-22, A-3), here for the client they are read with.
extension NodeModel {
    /// The services shared to this node, its own shares and its live tunnels, across its rooms.
    func menuBarFacts() async -> MenuBarFacts {
        var facts = MenuBarFacts()
        for room in rooms where room.open {
            if let listed = try? await client.services(room: room.id) {
                facts.services += listed.shared.filter { $0.by != "you" }
                    .map { .init(address: $0.address, canonical: $0.canonical, by: $0.by) }
            }
            if let mine = try? await client.shares(room: room.id) {
                facts.shares += mine.map {
                    .init(room: room.id, roomName: room.name, name: $0.name, tag: $0.tag)
                }
            }
        }
        if let report = try? await client.status(),
           let json = try? JSONSerialization.jsonObject(with: Data(report.utf8)) as? [String: Any],
           let tunnels = json["tunnels"] as? [[String: Any]] {
            let names = Dictionary(trusted.map { ($0.fingerprint, $0.name) }) { a, _ in a }
            facts.tunnels = tunnels.compactMap { t in
                guard let id = t["id"] as? Int, let peer = t["peer"] as? String,
                      let service = t["service"] as? String else { return nil }
                return .init(id: id, peer: names[peer] ?? String(peer.prefix(12)), service: service,
                             outbound: (t["direction"] as? String) == "out")
            }
        }
        return facts
    }

    /// Stop one of this node's shares.
    func stopShare(_ share: MenuBarFacts.Share) async {
        do {
            _ = try await client.shareStop(room: share.room, selector: share.tag)
        } catch {
            said = sentence(error)
        }
    }
}
