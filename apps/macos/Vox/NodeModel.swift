// The node the app acts as, once attached: its rooms grouped by what they need from the person
// (ADR-028 W-2), the room on screen, its members and their trust (L-4), and the status bar's facts
// (W-1).

import AppKit
import Foundation
import os
import ServiceManagement

/// What the read path does, at debug level (`log stream --level debug --predicate
/// 'subsystem == "us.vox.app"'`): ids and counts only, never message text.
let readLog = Logger(subsystem: "us.vox.app", category: "read")

/// A room's composer as it was left: its text, To:, Urgent and the reply being written (D12).
struct RoomDraft {
    var text = ""
    var to: Set<String> = []
    var urgent = false
    var reply: RoomMessage?
}

@MainActor
final class NodeModel: ObservableObject {
    /// What the window shows in its middle.
    enum Selection: Hashable {
        case room(String)
        case keyring
        case decisions
        case services
        /// A trust offer waiting, by the offered node's fingerprint (ADR-028 K-15).
        case offer(String)
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
        /// Approvals and questions waiting on this node in Sessions it may drive here (ADR-029
        /// CL-2).
        var waiting = 0

        /// What it needs from the person, by the rule the TUI groups by (W-2): a Session waiting
        /// on this node needs it too (CL-2).
        var need: RoomGroup {
            waiting > 0 ? .needsYou
                : roomGroup(toYou: UInt32(addressed), new: UInt32(new), coordination: UInt32(coordination))
        }

        /// The room's unread in words, as its row says it.
        var words: String {
            var parts: [String] = []
            if addressed > 0 { parts.append("\(addressed) to you") }
            if waiting > 0 { parts.append("waiting \(waiting)") }
            if urgent > 0 { parts.append("\(urgent) urgent") }
            if new > 0 { parts.append("\(new) new") }
            if coordination > 0 { parts.append("\(coordination) coordination") }
            return parts.isEmpty ? "nothing unread" : parts.joined(separator: ", ")
        }
    }

    /// A member that joined the room on screen while it was on screen (K-7).
    struct JoinLine: Equatable {
        let fingerprint: String
        let at: UInt64
        var said: String
    }

    /// A member of the room on screen.
    struct MemberRow: Identifiable, Equatable {
        let id: String
        let name: String
        let trust: Trust
        /// Whether this node's keyring entry for it grants drive as well as read (K-14).
        let drive: Bool
        /// Whether it trusts this node: it has granted this node consent (ADR-007 G-9), whether
        /// or not this node trusts it back.
        var trustsYou = false
        /// Why this node's key for it here waits, if it does (ADR-030 D-5, W-4).
        var keyWaits: String?
    }

    let node: String
    let me: String
    private let client: VoxClient

    @Published private(set) var rooms: [Room] = []
    @Published var selection: Selection?
    /// The first message that was unread when the room came on screen, and how many were: where
    /// the timeline draws its unread line. It stays while the room is on screen; what arrives
    /// meanwhile is read as it is shown.
    @Published private(set) var unreadFrom: String?
    @Published private(set) var unreadCount = 0
    @Published private(set) var messages: [RoomMessage] = [] {
        didSet {
            byID = Dictionary(messages.map { ($0.id, $0) }) { $1 }
            var said: [String: NodePlatform] = [:]
            for message in messages { if let p = message.platform { said[message.author] = p } }
            if said != platforms { platforms = said }
        }
    }
    /// The room on screen's messages by id, for what is in view.
    private(set) var byID: [String: RoomMessage] = [:]
    /// The platform each member's node says it runs on, from its latest `hello` that says so in
    /// the room on screen (ADR-020 §4.9b), by fingerprint: its claim, never checked.
    @Published private(set) var platforms: [String: NodePlatform] = [:]
    /// Who has read each of this node's own messages in the room on screen, by message id (R-6).
    @Published private(set) var readBy: [String: [String]] = [:]
    /// Where each of this node's own messages is, while no member is known to have read it
    /// (ADR-028 R-6, D9): "only on this machine", "on N of M members' nodes".
    @Published private(set) var whereabouts: [String: String] = [:]
    /// Who joined the room on screen while it was on screen, and when (ADR-028 K-7, D10): said
    /// in its timeline with which of the keyring's nodes trust the newcomer, said again as that
    /// grows.
    @Published private(set) var joins: [JoinLine] = []
    /// Who has pulled each of this node's own shares in the room on screen, verified, by the
    /// share's message id (ADR-028 F-6, #498).
    @Published private(set) var pulledBy: [String: [String]] = [:]
    /// The room on screen's retention, as a person reads it (ADR-028 R-7).
    @Published private(set) var retention = ""
    /// The room on screen's retention in seconds, 0 for forever; `nil` until read. What the
    /// Retention sheet opens at (D14).
    @Published private(set) var retentionSecs: UInt64?
    /// What the room on screen's timeline shows (ADR-029 CL-2): General each time a room opens.
    @Published var showing: Showing = .general {
        didSet {
            guard showing != oldValue else { return }
            // Another Session's entries are never drawn, nor acted on, under this one's header
            // while it loads (D3): cleared, and said to be loading.
            sessionEntries = []
            sessionNote = nil
            sessionLoading = showingSession
            // What was selected was in the other view's rows: Focus Timeline and ↑/↓ start
            // afresh in this one (P14), as on opening another room.
            selectedMessage = nil
            selectedMessages = []
            // A request chosen in another view is not in this one's rows: kept, the timeline
            // would centre it, not follow its newest line. openRequest chooses it after this.
            selectedRequest = nil
            selectionAnchor = nil
            Task { await readSession() }
        }
    }
    /// The Session on screen is being read: its timeline says "Loading…" (D3).
    @Published private(set) var sessionLoading = false

    /// What is typed, kept per destination while the app runs, in memory only: nothing goes on
    /// disk or the wire (D12). A room's draft, To:, Urgent and reply, by room id.
    var roomDrafts: [String: RoomDraft] = [:]
    /// A Session's draft, by its destination (`room/node/session`).
    var sessionDrafts: [String: String] = [:]
    /// What each room last showed (General, All, or a Session), restored when it opens again.
    var lastShowing: [String: Showing] = [:]

    /// The request selected in the Session on screen, by its reference: what Approve (⌥⌘Y) and
    /// Reject (⌥⌘N) act on, and where ⌘J and a notification land (P1).
    @Published var selectedRequest: String?
    /// The requests waiting on this node already known, by `room/node/session/reference`: one
    /// that is new notifies, once per Session (P1). Taken in silence the first time, so opening
    /// Vox notifies nothing.
    private var knownWaiting: Set<String> = []
    private var waitingSeen = false
    /// The room on screen's Sessions, open and ended (ADR-029 CL-2).
    @Published private(set) var sessions: [FfiSession] = []
    /// The Session on screen's entries, oldest first, to a member with drive (SC-1).
    @Published private(set) var sessionEntries: [FfiSessionEntry] = []
    /// What the node says of the Session on screen besides its entries: "opening not received yet".
    @Published private(set) var sessionNote: String?
    /// What was done to the room on screen (its retention set, its name changed), oldest first.
    @Published private(set) var notices: [RoomNoticeRow] = []
    /// Where this node's verified copy of each share it pulled in the room on screen is, by the
    /// share's message id (ADR-028 F-3, F-4): what its card opens with Quick Look.
    @Published private(set) var pulled: [String: String] = [:]
    /// Where each pull of the room on screen's file offers stands that is not done, by the
    /// share's message id (F-3, D5): being pulled, waiting for its sharer, or failed.
    @Published private(set) var pulling: [String: PullState] = [:]
    /// A file handed to Vox from elsewhere (the Finder Services item, M-24), waiting for the room
    /// on screen to take it: its To: and note are asked there.
    @Published var incoming: URL?
    // ---- what the menus, keys and palette ask for (M-19–M-21) ---------------------------------

    /// The sheet a menu, key or palette action opened.
    @Published var sheet: NodeSheet?
    /// Whether the room's inspector shows (View > Hide Inspector, ⌥⌘I), kept across launches.
    @Published var inspectorShown = Columns.inspectorShown {
        didSet { UserDefaults.standard.set(inspectorShown, forKey: Columns.inspectorShownKey) }
    }
    /// Asks the room on screen to choose a file to attach (⌘O); each ask counts one up.
    @Published var attachAsked = 0
    /// ⌘O while a Session is shown, to a member with drive: a file sent to that Session (D2).
    @Published var sessionAttachAsked = 0
    /// Asks the room on screen to send its draft urgent (⌘↩).
    @Published var urgentAsked = 0
    /// The message selected in the timeline, and the one the composer replies to (⌘R): the one
    /// the keyboard is on.
    @Published var selectedMessage: String?
    /// Every message selected in the timeline, for ⌘C (v0.4.1): the one above, and those ⌘-click,
    /// ⇧-click, ⇧↑/⇧↓ or a drag across rows added.
    @Published var selectedMessages: Set<String> = []
    /// Where a ⇧-click or ⇧↑/⇧↓ range starts.
    var selectionAnchor: String?
    @Published var replyTo: RoomMessage?
    /// A message a quote was clicked to reach (ADR-028 R-9): the room's timeline scrolls to it and
    /// selects it, then sets this back to nil.
    @Published var jumpTo: String?
    /// The service card selected above the timeline, whose command ⌘⇧C copies.
    @Published var selectedService: SharedService?
    /// What the last operation came to (P6): done, refused, or not known whether it was done,
    /// with the operation that made it. A sheet shows only its own; a new operation clears it.
    @Published private(set) var outcome: Outcome?
    /// The operation under way, which an outcome is filed under.
    private var operation = ""
    /// What the last operation did, said where the person is (E-5): `outcome`, when done.
    var did: String? { outcome.flatMap { $0.kind == .done ? $0.words : nil } }

    /// The services members share in the room on screen, as cards above its timeline.
    @Published private(set) var roomServices: [SharedService] = []
    /// What the last keyring change did, or why it failed, in the daemon's words (E-5, M-7).
    @Published private(set) var keyringDid: String?
    @Published private(set) var keyringFailed: String?
    /// The keyring change waiting for the identity passphrase (the keyring window has closed,
    /// ADR-026 N-2), bound to what it changes (D1): made only with it, cleared by Cancel and by
    /// any keyring change that succeeds, and replaced only when the person says so.
    @Published private(set) var keyringPending: KeyringPending?
    /// A second gated change while one waits: asked about first, never put in silently (D1).
    @Published private(set) var keyringReplacing: KeyringPending?

    /// Follows who has read what while a room is on screen.
    private var watching: Task<Void, Never>?
    /// Follows the node's facts (keyring, nodes, peers) while the model lives.
    private var following: Task<Void, Never>?
    @Published private(set) var members: [MemberRow] = []
    @Published private(set) var trusted: [TrustedNode] = []
    /// Trust offers waiting on this node: newcomers, and nodes that trust it (ADR-028 K-15, K-17).
    @Published private(set) var offers: [OfferInfo] = []
    /// The trusted nodes that trust this node back, as the rooms shared with them record it (L-4).
    @Published private(set) var trustsBack: Set<String> = []
    /// The members of the room on screen whose trust in this node has reached it, in the keyring
    /// or not (ADR-028 R-5, D4).
    @Published private(set) var trustsMe: Set<String> = []
    /// The node whose card is open (D4): from a member row, a message's author or a decision row.
    @Published var card: NodeCardFor?
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
    /// The room whose family LAN was turned on while the LAN helper waits for the person's
    /// approval: its sheet is up, and the LAN goes on once the helper is allowed.
    @Published private(set) var lanAsking: String?

    /// The family LAN's root helper: the bundle's launchd daemon (ADR-014 M-10).
    private var lanHelper: any BackgroundItem { Daemon.lanHelper }

    /// The LAN helper's status, asked off the main thread. Asking is a call to launchd's smd that
    /// waits about 20 ms; made every few seconds on the main thread, it held up the answer to
    /// macOS's "may this notification show as a banner while Vox is in front?", macOS filed the
    /// notification in Notification Center first, and no banner showed (#450 walkthrough).
    private nonisolated static func lanHelperStatus() async -> SMAppService.Status {
        await Task.detached { Daemon.lanHelper.status }.value
    }
    /// Why the last operation was not done, or may not have been, in the daemon's words (M-7):
    /// `outcome`, when not done.
    var said: String? { outcome.flatMap { $0.kind == .done ? nil : $0.words } }
    /// A room link to fill the Join sheet with, taken by the sheet when it opens.
    @Published var joinLink: String?

    /// Open the Join sheet with `link` filled in (a vox:// link the system opened the app with).
    func offerJoin(_ link: String) {
        joinLink = link
        sheet = .joinRoom
    }

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
        notifier.openRequest = { [weak self] room, node, session, reference in
            Task { await self?.openRequest(room: room, node: node, session: session, reference: reference) }
        }
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
            readLog.debug("follow: subscribed to the node's events")
        } catch {
            readLog.debug("follow: subscribing failed: \(sentence(error), privacy: .public)")
            reportBackground(error)
        }
        follow()
    }

    /// Read the node's facts again every few seconds, each published only when it changed: the
    /// keyring and its window, the nodes on this Mac, the peers, and what waits on this node in
    /// each room's Sessions. A change made elsewhere (the CLI, another client) shows without a
    /// notice.
    private func follow() {
        following?.cancel()
        following = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                guard let self else { return }
                await self.readFacts()
                await self.readWaiting()
                await self.readNewOnScreen()
            }
        }
    }

    /// The room on screen read again from its newest message, and anything the node's events did
    /// not bring added as if it had: a missed or dead event stream hides a message for one turn of
    /// this loop at most (the walkthrough's WHERE-15, posted while every peer was offline, never
    /// came as an event to the reopened app).
    private func readNewOnScreen() async {
        guard case let .room(id) = selection else { return }
        let after = messages.last?.id ?? ""
        guard let rows = try? await client.read(room: id, after: after, limit: 0),
              case .room(id) = selection else { return }
        let new = rows.filter { byID[$0.id] == nil && !$0.owed }
        guard !new.isEmpty else { return }
        readLog.debug("follow: \(new.count) message(s) in \(id, privacy: .public) found by the read, not by an event")
        for message in new { arrived(message, in: id) }
    }

    /// The keyring, the nodes on this Mac, the peers and the keyring window, assigned only when
    /// they changed; and who trusts back, while the keyring is on screen.
    private func readFacts() async {
        if let keyring = try? await client.trustList(), keyring != trusted { trusted = keyring }
        if let waiting = try? await client.pendingOffers(), waiting != offers { offers = waiting }
        if let fresh = try? await client.nodes(), fresh != nodes { nodes = fresh }
        if let view = try? await client.view() {
            if Int(view.peers) != peers { peers = Int(view.peers) }
            if view.keyring != keyring { keyring = view.keyring }
        }
        await recheckLanHelper()
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
            guard let rows = try? await client.unread(room: room.id) else { continue }
            seeded.insert(room.id)
            for message in rows { count(message, in: room.id) }
        }
    }

    /// Each room's unread messages, by id: counted once each, from what the node recorded as
    /// unread and from what arrives, and no longer counted once drawn in view with the window in
    /// front ([`drawn`]). Selecting a room reads nothing (ADR-028 R-6; the app panel's D18).
    private var counted: [String: [String: RoomMessage]] = [:]

    /// `message` counted unread in `room`, once: never this node's own.
    private func count(_ message: RoomMessage, in room: String) {
        guard message.author != me, counted[room]?[message.id] == nil,
              let i = rooms.firstIndex(where: { $0.id == room }) else { return }
        counted[room, default: [:]][message.id] = message
        switch message.level {
        case .toYou:
            rooms[i].addressed += 1
            if message.urgent { rooms[i].urgent += 1 }
        case .new: rooms[i].new += 1
        case .coordination: rooms[i].coordination += 1
        }
    }

    /// Message `id` seen in `room`: no longer counted.
    private func uncount(_ id: String, in room: String) {
        guard let message = counted[room]?.removeValue(forKey: id),
              let i = rooms.firstIndex(where: { $0.id == room }) else { return }
        switch message.level {
        case .toYou:
            rooms[i].addressed = max(0, rooms[i].addressed - 1)
            if message.urgent { rooms[i].urgent = max(0, rooms[i].urgent - 1) }
        case .new: rooms[i].new = max(0, rooms[i].new - 1)
        case .coordination: rooms[i].coordination = max(0, rooms[i].coordination - 1)
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
                    room.waiting = held.waiting
                }
                return room
            }
            if now != rooms { rooms = now }
            await readWaiting()
            await readFacts()
            let back = await readTrustsBack()
            if back != trustsBack { trustsBack = back }
        } catch {
            reportBackground(error)
        }
    }

    /// Put `selection` on screen at once: a room switched to shows nothing of the last one while
    /// its own is read (show reads it).
    func select(_ selection: Selection?) {
        guard selection != self.selection else { return }
        // The room left keeps what it showed and the reply being written (D12).
        if case let .room(left) = self.selection {
            lastShowing[left] = showing
            roomDrafts[left, default: RoomDraft()].reply = replyTo
        }
        self.selection = selection
        // A request chosen in another room is not in this one (P1): openRequest chooses it after.
        selectedRequest = nil
        // An offer's view says what its own Trust did, never an earlier keyring change.
        if case .offer = selection {
            keyringDid = nil
            keyringFailed = nil
        }
        guard case .room = selection else { return }
        messages = []
        unreadFrom = nil
        unreadCount = 0
        readBy = [:]
        whereabouts = [:]
        joins = []
        pulledBy = [:]
        pulled = [:]
        pulling = [:]
        retention = ""
        retentionSecs = nil
        notices = []
        sessions = []
        sessionEntries = []
        sessionNote = nil
        members = []
        roomServices = []
        selectedMessage = nil
        selectedMessages = []
        selectionAnchor = nil
        selectedService = nil
        // What this room last showed, and its reply, come back (D12): General the first time.
        if case let .room(opened) = selection {
            showing = lastShowing[opened] ?? .general
            replyTo = roomDrafts[opened]?.reply
        } else {
            showing = .general
            replyTo = nil
        }
    }

    /// Show `selection`. A room shown is not read by being chosen: each message is read as it is
    /// drawn in view with the window in front ([`drawn`], ADR-028 R-6).
    func show(_ selection: Selection?) async {
        select(selection)
        if case .decisions = selection {
            decisionEvents = await decisions()
        }
        guard case let .room(id) = selection else { return }
        if !seeded.contains(id), let rows = try? await client.unread(room: id) {
            seeded.insert(id)
            for message in rows { count(message, in: id) }
        }
        do {
            // Each read lands only if the room is still the one on screen: a quick switch must not
            // draw one room's messages under another.
            // What was unread as the room came on screen, before showing it marks it read: the
            // timeline's unread line goes above the first of it (ADR-028 R-8).
            let unread = ((try? await client.unread(room: id)) ?? []).filter { $0.author != me }
            let read = try await client.read(room: id, after: "", limit: 0)
            guard case .room(id) = self.selection else { return }
            let unreadIDs = Set(unread.map(\.id))
            unreadFrom = read.first { unreadIDs.contains($0.id) }?.id
            unreadCount = unread.count
            messages = read
            let services = (try? await client.services(room: id).shared) ?? []
            let rows = try await memberRows(id)
            let kept = (try? await client.retention(room: id)) ?? ""
            let keptSecs = try? await client.retentionSecs(room: id)
            let done = (try? await client.notices(room: id)) ?? []
            let listed = (try? await client.sessions(room: id)) ?? []
            guard case .room(id) = self.selection else { return }
            roomServices = services
            members = rows
            retention = kept
            retentionSecs = keptSecs
            notices = done
            sessions = listed
            // A Session restored as this room's last view is read once the room lists it (D12).
            if showingSession { await readSession() }
            watchReads(id)
        } catch {
            reportBackground(error)
        }
    }

    // ---- the keyring (M-16) ----------------------------------------------------------------

    /// Where `fingerprint` stands with this node, each direction, as far as this node knows: its
    /// keyring, and the consent grants of the room on screen and of every trusted node (D4).
    func trust(of fingerprint: String) -> Trust {
        Trust.of(inKeyring: trusted.contains { $0.fingerprint == fingerprint },
                 trustsYou: trustsMe.contains(fingerprint) || trustsBack.contains(fingerprint))
    }


    /// The rooms this node holds that `fingerprint` is a member of, by name (G2).
    func sharedRooms(with fingerprint: String) async -> [String] {
        var names: [String] = []
        for room in rooms {
            if let roster = try? await client.roster(room: room.id),
               roster.contains(where: { $0.fingerprint == fingerprint }) {
                names.append(room.name)
            }
        }
        return names
    }

    /// Open `fingerprint`'s card (D4), named `name` as the room names it.
    func openCard(_ fingerprint: String, name: String, act: NodeCardFor.Act? = nil) {
        keyringDid = nil
        keyringFailed = nil
        card = NodeCardFor(fingerprint: fingerprint, name: name, act: act)
    }

    /// Trust `fingerprint` as `alias`, granting read, and drive as well when `drive` (K-14,
    /// K-16). Whether it was done.
    func trust(_ fingerprint: String, as alias: String, drive: Bool) async -> Bool {
        let fp = fingerprint.filter { !$0.isWhitespace && $0 != "-" && $0 != "·" }.lowercased()
        return await keyringChange(fingerprint: fp, alias: alias,
                                   words: "trust \(alias), \(Capability.words(drive))",
                                   action: "Trust") { [client] pass in
            try await client.trustAdd(fingerprint: fp, name: alias, drive: drive,
                                      identityPassphrase: pass)
            return "Trusting \(fp.prefix(12)) as \(alias), \(Capability.words(drive))."
        }
    }

    /// Give `node` drive as well as read, or (`drive` false) read only (K-14).
    func setCapability(_ node: TrustedNode, drive: Bool) async -> Bool {
        await keyringChange(fingerprint: node.fingerprint, alias: node.name,
                            words: "give \(node.name) \(Capability.words(drive))",
                            action: drive ? "Give Drive" : "Read Only") { [client] pass in
            try await client.setCapability(fingerprint: node.fingerprint, drive: drive,
                                           identityPassphrase: pass)
            return "\(node.name) now has \(Capability.words(drive))."
        }
    }

    /// Show `fingerprint` as `alias` from now on.
    func rename(_ fingerprint: String, to alias: String) async -> Bool {
        let was = trusted.first { $0.fingerprint == fingerprint }?.name ?? String(fingerprint.prefix(12))
        return await keyringChange(fingerprint: fingerprint, alias: alias,
                                   words: "rename \(was) to \(alias)", action: "Rename") { [client] pass in
            try await client.trustRename(fingerprint: fingerprint, name: alias,
                                         identityPassphrase: pass)
            return "\(fingerprint.prefix(12)) is now \(alias)."
        }
    }

    /// Remove `node` from the keyring.
    /// Whether it was done; when not, why is `keyringFailed`, or the passphrase is asked for.
    @discardableResult
    func untrust(_ node: TrustedNode) async -> Bool {
        await keyringChange(fingerprint: node.fingerprint, alias: node.name,
                            words: "remove \(node.name) from your keyring", action: "Remove") { [client] pass in
            try await client.trustRemove(fingerprint: node.fingerprint, identityPassphrase: pass)
            return "Removed \(node.name) from your keyring. Your sender key is rotated, and everyone you "
                + "still trust is re-keyed."
        }
    }

    /// The change `pending` names, made with the passphrase typed for it; its bytes are wiped at
    /// once. Nothing is made unless `pending` is still the change waiting (D1): a prompt drawn for
    /// one change never makes another.
    func retryKeyring(_ pending: KeyringPending, with secret: Secret) async {
        defer { secret.wipe() }
        guard keyringPending?.id == pending.id else { return }
        do {
            let passphrase = try secret.passphrase()
            defer { passphrase.wipe() }
            keyringDid = try await pending.run(passphrase)
            keyringFailed = nil
            if keyringPending?.id == pending.id { keyringPending = nil }
            await refresh()
        } catch {
            keyringFailed = sentence(error)
        }
    }

    /// Cancel the change waiting for the passphrase: it is not made (D1).
    func cancelKeyring() {
        keyringPending = nil
        keyringReplacing = nil
    }

    /// The person's answer to "Replace the waiting change?" (D1).
    func replaceKeyring(_ yes: Bool) {
        if yes, let next = keyringReplacing { keyringPending = next }
        keyringReplacing = nil
    }

    // ---- trust offers (ADR-028 K-15 to K-18) ------------------------------------------------

    /// Accept `offer`: trust it under `alias`, read or read + drive (K-16), behind the passphrase
    /// gate; the offer then leaves needs you. Whether it was done.
    func accept(_ offer: OfferInfo, as alias: String, drive: Bool) async -> Bool {
        guard await trust(offer.fingerprint, as: alias, drive: drive) else { return false }
        if let waiting = try? await client.pendingOffers() { offers = waiting }
        return true
    }

    /// Dismiss `offer`: here only, and silently (K-18); the node stays not in keyring, and trust
    /// stays reachable from the member pane.
    func dismiss(_ offer: OfferInfo) async {
        begin("dismiss-offer")
        do {
            try await client.dismissOffer(fingerprint: offer.fingerprint)
            if let waiting = try? await client.pendingOffers() { offers = waiting }
            if selection == .offer(offer.fingerprint) { selection = nil }
        } catch {
            report(error)
        }
    }

    /// Make a keyring change, asking for the passphrase when the node says the keyring window has
    /// closed (ADR-026 N-2, a typed refusal), and say what it did. The change waiting is named
    /// (D1): what, on whom, and the action that makes it.
    private func keyringChange(fingerprint: String, alias: String, words: String, action: String,
                               _ change: @escaping (Passphrase?) async throws -> String) async -> Bool {
        keyringDid = nil
        keyringFailed = nil
        do {
            keyringDid = try await change(nil)
            // Any change that succeeds clears the one waiting: it was made in another way, or
            // the person has moved on (D1).
            keyringPending = nil
            keyringReplacing = nil
            await refresh()
            return true
        } catch VoxError.PassphraseNeeded {
            let next = KeyringPending(fingerprint: fingerprint, alias: alias, words: words,
                                      action: action, run: change)
            if let waiting = keyringPending, waiting.words != next.words {
                keyringReplacing = next
            } else {
                keyringPending = next
            }
            return false
        } catch {
            keyringFailed = sentence(error)
            return false
        }
    }

    /// Register the LAN helper; macOS asks the person to approve it in System Settings, which
    /// the app opens and never clicks through (M-10, M-33).
    ///
    /// **Any earlier registration goes first.** macOS keeps the helper's background item by bundle
    /// identifier and label, so every copy of Vox.app shares it: a copy that registers finds the
    /// item another copy left and inherits its launch constraint, and launchd refuses this copy's
    /// helper as a code-signing violation, approved or not (#439, on the v0.4.0 release). Unless
    /// the helper is already enabled, it is unregistered before it is registered, so the item is
    /// made for this copy.
    func allowLanHelper() async {
        begin("lan-helper")
        if await Self.lanHelperStatus() != .enabled {
            try? await lanHelper.unregister()
        }
        do {
            try lanHelper.register()
        } catch {
            report(error)
        }
        let status = await Self.lanHelperStatus()
        if status == .requiresApproval {
            Daemon.openLoginItems()
        }
        lanHelperReady = status == .enabled
    }

    /// The family LAN turned on for `room`: at once when the LAN helper is allowed, else the helper
    /// is asked for (its sheet says where to allow it) and the LAN goes on once it is
    /// ([`recheckLanHelper`]). The helper is asked for only here, never before (ADR-014 M-12).
    func turnLanOn(_ room: String) async {
        if await Self.lanHelperStatus() == .enabled {
            lanHelperReady = true
            await setLan(room, on: true)
            return
        }
        lanAsking = room
        await allowLanHelper()
        await recheckLanHelper()
    }

    /// Whether the LAN helper is allowed now, as on every refresh and whenever Vox comes back to the
    /// front (the person returning from System Settings); allowed while a room's LAN waits for it,
    /// that room's sheet closes and its LAN goes on.
    func recheckLanHelper() async {
        let ready = await Self.lanHelperStatus() == .enabled
        if ready != lanHelperReady { lanHelperReady = ready }
        if ready, let room = lanAsking {
            lanAsking = nil
            await setLan(room, on: true)
        }
    }

    /// The helper's sheet closed without it: the LAN stays off.
    func cancelLanAsk() {
        lanAsking = nil
    }

    /// Remove the LAN helper: launchd stops it and it is no longer registered, so nothing of Vox
    /// runs as root. The family LAN is offered again only after the next approval (M-12).
    func removeLanHelper() async {
        begin("lan-helper")
        do {
            try await lanHelper.unregister()
        } catch {
            report(error)
        }
        lanHelperReady = await Self.lanHelperStatus() == .enabled
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

    /// **Pull a file offer now** (F-3, D5): the card's Download, as `vox room get` does. The node
    /// checks its SHA-256 before it keeps it, so the card shows a copy only once it is verified.
    /// How it goes is in `pulling`; where it landed, in `pulled`.
    func download(_ message: RoomMessage) async {
        guard let room = roomOnScreen, let file = message.file else { return }
        pulling[message.id] = .pulling(bytes: 0, of: file.size)
        do {
            let path = try await client.get(room: room, entry: message.id)
            guard roomOnScreen == room else { return }
            pulled[message.id] = path
            pulling[message.id] = nil
        } catch {
            guard roomOnScreen == room else { return }
            pulling[message.id] = .failed(why: sentence(error))
        }
    }

    /// Open the keyring's add form with `fingerprint` in it: the card's Trust… for a sharer not in
    /// the keyring (D5). Trusting it is still the person's own step.
    func askTrust(_ fingerprint: String) {
        select(.keyring)
        Task {
            await show(.keyring)
            keyringAsk = KeyringAsk(kind: .add, fingerprint: fingerprint)
        }
    }

    /// How this node names `fingerprint`: its alias, "you", or the fingerprint cut short.
    func nodeName(_ fingerprint: String) -> String {
        let node = fingerprint.split(separator: "/").first.map(String.init) ?? fingerprint
        if node == me { return "you" }
        if let alias = trusted.first(where: { $0.fingerprint == node })?.name, !alias.isEmpty {
            return alias
        }
        if let alias = members.first(where: { $0.id == node })?.name, !alias.isEmpty {
            return alias
        }
        return String(node.prefix(12))
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
        begin("create-room")
        return await withPassphrase(secret) { [client] p in try await client.createRoom(name: name, passphrase: p) }
    }

    /// Join a room by its link and passphrase, and show it. It keeps the name its members gave it.
    func joinRoom(_ link: String, passphrase secret: Secret) async -> Bool {
        begin("join-room")
        return await withPassphrase(secret) { [client] p in
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
            report(error)
            return false
        }
    }

    /// Copy the room on screen's link (⌘L), saying what it carries.
    func copyRoomLink() async {
        begin("copy-link")
        guard let id = roomOnScreen else { return }
        do {
            let link = try await client.link(room: id)
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(link.url, forType: .string)
            report(done: link.note.isEmpty ? "Room link copied." : "Room link copied. \(link.note)")
        } catch {
            report(error)
        }
    }

    /// Leave the room on screen, or end it for everyone: nil once done, else why not (D19), for
    /// the sheet that asked to say where it was asked.
    func leaveRoom(endingIt: Bool) async -> String? {
        begin("leave")
        guard let id = roomOnScreen else { return "No room is on screen to leave." }
        do {
            if endingIt { try await client.end(room: id) } else { try await client.leave(room: id) }
            report(done: endingIt ? "The room is ended for everyone." : "You left the room.")
            selection = nil
            await refresh()
            return nil
        } catch {
            report(error)
            return sentence(error)
        }
    }

    /// Set the room on screen's retention: no passphrase (ADR-028 K-11).
    func setRetention(_ seconds: UInt64) async -> Bool {
        begin("retention")
        guard let id = roomOnScreen else { return false }
        do {
            try await client.setRetention(room: id, ttlSecs: seconds)
            report(done: seconds == 0 ? "Messages here are kept for good."
                : "Messages here are kept for \(Retention.words(seconds)), then deleted everywhere.")
            return true
        } catch {
            report(error)
            return false
        }
    }

    /// Rename the room on screen: its one name, as every member sees it (ADR-028 R-1). Only its
    /// creator or an admin may; the node's refusal is said as it comes. No passphrase (K-11).
    func renameRoom(to name: String) async -> Bool {
        begin("rename")
        guard let id = roomOnScreen else { return false }
        do {
            try await client.renameRoom(room: id, name: name)
            report(done: "The room is now \(name) for every member.")
            await refresh()
            return true
        } catch {
            report(error)
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
            reportBackground(error)
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
        begin("admins")
        guard let id = roomOnScreen else { return }
        do {
            try await client.setAdmin(room: id, member: member, admin: admin)
        } catch {
            report(error)
        }
    }

    /// Copy the selected service's address (⌘⇧C): its canonical form, which works pasted on any
    /// member's machine (ADR-028 S-1, S-3), said by its readable one.
    func copyServiceCommand() {
        begin("copy")
        guard let service = selectedService else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(service.canonical, forType: .string)
        report(done: "Copied the address of \(service.address).")
    }

    /// Copy a service's whole address: its canonical form, which works pasted on any member's
    /// machine (S-1, S-3), said by its readable one (G3).
    func copyAddress(of service: SharedService) {
        begin("copy")
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(service.canonical, forType: .string)
        report(done: "Copied the address of \(service.address).")
    }

    /// Copy a service's command, as given: with the canonical address (S-3).
    func copyCommand(_ command: String) {
        begin("copy")
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(command, forType: .string)
        report(done: "Copied: \(command)")
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
        begin("share")
        do {
            try await client.serviceAdd(room: room, tag: tag, local: local)
            report(done: "Shared \(tag) (\(local)).")
            return nil
        } catch {
            report(error)
            return sentence(error)
        }
    }

    /// Stop sharing `tag` in `room`.
    func stopService(room: String, tag: String) async {
        begin("stop-share")
        do {
            try await client.serviceRemove(room: room, tag: tag)
            report(done: "Stopped sharing \(tag).")
        } catch {
            report(error)
        }
    }

    /// The next room that needs the person, if any (W-2).
    func nextNeedingYou() async {
        if let room = group(.needsYou).first {
            // A request waiting in one of its Sessions: that Session, that request (P1).
            if let waiting = await firstWaiting(in: room.id) {
                await openRequest(room: room.id, node: waiting.node, session: waiting.session,
                                  reference: waiting.reference)
            } else {
                await show(.room(room.id))
            }
        } else if let offer = offers.first {
            await show(.offer(offer.fingerprint))
        }
    }

    /// Share the file or folder at `url` in the room on screen, addressed to `to` (members'
    /// fingerprints; none: the room) with `note`, in one message (ADR-028 F-1). Whether it was.
    func attach(_ url: URL, to: [String], note: String, urgent: Bool = false) async -> Bool {
        begin("attach")
        guard case let .room(id) = selection else { return false }
        do {
            _ = try await client.share(room: id, path: url.path, to: to, note: note, re: "",
                                       urgent: urgent, count: 0, forSecs: 0)
            return true
        } catch {
            report(error)
            return false
        }
    }

    /// Post `text` to the room on screen; whether the node took it.
    @discardableResult
    func post(_ text: String, to: [String] = [], urgent: Bool = false, re: String = "") async -> Bool {
        begin("post")
        guard case let .room(id) = selection else { return false }
        do {
            try await client.post(room: id, text: text, to: to, re: re, urgent: urgent)
            return true
        } catch {
            report(error)
            return false
        }
    }

    // ---- what an operation came to (P6) ------------------------------------------------------

    /// Start an operation: what the last one came to is cleared, so a result is never left over
    /// from another (P6).
    func begin(_ operation: String) {
        self.operation = operation
        outcome = nil
    }

    /// Why `operation` was not done, or may not have been: what its own sheet shows, and nothing
    /// another operation left (P6).
    func failure(of operation: String) -> Outcome? {
        outcome.flatMap { $0.operation == operation && $0.kind != .done ? $0 : nil }
    }

    /// Take the outcome down: the status bar's dismiss, and a sheet that opens afresh.
    func clearOutcome(of operation: String? = nil) {
        if operation == nil || outcome?.operation == operation { outcome = nil }
    }

    /// The operation under way was done.
    private func report(done words: String) {
        outcome = Outcome(operation: operation, kind: .done, words: words)
    }

    /// The operation under way was refused, or whether it was done is not known: the daemon's
    /// sentence, never a type's name (M-7).
    private func report(_ error: Error) {
        outcome = Outcome(operation: operation, kind: Outcome.kind(of: error), words: sentence(error))
    }

    /// Something the app does on its own failed (a refresh, a read): said in the status bar, but
    /// never over what a person's own operation came to.
    private func reportBackground(_ error: Error) {
        guard outcome == nil || outcome?.operation == "" else { return }
        outcome = Outcome(operation: "", kind: Outcome.kind(of: error), words: sentence(error))
    }

    // ---- what the node says -------------------------------------------------------------------

    /// The messages drawn on screen are read (R-6): the node is told, as the TUI tells it what it
    /// draws, once each, in batches. This node's own, and those not received yet, are not.
    func drawn(_ message: RoomMessage, in room: String) {
        guard case .room(room) = selection, byID[message.id] != nil, message.author != me,
              !message.owed, !marked.contains(message.id) else {
            readLog.debug("""
                not drawn: \(message.id, privacy: .public) on screen \(self.roomOnScreen ?? "none", privacy: .public) \
                known \(self.byID[message.id] != nil) mine \(message.author == self.me) owed \(message.owed) \
                marked \(self.marked.contains(message.id))
                """)
            return
        }
        readLog.debug("drawn: \(message.id, privacy: .public) in \(room, privacy: .public)")
        marked.insert(message.id)
        uncount(message.id, in: room)
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
                    readLog.debug("marked read: \(ids.count) in \(room, privacy: .public)")
                } catch {
                    readLog.debug("mark read failed in \(room, privacy: .public): \(sentence(error), privacy: .public)")
                    // Not recorded: drawn again, it is told again.
                    ids.forEach { self.marked.remove($0) }
                    self.reportBackground(error)
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
        let keyring = Dictionary(trusted.map { ($0.fingerprint, $0.drive) }) { $1 }
        let back = Set(consents.inbound)
        // Their trust in this node, whether or not this node trusts them (D4): both directions.
        if back != trustsMe { trustsMe = back }
        return roster.filter { $0.fingerprint != me }.map { m in
            let trust = Trust.of(inKeyring: keyring[m.fingerprint] != nil,
                                 trustsYou: back.contains(m.fingerprint))
            return MemberRow(id: m.fingerprint,
                             name: m.name.isEmpty ? String(m.fingerprint.prefix(12)) : m.name,
                             trust: trust, drive: keyring[m.fingerprint] ?? false,
                             trustsYou: back.contains(m.fingerprint),
                             keyWaits: m.keyWaits)
        }
    }

    /// The room on screen, read again every few seconds while it is there, each part published
    /// only when it changed: who has read this node's messages (read records arrive with the
    /// room's syncs and draw nothing of their own), the pulled copies, the services
    /// shared, and the members with their trust (one who joins while the room is on screen).
    private func watchReads(_ room: String) {
        watching?.cancel()
        watching = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                guard let self, case .room(room) = self.selection else { return }
                let reads = try? await self.client.readBy(room: room)
                let where_ = try? await self.client.whereabouts(room: room)
                let pulls = try? await self.client.pulledBy(room: room)
                let copies = try? await self.client.pulled(room: room)
                let states = try? await self.client.pullStates(room: room)
                let services = try? await self.client.services(room: room).shared
                let rows = try? await self.memberRows(room)
                let kept = try? await self.client.retention(room: room)
                let keptSecs = try? await self.client.retentionSecs(room: room)
                let done = try? await self.client.notices(room: room)
                guard case .room(room) = self.selection else { return }
                if let kept, kept != self.retention { self.retention = kept }
                if let keptSecs, keptSecs != self.retentionSecs { self.retentionSecs = keptSecs }
                if let done, done != self.notices { self.notices = done }
                let listed = try? await self.client.sessions(room: room)
                guard case .room(room) = self.selection else { return }
                if let listed, listed != self.sessions { self.sessions = listed }
                if let reads {
                    let now = Dictionary(uniqueKeysWithValues: reads.map { ($0.id, $0.names) })
                    if now != self.readBy { self.readBy = now }
                }
                if let where_ {
                    let now = Dictionary(where_.map { ($0.id, $0.words) }) { $1 }
                    if now != self.whereabouts { self.whereabouts = now }
                }
                if let pulls {
                    let now = Dictionary(pulls.map { ($0.id, $0.names) }) { $1 }
                    if now != self.pulledBy { self.pulledBy = now }
                }
                if let copies {
                    let now = Dictionary(copies.map { ($0.entry, $0.path) }) { $1 }
                    if now != self.pulled { self.pulled = now }
                }
                if let states {
                    let now = Dictionary(states.map { ($0.entry, $0.state) }) { $1 }
                    if now != self.pulling { self.pulling = now }
                }
                if let services, services != self.roomServices { self.roomServices = services }
                if let rows, rows != self.members {
                    // A member not listed before joined while the room was on screen (K-7).
                    let before = Set(self.members.map(\.id))
                    let came = rows.filter { !before.contains($0.id) }
                    self.members = rows
                    if !before.isEmpty || !came.isEmpty {
                        let at = UInt64(Date().timeIntervalSince1970 * 1000)
                        for m in came where !self.joins.contains(where: { $0.fingerprint == m.id }) {
                            self.joins.append(JoinLine(fingerprint: m.id, at: at, said: ""))
                        }
                    }
                }
                // Each join said, and said again as the room's consent grants name more of the
                // keyring's nodes trusting the newcomer.
                for (i, line) in self.joins.enumerated() {
                    if let said = try? await self.client.joinSaid(room: room, member: line.fingerprint),
                       case .room(room) = self.selection, i < self.joins.count,
                       self.joins[i].said != said {
                        self.joins[i].said = said
                    }
                }
            }
        }
    }

    fileprivate func arrived(_ message: RoomMessage, in room: String) {
        // Looked at: the room's own timeline (General or All) on screen in a window in front of
        // the person, following its newest message, so this one is drawn in view as it lands. A
        // room chosen but with a Session shown, scrolled up, or behind another window is not.
        let focused = lookingAt == room
        // A message the person is not looking at is notified: never this node's own, nor
        // coordination traffic, nor one whose body has not arrived.
        if notifies && !focused && message.author != me && message.level != .coordination
            && !message.owed {
            let name = rooms.first { $0.id == room }?.name ?? String(room.prefix(12))
            notifier.post(message, room: room, roomName: name, me: me)
        }
        if case .room(room) = selection {
            // A message already shown is replaced: one whose body had not arrived ("not received
            // yet", owed) is shown, and read, once it has; before, it stayed owed until the room
            // was opened again, and was never read.
            if let i = messages.firstIndex(where: { $0.id == message.id }) {
                messages[i] = message
            } else {
                messages.append(message)
            }
        }
        // Unread until drawn in view (this node's own never are), the room on screen too.
        guard message.author != me, !marked.contains(message.id) else { return }
        guard rooms.contains(where: { $0.id == room }) else {
            // A room joined or made since the rooms were read (by `vox room join`, say): read
            // them again, then count it.
            Task {
                await refresh()
                if rooms.contains(where: { $0.id == room }) { arrived(message, in: room) }
            }
            return
        }
        count(message, in: room)
    }

    /// The room whose own timeline is in view and following its newest message, in a window in
    /// front of the person, as RoomView last said; nil otherwise. A message arriving there is
    /// seen as it lands, so it is not notified.
    var lookingAt: String?

    fileprivate func noticed(_ text: String) {
        Task { await refresh() }
    }

    fileprivate func stopped(_ text: String) {
        ended = text
    }

    /// Attach this node again after it stopped, with `secret` if it needs its passphrase, and
    /// follow it as before: the window and its drafts stay.
    func attachAgain(_ secret: Secret?) async {
        begin("attach")
        do {
            let passphrase = try secret?.passphrase()
            defer { passphrase?.wipe() }
            _ = try await client.attach(node: node, passphrase: passphrase)
            ended = nil
            await start()
        } catch {
            report(error)
        }
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
        readLog.debug("follow: event message \(message.id, privacy: .public) in \(room, privacy: .public)")
        Task { @MainActor [weak model] in model?.arrived(message, in: room) }
    }

    func onNotice(text: String) {
        Task { @MainActor [weak model] in model?.noticed(text) }
    }

    func onEnded(text: String) {
        Task { @MainActor [weak model] in model?.stopped(text) }
    }

    func onSessions(room: String) {
        Task { @MainActor [weak model] in await model?.sessionsChanged(in: room) }
    }

    func onSessionEntry(room: String, node: String, sessionId: String) {
        Task { @MainActor [weak model] in await model?.sessionEntry(in: room, node: node, session: sessionId) }
    }
}

// A room's Sessions (ADR-029): read when one is shown, and again when the node says it changed.
extension NodeModel {
    /// The Session on screen's entries, to a member with drive; nothing to one without (SC-3).
    func readSession() async {
        guard let room = roomOnScreen, let s = shownSession, s.canDrive else {
            if !sessionEntries.isEmpty { sessionEntries = [] }
            if sessionNote != nil { sessionNote = nil }
            sessionLoading = false
            return
        }
        do {
            let read = try await client.sessionRead(room: room, node: s.nodeFingerprint,
                                                    sessionId: s.sessionId)
            // Drawn only for the destination it was read for, still on screen and still driven
            // (D3): the room, the Session's node and its id, and drive held.
            guard roomOnScreen == room, let now = shownSession, now.nodeFingerprint == s.nodeFingerprint,
                  now.sessionId == s.sessionId, now.canDrive else { return }
            if read.entries != sessionEntries { sessionEntries = read.entries }
            if read.note != sessionNote { sessionNote = read.note }
            sessionLoading = false
        } catch {
            reportBackground(error)
            sessionLoading = false
        }
    }

    /// Each open room's approvals and questions waiting on this node (CL-2), as the TUI counts
    /// them: what its Sessions say waits on this node.
    func readWaiting() async {
        for room in rooms where room.open {
            guard let listed = try? await client.sessions(room: room.id) else { continue }
            let n = listed.reduce(0) { $0 + Int($1.pending) }
            if let i = rooms.firstIndex(where: { $0.id == room.id }), rooms[i].waiting != n {
                rooms[i].waiting = n
            }
        }
        await noteWaiting()
    }

    /// The requests open in `room`'s Sessions this node drives, waiting on it, in each Session's
    /// order: `(node, session, reference, label)`.
    private func waiting(in room: String) async -> [(node: String, session: String, reference: String, label: String)] {
        guard let listed = try? await client.sessions(room: room) else { return [] }
        var found: [(node: String, session: String, reference: String, label: String)] = []
        for s in listed where s.pending > 0 && s.canDrive && s.open {
            guard let read = try? await client.sessionRead(room: room, node: s.nodeFingerprint,
                                                           sessionId: s.sessionId) else { continue }
            for e in read.entries {
                if let r = e.request, r.state == nil {
                    found.append((s.nodeFingerprint, s.sessionId, r.reference, s.label))
                }
            }
        }
        return found
    }

    /// The first request waiting in `room`, for ⌘J.
    private func firstWaiting(in room: String) async -> (node: String, session: String, reference: String)? {
        guard let w = await waiting(in: room).first else { return nil }
        return (w.node, w.session, w.reference)
    }

    /// A request that is new since the last look notifies, once per Session, replacing that
    /// Session's earlier one; a Session no longer waiting has its notification withdrawn (P1).
    /// Never the request's text (R-10).
    private func noteWaiting() async {
        var now: Set<String> = []
        var bySession: [String: (room: String, node: String, session: String, reference: String, label: String)] = [:]
        for room in rooms where room.open {
            for w in await waiting(in: room.id) {
                let key = "\(room.id)/\(w.node)/\(w.session)/\(w.reference)"
                now.insert(key)
                if !knownWaiting.contains(key) && waitingSeen {
                    bySession["\(room.id)/\(w.node)/\(w.session)"] = (room.id, w.node, w.session, w.reference, w.label)
                }
            }
        }
        for (_, w) in bySession {
            let name = rooms.first { $0.id == w.room }?.name ?? "a room"
            notifier.postWaiting(room: w.room, roomName: name, node: w.node, session: w.session,
                                 reference: w.reference, label: w.label)
        }
        let stillWaiting = Set(now.map { $0.split(separator: "/").prefix(3).joined(separator: "/") })
        for gone in Set(knownWaiting.map { $0.split(separator: "/").prefix(3).joined(separator: "/") })
            .subtracting(stillWaiting) {
            notifier.withdrawWaiting(sessionKey: gone)
        }
        knownWaiting = now
        waitingSeen = true
    }

    /// Open `room`, its Session `session` of `node`, and select its request `reference`, centred
    /// (P1): where a notification and ⌘J land.
    func openRequest(room: String, node: String, session: String, reference: String) async {
        await show(.room(room))
        showing = .session(node: node, id: session)
        selectedRequest = reference
    }

    /// The approval selected in the Session on screen, open and this node's to answer: what
    /// ⌥⌘Y and ⌥⌘N act on (P1). Questions are answered by their options, not these keys.
    var selectedApproval: (session: FfiSession, room: String, reference: String)? {
        guard let reference = selectedRequest, let s = shownSession, s.canDrive, s.open,
              let room = roomOnScreen,
              let r = sessionEntries.compactMap(\.request).first(where: { $0.reference == reference }),
              r.state == nil, !r.isQuestion else { return nil }
        return (s, room, reference)
    }

    /// Approve (⌥⌘Y) or Reject (⌥⌘N) the selected approval, and say what came of it (P1).
    func answerSelected(approve: Bool) async {
        guard let a = selectedApproval else { return }
        let action: DriveAction = approve ? .approve(reference: a.reference)
            : .reject(reference: a.reference, why: nil)
        // What came of it is this operation's outcome (P6): done, refused, or not known.
        begin(approve ? "approve-request" : "reject-request")
        switch await driveResult(a.session, in: a.room, action) {
        case let .taken(words): report(done: asSentence(words))
        case let .refused(words): outcome = Outcome(operation: operation, kind: .refused, words: asSentence(words))
        case let .unknown(words): outcome = Outcome(operation: operation, kind: .unknown, words: asSentence(words))
        }
        await readSession()
    }

    /// A Session in `room` opened, ended or was renamed, or what waits on this node changed.
    fileprivate func sessionsChanged(in room: String) async {
        if let listed = try? await client.sessions(room: room),
           let i = rooms.firstIndex(where: { $0.id == room }) {
            let n = listed.reduce(0) { $0 + Int($1.pending) }
            if rooms[i].waiting != n { rooms[i].waiting = n }
        }
        await noteWaiting()
        guard roomOnScreen == room, let listed = try? await client.sessions(room: room),
              roomOnScreen == room else { return }
        if listed != sessions { sessions = listed }
        await readSession()
    }

    /// A Session has a new entry, or a request in it was resolved.
    fileprivate func sessionEntry(in room: String, node: String, session: String) async {
        guard roomOnScreen == room, shownSession?.nodeFingerprint == node,
              shownSession?.sessionId == session else { return }
        await readSession()
    }

    /// Drive a Session (ADR-029 DR-1), for the Session view's controls (SessionDrive.swift).
    func drive(room: String, session: String, action: DriveAction) async throws -> DriveAnswer {
        try await client.drive(room: room, session: session, action: action)
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
        begin("stop-share")
        do {
            _ = try await client.shareStop(room: share.room, selector: share.tag)
        } catch {
            report(error)
        }
    }
}

/// What one operation came to (P6), kept apart: done, refused, or not known whether it was done
/// (the daemon stopped answering after it was asked).
struct Outcome: Equatable {
    enum Kind: Equatable { case done, refused, unknown }
    /// The operation that made it: a sheet shows only its own.
    let operation: String
    let kind: Kind
    /// What to say: what it did, or the daemon's sentence for why not.
    let words: String

    static func kind(of error: Error) -> Kind {
        if case VoxError.Unknown(_) = error { return .unknown }
        return .refused
    }
}
