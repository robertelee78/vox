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
        var unreadScanLimited = false
        /// Approvals and questions waiting on this node in Sessions it may drive here (ADR-029
        /// CL-2).
        var waiting = 0
        /// Trust offers waiting on this node from members of this room (K-15): shown in the room,
        /// and they need the person.
        var offered = 0
        /// What its first offer's row preview says: "xrsja33… joined — trust?".
        var offerSaid = ""
        /// Its newest message, for the row's time and preview (the decider, v0.4.3).
        var last: Preview?

        /// What it needs from the person, by the rule the TUI groups by (W-2): a Session waiting
        /// on this node needs it too (CL-2), and a trust offer from one of its members (K-15).
        var need: RoomGroup {
            waiting > 0 || offered > 0 ? .needsYou
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

    /// A room's newest message as its sidebar row says it: when, and "who: text" (or "new
    /// message" when this node cannot read it yet).
    struct Preview: Equatable {
        let id: String
        let millis: UInt64
        let words: String

        @MainActor init(_ m: RoomMessage, me: String) {
            id = m.id
            millis = m.createdMillis
            let said = m.owed ? "" : NodeModel.body(m)
                .split(whereSeparator: \.isNewline).first.map(String.init) ?? ""
            words = said.isEmpty ? "new message" : "\(NodeModel.author(m, me: me)): \(said)"
        }

        /// Whether `m` is a line a row may preview: the room's conversation, not a Session's
        /// opening or end, nor plumbing.
        static func shows(_ m: RoomMessage) -> Bool {
            !["session", "session-end", "ping", "pong"].contains(m.kind)
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
    @Published var selection: Selection? {
        didSet {
            roomReadGeneration = UUID()
            invalidateRoomAnchorState(preservingSnapshot: oldValue == selection)
            individualTrustFacts = [:]
            individualTrustReads = [:]
            rejectedRoomMark = nil
            clearThreadState()
            if case .room = selection { roomNeedsPage = true } else { roomNeedsPage = false }
        }
    }
    private var roomReadGeneration = UUID()
    private var rejectedRoomMark: String?
    private var roomMessageRevision = UUID()
    @Published private var roomNeedsPage = false
    var roomMembersPending: Bool { roomNeedsPage }
    /// The first message that was unread when the room came on screen, and how many were: where
    /// the timeline draws its unread line. It stays while the room is on screen; what arrives
    /// meanwhile is read as it is shown.
    @Published private(set) var unreadFrom: String?
    @Published private(set) var unreadCount = 0
    @Published private(set) var messages: [RoomMessage] = [] {
        didSet {
            roomMessageRevision = UUID()
            byID = Dictionary(messages.map { ($0.id, $0) }) { $1 }
            if let root = openThread { threadRootMessage = byID[root] }

            var said: [String: NodePlatform] = [:]
            for message in messages { if let p = message.platform { said[message.author] = p } }
            if said != platforms { platforms = said }
            scheduleThreadRefresh()
        }
    }
    /// Thread data is an authoritative retained/readable snapshot, separate from General pages.
    @Published private(set) var threadSummaries: [String: ThreadSummary] = [:]
    @Published private(set) var threadSummaryErrors: [String: String] = [:]
    @Published private(set) var openThread: String?
    @Published private(set) var threadRootMessage: RoomMessage?
    @Published private(set) var threadReplies: [RoomMessage] = []
    @Published private(set) var threadLoading = false
    @Published private(set) var threadHasMore = false
    @Published private(set) var threadError: String?
    private var threadGeneration = UUID()
    private var threadRefreshID = UUID()
    private var threadSummaryVersions: [String: UUID] = [:]
    private var threadAuthorRequests: [String: UUID] = [:]
    private var threadPageDirty = false
    private var threadRefreshDirty = false
    private var threadDisplayRevision: String?
    private var threadForcedSummaries: Set<String> = []
    private var threadPagesLoaded = 1
    private var threadRefreshTask: Task<Void, Never>?
    private var threadPageTask: Task<Void, Never>?

    @Published private(set) var roomOlder: UInt64 = 0
    private var roomBefore: String?
    @Published private var roomReadingOlder = false

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
    @Published private(set) var stepRetention: FfiStepRetention?
    @Published private(set) var stepRetentionAdmin = false
    @Published private(set) var stepRetentionLoading = false
    @Published private(set) var stepRetentionError: String?
    private var stepRetentionRead = UUID()
    /// What the room on screen's timeline shows (ADR-029 CL-2): General each time a room opens.
    @Published var showing: Showing = .general {
        didSet {
            guard showing != oldValue else { return }
            if showing != .general { closeThread() }
            // Another Session's entries are never drawn, nor acted on, under this one's header
            // while it loads (D3): cleared, and said to be loading.
            sessionPages.clear()
            sessionWindowRevision = UUID()
            timelineFollowingNewest = true
            selectedEarlierRequest = nil
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
            selectedSessionMetadata = nil
            selectedSessionMetadataKnown = false
            Task {
                await readSelectedSessionMetadata()
                await readSession()
            }
        }
    }
    /// The Session on screen is being read: its timeline says "Loading…" (D3).
    @Published private(set) var sessionLoading = false

    /// What is typed, kept per destination while the app runs, in memory only: nothing goes on
    /// disk or the wire (D12). A room's draft, To:, Urgent and reply, by room id.
    var roomDrafts: [String: RoomDraft] = [:]
    /// A Session's draft, by its destination (`room/node/session`).
    var sessionDrafts: [String: String] = [:]

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
    @Published private(set) var sessionsOpenNext: String?
    @Published private(set) var sessionsHistoryNext: String?
    @Published private(set) var sessionsMetadataLoading = false
    private var sessionsOpenAfter: String?
    private var sessionsHistoryAfter: String?
    private var sessionsMetadataRead = UUID()
    @Published private(set) var selectedSessionMetadata: FfiSession?
    @Published private(set) var selectedSessionMetadataKnown = false
    /// The Session on screen's entries, oldest first, to a member with drive (SC-1): its newest
    /// page, and the older pages the person scrolled up to (ADR-034 FR-4); never its whole
    /// history.
    /// Scroll position, independent of whether the app's window is foreground.
    @Published var timelineFollowingNewest = true
    private var sessionWindowRevision = UUID()
    var hasNewerTimeline: Bool { showingSession && sessionPages.hasNewer }
    @Published private var sessionPages = SessionPages()
    var sessionEntries: [FfiSessionEntry] { sessionPages.entries }
    /// A notification may point to a request before the newest page. It is shown separately,
    /// without reading every transcript entry between it and the newest page.
    @Published private(set) var selectedEarlierRequest: FfiSessionEntry?
    var sessionOlder: UInt64 { sessionPages.older }
    private var sessionBefore: String? { sessionPages.before }
    /// An older page is being read: one at a time.
    @Published private var sessionReadingOlder = false
    var readingOlderTimeline: Bool { showingSession ? sessionReadingOlder : roomReadingOlder }
    /// What the node says of the Session on screen besides its entries: "opening not received yet".
    @Published private(set) var sessionNote: String?
    /// What was done to the room on screen (its retention set, its name changed), oldest first.
    @Published private(set) var notices: [RoomNoticeRow] = []
    @Published private(set) var noticesBefore: NoticeCursor?
    @Published private(set) var governancePageError: String?
    private var noticesCursor: NoticeCursor?
    private var noticesRevision: UInt64?
    private var governanceRead = UUID()
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
    @Published private(set) var roomAnchorAuthority: RoomAnchorAuthority?
    @Published private(set) var roomAnchorEntries: [RoomAnchorEndpoint] = []
    private var roomAnchorSnapshotRoom: String?
    private var roomAnchorSnapshotNode: String?
    private var roomAnchorSnapshotEpoch: UUID?
    private var roomAnchorSnapshotGeneration: UUID?
    var roomAnchorSnapshotKnown: Bool {
        roomAnchorSnapshotRoom == roomOnScreen && roomAnchorSnapshotRoom != nil
            && roomAnchorSnapshotNode == me
    }
    var roomAnchorSnapshotCurrent: Bool {
        roomAnchorSnapshotKnown && daemonReachable && ended == nil && roomAnchorError == nil
            && roomAnchorSnapshotEpoch == nodeObservationEpoch
            && roomAnchorSnapshotGeneration == roomReadGeneration
    }
    @Published private(set) var roomAnchorReach: [String: String] = [:]
    @Published private(set) var roomAnchorReachError: String?
    @Published private(set) var roomAnchorError: String?
    @Published private(set) var roomAnchorLoading = false
    @Published private(set) var roomAnchorChanging = false
    private var roomAnchorRead = UUID()
    private var roomAnchorAction = UUID()
    private var roomAnchorAuthorityEpoch: UUID?
    private var roomAnchorAuthorityGeneration: UUID?
    var canManageRoomAnchors: Bool {
        guard let room = roomOnScreen, ended == nil, daemonReachable,
              let authority = roomAnchorAuthority else { return false }
        return authority.room == room && authority.node == me && authority.canManage
            && roomAnchorAuthorityEpoch == nodeObservationEpoch
            && roomAnchorAuthorityGeneration == roomReadGeneration
    }

    private var sheetInstance = UUID()
    @Published var sheet: NodeSheet? {
        didSet { if oldValue != sheet { sheetInstance = UUID() } }
    }
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
    @Published private var outcomes: [String: Outcome] = [:]
    /// The operation under way, which an outcome is filed under.
    @Published private(set) var activeOperations: [UUID: String] = [:]
    @Published private(set) var keyringWorking: String?

    func progress(of operation: String) -> String? {
        activeOperations.values.contains(operation) ? Self.progressWords(operation) : nil
    }

    var progressWords: String? {
        let words = Set(activeOperations.values).sorted().map(Self.progressWords)
        return words.isEmpty ? keyringWorking : words.joined(separator: " ")
    }

    private static func progressWords(_ operation: String) -> String {
        let words = ["bind-room": "Binding the room…", "decline-room": "Declining the room…",
                     "dismiss-offer": "Dismissing the offer…", "lan-helper": "Updating the LAN helper…",
                     "create-room": "Creating the room…", "join-room": "Joining the room…",
                     "copy-link": "Reading the room link…", "leave": "Leaving the room…",
                     "retention": "Setting retention…", "step-retention": "Setting Session step retention…",
                     "rename": "Renaming the room…",
                     "admins": "Updating room admins…", "copy": "Copying…",
                     "share": "Sharing the service…", "stop-share": "Stopping the share…",
                     "attach": "Attaching…", "post": "Sending the message…",
                     "approve-request": "Approving the request…", "reject-request": "Rejecting the request…"]
        return words[operation] ?? "Working…"
    }
    /// What the last operation did, said where the person is (E-5): `outcome`, when done.
    var did: String? { outcome.flatMap { $0.kind == .done ? $0.words : nil } }

    /// The services members share in the room on screen, as cards above its timeline.
    @Published private(set) var roomServices: [SharedService] = []
    @Published private(set) var roomServicesNext: ServiceCursor?
    private var roomServicesCursor: ServiceCursor?
    private var roomServicesRevision: UInt64?
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
    /// Canonical repositories waiting for an answer (ADR-031 RM-1, RM-5).
    @Published private(set) var roomAsks: [RoomAskInfo] = []
    /// The one repository being answered. Other repositories wait for this dialog to finish.
    @Published private(set) var roomAskDialog: RoomAskInfo?
    /// What the last answer to an ask did, or why it was not done: for the ask's view.
    @Published private(set) var roomAskSaid: RoomAnswerInfo?
    /// The directories already notified, so each ask notifies once (M-23).
    private var roomAsksNotified: Set<String> = []
    /// The trusted nodes that trust this node back, as the rooms shared with them record it (L-4).
    @Published private(set) var trustsBack: Set<String> = []
    /// The members of the room on screen whose trust in this node has reached it, in the keyring
    /// or not (ADR-028 R-5, D4).
    @Published private(set) var trustsMe: Set<String> = []
    /// The node whose card is open (D4): from a member row, a message's author or a decision row.
    struct IndividualTrustFact: Equatable {
        var allowed: Bool?
        var reason: String
    }
    @Published private(set) var individualTrustFacts: [String: IndividualTrustFact] = [:]
    private var individualTrustReads: [String: UUID] = [:]

    func canManageIndividualTrust(_ fingerprint: String) -> Bool {
        individualTrustFacts[fingerprint]?.allowed == true
    }

    func individualTrustReason(_ fingerprint: String) -> String {
        individualTrustFacts[fingerprint]?.reason ?? "Checking whether individual trust can be changed…"
    }

    func memberOffer(_ fingerprint: String, in room: String) -> OfferInfo? {
        offers.first { $0.fingerprint == fingerprint && $0.rooms.contains { $0.id == room } }
    }

    /// Selected-node authority, never inferred from a name, address or cached body.
    func refreshIndividualTrustEligibility(_ fingerprint: String, invalidate: Bool = false) async {
        let request = UUID(), generation = roomReadGeneration, epoch = nodeObservationEpoch
        let room = roomOnScreen
        individualTrustReads[fingerprint] = request
        // Entry checks retire stale authority; background refresh keeps a current form stable.
        if invalidate {
            individualTrustFacts[fingerprint] = IndividualTrustFact(allowed: nil, reason: "Checking whether individual trust can be changed…")
        }
        do {
            let fact = try await client.individualTrustEligibility(fingerprint: fingerprint)
            guard individualTrustReads[fingerprint] == request, generation == roomReadGeneration,
                  epoch == nodeObservationEpoch, roomOnScreen == room, ended == nil, !Task.isCancelled else { return }
            individualTrustFacts[fingerprint] = IndividualTrustFact(allowed: fact.canManageIndividualTrust, reason: fact.reason)
        } catch {
            guard individualTrustReads[fingerprint] == request, generation == roomReadGeneration,
                  epoch == nodeObservationEpoch, roomOnScreen == room, ended == nil, !Task.isCancelled else { return }
            individualTrustFacts[fingerprint] = IndividualTrustFact(allowed: nil, reason: sentence(error))
        }
    }

    private func checkIndividualTrust(_ fingerprint: String, operation: String) async -> Bool {
        let generation = roomReadGeneration, epoch = nodeObservationEpoch, request = UUID()
        individualTrustReads[fingerprint] = request
        individualTrustFacts[fingerprint] = IndividualTrustFact(allowed: nil, reason: "Checking whether individual trust can be changed…")
        do {
            let fact = try await client.individualTrustEligibility(fingerprint: fingerprint)
            guard individualTrustReads[fingerprint] == request, generation == roomReadGeneration, epoch == nodeObservationEpoch, ended == nil, !Task.isCancelled else { return false }
            individualTrustFacts[fingerprint] = IndividualTrustFact(allowed: fact.canManageIndividualTrust, reason: fact.reason)
            guard fact.canManageIndividualTrust else {
                let refused = Outcome(operation: operation, kind: .refused, words: fact.reason)
                outcomes[operation] = refused
                outcome = refused
                return false
            }
            return true
        } catch {
            guard individualTrustReads[fingerprint] == request, generation == roomReadGeneration, epoch == nodeObservationEpoch, ended == nil, !Task.isCancelled else { return false }
            individualTrustFacts[fingerprint] = IndividualTrustFact(allowed: nil, reason: sentence(error))
            report(error, operation: operation)
            return false
        }
    }

    private var individualTrustIntent = UUID()
    @Published var card: NodeCardFor? { didSet { individualTrustIntent = UUID() } }
    /// The keyring row selected, by fingerprint: what Keyring > Compare, Rename and Remove act on.
    @Published var keyringSelected: String?
    /// What a Keyring menu action asks the keyring view to open; each ask counts one up.
    @Published var keyringAsk: KeyringAsk?
    @Published private(set) var nodes: [NodeSummary] = []
    @Published private(set) var peers = 0
    /// Last-known states are never presented as current while the daemon cannot be reached.
    @Published private(set) var daemonReachable = true
    private var nodeObservationEpoch = UUID()
    @Published private(set) var machineStateKnown = false
    @Published private(set) var daemonFailure: String?
    var peerWords: String { daemonReachable ? (peers == 1 ? "1 peer" : "\(peers) peers") : "peers unknown" }
    struct HealthNotice: Decodable, Identifiable, Equatable {
        let key: String
        let message: String
        var id: String { key }
    }
    private struct HealthReport: Decodable {
        let unhealthy: [HealthNotice]
        let recovered: [HealthNotice]?
        let log_path: String?
    }
    @Published private(set) var health: [HealthNotice] = []
    @Published private(set) var recovered: [HealthNotice] = []
    @Published private(set) var logPath: String?

    func roomHealth(_ room: String) -> String? {
        guard daemonReachable else { return nil }
        let messages = health.filter { $0.key == "room-store:\(room)" || $0.key.hasPrefix("sync-failing:\(room):") }
            .map(\.message)
        return messages.isEmpty ? nil : messages.joined(separator: " ")
    }

    private func readHealth() async {
        do {
            let json = try await client.status()
            let report = try JSONDecoder().decode(HealthReport.self, from: Data(json.utf8))
            if report.unhealthy != health { health = report.unhealthy }
            if report.recovered ?? [] != recovered { recovered = report.recovered ?? [] }
            if report.log_path != logPath { logPath = report.log_path }
        } catch {
            reportBackground(error)
        }
    }

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
    @Published private(set) var ended: String? {
        didSet { if ended != nil { clearThreadState() } }
    }

    /// Whether macOS lets Vox notify; nil until it says.
    @Published private(set) var notifying: Bool?
    /// Whether this model posts notifications at all.
    private let notifies: Bool
    /// Local notifications for messages in rooms the person is not looking at (M-23).
    private let notifier = Notifier.shared

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
    /// The rooms as the sidebar lists them (the decider, v0.4.3, "more like" a chat list): the
    /// most recent activity first, a room with none by name.
    var orderedRooms: [Room] {
        rooms.sorted {
            let (a, b) = ($0.last?.millis ?? 0, $1.last?.millis ?? 0)
            if a != b { return a > b }
            return $0.name.localizedStandardCompare($1.name) == .orderedAscending
        }
    }

    /// Each room's newest message read so far, by room: the next read starts after it.
    private var lastRead: [String: String] = [:]

    /// Read what `room` has after its newest message read so far, for its row's preview.
    private func readLast(_ room: String) async {
        do {
            let rows: [RoomMessage]
            if let after = lastRead[room] {
                do {
                    rows = try await client.read(room: room, after: after, limit: 0)
                } catch where Self.rejectedForwardMark(error) {
                    // Retention can remove the last preview row. Retire its mark before the
                    // bounded read, so a failed recovery never retries that expired mark.
                    lastRead[room] = nil
                    rows = try await client.roomRead(room: room).messages
                }
            } else {
                rows = try await client.roomRead(room: room).messages
            }
            guard let newest = rows.last else { return }
            lastRead[room] = newest.id
            guard let shown = rows.last(where: Preview.shows),
                  let i = rooms.firstIndex(where: { $0.id == room }),
                  shown.createdMillis >= rooms[i].last?.millis ?? 0 else { return }
            let preview = Preview(shown, me: me)
            if rooms[i].last != preview { rooms[i].last = preview }
        } catch {
            reportBackground(error)
        }
    }

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
                guard self.daemonReachable else { continue }
                await self.readWaiting()
                if self.showingSession {
                    await self.readSelectedSessionMetadata()
                    await self.readSession()
                }
                else { await self.readNewOnScreen() }
            }
        }
    }

    /// The room on screen read again from its newest message, and anything the node's events did
    /// not bring added as if it had: a missed or dead event stream hides a message for one turn of
    /// this loop at most (the walkthrough's WHERE-15, posted while every peer was offline, never
    /// came as an event to the reopened app).
    private func readNewOnScreen() async {
        guard case let .room(id) = selection, ended == nil else { return }
        let generation = roomReadGeneration
        let messageRevision = roomMessageRevision
        let loaded = messages.map(\.id)
        do {
            let rows: [RoomMessage]
            var recovery: FfiRoomRead?
            if !roomNeedsPage, let after = messages.last?.id, after != rejectedRoomMark {
                do {
                    rows = try await client.read(room: id, after: after, limit: 0)
                } catch where Self.rejectedForwardMark(error) {
                    guard generation == roomReadGeneration, selection == .room(id), ended == nil else { return }
                    rejectedRoomMark = after
                    let page = try await client.roomReadRetaining(room: id, loaded: loaded)
                    rows = page.messages
                    recovery = page
                }
            } else {
                let page = try await client.roomReadRetaining(room: id, loaded: loaded)
                rows = page.messages
                recovery = page
            }
            guard generation == roomReadGeneration, selection == .room(id), ended == nil else { return }
            var recoveredMembers: (rows: [MemberRow], trustsMe: Set<String>, presented: [String: String])?
            if recovery != nil { recoveredMembers = try await memberRows(id) }
            guard generation == roomReadGeneration, selection == .room(id), ended == nil else { return }
            // An event may have delivered a new body or row while the page or roster awaited.
            // Keep that visible result and retry reanchoring instead of replacing it with an
            // earlier snapshot. IDs alone cannot detect an owed row gaining its body.
            if recovery != nil && messageRevision != roomMessageRevision { return }
            let new = rows.filter { byID[$0.id] == nil && !$0.owed }
            if let page = recovery {
                // Keep the valid view until this same selection's replacement is ready.
                roomOlder = page.older
                roomBefore = page.before
                messages = page.messages
                if let recoveredMembers {
                    members = recoveredMembers.rows
                    trustsMe = recoveredMembers.trustsMe
                    for (fingerprint, name) in recoveredMembers.presented { rememberPresentation(fingerprint, name) }
                }
                rejectedRoomMark = nil
                roomNeedsPage = false
                lastRead[id] = page.messages.last?.id
                watchReads(id)
            }
            for message in new { arrived(message, in: id) }
        } catch {
            guard generation == roomReadGeneration, selection == .room(id), ended == nil else { return }
            reportBackground(error)
        }
    }

    /// Only a refused forward history mark warrants reanchoring. A disconnect, permission
    /// refusal or malformed reply must retain its own error instead of becoming an empty page.
    private static func rejectedForwardMark(_ error: Error) -> Bool {
        guard case let VoxError.Failed(reason) = error else { return false }
        return reason == "page mark not in this room's timeline"
    }

    /// The timeline's previous page is fetched only at the person's scroll position or request.
    func readOlderTimeline() async {
        if showingSession {
            await readOlderSession()
            return
        }
        guard let room = roomOnScreen, let before = roomBefore, !roomReadingOlder, ended == nil else { return }
        let generation = roomReadGeneration
        roomReadingOlder = true
        defer { if generation == roomReadGeneration { roomReadingOlder = false } }
        do {
            let page = try await client.roomReadOlder(room: room, before: before)
            guard generation == roomReadGeneration, roomOnScreen == room, roomBefore == before, ended == nil else { return }
            let held = Set(messages.map(\.id))
            messages = page.messages.filter { !held.contains($0.id) } + messages
            roomOlder = page.older
            roomBefore = page.before
        } catch {
            guard generation == roomReadGeneration, roomOnScreen == room, ended == nil else { return }
            reportBackground(error)
        }
    }

    /// The keyring, the nodes on this Mac, the peers and the keyring window, assigned only when
    /// they changed; and who trusts back, while the keyring is on screen.
    var nodeStatus: String? {
        guard daemonReachable, machineStateKnown else { return nil }
        return nodes.first(where: { $0.name == node })?.status
    }

    func refreshMachineState() async { await readFacts() }

    private func readFacts() async {
        let epoch = nodeObservationEpoch
        // Reachability first: failed reads must not leave stale node/peer states visible.
        do {
            let fresh = try await client.nodes()
            guard epoch == nodeObservationEpoch, !Task.isCancelled else { return }
            let recovering = !daemonReachable
            machineStateKnown = true
            daemonFailure = nil
            if fresh != nodes { nodes = fresh }
            if fresh.first(where: { $0.name == node })?.state != "attached" {
                nodeObservationEpoch = UUID()
                invalidateRoomAnchorState(preservingSnapshot: true)
                daemonReachable = true
                ended = fresh.first(where: { $0.name == node })?.status == "Locked"
                    ? "Node \(node) is Locked." : "Node \(node) is unavailable."
                releaseHistoryViews()
                peers = 0
                return
            }
            let view = try await client.view()
            guard epoch == nodeObservationEpoch, !Task.isCancelled else { return }
            daemonReachable = true
            // Both public daemon and held-node reads succeeded for this observation epoch.
            // Retire only a typed background connection fault, even when another poll never
            // changed daemonReachable. Foreground and unrelated read failures remain visible.
            if outcome?.operation == "", outcome?.backgroundConnectivity == true { outcome = nil }
            if Int(view.peers) != peers { peers = Int(view.peers) }
            if view.keyring != keyring { keyring = view.keyring }
            if fresh.first(where: { $0.name == node })?.state == "attached" {
                ended = nil
            }
            if recovering {
                // A live connection does not establish that the selected room's snapshot
                // or its watcher survived the interruption. Preserve its visible content
                // until an authoritative page and roster replace it together.
                if case .room = selection {
                    threadDisplayRevision = nil
                    roomReadGeneration = UUID()
                    roomNeedsPage = true
                    watching?.cancel()
                    stepRetentionRead = UUID()
                    stepRetentionLoading = false
                }

                try await client.subscribe(listener: Listener(model: self))
                guard epoch == nodeObservationEpoch, !Task.isCancelled else { return }
                lastRead.removeAll()
                await refresh()
                guard epoch == nodeObservationEpoch, !Task.isCancelled else { return }
                await reconcileUnread()
                guard epoch == nodeObservationEpoch, !Task.isCancelled else { return }
            }
        } catch {
            guard epoch == nodeObservationEpoch, !Task.isCancelled else { return }
            daemonReachable = false
            individualTrustFacts = [:]
            individualTrustReads = [:]
            machineStateKnown = false
            nodeObservationEpoch = UUID()
            threadDisplayRevision = nil
            invalidateRoomAnchorState(preservingSnapshot: true)
            daemonFailure = sentence(error)
            reportBackground(error)
            return
        }
        let currentTrust = try? await client.trustList()
        guard epoch == nodeObservationEpoch, !Task.isCancelled else { return }
        if let currentTrust, currentTrust != trusted { trusted = currentTrust }
        let currentOffers = try? await client.pendingOffers()
        guard epoch == nodeObservationEpoch, !Task.isCancelled else { return }
        if let currentOffers, currentOffers != offers { offers = currentOffers }
        let eligibilityTargets = Set(members.map(\.id) + offers.map(\.fingerprint) + (card.map { [$0.fingerprint] } ?? []))
        for fingerprint in eligibilityTargets {
            await refreshIndividualTrustEligibility(fingerprint)
            guard epoch == nodeObservationEpoch, !Task.isCancelled else { return }
        }
        await readRoomAsks()
        guard epoch == nodeObservationEpoch, !Task.isCancelled else { return }
        // Each room counts the offers from its members (K-15), shown in it.
        for i in rooms.indices {
            let here = offers.filter { $0.rooms.contains { $0.id == rooms[i].id } }
            if rooms[i].offered != here.count { rooms[i].offered = here.count }
            let said = here.first.map { "\($0.short)… \($0.whyWords) — trust?" } ?? ""
            if rooms[i].offerSaid != said { rooms[i].offerSaid = said }
        }
        await readHealth()
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
            if let consents = try? await client.memberConsents(room: room.id) {
                back.formUnion(consents.inbound)
            }
        }
        return back
    }

    /// Rooms whose unread was counted from what the node recorded as read.
    private var seeded: Set<String> = []

    /// Only scalar facts are retained; unread bodies remain in the node's store.
    func seedUnread() async {
        for room in rooms where room.open && !seeded.contains(room.id) {
            do { _ = try await readUnreadSummary(room.id) }
            catch is CancellationError {}
            catch { reportBackground(error) }
        }
    }

    private func reconcileUnread() async {
        for room in rooms where room.open {
            do { _ = try await readUnreadSummary(room.id) }
            catch is CancellationError {}
            catch { reportBackground(error) }
        }
    }

    @discardableResult
    private func readUnreadSummary(_ room: String) async throws -> RoomUnread {
        let epoch = nodeObservationEpoch
        let facts = try await client.unreadSummary(room: room)
        guard epoch == nodeObservationEpoch, !Task.isCancelled,
              let i = rooms.firstIndex(where: { $0.id == room && $0.open }) else {
            throw CancellationError()
        }
        rooms[i].addressed = Int(clamping: facts.addressed)
        rooms[i].urgent = Int(clamping: facts.urgent)
        rooms[i].new = Int(clamping: facts.new)
        rooms[i].coordination = Int(clamping: facts.coordination)
        rooms[i].unreadScanLimited = facts.scanLimited
        seeded.insert(room)
        return facts
    }

    /// Coalesce live events to one reader, rather than a body cache or a task per message.
    /// The FIFO contains only identities of currently open rooms, never message IDs.
    private var unreadDirty: [String] = []
    private var unreadRefreshing: Task<Void, Never>?

    private func scheduleUnread(_ room: String) {
        guard rooms.contains(where: { $0.id == room && $0.open }) else { return }
        if !unreadDirty.contains(room) { unreadDirty.append(room) }
        guard unreadRefreshing == nil else { return }
        let epoch = nodeObservationEpoch
        unreadRefreshing = Task { [weak self] in
            guard let self else { return }
            defer { self.unreadRefreshing = nil }
            while epoch == self.nodeObservationEpoch, !Task.isCancelled,
                  let id = self.unreadDirty.first {
                self.unreadDirty.removeFirst()
                do { _ = try await self.readUnreadSummary(id) }
                catch {
                    if epoch == self.nodeObservationEpoch && !Task.isCancelled {
                        self.reportBackground(error)
                    }
                }
            }
            if epoch != self.nodeObservationEpoch { self.unreadDirty.removeAll() }
        }
    }

    private func count(_ message: RoomMessage, in room: String) {
        guard message.author != me else { return }
        scheduleUnread(room)
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
                    room.unreadScanLimited = held.unreadScanLimited
                    room.waiting = held.waiting
                    room.offered = held.offered
                    room.offerSaid = held.offerSaid
                    room.last = held.last
                }
                return room
            }
            if now != rooms { rooms = now }
            for room in now { await readLast(room.id) }
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
        // Preserve the room's reply draft when leaving it (D12).
        if case let .room(left) = self.selection {
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
        guard case .room = selection else {
            releaseHistoryViews()
            return
        }
        messages = []
        roomReadingOlder = false
        roomOlder = 0
        roomBefore = nil
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
        stepRetention = nil
        stepRetentionAdmin = false
        stepRetentionLoading = false
        stepRetentionError = nil
        stepRetentionRead = UUID()
        notices = []
        noticesBefore = nil
        noticesCursor = nil
        noticesRevision = nil
        roomServicesNext = nil
        roomServicesCursor = nil
        roomServicesRevision = nil
        governancePageError = nil
        governanceRead = UUID()
        sessions = []
        sessionsOpenAfter = nil
        sessionsHistoryAfter = nil
        sessionsOpenNext = nil
        sessionsHistoryNext = nil
        sessionsMetadataRead = UUID()
        sessionsMetadataLoading = false
        sessionPages.clear()
        selectedEarlierRequest = nil
        sessionNote = nil
        members = []
        roomServices = []
        selectedMessage = nil
        selectedMessages = []
        selectionAnchor = nil
        selectedService = nil
        // Every room opens at General (ADR-033 LY-4); its reply draft is retained.
        if case let .room(opened) = selection {
            showing = .general
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
        guard case let .room(id) = selection, ended == nil else { return }
        let generation = roomReadGeneration
        let messageRevision = roomMessageRevision
        roomNeedsPage = true
        do {
            // Each read lands only if the room is still the one on screen: a quick switch must not
            // draw one room's messages under another.
            // What was unread as the room came on screen, before showing it marks it read: the
            // timeline's unread line goes above the first of it (ADR-028 R-8).
            let unread = try await readUnreadSummary(id)
            let page = try await client.roomRead(room: id)
            let read = page.messages
            guard generation == roomReadGeneration, self.selection == .room(id), ended == nil else { return }
            let services = try await client.servicesPage(room: id, after: nil, revision: nil)
            let rows = try await memberRows(id)
            let kept = (try? await client.retention(room: id)) ?? ""
            let keptSecs = try? await client.retentionSecs(room: id)
            let done = try await client.noticesPage(room: id, before: nil, revision: nil)
            let livePage = try await client.sessionsOpenPage(room: id, after: nil)
            let historyPage = try await client.sessionsPage(room: id, after: nil)
            guard generation == roomReadGeneration, self.selection == .room(id), ended == nil else { return }
            guard messageRevision == roomMessageRevision else { return }
            // The page and its inspector replace the prior view together, after both reads
            // have succeeded. An ordinary refresh must not publish a half-empty room.
            roomOlder = page.older
            roomBefore = page.before
            unreadFrom = unread.first
            unreadCount = Int(clamping: unread.addressed + unread.new + unread.coordination)
            messages = read
            roomNeedsPage = false
            roomServices = services.shared
            roomServicesNext = services.next
            roomServicesRevision = services.revision
            members = rows.rows
            trustsMe = rows.trustsMe
            for (fingerprint, name) in rows.presented { rememberPresentation(fingerprint, name) }
            retention = kept
            retentionSecs = keptSecs
            notices = done.rows
            noticesBefore = done.before
            noticesRevision = done.revision
            sessions = livePage.sessions + historyPage.sessions.filter { !$0.open }
            sessionsOpenNext = livePage.next
            sessionsHistoryNext = historyPage.next
            await loadStepRetention()
            guard !Task.isCancelled, generation == roomReadGeneration, selection == .room(id), ended == nil else { return }
            await loadRoomAnchorState()
            guard generation == roomReadGeneration, self.selection == .room(id), ended == nil else { return }
            // A Session restored as this room's last view is read once the room lists it (D12).
            if showingSession { await readSession() }
            watchReads(id)
        } catch {
            guard generation == roomReadGeneration, self.selection == .room(id), ended == nil else { return }
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
    func openTrustCard(_ fingerprint: String, name: String) async {
        let intent = UUID()
        individualTrustIntent = intent
        guard await checkIndividualTrust(fingerprint, operation: "trust"),
              individualTrustIntent == intent, !Task.isCancelled else { return }
        keyringDid = nil
        keyringFailed = nil
        card = NodeCardFor(fingerprint: fingerprint, name: name, act: .trust)
    }

    func prepareCardTrust(_ fingerprint: String) async -> Bool {
        let intent = individualTrustIntent
        guard card?.fingerprint == fingerprint,
              await checkIndividualTrust(fingerprint, operation: "trust"),
              individualTrustIntent == intent, card?.fingerprint == fingerprint,
              !Task.isCancelled else { return false }
        return true
    }

    func openCard(_ fingerprint: String, name: String, act: NodeCardFor.Act? = nil) {
        if act == .trust {
            Task { await openTrustCard(fingerprint, name: name) }
            return
        }
        keyringDid = nil
        keyringFailed = nil
        card = NodeCardFor(fingerprint: fingerprint, name: name, act: act)
    }

    /// Trust `fingerprint` as `alias`, granting read, and drive as well when `drive` (K-14,
    /// K-16). Whether it was done.
    /// Self-names are ephemeral metadata, never keyring or grants.
    @Published var presentedNames: [String: String] = [:]

    private func rememberPresentation(_ fingerprint: String, _ name: String) {
        if presentedNames[fingerprint] == nil, presentedNames.count >= 4096, let oldest = presentedNames.keys.sorted().first { presentedNames.removeValue(forKey: oldest) }
        presentedNames[fingerprint] = name
    }

    func presentedDisplayName(_ fingerprint: String, _ name: String) -> String {
        let otherNames = presentedNames.filter { $0.key != fingerprint }.map { $0.value }
            + trusted.filter { $0.fingerprint != fingerprint }.map { $0.name }
            + offers.filter { $0.fingerprint != fingerprint }.map { $0.presentedName }
        return clashingAlias(others: otherNames, alias: name) == nil ? name : name + "#" + fingerprint.prefix(6)
    }

    func identityInput(_ text: String) -> CopiedIdentity? {
        let raw = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if raw.hasSuffix(">"), let start = raw.range(of: " <", options: .backwards) {
            let name = String(raw[..<start.lowerBound])
            let tail = raw[start.upperBound...].dropLast()
            let fp = tail.filter { !$0.isWhitespace && $0 != "-" && $0 != "·" }.lowercased()
            return try? parseCopiedIdentity(text: "\(name) <\(fp)>")
        }
        return try? parseCopiedIdentity(text: raw.filter { !$0.isWhitespace && $0 != "-" && $0 != "·" }.lowercased())
    }

    func presentedName(_ fingerprint: String) async -> String? {
        guard let identity = identityInput(fingerprint) else { return nil }
        if let name = try? await client.presentedName(fingerprint: identity.fingerprint) {
            rememberPresentation(identity.fingerprint, name)
            return name
        }
        return nil
    }

    func suggestedName(_ identity: String) async -> String? {
        guard let parsed = identityInput(identity) else { return nil }
        if let name = parsed.name { return name }
        return await presentedName(parsed.fingerprint)
    }

    func trust(_ fingerprint: String, as alias: String, drive: Bool) async -> Bool {
        guard let parsed = identityInput(fingerprint) else { return false }
        let fp = parsed.fingerprint
        guard await checkIndividualTrust(fp, operation: "trust") else { return false }
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
        let empty = secret.isEmpty
        defer { secret.wipe() }
        guard keyringPending?.id == pending.id, keyringWorking == nil else { return }
        keyringWorking = "Updating your keyring…"
        defer { keyringWorking = nil }
        do {
            let passphrase = try secret.passphrase()
            defer { passphrase.wipe() }
            keyringDid = try await pending.run(passphrase)
            keyringFailed = nil
            if keyringPending?.id == pending.id { keyringPending = nil }
            await refresh()
        } catch {
            // Left empty for an identity that has a passphrase: one line saying it is needed,
            // not the daemon's refusal of an empty one.
            keyringFailed = empty
                ? "This node's identity has a passphrase: type it to \(pending.words)."
                : sentence(error)
        }
    }

    /// Cancel the change waiting for the passphrase: it is not made (D1).
    func cancelKeyring() {
        keyringPending = nil
        keyringReplacing = nil
        // Its failure goes with it (P6): a cancelled change leaves no sentence behind.
        keyringFailed = nil
    }

    /// The person's answer to "Replace the waiting change?" (D1).
    func replaceKeyring(_ yes: Bool) {
        if yes, let next = keyringReplacing { keyringPending = next }
        keyringReplacing = nil
    }

    // ---- a repo with no room (ADR-029 RB-5 to RB-7) -------------------------------------------

    /// The asks, read again: a new one notifies once, never with more than which harness and
    /// which directory.
    func readRoomAsks() async {
        guard let asks = try? await client.roomAsks() else { return }
        if asks != roomAsks { roomAsks = asks }
        let dirs = Set(asks.map(\.dir))
        if notifies {
            for ask in asks where !roomAsksNotified.contains(ask.dir) {
                notifier.postRoomAsk(dir: ask.dir, sentence: ask.sentence)
            }
            for gone in roomAsksNotified.subtracting(dirs) { notifier.withdrawRoomAsk(dir: gone) }
        }
        roomAsksNotified = dirs
        if let current = roomAskDialog {
            if let fresh = asks.first(where: { $0.dir == current.dir }) {
                roomAskDialog = fresh
            } else if !activeOperations.values.contains("bind-room")
                        && !activeOperations.values.contains("decline-room") {
                finishRoomAsk()
            }
        }
        if sheet == nil, card == nil, lanAsking == nil, let ask = asks.first {
            roomAskDialog = ask
            roomAskSaid = nil
            clearOutcome(of: "bind-room")
            clearOutcome(of: "decline-room")
            sheet = .repoRoom
        }
    }

    /// Creation uses the app's selected (person's) node. The room secret is reused only for the
    /// verified bind; no identity passphrase or keyring change is involved (RM-2, KP-1).
    func createRepoRoom(_ dir: String, name: String,
                        passphrase secret: Secret) async -> (room: String?, bound: Bool) {
        let operation = "bind-room"
        let attempt = begin(operation)
        defer { end(attempt) }
        roomAskSaid = nil
        var created: String?
        do {
            let passphrase = try secret.passphrase()
            defer { passphrase.wipe() }
            let room = try await client.createRoom(name: name, passphrase: passphrase)
            created = room
            let link = try await client.link(room: room).url
            roomAskSaid = try await client.bindRoom(dir: dir, link: link, passphrase: passphrase)
            await refresh()
            await readRoomAsks()
            await show(.room(room))
            return (room, roomAskSaid?.done == true)
        } catch {
            secret.wipe()
            report(error, operation: operation)
            await refresh()
            return (created, false)
        }
    }

    /// Bind `dir` to the room this node holds by `room`'s id, or to the room `link` names (one of
    /// them is given), joined with the passphrase the person typed (RB-6): what `vox room join
    /// <link> --node <node> --bind <dir>` does. Whether it was done.
    func bindRoom(_ dir: String, room: String?, link: String?, passphrase secret: Secret) async -> Bool {
        let operation = "bind-room"
        let attempt = begin(operation)
        defer { end(attempt) }
        roomAskSaid = nil
        do {
            var address = link?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if let room { address = try await client.link(room: room).url }
            let passphrase = try secret.passphrase()
            defer { passphrase.wipe() }
            let answer = try await client.bindRoom(dir: dir, link: address, passphrase: passphrase)
            roomAskSaid = answer
            await readRoomAsks()
            return answer.done
        } catch {
            secret.wipe()
            report(error, operation: operation)
            return false
        }
    }

    /// Join the room the room map binds `dir` to already, for every node of a session there that is
    /// not in it, with the map's own link and passphrase (RB-5a): nothing is typed. Whether it was
    /// done.
    func joinBoundRoom(_ dir: String) async -> Bool {
        let operation = "bind-room"
        let attempt = begin(operation)
        defer { end(attempt) }
        roomAskSaid = nil
        do {
            let none = try Secret(Data()).passphrase()
            defer { none.wipe() }
            let answer = try await client.bindRoom(dir: dir, link: "", passphrase: none)
            roomAskSaid = answer
            await readRoomAsks()
            return answer.done
        } catch {
            report(error, operation: operation)
            return false
        }
    }

    /// The answered repository leaves the dialog. The usual status bar keeps its result.
    func finishRoomAsk() {
        if let answer = roomAskSaid, answer.done {
            report(operation: "bind-room", done: answer.said.joined(separator: "\n"))
        }
        roomAskDialog = nil
        roomAskSaid = nil
        if sheet == .repoRoom { sheet = nil }
    }

    func clearRoomAskFailure() {
        roomAskSaid = nil
        clearOutcome(of: "bind-room")
        clearOutcome(of: "decline-room")
    }

    /// Say no for `dir` (RB-7): it stays tied to no room, and nothing started there is asked again.
    func declineRoom(_ dir: String) async -> Bool {
        let operation = "decline-room"
        let attempt = begin(operation)
        defer { end(attempt) }
        roomAskSaid = nil
        do {
            roomAskSaid = try await client.declineRoom(dir: dir)
            await readRoomAsks()
            return roomAskSaid?.done == true
        } catch {
            report(error, operation: operation)
            return false
        }
    }

    // ---- trust offers (ADR-028 K-15 to K-18) ------------------------------------------------

    /// Accept `offer`: trust it under `alias`, read or read + drive (K-16), behind the passphrase
    /// gate; the offer then leaves needs you. Whether it was done.
    func accept(_ offer: OfferInfo, as alias: String, drive: Bool) async -> Bool {
        let generation = roomReadGeneration, epoch = nodeObservationEpoch
        guard await trust(offer.fingerprint, as: alias, drive: drive) else { return false }
        let waiting = try? await client.pendingOffers()
        guard generation == roomReadGeneration, epoch == nodeObservationEpoch, ended == nil, !Task.isCancelled else { return false }
        if let waiting { offers = waiting }
        return true
    }

    /// Dismiss `offer`: here only, and silently (K-18); the node stays not in keyring, and trust
    /// stays reachable from the member pane.
    func dismiss(_ offer: OfferInfo) async {
        let operation = "dismiss-offer"
        guard await checkIndividualTrust(offer.fingerprint, operation: operation) else { return }
        let generation = roomReadGeneration, epoch = nodeObservationEpoch
        let attempt = begin(operation)
        defer { end(attempt) }
        do {
            try await client.dismissOffer(fingerprint: offer.fingerprint)
            let waiting = try? await client.pendingOffers()
            guard generation == roomReadGeneration, epoch == nodeObservationEpoch, ended == nil, !Task.isCancelled else { return }
            if let waiting { offers = waiting }
            if selection == .offer(offer.fingerprint) { selection = nil }
        } catch {
            guard generation == roomReadGeneration, epoch == nodeObservationEpoch, ended == nil, !Task.isCancelled else { return }
            report(error, operation: operation)
        }
    }

    /// Make a keyring change, asking for the passphrase when the node says the keyring window has
    /// closed (ADR-026 N-2, a typed refusal), and say what it did. The change waiting is named
    /// (D1): what, on whom, and the action that makes it.
    private func keyringChange(fingerprint: String, alias: String, words: String, action: String,
                               _ change: @escaping (Passphrase?) async throws -> String) async -> Bool {
        guard keyringWorking == nil else { return false }
        keyringWorking = "Updating your keyring…"
        defer { keyringWorking = nil }
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
        let operation = "lan-helper"
        let attempt = begin(operation)
        defer { end(attempt) }
        do {
            let status = await Self.lanHelperStatus()
            if status != .enabled && status != .notRegistered { try await lanHelper.unregister() }
            if status != .enabled { try lanHelper.register() }
        } catch {
            report(error, operation: operation)
            return
        }
        let status = await Self.lanHelperStatus()
        if status == .requiresApproval {
            Daemon.openLoginItems()
        }
        lanHelperReady = status == .enabled
        report(operation: operation, done: lanHelperReady ? "The LAN helper is ready."
               : "The LAN helper is waiting for your approval in System Settings.")
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
        let operation = "lan-helper"
        let attempt = begin(operation)
        defer { end(attempt) }
        do {
            try await lanHelper.unregister()
            report(operation: operation, done: "Removed the LAN helper.")
        } catch {
            report(error, operation: operation)
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
        let ordered = orderedRooms
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

    /// A sheet's search results belong to this exact actor, room generation and sheet.
    var anchorChoiceContext: String {
        me + "/" + nodeObservationEpoch.uuidString + "/" + roomReadGeneration.uuidString
            + "/" + (sheet?.rawValue ?? "closed") + "/" + sheetInstance.uuidString
    }

    func previewRoomAnchorChoices(_ anchors: [RoomAnchorEndpoint], context: String) async throws -> RoomLinkPreview {
        guard context == anchorChoiceContext, ended == nil, sheet == .newRoom else { throw CancellationError() }
        let preview = try await client.previewRoomLink(anchors: anchors, node: me)
        guard !Task.isCancelled, context == anchorChoiceContext, ended == nil,
              preview.node == me else { throw CancellationError() }
        return preview
    }

    func searchRoomAnchorChoices(context: String) async throws -> [RoomAnchorEndpoint] {
        guard context == anchorChoiceContext, ended == nil,
              sheet == .newRoom || sheet == .roomAnchors else { throw CancellationError() }
        let found = try await client.searchAnchors()
        guard !Task.isCancelled, context == anchorChoiceContext, ended == nil else { throw CancellationError() }
        return found
    }

    func resolveRoomAnchorChoice(_ input: String, context: String) async throws -> RoomAnchorEndpoint {
        guard context == anchorChoiceContext, ended == nil,
              sheet == .newRoom || sheet == .roomAnchors else { throw CancellationError() }
        let found = try await client.resolveAnchorEndpoint(input: input)
        guard !Task.isCancelled, context == anchorChoiceContext, ended == nil else { throw CancellationError() }
        return found
    }

    /// Create from a snapshot of explicitly kept, already numeric endpoints. Search and DNS
    /// never hold this mutation, and closing/changing the sheet retires its UI publication.
    func createRoom(_ name: String, passphrase secret: Secret, anchors: [RoomAnchorEndpoint],
                    context: String) async -> Bool {
        let operation = "create-room", attempt = begin("create-room")
        defer { end(attempt) }
        guard context == anchorChoiceContext, sheet == .newRoom, ended == nil else { secret.wipe(); return false }
        do {
            let passphrase = try secret.passphrase()
            defer { passphrase.wipe() }
            let room = try await client.createRoomWithAnchors(name: name, passphrase: passphrase,
                                                             anchors: anchors, node: me)
            guard !Task.isCancelled, context == anchorChoiceContext, ended == nil else { return false }
            report(operation: operation, done: "Created the room.")
            await refresh()
            guard !Task.isCancelled, context == anchorChoiceContext, ended == nil else { return false }
            await show(.room(room))
            return true
        } catch {
            guard !Task.isCancelled, context == anchorChoiceContext, ended == nil else { return false }
            report(error, operation: operation)
            return false
        }
    }

    /// Create a room named `name` under `passphrase`, and show it.
    func createRoom(_ name: String, passphrase secret: Secret) async -> Bool {
        let operation = "create-room"
        let attempt = begin(operation)
        defer { end(attempt) }
        return await withPassphrase(secret, operation: operation) { [client] p in try await client.createRoom(name: name, passphrase: p) }
    }

    /// Join a room by its link and passphrase, and show it. It keeps the name its members gave it.
    func joinRoom(_ link: String, passphrase secret: Secret) async -> Bool {
        let operation = "join-room"
        let attempt = begin(operation)
        defer { end(attempt) }
        return await withPassphrase(secret, operation: operation) { [client] p in
            try await client.joinRoom(link: link, passphrase: p)
        }
    }

    private func withPassphrase(_ secret: Secret, operation: String,
                                _ act: (Passphrase) async throws -> String) async -> Bool {
        do {
            let passphrase = try secret.passphrase()
            defer { passphrase.wipe() }
            let room = try await act(passphrase)
            report(operation: operation, done: operation == "create-room" ? "Created the room." : "Joined the room.")
            await refresh()
            await show(.room(room))
            return true
        } catch {
            report(error, operation: operation)
            return false
        }
    }

    /// Copy the requested room's link; menus pass the clicked row, commands use the selected room.
    func copyRoomLink(room requested: String? = nil) async {
        let operation = "copy-link"
        let attempt = begin(operation)
        defer { end(attempt) }
        guard let id = requested ?? roomOnScreen, rooms.contains(where: { $0.id == id }) else { return }
        let epoch = nodeObservationEpoch, actor = me
        do {
            let link = try await client.link(room: id)
            guard !Task.isCancelled, nodeObservationEpoch == epoch, me == actor,
                  rooms.contains(where: { $0.id == id }) else { return }
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(link.url, forType: .string)
            report(operation: operation, done: link.note.isEmpty ? "Room link copied." : "Room link copied. \(link.note)")
        } catch {
            guard nodeObservationEpoch == epoch, me == actor else { return }
            report(error, operation: operation)
        }
    }

    /// Deliberately mark the clicked room's captured received history, not only loaded rows.
    func markRoomRead(_ room: String) async {
        let actor = me, epoch = nodeObservationEpoch
        guard rooms.contains(where: { $0.id == room }), ended == nil else { return }
        let operation = "mark-room-read", attempt = begin("mark-room-read")
        defer { end(attempt) }
        do {
            let count = try await client.markRoomRead(room: room, node: actor)
            guard !Task.isCancelled, me == actor, nodeObservationEpoch == epoch,
                  rooms.contains(where: { $0.id == room }) else { return }
            report(operation: operation, done: count == 0
                   ? "No received messages from other members to mark read in this room."
                   : "Room marked as read.")
            await refresh()
        } catch {
            guard me == actor, nodeObservationEpoch == epoch else { return }
            report(error, operation: operation)
        }
    }

    /// Leave the room on screen, or end it for everyone: nil once done, else why not (D19), for
    /// the sheet that asked to say where it was asked.
    func leaveRoom(endingIt: Bool) async -> String? {
        let operation = "leave"
        let attempt = begin(operation)
        defer { end(attempt) }
        guard let id = roomOnScreen else { return "No room is on screen to leave." }
        do {
            if endingIt { try await client.end(room: id) } else { try await client.leave(room: id) }
            report(operation: operation, done: endingIt ? "The room is ended for everyone." : "You left the room.")
            selection = nil
            await refresh()
            return nil
        } catch {
            report(error, operation: operation)
            return sentence(error)
        }
    }

    /// Set the room on screen's retention: no passphrase (ADR-028 K-11).
    func setRetention(_ seconds: UInt64) async -> Bool {
        let operation = "retention"
        let attempt = begin(operation)
        defer { end(attempt) }
        guard let id = roomOnScreen else { return false }
        do {
            try await client.setRetention(room: id, ttlSecs: seconds)
            report(operation: operation, done: seconds == 0 ? "Messages here are kept for good."
                : "Messages here are kept for \(Retention.words(seconds)), then deleted everywhere.")
            return true
        } catch {
            report(error, operation: operation)
            return false
        }
    }

    private func invalidateRoomAnchorState(preservingSnapshot: Bool = false) {
        roomAnchorRead = UUID()
        roomAnchorAction = UUID()
        roomAnchorAuthority = nil
        roomAnchorAuthorityEpoch = nil
        roomAnchorAuthorityGeneration = nil
        // Retire every authority/action even when a same-identity read-only snapshot remains.
        if preservingSnapshot && roomAnchorSnapshotKnown {
            roomAnchorSnapshotEpoch = nil
            roomAnchorSnapshotGeneration = nil
            roomAnchorError = "Room configuration unavailable; showing last known configuration."
            roomAnchorReachError = "Identity reach unavailable; showing last known observation."
        } else {
            roomAnchorEntries = []
            roomAnchorReach = [:]
            roomAnchorReachError = nil
            roomAnchorError = nil
            roomAnchorSnapshotRoom = nil
            roomAnchorSnapshotNode = nil
            roomAnchorSnapshotEpoch = nil
            roomAnchorSnapshotGeneration = nil
        }
        roomAnchorLoading = false
        roomAnchorChanging = false
        if sheet == .roomAnchors { sheet = nil }
    }

    func loadRoomAnchorState() async {
        guard let room = roomOnScreen, ended == nil else { return }
        let generation = roomReadGeneration, epoch = nodeObservationEpoch, request = UUID()
        roomAnchorRead = request
        roomAnchorLoading = true
        defer { if roomAnchorRead == request { roomAnchorLoading = false } }
        @MainActor func current() -> Bool {
            !Task.isCancelled && roomAnchorRead == request && roomReadGeneration == generation
                && nodeObservationEpoch == epoch && roomOnScreen == room && ended == nil
        }
        do {
            let authority = try await client.roomAnchorAuthority(room: room)
            guard current() else { return }
            guard authority.room == room, authority.node == me else {
                throw VoxError.Failed(reason: "The room-anchor authority belongs to another room or node.")
            }
            roomAnchorAuthority = authority
            roomAnchorAuthorityEpoch = epoch
            roomAnchorAuthorityGeneration = generation
            let configuration = try await client.roomAnchorConfiguration(room: room)
            guard current() else { return }
            guard configuration.room == room, configuration.node == me else {
                throw VoxError.Failed(reason: "The anchor configuration belongs to another room or node.")
            }
            roomAnchorEntries = configuration.anchors
            roomAnchorSnapshotRoom = room
            roomAnchorSnapshotNode = me
            roomAnchorSnapshotEpoch = epoch
            roomAnchorSnapshotGeneration = generation
            roomAnchorError = nil
            // Reach is an identity-level observation across machine sources, not proof that
            // every address in this room's signed configuration is reachable.
            do {
                let inventory = try await client.anchors()
                guard current() else { return }
                roomAnchorReach = Dictionary(uniqueKeysWithValues: inventory.map { ($0.fingerprint, $0.reachText) })
                roomAnchorReachError = nil
            } catch {
                guard current() else { return }
                roomAnchorReachError = sentence(error)
            }
        } catch {
            guard current() else { return }
            roomAnchorAuthority = nil
            roomAnchorError = sentence(error)
        }
    }

    func openRoomAnchors() async {
        let room = roomOnScreen, generation = roomReadGeneration, epoch = nodeObservationEpoch
        roomAnchorAuthority = nil
        await loadRoomAnchorState()
        guard !Task.isCancelled, roomOnScreen == room, roomReadGeneration == generation,
              nodeObservationEpoch == epoch, canManageRoomAnchors else { return }
        sheet = .roomAnchors
    }

    /// Resolve input without a manual write; only the held actor signs this room's change.
    @discardableResult
    func changeRoomAnchor(input: String? = nil, removing: String? = nil) async -> Bool {
        guard let room = roomOnScreen, ended == nil, !roomAnchorChanging, sheet == .roomAnchors,
              (input != nil) != (removing != nil) else { return false }
        let generation = roomReadGeneration, epoch = nodeObservationEpoch, request = UUID()
        let editor = sheetInstance
        roomAnchorAction = request
        roomAnchorChanging = true
        roomAnchorAuthority = nil
        roomAnchorError = nil
        defer { if roomAnchorAction == request { roomAnchorChanging = false } }
        @MainActor func current() -> Bool {
            !Task.isCancelled && sheet == .roomAnchors && sheetInstance == editor
                && roomAnchorAction == request && roomReadGeneration == generation
                && nodeObservationEpoch == epoch && roomOnScreen == room && ended == nil
        }
        do {
            let authority = try await client.roomAnchorAuthority(room: room)
            guard current() else { return false }
            guard authority.room == room, authority.node == me, authority.canManage else {
                throw VoxError.Failed(reason: "Only the room's creator or an admin can change its anchors.")
            }
            roomAnchorAuthority = authority
            roomAnchorAuthorityEpoch = epoch
            roomAnchorAuthorityGeneration = generation
            if let input {
                let spec = try await client.resolveAnchor(input: input)
                guard current() else { return false }
                try await client.addRoomAnchorPinned(room: room, spec: spec)
            } else if let removing {
                try await client.removeRoomAnchor(room: room, fingerprint: removing)
            }
            guard current() else { return false }
            await loadRoomAnchorState()
            guard current() else { return false }
            return true
        } catch {
            guard current() else { return false }
            roomAnchorAuthority = nil
            roomAnchorError = sentence(error)
            return false
        }
    }

    /// Separate room step policy and this node's effective limit, read together with who may
    /// change the room rule. Failures stay in the Retention sheet with a retry.
    func loadStepRetention() async {
        guard let id = roomOnScreen, !stepRetentionLoading else { return }
        let generation = roomReadGeneration
        let token = UUID()
        stepRetentionRead = token
        stepRetentionLoading = true
        defer { if stepRetentionRead == token { stepRetentionLoading = false } }
        do {
            let identity = me
            let (value, admins) = try await AppRequest.run("Reading Session step retention") { [client] in
                let value = try await client.stepRetention(room: id)
                let admin = try await client.isAdmin(room: id, member: identity)
                return (value, admin)
            }
            guard !Task.isCancelled, roomReadGeneration == generation, ended == nil,
                  roomOnScreen == id, stepRetentionRead == token else { return }
            stepRetention = value
            stepRetentionAdmin = admins
            stepRetentionError = nil
        } catch {
            guard !Task.isCancelled, roomReadGeneration == generation, ended == nil,
                  roomOnScreen == id, stepRetentionRead == token else { return }
            stepRetentionError = sentence(error)
        }
    }

    func setStepRetention(_ seconds: UInt64) async -> Bool {
        guard let id = roomOnScreen else { return false }
        let operation = "step-retention"
        let attempt = begin(operation)
        defer { end(attempt) }
        do {
            try await AppRequest.run("Setting Session step retention") { [client] in
                try await client.setStepRetention(room: id, seconds: seconds)
            }
            guard roomOnScreen == id else { return true }
            // A read started before the setter must not overwrite the new rule.
            stepRetentionRead = UUID()
            stepRetentionLoading = false
            await loadStepRetention()
            let scope = stepRetentionAdmin ? "The room's Session step rule is" : "This node's Session step rule is"
            report(operation: operation, done: "\(scope) \(Retention.words(seconds)). Message retention still applies.")
            return true
        } catch {
            report(error, operation: operation)
            return false
        }
    }

    /// Rename the room on screen: its one name, as every member sees it (ADR-028 R-1). Only its
    /// creator or an admin may; the node's refusal is said as it comes. No passphrase (K-11).
    func renameRoom(to name: String) async -> Bool {
        let operation = "rename"
        let attempt = begin(operation)
        defer { end(attempt) }
        guard let id = roomOnScreen else { return false }
        do {
            try await client.renameRoom(room: id, name: name)
            report(operation: operation, done: "The room is now \(name) for every member.")
            await refresh()
            return true
        } catch {
            report(error, operation: operation)
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

    /// Bind an ending permission read to the same room and acting node throughout.
    func canEndRoom(_ room: String) async throws -> Bool {
        let epoch = nodeObservationEpoch, actor = me, generation = roomReadGeneration, editor = sheetInstance
        guard roomOnScreen == room, sheet == .end, ended == nil else {
            throw VoxError.Failed(reason: "The room to end is no longer selected.")
        }
        let admin = try await client.isAdmin(room: room, member: actor)
        guard !Task.isCancelled, nodeObservationEpoch == epoch, me == actor,
              roomReadGeneration == generation, roomOnScreen == room, sheet == .end, sheetInstance == editor, ended == nil else {
            throw VoxError.Failed(reason: "The room or acting node changed while checking who may end it.")
        }
        return admin
    }

    /// A late ending reply must never clear a newer room or close a replacement sheet.
    func endRoomFromSheet(_ room: String) async -> String? {
        let epoch = nodeObservationEpoch, actor = me, generation = roomReadGeneration, editor = sheetInstance
        let operation = "end-room", attempt = begin("end-room")
        defer { end(attempt) }
        func current() -> Bool {
            !Task.isCancelled && nodeObservationEpoch == epoch && me == actor
                && roomReadGeneration == generation && roomOnScreen == room
                && sheet == .end && sheetInstance == editor && ended == nil
        }
        guard current() else { return nil }
        do {
            guard try await canEndRoom(room) else {
                return "Only this room's creator or an admin can end it for everyone."
            }
            guard current() else { return nil }
            try await client.end(room: room)
            guard current() else { return nil }
            report(operation: operation, done: "The room is ended for everyone.")
            sheet = nil
            select(nil)
            await refresh()
            return nil
        } catch {
            guard current() else { return nil }
            report(error, operation: operation)
            return sentence(error)
        }
    }

    /// One active admin page, with its creator separately identified.
    func adminsPage(after: String? = nil, revision: UInt64? = nil) async -> RoomAdmins? {
        guard let id = roomOnScreen else { return nil }
        do { return try await client.adminsPage(room: id, after: after, revision: revision) }
        catch { report(error, operation: "admins"); return nil }
    }

    /// Make a member an admin of the room on screen, or take it back.
    func setAdmin(_ member: String, _ admin: Bool) async {
        let operation = "admins"
        let attempt = begin(operation)
        defer { end(attempt) }
        guard let id = roomOnScreen else { return }
        do {
            try await client.setAdmin(room: id, member: member, admin: admin)
            report(operation: operation, done: admin ? "Made the member an admin." : "Removed the member's admin role.")
        } catch {
            report(error, operation: operation)
        }
    }

    /// Copy the selected service's address (⌘⇧C): its canonical form, which works pasted on any
    /// member's machine (ADR-028 S-1, S-3), said by its readable one.
    func copyServiceCommand() {
        let operation = "copy"
        let attempt = begin(operation)
        defer { end(attempt) }
        guard let service = selectedService else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(service.canonical, forType: .string)
        report(operation: operation, done: "Copied the address of \(service.address).")
    }

    /// Copy a service's whole address: its canonical form, which works pasted on any member's
    /// machine (S-1, S-3), said by its readable one (G3).
    func copyAddress(of service: SharedService) {
        let operation = "copy"
        let attempt = begin(operation)
        defer { end(attempt) }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(service.canonical, forType: .string)
        report(operation: operation, done: "Copied the address of \(service.address).")
    }

    /// Copy a service's command, as given: with the canonical address (S-3).
    func copyCommand(_ command: String) {
        let operation = "copy"
        let attempt = begin(operation)
        defer { end(attempt) }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(command, forType: .string)
        report(operation: operation, done: "Copied: \(command)")
    }

    /// A room's services, as the daemon lists them.
    func services(of room: String, after: ServiceCursor? = nil, revision: UInt64? = nil) async throws -> RoomServices {
        try await client.servicesPage(room: room, after: after, revision: revision)
    }

    /// Replace selected governance pages. A stale cursor keeps the last good view visible.
    func readGovernancePages(first: Bool = false, nextServices: Bool = false, olderNotices: Bool = false) async {
        guard let room = roomOnScreen else { return }
        let generation = roomReadGeneration
        let token = UUID()
        governanceRead = token
        let serviceCursor = first ? nil : (nextServices ? roomServicesNext : roomServicesCursor)
        let noticeCursor = first ? nil : (olderNotices ? noticesBefore : noticesCursor)
        do {
            let services = try await client.servicesPage(room: room, after: serviceCursor,
                revision: serviceCursor == nil ? nil : roomServicesRevision)
            let done = try await client.noticesPage(room: room, before: noticeCursor,
                revision: noticeCursor == nil ? nil : noticesRevision)
            guard governanceRead == token, roomReadGeneration == generation, roomOnScreen == room, !Task.isCancelled else { return }
            roomServices = services.shared
            roomServicesCursor = serviceCursor
            roomServicesNext = services.next
            roomServicesRevision = services.revision
            notices = done.rows
            noticesCursor = noticeCursor
            noticesBefore = done.before
            noticesRevision = done.revision
            governancePageError = nil
        } catch {
            guard governanceRead == token, roomReadGeneration == generation, roomOnScreen == room else { return }
            governancePageError = sentence(error)
        }
    }

    /// A room's members.
    func rosterOf(_ room: String) async throws -> [Member] {
        try await client.roster(room: room)
    }

    /// What listens on this Mac, as one-step sharing lists it (S-4).
    func listeningHere() async throws -> ListeningServices {
        try await client.listening()
    }

    /// What sharing the service on `port` would do, said before it is shared (S-4).
    func previewShare(port: UInt16, udp: Bool) async throws -> ServicePreview {
        try await client.servicePreview(port: port, udp: udp)
    }

    /// Share `local` in `room` as `tag`; nil when shared, else the daemon's sentence.
    func shareService(room: String, tag: String, local: String) async -> String? {
        let operation = "share"
        let attempt = begin(operation)
        defer { end(attempt) }
        do {
            try await client.serviceAdd(room: room, tag: tag, local: local)
            report(operation: operation, done: "Shared \(tag) (\(local)).")
            return nil
        } catch {
            report(error, operation: operation)
            return sentence(error)
        }
    }

    /// Stop sharing `tag` in `room`.
    func stopService(room: String, tag: String) async {
        let operation = "stop-share"
        let attempt = begin(operation)
        defer { end(attempt) }
        do {
            try await client.serviceRemove(room: room, tag: tag)
            report(operation: operation, done: "Stopped sharing \(tag).")
        } catch {
            report(error, operation: operation)
        }
    }

    /// Share the file or folder at `url` in the room on screen, addressed to `to` (members'
    /// fingerprints; none: the room) with `note`, in one message (ADR-028 F-1). Whether it was.
    func attach(_ url: URL, to: [String], note: String, urgent: Bool = false) async -> Bool {
        let operation = "attach"
        let attempt = begin(operation)
        defer { end(attempt) }
        guard case let .room(id) = selection else { return false }
        do {
            _ = try await client.share(room: id, path: url.path, to: to, note: note, re: "",
                                       urgent: urgent, count: 0, forSecs: 0)
            report(operation: operation, done: "Shared \(url.lastPathComponent).")
            return true
        } catch {
            report(error, operation: operation)
            return false
        }
    }

    /// Post `text` to the room on screen; whether the node took it.
    @discardableResult
    func post(_ text: String, to: [String] = [], urgent: Bool = false, re: String = "") async -> Bool {
        let operation = "post"
        let attempt = begin(operation)
        defer { end(attempt) }
        guard case let .room(id) = selection else { return false }
        do {
            try await client.post(room: id, text: text, to: to, re: re, urgent: urgent)
            report(operation: operation, done: "Sent the message.")
            return true
        } catch {
            report(error, operation: operation)
            return false
        }
    }

    // ---- what an operation came to (P6) ------------------------------------------------------

    /// Start an operation: what the last one came to is cleared, so a result is never left over
    /// from another (P6).
    private func begin(_ operation: String) -> UUID {
        let id = UUID()
        activeOperations[id] = operation
        outcomes[operation] = nil
        outcome = nil
        return id
    }

    private func end(_ id: UUID) { activeOperations[id] = nil }

    /// Why `operation` was not done, or may not have been: what its own sheet shows, and nothing
    /// another operation left (P6).
    func failure(of operation: String) -> Outcome? {
        outcomes[operation].flatMap { $0.kind != .done ? $0 : nil }
    }

    /// Take the outcome down: the status bar's dismiss, and a sheet that opens afresh.
    func clearOutcome(of operation: String? = nil) {
        if let operation { outcomes[operation] = nil } else { outcomes = [:] }
        if operation == nil || outcome?.operation == operation { outcome = nil }
    }

    /// The operation under way was done.
    private func report(operation: String, done words: String) {
        let result = Outcome(operation: operation, kind: .done, words: words)
        outcomes[operation] = result
        outcome = result
    }

    /// The operation under way was refused, or whether it was done is not known: the daemon's
    /// sentence, never a type's name (M-7).
    private func report(_ error: Error, operation: String) {
        let result = Outcome(operation: operation, kind: Outcome.kind(of: error), words: sentence(error))
        outcomes[operation] = result
        outcome = result
    }

    /// Something the app does on its own failed (a refresh, a read): said in the status bar, but
    /// never over what a person's own operation came to.
    private func reportBackground(_ error: Error) {
        guard outcome == nil || outcome?.operation == "" else { return }
        let connectivity: Bool
        switch error {
        case VoxError.Unreachable(_), VoxError.ReadInterrupted(_): connectivity = true
        default: connectivity = false
        }
        outcome = Outcome(operation: "", kind: Outcome.kind(of: error), words: sentence(error),
                          backgroundConnectivity: connectivity)
    }

    // ---- what the node says -------------------------------------------------------------------

    /// The messages drawn on screen are read (R-6): the node is told, as the TUI tells it what it
    /// draws, once each, in batches. This node's own, and those not received yet, are not.
    func drawn(_ message: RoomMessage, in room: String) {
        if readMarkEpoch != nodeObservationEpoch {
            // Let a prior actor's in-flight request settle before admitting another batch.
            guard flushing == nil else { return }
            marked.removeAll()
            markedOrder.removeAll()
            unmarked.removeAll()
            readRoomOrder.removeAll()
            pendingReadIDs.removeAll()
            readMarkEpoch = nodeObservationEpoch
        }
        guard case .room(room) = selection, byID[message.id] != nil, message.author != me,
              !message.owed, !marked.contains(message.id),
              !pendingReadIDs.contains(message.id) else { return }
        // Backpressure leaves the row unread. A later visible-row pass retries it;
        // no unread badge is decremented and no successful mark is claimed here.
        guard pendingReadIDs.count < Self.pendingReadLimit else { return }
        pendingReadIDs.insert(message.id)
        if unmarked[room] == nil { readRoomOrder.append(room) }
        unmarked[room, default: []].append(message.id)
        guard flushing == nil else { return }
        let epoch = nodeObservationEpoch
        flushing = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 300_000_000)
            guard let self else { return }
            defer {
                self.flushing = nil
                if epoch != self.nodeObservationEpoch {
                    self.unmarked.removeAll()
                    self.readRoomOrder.removeAll()
                    self.pendingReadIDs.removeAll()
                }
            }
            // One worker, including its awaited acknowledgement. IDs in flight retain
            // their slots in the shared 1024 budget, so a slow daemon cannot grow a backlog.
            while epoch == self.nodeObservationEpoch, !Task.isCancelled,
                  !self.readRoomOrder.isEmpty {
                let room = self.readRoomOrder.removeFirst()
                guard let ids = self.unmarked.removeValue(forKey: room) else { continue }
                var acknowledged = false
                do {
                    try await self.client.markRead(room: room, ids: ids)
                    guard epoch == self.nodeObservationEpoch, !Task.isCancelled else { return }
                    for id in ids {
                        if self.marked.insert(id).inserted { self.markedOrder.append(id) }
                    }
                    while self.markedOrder.count > Self.recentReadLimit {
                        self.marked.remove(self.markedOrder.removeFirst())
                    }
                    acknowledged = true
                    self.scheduleUnread(room)
                    readLog.debug("marked read: \(ids.count) in \(room, privacy: .public)")
                } catch {
                    if epoch == self.nodeObservationEpoch && !Task.isCancelled {
                        self.reportBackground(error)
                    }
                }
                self.pendingReadIDs.subtract(ids)
                if acknowledged { self.readMarkRevision = UUID() }
            }
        }
    }

    /// Recent successful deduplication only. Evicted IDs may be marked again idempotently;
    /// durable read state belongs to the node, not this bounded client cache.
    @Published private(set) var readMarkRevision = UUID()
    private static let recentReadLimit = 1024
    private static let pendingReadLimit = 1024
    private var readMarkEpoch = UUID()
    private var marked: Set<String> = []
    private var markedOrder: [String] = []
    private var pendingReadIDs: Set<String> = []
    private var unmarked: [String: [String]] = [:]
    private var readRoomOrder: [String] = []
    private var flushing: Task<Void, Never>?

    /// The members of `room` other than this node, with the trust each has here.
    private func memberRows(_ room: String) async throws -> (rows: [MemberRow], trustsMe: Set<String>, presented: [String: String]) {
        let roster = try await client.roster(room: room)
        let consents = try await client.memberConsents(room: room)
        let keyring = Dictionary(trusted.map { ($0.fingerprint, $0.drive) }) { $1 }
        let back = Set(consents.inbound)
        // Their trust in this node, whether or not this node trusts them (D4): both directions.
        let displayNames = roster.map { m in (m.fingerprint, m.name.isEmpty ? m.presentedName : m.name) }
        let rows = roster.filter { $0.fingerprint != me }.map { m in
            let trust = Trust.of(inKeyring: keyring[m.fingerprint] != nil,
                                 trustsYou: back.contains(m.fingerprint))
            let rawName = m.name.isEmpty ? m.presentedName : m.name
            let clash = clashingAlias(others: displayNames.filter { $0.0 != m.fingerprint }.map { $0.1 }, alias: rawName) != nil
            let shown = rawName.isEmpty ? String(m.fingerprint.prefix(12)) : rawName + (clash ? "#" + m.fingerprint.prefix(6) : "")
            return MemberRow(id: m.fingerprint,
                             name: m.name.isEmpty && !m.presentedName.isEmpty ? "\(shown) · \(m.fingerprint.prefix(12))" : shown,
                             trust: trust, drive: keyring[m.fingerprint] ?? false,
                             trustsYou: back.contains(m.fingerprint),
                             keyWaits: m.keyWaits)
        }
        return (rows, back, Dictionary(uniqueKeysWithValues: roster.filter { !$0.presentedName.isEmpty }
            .map { ($0.fingerprint, $0.presentedName) }))
    }

    /// The room on screen, read again every few seconds while it is there, each part published
    /// only when it changed: who has read this node's messages (read records arrive with the
    /// room's syncs and draw nothing of their own), the pulled copies, the services
    /// shared, and the members with their trust (one who joins while the room is on screen).
    private func watchReads(_ room: String) {
        watching?.cancel()
        let generation = roomReadGeneration
        watching = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                guard !Task.isCancelled, let self, self.roomReadGeneration == generation,
                      self.selection == .room(room), self.ended == nil else { return }
                let reads = try? await self.client.readBy(room: room)
                let where_ = try? await self.client.whereabouts(room: room)
                let pulls = try? await self.client.pulledBy(room: room)
                let copies = try? await self.client.pulled(room: room)
                let states = try? await self.client.pullStates(room: room)
                let rows = try? await self.memberRows(room)
                let kept = try? await self.client.retention(room: room)
                let keptSecs = try? await self.client.retentionSecs(room: room)
                await self.readGovernancePages()
                guard !Task.isCancelled, self.roomReadGeneration == generation,
                      self.selection == .room(room), self.ended == nil else { return }
                if let kept, kept != self.retention { self.retention = kept }
                if let keptSecs, keptSecs != self.retentionSecs { self.retentionSecs = keptSecs }
                await self.loadStepRetention()
                guard !Task.isCancelled, self.roomReadGeneration == generation,
                      self.selection == .room(room), self.ended == nil else { return }
                await self.loadRoomAnchorState()
                guard !Task.isCancelled, self.roomReadGeneration == generation,
                      self.selection == .room(room), self.ended == nil else { return }
                await self.refreshSessionMetadata()
                let listed = self.sessions
                guard !Task.isCancelled, self.roomReadGeneration == generation,
                      self.selection == .room(room), self.ended == nil else { return }
                if listed != self.sessions { self.sessions = listed }
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
                if let rows {
                    if rows.trustsMe != self.trustsMe { self.trustsMe = rows.trustsMe }
                    for (fingerprint, name) in rows.presented { self.rememberPresentation(fingerprint, name) }
                    if rows.rows != self.members {
                        // A member not listed before joined while the room was on screen (K-7).
                        let before = Set(self.members.map(\.id))
                        let came = rows.rows.filter { !before.contains($0.id) }
                        self.members = rows.rows
                        if !before.isEmpty || !came.isEmpty {
                            let at = UInt64(Date().timeIntervalSince1970 * 1000)
                            for m in came where !self.joins.contains(where: { $0.fingerprint == m.id }) {
                                self.joins.append(JoinLine(fingerprint: m.id, at: at, said: ""))
                            }
                        }
                    }
                }
                self.scheduleThreadRefresh()
                // Each join said, and said again as the room's consent grants name more of the
                // keyring's nodes trusting the newcomer.
                for (i, line) in self.joins.enumerated() {
                    if let said = try? await self.client.joinSaid(room: room, member: line.fingerprint),
                       !Task.isCancelled, self.roomReadGeneration == generation,
                       self.selection == .room(room), self.ended == nil, i < self.joins.count,
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
        // The room's row previews it.
        if Preview.shows(message), let i = rooms.firstIndex(where: { $0.id == room }),
           message.createdMillis >= rooms[i].last?.millis ?? 0 {
            let preview = Preview(message, me: me)
            if rooms[i].last != preview { rooms[i].last = preview }
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
        nodeObservationEpoch = UUID()
        roomReadGeneration = UUID()
        invalidateRoomAnchorState(preservingSnapshot: true)
        rejectedRoomMark = nil
        roomNeedsPage = false
        // An ended stream does not establish whether a protected node is Locked or a
        // passphraseless node is already Ready again. Display only the fresh snapshot.
        releaseHistoryViews()
        ended = "Node \(node) is unavailable."
        machineStateKnown = false
        daemonReachable = text.localizedCaseInsensitiveContains("detached")
            || text.localizedCaseInsensitiveContains("Locked")
        if !daemonReachable { daemonFailure = text }
        Task { [weak self] in await self?.readFacts() }
    }

    /// Recoverable history is reloaded from the node after leaving a view or losing its
    /// owner. Drafts are user working state and are preserved independently of these caches.
    private func releaseHistoryViews() {
        clearThreadState()
        messages = []
        roomOlder = 0
        roomBefore = nil
        unreadFrom = nil
        unreadCount = 0
        sessionPages.clear()
        sessionWindowRevision = UUID()
        selectedEarlierRequest = nil
        selectedSessionMetadata = nil
        selectedSessionMetadataKnown = false
        sessionNote = nil
        sessionLoading = false
        readBy = [:]
        whereabouts = [:]
        pulledBy = [:]
        pulled = [:]
    }

    /// Resume the same window after its owner has unlocked the node. Credentials and
    /// the unlock mutation belong to AppModel; this only restores observation.
    func resumeAfterUnlock(currentOwner: @MainActor () -> Bool) async throws -> Bool {
        let epoch = nodeObservationEpoch
        guard currentOwner(), nodeObservationEpoch == epoch, !Task.isCancelled else { return false }
        let fresh = try await client.nodes()
        guard currentOwner(), nodeObservationEpoch == epoch, !Task.isCancelled else { return false }
        guard fresh.first(where: { $0.name == node })?.status == "Ready" else { return false }
        let view = try await client.view()
        guard currentOwner(), nodeObservationEpoch == epoch, !Task.isCancelled else { return false }
        try await client.subscribe(listener: Listener(model: self))
        guard currentOwner(), nodeObservationEpoch == epoch, !Task.isCancelled else { return false }
        nodes = fresh
        machineStateKnown = true
        daemonReachable = true
        daemonFailure = nil
        peers = Int(view.peers)
        keyring = view.keyring
        ended = nil
        // These install owned tasks synchronously; no old request can start them after
        // ownership has changed at an awaited boundary.
        if case let .room(room) = selection {
            roomReadGeneration = UUID()
            roomNeedsPage = true
            watching?.cancel()
            stepRetentionRead = UUID()
            stepRetentionLoading = false
            watchReads(room)
        }
        follow()
        return true
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
    /// One open page and one history page are retained, never the complete descriptor log.
    func refreshSessionMetadata() async {
        guard let room = roomOnScreen else { return }
        let epoch = nodeObservationEpoch, generation = roomReadGeneration, token = UUID()
        let liveAfter = sessionsOpenAfter, historyAfter = sessionsHistoryAfter
        sessionsMetadataRead = token
        sessionsMetadataLoading = true
        defer { if sessionsMetadataRead == token { sessionsMetadataLoading = false } }
        do {
            let live = try await client.sessionsOpenPage(room: room, after: liveAfter)
            let history = try await client.sessionsPage(room: room, after: historyAfter)
            guard token == sessionsMetadataRead, epoch == nodeObservationEpoch,
                  generation == roomReadGeneration, roomOnScreen == room else { return }
            sessions = live.sessions + history.sessions.filter { !$0.open }
            sessionsOpenNext = live.next
            sessionsHistoryNext = history.next
        } catch {
            guard token == sessionsMetadataRead, epoch == nodeObservationEpoch,
                  generation == roomReadGeneration, roomOnScreen == room else { return }
            reportBackground(error)
        }
    }

    func nextOpenSessions() async {
        guard !sessionsMetadataLoading, let next = sessionsOpenNext else { return }
        sessionsOpenAfter = next
        await refreshSessionMetadata()
    }

    func firstOpenSessions() async {
        guard !sessionsMetadataLoading else { return }
        sessionsOpenAfter = nil
        await refreshSessionMetadata()
    }

    func nextSessionHistory() async {
        guard !sessionsMetadataLoading, let next = sessionsHistoryNext else { return }
        sessionsHistoryAfter = next
        await refreshSessionMetadata()
    }

    func firstSessionHistory() async {
        guard !sessionsMetadataLoading else { return }
        sessionsHistoryAfter = nil
        await refreshSessionMetadata()
    }

    /// Exact selected metadata stays independent of the bounded tab/history pages.
    func readSelectedSessionMetadata() async {
        guard let room = roomOnScreen, case let .session(node, id) = showing else {
            selectedSessionMetadata = nil
            selectedSessionMetadataKnown = false
            return
        }
        let epoch = nodeObservationEpoch, generation = roomReadGeneration
        func current() -> Bool {
            roomOnScreen == room && showing == .session(node: node, id: id)
                && epoch == nodeObservationEpoch && generation == roomReadGeneration
        }
        do {
            let found = try await client.session(room: room, node: node, sessionId: id)
            guard current() else { return }
            selectedSessionMetadata = found
            selectedSessionMetadataKnown = true
            if found == nil {
                sessionPages.clear()
                sessionWindowRevision = UUID()
                selectedEarlierRequest = nil
                sessionNote = "This Session's opening is no longer available."
                sessionLoading = false
            }
        } catch {
            guard current() else { return }
            selectedSessionMetadata = nil
            selectedSessionMetadataKnown = true
            sessionLoading = false
            sessionPages.clear()
            sessionWindowRevision = UUID()
            selectedEarlierRequest = nil
            sessionNote = sentence(error)
            reportBackground(error)
        }
    }

    /// The Session on screen's entries, to a member with drive; nothing to one without (SC-3).
    func readSession() async {
        if showingSession && selectedSessionMetadataKnown && selectedSessionMetadata == nil { return }
        guard let room = roomOnScreen, let s = shownSession, s.canDrive else {
            sessionPages.clear()
            selectedEarlierRequest = nil
            if sessionNote != nil { sessionNote = nil }
            sessionLoading = false
            return
        }
        let revision = sessionWindowRevision
        let follows = timelineFollowingNewest
        let epoch = nodeObservationEpoch, generation = roomReadGeneration
        let heldIDs = sessionEntries.map(\.id)
        let heldInstance = sessionPages.instance
        func current() -> Bool {
            roomOnScreen == room && shownSession?.nodeFingerprint == s.nodeFingerprint
                && shownSession?.sessionId == s.sessionId && shownSession?.canDrive == true
                && revision == sessionWindowRevision && follows == timelineFollowingNewest
                && epoch == nodeObservationEpoch && generation == roomReadGeneration
        }
        do {
            let read = try await client.sessionRead(room: room, node: s.nodeFingerprint,
                                                    sessionId: s.sessionId)
            guard current() else { return }
            var retained: FfiSessionRead?
            if !follows, !heldIDs.isEmpty, let heldInstance {
                guard heldInstance == read.instance else {
                    throw VoxError.Failed(reason: "The saved room changed while its Session window was open.")
                }
                retained = try await client.sessionEntries(room: room, node: s.nodeFingerprint,
                    sessionId: s.sessionId, instance: heldInstance, ids: heldIDs)
            }
            guard current() else { return }
            var pages = sessionPages
            if let retained, !pages.revalidate(retained) {
                throw VoxError.Failed(reason: "The saved room changed while refreshing held Session activity.")
            }
            pages.newest(read, following: follows)
            if pages != sessionPages {
                sessionPages = pages
                sessionWindowRevision = UUID()
            }
            if read.note != sessionNote { sessionNote = read.note }
            sessionLoading = false
            if let now = shownSession { await refreshSessionRequests(room: room, session: now) }
        } catch {
            guard current() else { return }
            // A failed protected read cannot authorize formerly cached bodies. Preserve
            // destination identity and report the refusal, so a fresh valid read can recover.
            sessionPages.clear()
            sessionWindowRevision = UUID()
            selectedEarlierRequest = nil
            sessionNote = sentence(error)
            reportBackground(error)
            sessionLoading = false
        }
    }

    /// End on an older Session window reloads the actual newest page from disk.
    func readNewestTimeline() async {
        guard showingSession else { return }
        timelineFollowingNewest = true
        sessionWindowRevision = UUID()
        await readSession()
    }

    /// The page of the Session on screen's entries before those held (ADR-034 FR-4): read when
    /// the person scrolls up to the top, or asks, and put before them. One page at a time.
    func readOlderSession() async {
        guard let room = roomOnScreen, let s = shownSession, s.canDrive,
              let before = sessionBefore, !sessionReadingOlder else { return }
        timelineFollowingNewest = false
        let revision = sessionWindowRevision
        let epoch = nodeObservationEpoch, generation = roomReadGeneration
        sessionReadingOlder = true
        defer { sessionReadingOlder = false }
        do {
            let read = try await client.sessionReadOlder(room: room, node: s.nodeFingerprint,
                                                         sessionId: s.sessionId, before: before)
            guard roomOnScreen == room, let now = shownSession, now.nodeFingerprint == s.nodeFingerprint,
                  now.sessionId == s.sessionId, now.canDrive, sessionBefore == before,
                  revision == sessionWindowRevision else { return }
            guard sessionPages.instance == read.instance else {
                throw VoxError.Failed(reason: "The saved room changed while loading older Session activity.")
            }
            guard sessionPages.older(read, asked: before) else { return }
            sessionWindowRevision = UUID()
            await refreshSessionRequests(room: room, session: now)
        } catch {
            guard revision == sessionWindowRevision, epoch == nodeObservationEpoch,
                  generation == roomReadGeneration, roomOnScreen == room,
                  shownSession?.nodeFingerprint == s.nodeFingerprint,
                  shownSession?.sessionId == s.sessionId else { return }
            sessionPages.clear()
            sessionWindowRevision = UUID()
            selectedEarlierRequest = nil
            sessionNote = sentence(error)
            reportBackground(error)
        }
    }

    /// Current state for the loaded requests and any request selected from a notification.
    /// The daemon uses its request index; no transcript history is walked to find them.
    private func refreshSessionRequests(room: String, session s: FfiSession) async {
        let selected = selectedRequest
        let revision = sessionWindowRevision
        let epoch = nodeObservationEpoch, generation = roomReadGeneration
        let instance = sessionPages.instance
        func currentContext() -> Bool {
            roomOnScreen == room && shownSession?.nodeFingerprint == s.nodeFingerprint
                && shownSession?.sessionId == s.sessionId && shownSession?.canDrive == true
                && selectedRequest == selected && revision == sessionWindowRevision
                && epoch == nodeObservationEpoch && generation == roomReadGeneration
        }
        var references = Set(sessionEntries.compactMap { $0.request?.reference })
        if let selected { references.insert(selected) }
        guard !references.isEmpty else {
            selectedEarlierRequest = nil
            return
        }
        do {
            // One indexed newest page per already-held/explicitly-selected reference.
            // Keep one current request row per reference, never its resolution transcript.
            var current: [FfiSessionEntry] = []
            for reference in references.sorted() {
                let page = try await client.sessionRequestsPage(room: room, node: s.nodeFingerprint,
                    sessionId: s.sessionId, reference: reference, before: nil)
                guard currentContext() else { return }
                if let instance, page.instance != instance {
                    throw VoxError.Failed(reason: "The saved room changed while refreshing its requests.")
                }
                if let row = page.entries.last(where: { $0.request?.reference == reference }) {
                    current.append(row)
                }
            }
            guard currentContext() else { return }
            var pages = sessionPages
            pages.refreshRequests(current)
            if pages != sessionPages {
                sessionPages = pages
                sessionWindowRevision = UUID()
            }
            selectedEarlierRequest = current.first { entry in
                entry.request?.reference == selected && !sessionEntries.contains(where: { $0.id == entry.id })
            }
        } catch {
            guard currentContext() else { return }
            selectedEarlierRequest = nil
            reportBackground(error)
        }
    }

    /// Each open room's approvals and questions waiting on this node (CL-2), as the TUI counts
    /// them: what its Sessions say waits on this node.
    func readWaiting() async {
        let epoch = nodeObservationEpoch
        for room in rooms where room.open {
            do {
                let count = try await client.sessionsWaiting(room: room.id)
                guard epoch == nodeObservationEpoch, !Task.isCancelled else { return }
                guard let n = Int(exactly: count) else {
                    throw VoxError.Failed(reason: "The node's waiting count cannot be displayed accurately.")
                }
                if let i = rooms.firstIndex(where: { $0.id == room.id && $0.open }),
                   rooms[i].waiting != n { rooms[i].waiting = n }
            } catch {
                guard epoch == nodeObservationEpoch, !Task.isCancelled else { return }
                reportBackground(error)
            }
        }
        guard epoch == nodeObservationEpoch, !Task.isCancelled else { return }
        await noteWaiting()
    }

    /// Current pending targets come from the node's index; ended Session history and
    /// resolution transcripts are never collected to discover them.
    private func waiting(in room: String) async throws -> [(node: String, session: String, reference: String, label: String)] {
        let epoch = nodeObservationEpoch
        var after: String?
        var found: [(node: String, session: String, reference: String, label: String)] = []
        repeat {
                let page = try await client.sessionsPendingPage(room: room, after: after)
                guard epoch == nodeObservationEpoch, !Task.isCancelled else { throw CancellationError() }
                for target in page.targets {
                    guard let session = try await client.session(room: room, node: target.node,
                        sessionId: target.sessionId), session.open, session.canDrive else { continue }
                    let head = try await client.sessionRead(room: room, node: target.node,
                        sessionId: target.sessionId)
                    let held = try await client.sessionEntries(room: room, node: target.node,
                        sessionId: target.sessionId, instance: head.instance, ids: [target.entry])
                    guard epoch == nodeObservationEpoch, !Task.isCancelled else { throw CancellationError() }
                    if let request = held.entries.first(where: { $0.id == target.entry })?.request,
                       request.state == nil {
                        found.append((target.node, target.sessionId, request.reference, session.label))
                    }
                }
                if let next = page.next, next == after {
                    throw VoxError.Failed(reason: "The pending request page did not advance.")
                }
                after = page.next
        } while after != nil
        return found
    }

    /// A request that is new since the last look notifies, once per Session, replacing that
    /// Session's earlier one; a Session no longer waiting has its notification withdrawn (P1).
    /// Never the request's text (R-10).
    private func noteWaiting() async {
        let epoch = nodeObservationEpoch
        var now: Set<String> = []
        var bySession: [String: (room: String, node: String, session: String, reference: String, label: String)] = [:]
        do {
        for room in rooms where room.open {
            let targets = try await waiting(in: room.id)
            guard epoch == nodeObservationEpoch, !Task.isCancelled else { return }
            for w in targets {
                let key = "\(room.id)/\(w.node)/\(w.session)/\(w.reference)"
                now.insert(key)
                if !knownWaiting.contains(key) && waitingSeen {
                    bySession["\(room.id)/\(w.node)/\(w.session)"] = (room.id, w.node, w.session, w.reference, w.label)
                }
            }
        }
        } catch {
            guard epoch == nodeObservationEpoch, !Task.isCancelled else { return }
            reportBackground(error)
            return // No notification withdrawal from an incomplete scan.
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
        if let s = shownSession, s.canDrive { await refreshSessionRequests(room: room, session: s) }
    }

    /// The approval selected in the Session on screen, open and this node's to answer: what
    /// ⌥⌘Y and ⌥⌘N act on (P1). Questions are answered by their options, not these keys.
    var selectedApproval: (session: FfiSession, room: String, reference: String)? {
        guard let reference = selectedRequest, let s = shownSession, s.canDrive, s.open,
              let room = roomOnScreen,
              let r = (sessionEntries + [selectedEarlierRequest].compactMap { $0 })
                .compactMap(\.request).first(where: { $0.reference == reference }),
              r.state == nil, !r.isQuestion else { return nil }
        return (s, room, reference)
    }

    /// Approve (⌥⌘Y) or Reject (⌥⌘N) the selected approval, and say what came of it (P1).
    func answerSelected(approve: Bool) async {
        guard let a = selectedApproval else { return }
        let action: DriveAction = approve ? .approve(reference: a.reference)
            : .reject(reference: a.reference, why: nil)
        // What came of it is this operation's outcome (P6): done, refused, or not known.
        let operation = approve ? "approve-request" : "reject-request"
        let attempt = begin(operation)
        defer { end(attempt) }
        switch await driveResult(a.session, in: a.room, action) {
        case let .taken(words): report(operation: operation, done: asSentence(words))
        case let .refused(words): report(VoxError.Failed(reason: asSentence(words)), operation: operation)
        case let .unknown(words): report(VoxError.Unknown(reason: asSentence(words)), operation: operation)
        }
        await readSession()
    }

    /// A Session in `room` opened, ended or was renamed, or what waits on this node changed.
    fileprivate func sessionsChanged(in room: String) async {
        if let count = try? await client.sessionsWaiting(room: room), let n = Int(exactly: count),
           let i = rooms.firstIndex(where: { $0.id == room }) { rooms[i].waiting = n }
        await noteWaiting()
        guard roomOnScreen == room else { return }
        await refreshSessionMetadata()
        await readSelectedSessionMetadata()
        await readSession()
    }

    /// A Session has a new entry, or a request in it was resolved.
    fileprivate func sessionEntry(in room: String, node: String, session: String) async {
        guard roomOnScreen == room, shownSession?.nodeFingerprint == node,
              shownSession?.sessionId == session else { return }
        await readSession()
    }

    /// Drive a Session (ADR-029 DR-1), for the Session view's controls (SessionDrive.swift).
    func drive(room: String, node: String, session: String, action: DriveAction) async throws -> DriveAnswer {
        try await client.drive(room: room, node: node, session: session, action: action)
    }
}

// The menu bar extra's facts (M-22, A-3), here for the client they are read with.
extension NodeModel {
    /// The services shared to this node, its own shares and its live tunnels, across its rooms.
    func menuBarFacts() async -> MenuBarFacts {
        var facts = MenuBarFacts()
        for room in rooms where room.open {
            if let listed = try? await client.servicesPage(room: room.id, after: nil, revision: nil) {
                facts.services += listed.shared.filter { $0.by != "you" }
                    .map { .init(address: $0.address, canonical: $0.canonical, by: $0.by) }
                if listed.next != nil { facts.moreServiceRooms.append(.init(room: room.id, name: room.name)) }
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
        let operation = "stop-share"
        let attempt = begin(operation)
        defer { end(attempt) }
        do {
            _ = try await client.shareStop(room: share.room, selector: share.tag)
            report(operation: operation, done: "Stopped sharing \(share.name).")
        } catch {
            report(error, operation: operation)
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
    var backgroundConnectivity = false

    static func kind(of error: Error) -> Kind {
        if case VoxError.Unknown(_) = error { return .unknown }
        if case VoxError.ReadInterrupted(_) = error { return .unknown }
        return .refused
    }
}


// ADR-033 TH-2: independent, bounded thread reads never replace General or its read cursor.
extension NodeModel {
    private func clearThreadState() {
        threadGeneration = UUID()
        threadRefreshTask?.cancel()
        threadRefreshTask = nil
        threadRefreshID = UUID()
        threadRefreshDirty = false
        threadDisplayRevision = nil
        threadForcedSummaries = []
        threadSummaryVersions = [:]
        threadAuthorRequests = [:]
        threadPageDirty = false
        threadPagesLoaded = 1
        threadPageTask?.cancel()
        threadSummaries = [:]
        threadSummaryErrors = [:]
        openThread = nil
        threadRootMessage = nil
        threadReplies = []
        threadLoading = false
        threadHasMore = false
        threadError = nil
    }

    private func threadReadIsCurrent(room: String, generation: UUID, epoch: UUID, request: UUID) -> Bool {
        roomReadGeneration == generation && nodeObservationEpoch == epoch
            && roomOnScreen == room && ended == nil && threadRefreshID == request
    }

    private func scheduleThreadRefresh() {
        guard let room = roomOnScreen, ended == nil else { return }
        threadRefreshDirty = true
        guard threadRefreshTask == nil else { return }
        let generation = roomReadGeneration
        let epoch = nodeObservationEpoch
        let refreshID = UUID()
        threadRefreshID = refreshID
        threadRefreshTask = Task { [weak self] in
            guard let self else { return }
            defer {
                if self.threadRefreshID == refreshID {
                    self.threadRefreshTask = nil
                    if self.threadRefreshDirty { self.scheduleThreadRefresh() }
                }
            }
            repeat {
                self.threadRefreshDirty = false
                @MainActor func current() -> Bool {
                    !Task.isCancelled && self.threadReadIsCurrent(room: room, generation: generation,
                        epoch: epoch, request: refreshID)
                }
                let revision: String
                do {
                    revision = try await self.client.roomDisplayRevision(room: room)
                    guard current() else { return }
                } catch {
                    guard current() else { return }
                    // A refused revision is not permission to retain formerly readable bodies.
                    self.threadDisplayRevision = nil
                    self.threadSummaries = [:]
                    self.threadSummaryVersions = [:]
                    self.threadAuthorRequests = [:]
                    self.retireThreadSelection()
                    self.threadRootMessage = nil
                    self.threadReplies = []
                    self.threadHasMore = false
                    self.threadGeneration = UUID()
                    self.threadPageTask?.cancel()
                    self.threadPageDirty = false
                    self.threadLoading = false
                    self.threadError = sentence(error)
                    for root in self.messages.filter({ $0.thread.isEmpty && !$0.owed }).map(\.id) {
                        self.threadSummaryErrors[root] = sentence(error)
                    }
                    return
                }
                let changed = self.threadDisplayRevision != revision
                self.threadDisplayRevision = revision
                if changed { self.refreshOpenThread() }
                let roots = self.messages.filter { $0.thread.isEmpty && !$0.owed }.map(\.id)
                let known = Set(roots)
                self.threadSummaries = self.threadSummaries.filter { known.contains($0.key) }
                self.threadSummaryErrors = self.threadSummaryErrors.filter { known.contains($0.key) }
                let forced = self.threadForcedSummaries
                self.threadForcedSummaries = []
                for root in roots where changed || forced.contains(root)
                    || (self.threadSummaries[root] == nil && self.threadSummaryErrors[root] == nil) {
                    guard current() else { return }
                    do {
                        let summary = try await self.client.threadSummary(room: room, root: root, afterAuthor: nil)
                        guard current() else { return }
                        guard summary.root == root else {
                            throw VoxError.Failed(reason: "The reply summary belongs to another message.")
                        }
                        self.threadSummaries[root] = summary
                        self.threadSummaryVersions[root] = UUID()
                        self.threadSummaryErrors[root] = nil
                    } catch {
                        guard current() else { return }
                        self.threadSummaries[root] = nil
                        self.threadSummaryVersions[root] = UUID()
                        self.threadSummaryErrors[root] = sentence(error)
                    }
                }
            } while self.threadRefreshDirty
        }
    }

    /// Only retained/readable messages of the currently displayed room can be acted on.
    var selectedChatMessage: RoomMessage? {
        guard roomOnScreen != nil, ended == nil, let id = selectedMessage else { return nil }
        // The center's currently displayed roots/tag rows remain actionable. Hidden General
        // reply bodies in the room cache are not an authority after a panel read refusal.
        if let current = timelineItems.compactMap(\.message).first(where: { $0.id == id && !$0.owed }) { return current }
        guard showing == .general, let root = openThread else { return nil }
        return threadReplies.first { $0.id == id && $0.thread == root && !$0.owed }
    }

    private func retireThreadSelection() {
        guard openThread != nil, let id = selectedMessage,
              threadReplies.contains(where: { $0.id == id })
                || messages.contains(where: { $0.id == id && !$0.thread.isEmpty }) else { return }
        selectedMessage = nil
        selectedMessages = []
        selectionAnchor = nil
    }

    struct ThreadSelectionScope: Equatable {
        let room: UUID
        let thread: UUID
        let node: UUID
    }
    var threadSelectionGeneration: ThreadSelectionScope {
        ThreadSelectionScope(room: roomReadGeneration, thread: threadGeneration, node: nodeObservationEpoch)
    }
    func threadSelectionIsCurrent(room: String, root: String, generation: ThreadSelectionScope) -> Bool {
        roomOnScreen == room && openThread == root && threadSelectionGeneration == generation && ended == nil
    }

    func showThread(_ message: RoomMessage) {
        guard roomOnScreen != nil, ended == nil, !message.owed, message.thread.isEmpty,
              messages.contains(where: { $0.id == message.id && !$0.owed }) else { return }
        selectedMessage = message.id
        selectedMessages = [message.id]
        selectionAnchor = message.id
        threadGeneration = UUID()
        threadPageTask?.cancel()
        threadLoading = false
        threadPagesLoaded = 1
        threadPageDirty = false
        openThread = message.id
        threadRootMessage = message
        threadReplies = []
        threadHasMore = false
        threadError = nil
        inspectorShown = true
        showing = .general
        refreshOpenThread()
    }

    func closeThread() {
        let root = openThread.flatMap { id in messages.first { $0.id == id && !$0.owed } }
        selectedMessage = root?.id
        selectedMessages = Set(root.map { [$0.id] } ?? [])
        selectionAnchor = root?.id
        threadGeneration = UUID()
        threadPageTask?.cancel()
        threadPagesLoaded = 1
        threadPageDirty = false
        openThread = nil
        threadRootMessage = nil
        threadReplies = []
        threadLoading = false
        threadHasMore = false
        threadError = nil
    }

    private func refreshOpenThread() {
        guard openThread != nil else { return }
        if threadLoading {
            threadPageDirty = true
            return
        }
        threadPageDirty = false
        loadThreadPage(replacing: true)
    }

    func moreThreadReplies() { loadThreadPage(replacing: false) }
    func retryThread() { loadThreadPage(replacing: true) }

    private func loadThreadPage(replacing: Bool) {
        guard let room = roomOnScreen, let root = openThread, ended == nil, !threadLoading else { return }
        let generation = threadGeneration
        let roomGeneration = roomReadGeneration
        let epoch = nodeObservationEpoch
        let cursor = replacing ? "" : threadReplies.last?.id ?? ""
        threadLoading = true
        threadError = nil
        threadPageTask = Task { [weak self] in
            guard let self else { return }
            defer {
                if self.threadGeneration == generation, self.openThread == root {
                    self.threadLoading = false
                    if self.threadPageDirty {
                        self.threadPageDirty = false
                        self.refreshOpenThread()
                    }
                }
            }
            @MainActor func current() -> Bool {
                !Task.isCancelled && self.roomOnScreen == room && self.openThread == root
                    && self.threadGeneration == generation && self.roomReadGeneration == roomGeneration
                    && self.nodeObservationEpoch == epoch && self.ended == nil
            }
            do {
                if self.threadRootMessage == nil {
                    // Recovery revalidates exactly one root through the daemon's indexed
                    // read; it never walks General or reuses a formerly readable cached body.
                    let readable = try await self.client.threadRoot(room: room, root: root)
                    guard current() else { return }
                    guard let readable, readable.id == root, !readable.owed, readable.thread.isEmpty else {
                        throw VoxError.Failed(reason: "The thread's starting message is no longer readable or retained.")
                    }
                    self.threadRootMessage = readable
                }
                var next = cursor
                var result: [RoomMessage] = []
                let pages = replacing ? self.threadPagesLoaded : 1
                var more = false
                var awaitingBodies = false
                for _ in 0..<pages {
                    let page = try await self.client.readThreadPage(room: room, root: root, since: next)
                    guard current() else { return }
                    guard page.allSatisfy({ $0.owed || $0.thread == root }),
                          page.isEmpty || page.last?.id != next else {
                        throw VoxError.Failed(reason: "The thread page did not belong to this thread or advance its cursor.")
                    }
                    result += page
                    more = !page.isEmpty
                    if page.isEmpty { break }
                    guard let mark = page.last, !mark.owed else {
                        // The current API refuses an owed cursor. Keep that absence honest;
                        // never drain/replay a page or pretend the thread ended.
                        awaitingBodies = true
                        more = false
                        break
                    }
                    next = mark.id
                }
                if replacing { self.threadReplies = result }
                else {
                    let held = Set(self.threadReplies.map(\.id))
                    self.threadReplies += result.filter { !held.contains($0.id) }
                    if !result.isEmpty { self.threadPagesLoaded += 1 }
                }
                self.threadHasMore = more
                if awaitingBodies { self.threadError = "Some reply bodies have not been received. Retry when they arrive." }
                self.threadLoading = false
            } catch {
                guard current() else { return }
                // A read refusal is not an empty thread; old bodies are not retained under a
                // potentially changed read permission. The room/root identity stays for Retry.
                self.threadRootMessage = nil
                self.retireThreadSelection()
                self.threadReplies = []
                self.threadHasMore = false
                self.threadError = sentence(error)
                self.threadLoading = false
            }
        }
    }

    func threadMessage(_ id: String) -> RoomMessage? {
        threadRootMessage?.id == id ? threadRootMessage : threadReplies.first { $0.id == id }
    }

    func retryThreadSummary(_ root: String) {
        if threadSummaries[root]?.nextAuthor != nil {
            Task { await moreThreadAuthors(root) }
        } else {
            threadForcedSummaries.insert(root)
            scheduleThreadRefresh()
        }
    }

    func moreThreadAuthors(_ root: String) async {
        guard let room = roomOnScreen, let held = threadSummaries[root],
              let after = held.nextAuthor, ended == nil else { return }
        let generation = roomReadGeneration
        let epoch = nodeObservationEpoch
        let snapshot = threadSummaryVersions[root]
        let request = UUID()
        threadAuthorRequests[root] = request
        threadSummaryErrors[root] = nil
        @MainActor func current() -> Bool {
            roomOnScreen == room && roomReadGeneration == generation
                && nodeObservationEpoch == epoch && ended == nil && !Task.isCancelled
                && threadSummaryVersions[root] == snapshot && threadAuthorRequests[root] == request
        }
        do {
            let page = try await client.threadSummary(room: room, root: root, afterAuthor: after)
            guard current(), let latest = threadSummaries[root],
                  latest.root == held.root, latest.replyCount == held.replyCount,
                  latest.lastReplyMillis == held.lastReplyMillis,
                  latest.nextAuthor == held.nextAuthor,
                  latest.authors.map({ $0.fingerprint + "\u{0}" + $0.name })
                    == held.authors.map({ $0.fingerprint + "\u{0}" + $0.name }) else { return }
            guard page.root == root, page.nextAuthor != after else {
                throw VoxError.Failed(reason: "The thread's author page did not advance.")
            }
            // Only combine pages from the same authoritative count/time snapshot.
            guard page.replyCount == held.replyCount, page.lastReplyMillis == held.lastReplyMillis else {
                threadForcedSummaries.insert(root)
                scheduleThreadRefresh()
                return
            }
            let known = Set(held.authors.map(\.fingerprint))
            threadSummaries[root] = ThreadSummary(root: root, replyCount: held.replyCount,
                lastReplyMillis: held.lastReplyMillis,
                authors: held.authors + page.authors.filter { !known.contains($0.fingerprint) },
                nextAuthor: page.nextAuthor)
            threadSummaryVersions[root] = UUID()
        } catch {
            guard current() else { return }
            threadSummaryErrors[root] = sentence(error)
        }
    }
}
