// A room's authorized Sessions in its principal tab row (ADR-033 LY-1–3).
// General is the room conversation; ended Sessions are reached from the row's menu.

import AppKit
import SwiftUI

/// A draft belongs to the exact room, remote node and Session, never a display label.
struct SessionDraftKey: Hashable {
    let room: String
    let instance: Data
    let node: String
    let session: String
    let opening: String
}

/// Delivery state belongs to the Session, not to a particular rendered composer.
struct SessionDeliveryState {
    var said = ""
    var interruptSaid = ""
    var stopSaid = ""
    var sending = false
    var interrupting = false
    var stopping = false
}

/// What the room's timeline shows: its conversation, a selected tag, or one Session by node and id.
enum Showing: Hashable {
    case general
    case session(node: String, id: String)
    /// The room's messages tagged so (#636): a thread of one task, project or milestone.
    case tag(key: String, label: String)
}

extension NodeModel {
    /// The room's open Sessions, newest opening first (CL-2).
    var openSessions: [FfiSession] {
        sessions.filter { $0.open && $0.canDrive }.sorted { $0.openedAtMs > $1.openedAtMs }
    }

    /// The room's ended Sessions, newest end first.
    var endedSessions: [FfiSession] {
        sessions.filter { !$0.open && $0.canDrive }.sorted { ($0.endedAtMs ?? 0) > ($1.endedAtMs ?? 0) }
    }

    /// What needs the person, as the sidebar's NEEDS YOU counts it: its rooms and trust offers.
    /// An offer counts in the room it came from (K-15), and alone only when it came from none.
    var needsYouCount: Int {
        group(.needsYou).count
            + offers.filter { o in !rooms.contains { r in o.rooms.contains { $0.id == r.id } } }.count
    }

    /// A room's name as the sidebar says it, else its id's start.
    func roomName(_ room: String) -> String {
        rooms.first { $0.id == room }?.name ?? String(room.prefix(12))
    }

    var roomRosterWords: String {
        guard daemonReachable else { return "members unavailable" }
        guard !roomMembersPending else { return "members loading" }
        let count = members.count + 1
        return count == 1 ? "1 member" : "\(count) members"
    }

    func sessionTabLabel(_ session: FfiSession, includeName: Bool = false) -> String {
        let alias = session.nodeAlias.isEmpty
            ? (session.nodeFingerprint == me ? node : String(session.nodeFingerprint.prefix(12)))
            : session.nodeAlias
        // A partial page cannot establish that this is the node's only open Session.
        let several = sessionsOpenPaged || sessionsOpenNext != nil
            || openSessions.filter { $0.nodeFingerprint == session.nodeFingerprint }.count > 1
        guard includeName || several else { return alias }
        let name = session.name.flatMap { $0.isEmpty ? nil : $0 } ?? session.sessionId
        return "\(alias) · \(name)"
    }

    /// Every tag the room's messages on hand carry, sorted (#636): what the header's filter offers.
    /// Only messages this node can read carry any.
    var roomTags: [FfiMessageTag] {
        var tags: [String: FfiMessageTag] = [:]
        for message in messages { for tag in message.tagSelectors { tags[tag.key] = tag } }
        return tags.values.sorted { $0.label == $1.label ? $0.key < $1.key : $0.label < $1.label }
    }

    var showingSession: Bool {
        if case .session = showing { return true }
        return false
    }

    /// Exact selected metadata remains usable when its descriptor is outside the current page.
    var shownSession: FfiSession? {
        guard case let .session(node, id) = showing else { return nil }
        if selectedSessionMetadataKnown && selectedSessionMetadata == nil { return nil }
        if let selectedSessionMetadata,
           selectedSessionMetadata.nodeFingerprint == node, selectedSessionMetadata.sessionId == id {
            return selectedSessionMetadata
        }
        return sessions.first { $0.nodeFingerprint == node && $0.sessionId == id }
    }

    /// Pause is the owning node's live room state, independently of the saved transcript.
    /// An unavailable owner is unknown; absence of a response never means resumed.
    var sessionPauseWords: String? {
        guard showingSession, shownSession?.canDrive == true else { return nil }
        guard sessionPauseIsCurrent else { return "Pause status unknown; waiting for the selected Session." }
        if let error = sessionPauseError { return "Pause status unknown. \(error)" }
        guard let state = sessionPause else { return "Checking pause status…" }
        guard state.paused else { return nil }
        let when = Date(timeIntervalSince1970: Double(state.atMillis) / 1000)
            .formatted(date: .abbreviated, time: .standard)
        return "Paused by \(roomPauseName(state.by)) at \(when)"
    }

    /// Delivery observations belong only to the selected drive-authorized Session.
    var showsSessionAttention: Bool { showingSession && shownSession?.canDrive == true }

    func sessionAttentionWords(_ row: SessionAttentionRow) -> String {
        switch row.state {
        case .queued:
            switch row.wait {
            case .nextCodexTurn: return "Waiting for next Codex turn"
            case .paused: return "Queued — room paused"
            case .nextTurnAfterResume: return "Queued — waiting for the next turn after resume"
            case .adapterUnavailable: return "Queued — delivery adapter unavailable"
            case .unknown: return "Queued — notice acceptance unknown; awaiting a context receipt"
            case nil: return "Queued"
            }
        case .delivered: return "Delivered to harness; running turn not observed"
        case .answering: return "Answering — running turn observed"
        case .answered: return "Answered"
        case .unavailable: return "Unavailable"
        }
    }

    func sessionPauseMark(_ session: FfiSession) -> String {
        guard showing == .session(node: session.nodeFingerprint, id: session.sessionId),
              sessionPauseIsCurrent, sessionPause?.paused == true,
              sessionPauseError == nil else { return "" }
        return " · Paused"
    }

    /// Another node's Session's header, with drive or without (ADR-029 MD-3, as the TUI says it):
    /// its name and id are that node's claim. None for this node's own Sessions (their node's
    /// alias is empty): the claim is this node's own.
    var sessionHeader: String? {
        guard let s = shownSession, !s.nodeAlias.isEmpty else { return nil }
        return "\(s.label) — name and id as \(s.nodeAlias) says"
    }
}

/// The room's principal line: truthful roster, General and authorized Session tabs (LY-1–3).
private struct RoomSessionTab: Identifiable {
    let room: String
    let session: FfiSession
    var id: String { "\(room)/\(session.nodeFingerprint)/\(session.sessionId)" }
}

struct RoomTabs: View {
    @ObservedObject var model: NodeModel
    let room: String

    var body: some View {
        HStack(spacing: Space.s8) {
            Text(model.roomName(room)).fontWeight(.semibold)
                .lineLimit(1).accessibilityIdentifier("room-tab-name")
            Text(model.roomRosterWords).secondaryText()
                .accessibilityIdentifier("room-tab-members")
            Divider().frame(height: 20)
            ScrollView(.horizontal, showsIndicators: true) {
                HStack(spacing: Space.s8) {
                    tab("General", .general, id: "session-general")
                    ForEach(model.openSessions.map { RoomSessionTab(room: room, session: $0) }) { item in
                        let session = item.session
                        Divider().frame(height: 20)
                        tab((session.pending > 0 ? "! " + model.sessionTabLabel(session) + " · waiting on you"
                                                : model.sessionTabLabel(session)) + model.sessionPauseMark(session),
                            .session(node: session.nodeFingerprint, id: session.sessionId),
                            id: "session-\(session.shortId)")
                    }
                    if model.sessionsOpenNext != nil || model.sessionsOpenPaged {
                        Menu("Open Sessions") {
                            Button("First open Sessions") { Task { await model.firstOpenSessions() } }
                                .disabled(!model.sessionsOpenPaged)
                            if model.sessionsOpenNext != nil {
                                Button("More open Sessions") { Task { await model.nextOpenSessions() } }
                            }
                        }
                        .disabled(model.sessionsMetadataLoading)
                        .accessibilityIdentifier("sessions-open-pages")
                        .copyMenu([("Copy Label", "Open Sessions")])
                    }
                    if !model.endedSessions.isEmpty || model.sessionsHistoryNext != nil || model.sessionsHistoryPaged {
                        Divider().frame(height: 20)
                        let words = "Ended (\(model.endedSessions.count) on this page)"
                        Menu(words) {
                            Button("First history page") { Task { await model.firstSessionHistory() } }
                                .disabled(model.sessionsMetadataLoading || !model.sessionsHistoryPaged)
                            if model.sessionsHistoryNext != nil {
                                Button("Next history page") { Task { await model.nextSessionHistory() } }
                                    .disabled(model.sessionsMetadataLoading)
                            }
                            Divider()
                            ForEach(model.endedSessions.map { RoomSessionTab(room: room, session: $0) }) { item in
                                let session = item.session
                                Button(model.sessionTabLabel(session, includeName: true)) {
                                    model.showing = .session(node: session.nodeFingerprint, id: session.sessionId)
                                }.accessibilityIdentifier("session-\(session.shortId)")
                            }
                        }.accessibilityIdentifier("sessions-ended")
                            .copyMenu([("Copy Label", words)])
                    }
                }
                // Reserve the horizontal scroller inside the viewport so it cannot cover the tabs.
                .padding(.bottom, max(
                    NSScroller.scrollerWidth(for: .regular, scrollerStyle: .legacy),
                    NSScroller.scrollerWidth(for: .regular, scrollerStyle: .overlay)
                ))
            }.accessibilityIdentifier("room-session-tabs")
                // These words navigate. Inherited selection can install text-selection
                // overlays on their labels; right-click Copy preserves the displayed words.
                .textSelection(.disabled)
            if !model.roomTags.isEmpty || tagShown != nil {
                Menu {
                    Button("All messages") { model.showing = .general }
                    ForEach(model.roomTags, id: \.key) { tag in
                        Button(tag.label) { model.showing = .tag(key: tag.key, label: tag.label) }
                    }
                } label: { Label(tagShown ?? "Tags", systemImage: "tag") }
                .menuStyle(.borderlessButton).fixedSize()
                .accessibilityIdentifier("room-tag-filter")
                .textSelection(.disabled)
                .copyMenu([("Copy Label", tagShown ?? "Tags")])
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("room-tabs")
    }

    private var tagShown: String? {
        if case .tag(_, let label) = model.showing { return label }
        return nil
    }

    private func tab(_ words: String, _ showing: Showing, id: String) -> some View {
        let selected = model.showing == showing
        return Button { model.showing = showing } label: {
            Text(words).lineLimit(1).fixedSize()
                .selectionMark(selected).contentShape(Rectangle())
        }
        .buttonStyle(.plain).help(words)
        .accessibilityIdentifier(id).accessibilityLabel(words)
        .accessibilityAddTraits(selected ? .isSelected : [])
        .copyMenu([("Copy Label", words)])
    }
}

/// One entry of a Session, to a member with drive (CL-1, LY-5): a tool step folds to one line
/// with expandable Details. Replies, questions and approvals keep their full content visible,
/// with an open request's answers or its state once it is resolved or not answerable.
struct SessionEntryRow: View {
    @Environment(\.voxTextScale) private var scale
    @ObservedObject var model: NodeModel
    /// The room it was drawn in: its actions go there and to `session` only (D3).
    let room: String
    let session: FfiSession
    let entry: FfiSessionEntry
    /// Open a pulled copy with Quick Look.
    let look: (URL) -> Void
    @State private var details = false

    private var fullContent: Bool {
        ["reply", "question", "approval"].contains(entry.kind)
    }

    var body: some View {
        let reference = entry.request?.reference
        VStack(alignment: .leading, spacing: Space.s4 * scale) {
            // The line and its request's answers are the request's own element, inside the row:
            // the row is selected like a message (P14), the request as the one ⌥⌘Y and ⌥⌘N act
            // on (P1), and neither takes the other's place.
            VStack(alignment: .leading, spacing: Space.s4 * scale) {
                if entry.kind == "tool" {
                    HStack(alignment: .firstTextBaseline, spacing: Space.s8 * scale) {
                        summary.lineLimit(1)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        if !entry.details.isEmpty { detailsButton }
                    }
                } else {
                    summary
                }
                if fullContent && !entry.details.isEmpty {
                    // Approval Details are the tool's input; replies and questions are prose.
                    Text(entry.details).voxFont(entry.kind == "approval"
                        ? VoxTokens.Fonts.appMono : VoxTokens.Fonts.appText)
                        .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                        .accessibilityIdentifier("entry-content-\(entry.id)")
                }
                if let request = entry.request {
                    RequestView(model: model, room: room, session: session, request: request,
                                about: entry.line,
                                showsQuestionText: !(fullContent && !entry.details.isEmpty))
                }
            }
            // A request is selected by clicking it: what ⌥⌘Y and ⌥⌘N act on (P1).
            .modifier(RequestSelection(model: model, reference: reference))
            // A file the session sent, once this node has a verified copy (ADR-029 DR-1, F-11).
            if let file = entry.file, let pulled = file.pulledPath {
                HStack {
                    Button("Quick Look") { look(URL(fileURLWithPath: pulled)) }
                        .accessibilityIdentifier("quick-look-\(file.name)")
                    Button("Show in Finder") {
                        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: pulled)])
                    }
                }
            }
            if !fullContent && !entry.details.isEmpty {
                if entry.kind != "tool" { detailsButton }
                if details {
                    Text(entry.details).voxFont(VoxTokens.Fonts.appMono).secondaryText().textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("entry-details-text-\(entry.id)")
                }
            }
        }
        .voxPadding(.horizontal, Space.s4)
    }

    private var summary: some View {
        Text(entry.line).voxFont(fullContent ? VoxTokens.Fonts.appText : VoxTokens.Fonts.appMono)
            .textSelection(.enabled)
            .accessibilityIdentifier("entry-line-\(entry.id)")
    }

    private var detailsButton: some View {
        Button(details ? "Hide details" : "Details") { details.toggle() }
            .buttonStyle(.borderless).fixedSize()
            .accessibilityIdentifier("entry-details-\(entry.id)")
    }
}

/// A request's row marked while it is the one selected, and selected by a click (P1); any other
/// row as it is.
private struct RequestSelection: ViewModifier {
    @ObservedObject var model: NodeModel
    let reference: String?

    func body(content: Content) -> some View {
        if let reference {
            content.selectable(model.selectedRequest == reference) { model.selectedRequest = reference }
                .accessibilityIdentifier("request-row-\(reference)")
        } else {
            content
        }
    }
}

/// One bounded private page. This is never mounted in General or a room-wide member roster.
struct SessionAttentionView: View {
    @ObservedObject var model: NodeModel
    @State private var expanded = true

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: Space.s4) {
                if !model.sessionAttentionIsCurrent {
                    Text("Attention status unknown; waiting for the selected Session.").secondaryText().textSelection(.enabled)
                } else if let error = model.sessionAttentionError {
                    Text("Attention status unknown. \(error)").secondaryText().textSelection(.enabled)
                } else if let page = model.sessionAttention {
                    if page.preparing {
                        Text("Thread audience is still being checked").secondaryText().textSelection(.enabled)
                    } else if page.rows.isEmpty {
                        Text(page.next == nil ? "No observations on this page." : "No observations on this page; more pages are available.")
                            .secondaryText().textSelection(.enabled)
                    }
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: Space.s8) {
                            ForEach(page.rows, id: \.source) { row in
                                VStack(alignment: .leading, spacing: Space.s4) {
                                    Text("Message \(row.source.prefix(12)): \(model.sessionAttentionWords(row))")
                                        .textSelection(.enabled)
                                        .accessibilityIdentifier("session-attention-\(row.source)")
                                        .copyMenu([("Copy Message ID", row.source)])
                                    if let reason = row.reason, !reason.isEmpty {
                                        Text(reason).secondaryText().textSelection(.enabled)
                                    }
                                    if let answer = row.answer {
                                        Text("Answer \(answer.prefix(12))").secondaryText().textSelection(.enabled)
                                            .copyMenu([("Copy Answer ID", answer)])
                                    }
                                    Text("Observed \(Date(timeIntervalSince1970: Double(row.observedAtMs) / 1000).formatted(date: .abbreviated, time: .standard))")
                                        .secondaryText().textSelection(.enabled)
                                }.frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }.frame(maxHeight: Theme.scaled(180))
                } else {
                    Text("Checking attention status…").secondaryText().textSelection(.enabled)
                }
                HStack {
                    Button(model.sessionAttentionPaged ? "First attention page" : "Refresh attention") {
                        model.refreshSessionAttention()
                    }.accessibilityIdentifier("session-attention-refresh")
                    if model.sessionAttentionIsCurrent, model.sessionAttention?.next != nil {
                        Button("Next attention page") { model.nextSessionAttention() }
                            .accessibilityIdentifier("session-attention-next")
                    }
                    if model.sessionAttentionLoading { ProgressView().controlSize(.small) }
                }.disabled(model.sessionAttentionLoading)
                Text("Delivery does not promise a reply. These observations are private to members with drive access.")
                    .secondaryText().textSelection(.enabled)
            }
        } label: {
            Text("Room message attention").copyMenu([("Copy Label", "Room message attention")])
        }
        .textSelection(.disabled)
        .accessibilityIdentifier("session-attention")
    }
}
