// A room's Sessions (ADR-029 §8, CL-1 to CL-3): listed beside its conversation, above its
// members, in the TUI's words. General is the room's own conversation; All merges it with each
// Session's opening and end; a Session shows itself, its entries to a member with drive, and to
// one without only that it is there.

import AppKit
import SwiftUI

/// What the room's timeline shows (CL-2): its own conversation, that and every Session's opening
/// and end, or one Session, by its node and id.
enum Showing: Hashable {
    case general
    case all
    case session(node: String, id: String)
}

extension NodeModel {
    /// The room's open Sessions, newest opening first (CL-2).
    var openSessions: [FfiSession] {
        sessions.filter { $0.open }.sorted { $0.openedAtMs > $1.openedAtMs }
    }

    /// The room's ended Sessions, newest end first.
    var endedSessions: [FfiSession] {
        sessions.filter { !$0.open }.sorted { ($0.endedAtMs ?? 0) > ($1.endedAtMs ?? 0) }
    }

    /// Whether one Session is on screen, rather than the room's conversation or All.
    /// What needs the person, as the sidebar's NEEDS YOU counts it: its rooms and trust offers.
    var needsYouCount: Int { group(.needsYou).count + offers.count }

    /// A room's name as the sidebar says it, else its id's start.
    func roomName(_ room: String) -> String {
        rooms.first { $0.id == room }?.name ?? String(room.prefix(12))
    }

    /// The room header's facts: its members and its retention, always (R-7). What is shown is
    /// said once, by its tab (the decider, v0.4.3: a Session was named four times); an ended
    /// Session on screen is said to be one.
    var roomHeaderMeta: String {
        let people = members.count + 1
        let ended = shownSession.map { $0.open ? "" : " · Session ended" } ?? ""
        return "\(people == 1 ? "1 member" : "\(people) members") · ⏱ \(retention)\(ended)"
    }

    var showingSession: Bool {
        if case .session = showing { return true }
        return false
    }

    /// The Session on screen, if one is and the room still lists it.
    var shownSession: FfiSession? {
        guard case let .session(node, id) = showing else { return nil }
        return sessions.first { $0.nodeFingerprint == node && $0.sessionId == id }
    }

    /// Another node's Session's header, with drive or without (ADR-029 MD-3, as the TUI says it):
    /// its name and id are that node's claim. None for this node's own Sessions (their node's
    /// alias is empty): the claim is this node's own.
    var sessionHeader: String? {
        guard let s = shownSession, !s.nodeAlias.isEmpty else { return nil }
        return "\(s.label) — name and id as \(s.nodeAlias) says"
    }
}

/// The room's Sessions as tabs across the top of its conversation (CL-2, the decider v0.4.3):
/// General first, then All, then one tab per open Session by its title, a dot on one waiting on
/// this node; the ended ones under "Ended (N)" at the end, folded until opened. ⌘⇧[ and ⌘⇧] move
/// between them.
struct SessionTabs: View {
    @ObservedObject var model: NodeModel
    @State private var endedOpen = false

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: Space.s4) {
                tab("General", .general, id: "session-general")
                tab("All", .all, id: "session-all")
                ForEach(model.openSessions, id: \.self) { s in
                    tab(s.title, .session(node: s.nodeFingerprint, id: s.sessionId),
                        id: "session-\(s.shortId)", waiting: s.pending > 0)
                }
                let ended = model.endedSessions
                if !ended.isEmpty {
                    Button { endedOpen.toggle() } label: {
                        Label("Ended (\(ended.count))", systemImage: endedOpen ? "chevron.down" : "chevron.right")
                            .secondaryLine()
                            .padding(.horizontal, Space.s8).padding(.vertical, Space.s4)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityIdentifier("sessions-ended")
                    .accessibilityValue(endedOpen ? "expanded" : "collapsed")
                    // An ended Session on screen keeps its tab while the others are folded.
                    ForEach(ended.filter { endedOpen || model.showing == .session(node: $0.nodeFingerprint, id: $0.sessionId) },
                            id: \.self) { s in
                        tab(s.title, .session(node: s.nodeFingerprint, id: s.sessionId),
                            id: "session-\(s.shortId)", ended: true)
                    }
                }
            }
            .padding(.horizontal, Space.s8)
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("sessions")
    }

    private func tab(_ title: String, _ showing: Showing, id: String, waiting: Bool = false,
                     ended: Bool = false) -> some View {
        let on = model.showing == showing
        let spoken = waiting ? "\(title), waiting on you" : ended ? "\(title), ended" : title
        return Button { model.showing = showing } label: {
            HStack(spacing: Space.s4) {
                if waiting {
                    Circle().fill(VoxTokens.Colors.attention).frame(width: 6, height: 6)
                        .accessibilityHidden(true)
                }
                Text(title).lineLimit(1).truncationMode(.middle)
                    .fontWeight(on ? .semibold : .regular)
                    .foregroundStyle(on || !ended ? VoxTokens.Colors.textPrimary : VoxTokens.Colors.textSecondary)
            }
            .frame(maxWidth: 220)
            .padding(.horizontal, Space.s8).padding(.vertical, Space.s4)
            // The tab on screen is underlined in the accent (L-3).
            .overlay(alignment: .bottom) {
                Rectangle().fill(on ? VoxTokens.Colors.accent : .clear).frame(height: 2)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(spoken)
        .accessibilityIdentifier(id)
        .accessibilityLabel(spoken)
        .accessibilityAddTraits(on ? .isSelected : [])
    }
}

extension NodeModel {
    /// The tabs in their order, as SessionTabs draws them with Ended open: what ⌘⇧[ and ⌘⇧] step
    /// through.
    var tabOrder: [Showing] {
        [.general, .all] + (openSessions + endedSessions).map { .session(node: $0.nodeFingerprint, id: $0.sessionId) }
    }

    /// The tab `by` places from the one on screen, stopping at either end (⌘⇧[ is -1, ⌘⇧] +1).
    func stepTab(_ by: Int) {
        let order = tabOrder
        guard let at = order.firstIndex(of: showing) else { return showing = .general }
        showing = order[max(0, min(order.count - 1, at + by))]
    }
}

/// One entry of a Session, to a member with drive (CL-1): its one line, word for word as `vox room
/// session` prints it, and its Details (the full input and output) when asked; an open request's
/// answers (SessionDrive.swift), or its state once it is resolved or not answerable.
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
    /// The pointer is over the row: its Details appears then, or while it is selected.
    @State private var hovering = false

    var body: some View {
        if entry.kind == "turn-end" {
            // The end of a turn is space and a hairline, not words (the decider, v0.4.3).
            Hairline()
                .voxPadding(.vertical, Space.s8)
                .accessibilityElement()
                .accessibilityLabel("turn ended")
                .accessibilityIdentifier("entry-line-\(entry.id)")
        } else {
            row
        }
    }

    /// What a person reads: what was typed and the replies in the text face, a line's words
    /// otherwise; monospace only in Details, for code and tool output (v0.4.3).
    @ViewBuilder private var said: some View {
        switch entry.kind {
        case "user":
            VStack(alignment: .leading, spacing: Space.s4 * scale) {
                Text("typed at the terminal").secondaryLine()
                Text(entry.said).textSelection(.enabled)
                    .accessibilityIdentifier("entry-said-\(entry.id)")
            }
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("entry-line-\(entry.id)")
        case "reply":
            VStack(alignment: .leading, spacing: 0) {
                Text(entry.said).textSelection(.enabled)
                    .accessibilityIdentifier("entry-said-\(entry.id)")
            }
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("entry-line-\(entry.id)")
        default:
            Text(entry.line).textSelection(.enabled)
                .accessibilityIdentifier("entry-line-\(entry.id)")
        }
    }

    private var row: some View {
        let reference = entry.request?.reference
        let selected = model.selectedMessages.contains("entry-\(entry.id)")
        return VStack(alignment: .leading, spacing: Space.s4 * scale) {
            // The line and its request's answers are the request's own element, inside the row:
            // the row is selected like a message (P14), the request as the one ⌥⌘Y and ⌥⌘N act
            // on (P1), and neither takes the other's place.
            VStack(alignment: .leading, spacing: Space.s4 * scale) {
                said
                if let request = entry.request {
                    RequestView(model: model, room: room, session: session, request: request,
                                about: entry.line)
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
            // A small disclosure, there while the row is pointed at or selected, or open.
            if !entry.details.isEmpty && (hovering || selected || details) {
                Button { details.toggle() } label: {
                    Label(details ? "Hide details" : "Details",
                          systemImage: details ? "chevron.down" : "chevron.right")
                }
                .buttonStyle(.plain)
                .secondaryLine()
                .accessibilityIdentifier("entry-details-\(entry.id)")
                if details {
                    Text(entry.details).voxFont(VoxTokens.Fonts.appMono).secondaryText().textSelection(.enabled)
                        .accessibilityIdentifier("entry-details-text-\(entry.id)")
                }
            }
        }
        .voxPadding(.horizontal, Space.s4)
        .onHover { hovering = $0 }
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
