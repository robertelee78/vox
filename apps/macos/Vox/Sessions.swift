// A room's Sessions (ADR-029 §8, CL-1 to CL-3): listed beside its conversation, above its
// members, in the TUI's words. General is the room's own conversation; All merges it with each
// Session's opening and end; a Session shows itself, its entries to a member with drive, and to
// one without only that it is there.

import AppKit
import SwiftUI

/// What the room's timeline shows (CL-2): its own conversation, that and every Session's opening
/// and end, or one Session, by its node and id.
enum Showing: Equatable {
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

    /// The room header's facts: members, what is shown, and the retention, always (R-7).
    var roomHeaderMeta: String {
        let people = members.count + 1
        let shown: String
        switch showing {
        case .general: shown = "General"
        case .all: shown = "All"
        case .session: shown = shownSession?.label ?? "a Session"
        }
        return "\(people == 1 ? "1 member" : "\(people) members") · \(shown) · ⏱ \(retention)"
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

/// The room's Sessions, above its members (CL-2): General, All, the open Sessions (one waiting on
/// this node marked "!", CL-2), and the ended ones under "Ended (N)", folded until opened.
struct SessionsList: View {
    @ObservedObject var model: NodeModel
    @State private var endedOpen = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("SESSIONS").eyebrow().secondaryText()
                .accessibilityAddTraits(.isHeader)
            row("General", .general, id: "session-general")
            row("All", .all, id: "session-all")
            ForEach(model.openSessions, id: \.self) { s in
                row(s.pending > 0 ? "! \(s.label) · waiting on you" : "● \(s.label)",
                    .session(node: s.nodeFingerprint, id: s.sessionId), id: "session-\(s.shortId)")
            }
            let ended = model.endedSessions
            if !ended.isEmpty {
                Button { endedOpen.toggle() } label: {
                    Label("Ended (\(ended.count))", systemImage: endedOpen ? "chevron.down" : "chevron.right")
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("sessions-ended")
                .accessibilityValue(endedOpen ? "expanded" : "collapsed")
                if endedOpen {
                    ForEach(ended, id: \.self) { s in
                        row("\(s.label) · ended", .session(node: s.nodeFingerprint, id: s.sessionId),
                            id: "session-\(s.shortId)")
                    }
                }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("sessions")
    }

    private func row(_ words: String, _ showing: Showing, id: String) -> some View {
        let on = model.showing == showing
        return Button { model.showing = showing } label: {
            // Two lines, not cut: a label's middle is the Session's name.
            Text(words).lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .selectionMark(on)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(words)
        .accessibilityIdentifier(id)
        .accessibilityLabel(words)
        .accessibilityAddTraits(on ? .isSelected : [])
    }
}

/// One entry of a Session, to a member with drive (CL-1): its one line, word for word as `vox room
/// session` prints it, and its Details (the full input and output) when asked; an open request's
/// answers (SessionDrive.swift), or its state once it is resolved or not answerable.
struct SessionEntryRow: View {
    @ObservedObject var model: NodeModel
    let session: FfiSession
    let entry: FfiSessionEntry
    /// Open a pulled copy with Quick Look.
    let look: (URL) -> Void
    @State private var details = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(entry.line).font(Theme.mono).textSelection(.enabled)
                .accessibilityIdentifier("entry-line-\(entry.id)")
            if let request = entry.request {
                RequestView(model: model, session: session, request: request, about: entry.line)
            }
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
            if !entry.details.isEmpty {
                Button(details ? "Hide details" : "Details") { details.toggle() }
                    .buttonStyle(.borderless)
                    .accessibilityIdentifier("entry-details-\(entry.id)")
                if details {
                    Text(entry.details).font(Theme.mono).secondaryText().textSelection(.enabled)
                        .accessibilityIdentifier("entry-details-text-\(entry.id)")
                }
            }
        }
        .padding(.horizontal, 4)
    }
}
