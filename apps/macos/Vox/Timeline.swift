// The room's timeline as drawn (ADR-029 CL-2): for General, its messages and, among them by time,
// what was done to the room (its retention set, its name changed, ADR-028 R-1, R-7); for All,
// those and each Session's opening and end; for one Session, its opening and end and, to a member
// with drive, its entries. A Session's activity is never the room's (SC-4). Under a title that
// says what is shown and the room's retention, in the TUI's words.

import SwiftUI

/// One line of the timeline: a message, a line about the room or a Session among the messages, or
/// a Session's entry, by time.
struct TimelineItem: Identifiable {
    let id: String
    let millis: UInt64
    let message: RoomMessage?
    let notice: String?
    let entry: FfiSessionEntry?

    static func message(_ m: RoomMessage) -> TimelineItem {
        TimelineItem(id: m.id, millis: m.createdMillis, message: m, notice: nil, entry: nil)
    }

    static func notice(_ id: String, _ text: String, at millis: UInt64) -> TimelineItem {
        TimelineItem(id: id, millis: millis, message: nil, notice: text, entry: nil)
    }

    static func entry(_ e: FfiSessionEntry) -> TimelineItem {
        TimelineItem(id: "entry-\(e.id)", millis: e.atMs, message: nil, notice: nil, entry: e)
    }

    /// "<label> opened" and, once it ended, "<label> ended".
    static func openedAndEnded(_ s: FfiSession) -> [TimelineItem] {
        var lines = [notice("opened-\(s.nodeFingerprint)-\(s.sessionId)", "\(s.label) opened",
                            at: s.openedAtMs)]
        if let ended = s.endedAtMs {
            lines.append(notice("ended-\(s.nodeFingerprint)-\(s.sessionId)", "\(s.label) ended",
                                at: ended))
        }
        return lines
    }
}

extension NodeModel {
    /// The timeline's title (CL-2): what is shown, and the room's retention (ADR-028 R-7).
    var timelineTitle: String {
        let shown: String
        switch showing {
        case .general: shown = ""
        case .all: shown = " — All"
        case .session:
            if let s = shownSession {
                shown = " — \(s.label)\(s.open ? " · open" : " · ended")"
            } else {
                shown = " — a Session this room no longer lists"
            }
        }
        return "Timeline\(shown) · ⏱ \(retention)"
    }

    /// What the timeline draws, by time.
    var timelineItems: [TimelineItem] {
        let room = messages.map(TimelineItem.message)
            + notices.map { .notice("notice-\($0.id)", noticeWords($0), at: $0.createdMillis) }
        switch showing {
        case .general:
            return room.sorted { $0.millis < $1.millis }
        case .all:
            return (room + sessions.flatMap(TimelineItem.openedAndEnded))
                .sorted { $0.millis < $1.millis }
        case .session:
            guard let s = shownSession else { return [] }
            var lines = TimelineItem.openedAndEnded(s)
            if s.canDrive {
                lines += sessionEntries.map(TimelineItem.entry)
                lines.sort { $0.millis < $1.millis }
                if let note = sessionNote {
                    lines.append(.notice("note-\(s.sessionId)", note, at: .max))
                }
            } else {
                lines.append(.notice("no-drive-\(s.sessionId)",
                                     "Only members \(s.nodeAlias) trusts with drive see inside this Session.",
                                     at: .max))
            }
            return lines
        }
    }

    /// "<who> <what>", who named as the TUI names them: you, the alias, or the fingerprint's first
    /// 26 characters marked "(not in keyring)".
    func noticeWords(_ n: RoomNoticeRow) -> String {
        let who = n.author == me ? "you"
            : n.authorName.isEmpty ? "\(n.author.prefix(26)) (not in keyring)" : n.authorName
        return "\(who) \(n.what)"
    }
}
