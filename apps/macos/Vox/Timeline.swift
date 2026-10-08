// The room's timeline as drawn (ADR-029 CL-2): for General, its messages and, among them in the room's order,
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
    /// The timeline's title (CL-2): what is shown, and for the room's own lines (General, All) its
    /// retention (ADR-028 R-7).
    var timelineTitle: String {
        switch showing {
        case .general: return "Timeline · ⏱ \(retention)"
        case .all: return "Timeline — All · ⏱ \(retention)"
        // A Session's title has no retention: it is the room's (as the TUI says it).
        case .session:
            guard let s = shownSession else { return "Timeline — a Session this room no longer lists" }
            return "Timeline — \(s.label)\(s.open ? " · open" : " · ended")"
        }
    }

    /// The room's messages and what was done to it, in the room's order: each notice right after
    /// the message the node says it follows (the tie-break for the same millisecond); one that
    /// follows a message not shown here, by time.
    var roomItems: [TimelineItem] {
        let shown = Set(messages.map(\.id))
        let item = { (n: RoomNoticeRow) in
            TimelineItem.notice("notice-\(n.id)", self.noticeWords(n), at: n.createdMillis)
        }
        let placed = notices.filter { $0.after.isEmpty || shown.contains($0.after) }
        var items = placed.filter { $0.after.isEmpty }.map(item)
        for m in messages {
            items.append(.message(m))
            items += placed.filter { $0.after == m.id }.map(item)
        }
        for n in notices where !n.after.isEmpty && !shown.contains(n.after) {
            items.insert(item(n), at: items.firstIndex { $0.millis > n.createdMillis } ?? items.count)
        }
        return items
    }

    /// What the timeline draws.
    var timelineItems: [TimelineItem] {
        switch showing {
        case .general:
            return roomItems
        case .all:
            // Each Session's opening and end among the room's lines, by time.
            var items = roomItems
            for line in sessions.flatMap(TimelineItem.openedAndEnded) {
                items.insert(line, at: items.firstIndex { $0.millis > line.millis } ?? items.count)
            }
            return items
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
