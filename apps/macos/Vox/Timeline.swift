// The room's timeline as drawn: its messages, and among them, by time, what was done to the room
// (its retention set, its name changed), in the TUI's words (ADR-028 R-1, R-7); under a title
// that says the room's retention.

import SwiftUI

/// One line of the timeline: a message, or a line about the room among the messages, by time.
struct TimelineItem: Identifiable {
    let id: String
    let millis: UInt64
    let message: RoomMessage?
    let notice: String?

    static func message(_ m: RoomMessage) -> TimelineItem {
        TimelineItem(id: m.id, millis: m.createdMillis, message: m, notice: nil)
    }

    static func notice(_ id: String, _ text: String, at millis: UInt64) -> TimelineItem {
        TimelineItem(id: id, millis: millis, message: nil, notice: text)
    }
}

extension NodeModel {
    /// The timeline's title: the room's retention (ADR-028 R-7), as the TUI's says it.
    var timelineTitle: String {
        "Timeline · ⏱ \(retention)"
    }

    /// The room's messages and what was done to it, in the room's order: each notice right after
    /// the message the node says it follows (its time claims seconds only, so by time it could
    /// draw above a message sent earlier in the same second); one that follows a message not
    /// shown here, by time.
    var timelineItems: [TimelineItem] {
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
            let at = items.firstIndex { $0.millis > n.createdMillis } ?? items.count
            items.insert(item(n), at: at)
        }
        return items
    }

    /// "<who> <what>", who named as the TUI names them: you, the alias, or the fingerprint's first
    /// 26 characters marked "(not in keyring)".
    func noticeWords(_ n: RoomNoticeRow) -> String {
        let who = n.author == me ? "you"
            : n.authorName.isEmpty ? "\(n.author.prefix(26)) (not in keyring)" : n.authorName
        return "\(who) \(n.what)"
    }
}
