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

    /// The room's messages and what was done to it, by time.
    var timelineItems: [TimelineItem] {
        (messages.map(TimelineItem.message)
            + notices.map { .notice("notice-\($0.id)", noticeWords($0), at: $0.createdMillis) })
            .sorted { $0.millis < $1.millis }
    }

    /// "<who> <what>", who named as the TUI names them: you, the alias, or the fingerprint's first
    /// 26 characters marked "(not in keyring)".
    func noticeWords(_ n: RoomNoticeRow) -> String {
        let who = n.author == me ? "you"
            : n.authorName.isEmpty ? "\(n.author.prefix(26)) (not in keyring)" : n.authorName
        return "\(who) \(n.what)"
    }
}
