// Notifications (ADR-014 M-23, ADR-028 R-10): local only, one per message that arrives in a room
// the person is not looking at, grouped by room, and never with the message's text — who wrote, to
// whom and whether it is urgent, nothing of what it says. There is no remote push.

import AppKit
import UserNotifications

@MainActor
final class Notifier: NSObject, UNUserNotificationCenterDelegate {
    /// Opens the room a notification is about.
    var open: ((String) -> Void)?
    /// Opens a Session's waiting request a notification is about: room, node, session, reference.
    var openRequest: ((String, String, String, String) -> Void)?
    /// Told whether Vox may notify, once macOS says: the status bar says when it may not.
    var allowed: ((Bool) -> Void)?
    private var asked = false

    /// Ask once whether Vox may notify; macOS asks the person.
    func ask() {
        guard !asked else { return }
        asked = true
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound]) { [weak self] granted, _ in
            Task { @MainActor in self?.allowed?(granted) }
        }
    }

    /// One notification for `message` in `room`, named `roomName`: who wrote, whether to this node,
    /// whether urgent, grouped under the room (R-10). The text stays in Vox.
    func post(_ message: RoomMessage, room: String, roomName: String, me: String) {
        let content = UNMutableNotificationContent()
        content.title = roomName
        let who = message.authorName.isEmpty ? String(message.author.prefix(12)) : message.authorName
        content.body = Notifier.body(who: who, toYou: message.to.contains(me),
                                     urgent: message.urgent, file: message.file != nil)
        content.threadIdentifier = room
        content.userInfo = ["room": room]
        content.sound = message.urgent && message.to.contains(me) ? .default : nil
        let request = UNNotificationRequest(identifier: message.id, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request) { _ in }
    }

    /// One notification for a Session waiting on this node (P1), replacing that Session's earlier
    /// one: which Session, never what it asks (R-10). Clicking it opens that request.
    func postWaiting(room: String, roomName: String, node: String, session: String,
                     reference: String, label: String) {
        let content = UNMutableNotificationContent()
        content.title = roomName
        content.body = "\(label) is waiting on you"
        content.threadIdentifier = room
        content.userInfo = ["room": room, "node": node, "session": session, "reference": reference]
        content.sound = .default
        let request = UNNotificationRequest(identifier: Notifier.waitingID("\(room)/\(node)/\(session)"),
                                            content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request) { _ in }
    }

    /// A Session no longer waiting: its notification goes.
    func withdrawWaiting(sessionKey: String) {
        let id = Notifier.waitingID(sessionKey)
        UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: [id])
        UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: [id])
    }

    nonisolated static func waitingID(_ sessionKey: String) -> String { "waiting-\(sessionKey)" }

    /// One notification for a directory with no room (ADR-029 RB-5): which harness, which
    /// directory. Clicking it brings Vox forward, where the ask is a banner across the window.
    func postRoomAsk(dir: String, sentence: String) {
        let content = UNMutableNotificationContent()
        content.title = "Which room is this repo in?"
        content.body = sentence
        content.userInfo = ["ask": dir]
        content.sound = .default
        let request = UNNotificationRequest(identifier: Notifier.roomAskID(dir), content: content,
                                            trigger: nil)
        UNUserNotificationCenter.current().add(request) { _ in }
    }

    /// A directory answered, or no longer asked about: its notification goes.
    func withdrawRoomAsk(dir: String) {
        let id = Notifier.roomAskID(dir)
        UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: [id])
        UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: [id])
    }

    nonisolated static func roomAskID(_ dir: String) -> String { "room-ask-\(dir)" }

    /// What a notification says: never the message's text.
    nonisolated static func body(who: String, toYou: Bool, urgent: Bool, file: Bool) -> String {
        let what = file ? "shared a file" : "wrote"
        switch (toYou, urgent) {
        case (true, true): return "\(who) \(what) to you, urgent"
        case (true, false): return "\(who) \(what) to you"
        case (false, _): return "\(who) \(what)"
        }
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            didReceive response: UNNotificationResponse,
                                            withCompletionHandler done: @escaping () -> Void) {
        let info = response.notification.request.content.userInfo
        let room = info["room"] as? String
        let node = info["node"] as? String
        let session = info["session"] as? String
        let reference = info["reference"] as? String
        Task { @MainActor in
            if let room, let node, let session, let reference {
                self.openRequest?(room, node, session, reference)
            } else if let room {
                self.open?(room)
            }
            NSApp.activate(ignoringOtherApps: true)
            done()
        }
    }

    /// Shown even while Vox is in front, for a room other than the one on screen.
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            willPresent notification: UNNotification,
                                            withCompletionHandler done:
                                            @escaping (UNNotificationPresentationOptions) -> Void) {
        done([.banner, .list])
    }
}
