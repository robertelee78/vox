// Menus, keys and the command palette (ADR-014 M-19–M-21): every action is listed once, here,
// and the menus, the M-20 keys and the palette (⌘K) all come from that one list.

import AppKit
import SwiftUI

/// A sheet a menu, key or palette action opens.
enum NodeSheet: String, Identifiable {
    case palette, newRoom, joinRoom, fingerprint, retention, admins, leave, end
    var id: String { rawValue }
}

/// One action: where it lives in the menus, its key (M-20), whether it can act now, and what it
/// does.
struct VoxAction: Identifiable {
    let menu: String
    let title: String
    let key: KeyEquivalent?
    let modifiers: EventModifiers
    let enabled: Bool
    let run: @MainActor () -> Void
    var id: String { "\(menu)/\(title)" }

    init(_ menu: String, _ title: String, _ key: KeyEquivalent? = nil,
         _ modifiers: EventModifiers = .command, enabled: Bool = true,
         run: @escaping @MainActor () -> Void) {
        (self.menu, self.title, self.key, self.modifiers, self.enabled, self.run) =
            (menu, title, key, modifiers, enabled, run)
    }
}

extension NodeModel {
    /// Every action, in menu order (M-21), with the M-20 keys.
    func actions() -> [VoxAction] { VoxAction.all(self) }
}

extension VoxAction {
    /// Every action, in menu order (M-21), with the M-20 keys: of `node`, or, before a node is
    /// attached, each listed and none enabled. The menus are never empty: SwiftUI leaves out a
    /// menu that is empty when the app opens and does not bring it back later, and the File menu
    /// went missing that way.
    @MainActor static func all(_ node: NodeModel?) -> [VoxAction] {
        let live = node != nil
        let inRoom = node?.roomOnScreen != nil
        let digits: [VoxAction] = (1...9).map { n in
            VoxAction("View", "Room \(n)", KeyEquivalent(Character("\(n)")), enabled: live) {
                Task { await node?.showRoom(at: n) }
            }
        }
        return [
            VoxAction("File", "New Room…", "n", enabled: live) { node?.sheet = .newRoom },
            VoxAction("File", "Join Room…", "j", [.command, .shift], enabled: live) {
                node?.sheet = .joinRoom
            },
            VoxAction("File", "Attach File…", "o", enabled: inRoom) { node?.attachAsked += 1 },
            VoxAction("Room", "Copy Room Link", "l", enabled: inRoom) {
                Task { await node?.copyRoomLink() }
            },
            VoxAction("Room", "Retention…", enabled: inRoom) { node?.sheet = .retention },
            VoxAction("Room", "Admins…", enabled: inRoom) { node?.sheet = .admins },
            VoxAction("Room", "Reply to Selected Message", "r",
                      enabled: inRoom && node?.selectedMessage != nil) {
                node?.replyTo = node?.messages.first { $0.id == node?.selectedMessage }
            },
            VoxAction("Room", "Send Urgent", .return, enabled: inRoom) { node?.urgentAsked += 1 },
            VoxAction("Room", "Copy Selected Service's Command", "c", [.command, .shift],
                      enabled: node?.selectedService != nil) { node?.copyServiceCommand() },
            VoxAction("Room", "Next Room That Needs You", "j", enabled: live) {
                Task { await node?.nextNeedingYou() }
            },
            VoxAction("Room", "Leave…", enabled: inRoom) { node?.sheet = .leave },
            VoxAction("Room", "End for Everyone…", enabled: inRoom) { node?.sheet = .end },
            VoxAction("Node", "Show Fingerprint", "i", enabled: live) { node?.sheet = .fingerprint },
            VoxAction("Keyring", "Add…", enabled: live) { Task { await node?.show(.keyring) } },
            VoxAction("Keyring", "Compare…", enabled: live) { Task { await node?.show(.keyring) } },
            VoxAction("Keyring", "Rename…", enabled: live) { Task { await node?.show(.keyring) } },
            VoxAction("Keyring", "Remove…", enabled: live) { Task { await node?.show(.keyring) } },
            VoxAction("View", "Command Palette", "k", enabled: live) { node?.sheet = .palette },
            VoxAction("View", "Room", enabled: inRoom) { node?.showLanes = false },
            VoxAction("View", "Lanes", "l", [.command, .shift],
                      enabled: inRoom && node?.roomHasAgents == true) {
                node?.showLanes = true
            },
            VoxAction("View", "Keyring", "k", [.command, .shift], enabled: live) {
                Task { await node?.show(.keyring) }
            },
            VoxAction("View", "Decision Record", "d", [.command, .shift], enabled: live) {
                Task { await node?.show(.decisions) }
            },
        ] + digits
    }
}

/// The menu bar's menus (M-21), from the one action list.
struct VoxCommands: Commands {
    @ObservedObject var app: AppModel

    var body: some Commands {
        CommandGroup(replacing: .newItem) { items("File") }
        CommandMenu("Room") { items("Room") }
        CommandMenu("Node") {
            Button("Attach…") { Task { await app.start() } }
                .disabled(app.node != nil)
            Button("Detach") { Task { await app.detachNode() } }
                .disabled(app.node == nil)
            items("Node")
        }
        CommandMenu("Keyring") { items("Keyring") }
        CommandGroup(before: .toolbar) { items("View") }
    }

    @ViewBuilder
    private func items(_ menu: String) -> some View {
        if let node = app.node {
            NodeMenuItems(node: node, menu: menu)
        } else {
            MenuItems(actions: VoxAction.all(nil), menu: menu)
        }
    }
}

/// A menu's items of an attached node, kept current as the node changes (a room shown, a message
/// selected).
private struct NodeMenuItems: View {
    @ObservedObject var node: NodeModel
    let menu: String

    var body: some View { MenuItems(actions: node.actions(), menu: menu) }
}

private struct MenuItems: View {
    let actions: [VoxAction]
    let menu: String

    var body: some View {
        ForEach(actions.filter { $0.menu == menu }) { action in
            let button = Button(action.title) { action.run() }.disabled(!action.enabled)
            if let key = action.key {
                button.keyboardShortcut(key, modifiers: action.modifiers)
            } else {
                button
            }
        }
    }
}

/// The command palette (⌘K, M-19): every action, found by typing.
struct Palette: View {
    @ObservedObject var model: NodeModel
    @State private var query = ""

    private var found: [VoxAction] {
        let all = model.actions().filter(\.enabled)
        guard !query.isEmpty else { return all }
        return all.filter { "\($0.menu) \($0.title)".localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField("Type a command", text: $query)
                .onSubmit { if let first = found.first { done(first) } }
                .accessibilityIdentifier("palette-query")
            ScrollView {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(found) { action in
                        Button { done(action) } label: {
                            HStack {
                                Text(action.title)
                                Spacer()
                                Text(action.menu).font(Theme.eyebrow).secondaryText()
                            }
                        }
                        .buttonStyle(.plain)
                        .accessibilityIdentifier("palette-\(action.title)")
                    }
                }
            }
            .frame(height: 280)
        }
        .padding(16)
        .frame(width: 420)
    }

    private func done(_ action: VoxAction) {
        model.sheet = nil
        DispatchQueue.main.async { action.run() }
    }
}

/// The sheets the actions open.
struct NodeSheets: View {
    @ObservedObject var model: NodeModel
    let sheet: NodeSheet

    var body: some View {
        switch sheet {
        case .palette: Palette(model: model)
        case .newRoom: RoomForm(model: model, joining: false)
        case .joinRoom: RoomForm(model: model, joining: true)
        case .fingerprint: FingerprintSheet(model: model)
        case .retention: RetentionSheet(model: model)
        case .admins: AdminsSheet(model: model)
        case .leave: LeaveSheet(model: model, ending: false)
        case .end: LeaveSheet(model: model, ending: true)
        }
    }
}

/// New Room, with the name every member sees, or Join Room with its link; and its passphrase. A
/// joined room keeps the name its members gave it (ADR-028 R-1).
private struct RoomForm: View {
    @ObservedObject var model: NodeModel
    let joining: Bool
    @State private var link = ""
    @State private var name = ""
    @State private var field = SecureFieldHolder()

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(joining ? "Join a room" : "New room").font(Theme.heading)
            if joining {
                TextField("Room link (vox://…)", text: $link).font(Theme.mono)
            } else {
                TextField("Its name, as every member sees it", text: $name)
                    .accessibilityIdentifier("room-form-name")
            }
            Text(joining ? "The room's passphrase, sent to you another way than its link."
                : "A passphrase for the room: send it another way than its link.").secondaryText()
            SecureInput(holder: field) { submit() }.frame(width: 320)
                .accessibilityIdentifier("room-form-passphrase")
            if let said = model.said { StateMark(kind: .danger, words: said).textSelection(.enabled) }
            HStack {
                Button("Cancel") { model.sheet = nil }.keyboardShortcut(.cancelAction)
                Button(joining ? "Join" : "Create") { submit() }.keyboardShortcut(.defaultAction)
                    .disabled(joining ? link.isEmpty : name.isEmpty)
                    .accessibilityIdentifier("room-form-submit")
            }
        }
        .padding(24)
        .frame(width: 440)
    }

    private func submit() {
        let bytes = field.take()
        let (l, n) = (link, name)
        Task {
            let ok = joining ? await model.joinRoom(l, passphrase: bytes)
                : await model.createRoom(n, passphrase: bytes)
            if ok { model.sheet = nil }
        }
    }
}

/// This node's fingerprint, grouped with its art (K-1).
private struct FingerprintSheet: View {
    @ObservedObject var model: NodeModel

    var body: some View {
        let card = fingerprintCard(fingerprint: model.me)
        VStack(alignment: .leading, spacing: 12) {
            Text("Node \(model.node)").font(Theme.heading)
            VStack(spacing: 0) {
                ForEach(Array(card.art.enumerated()), id: \.offset) { Text($0.element) }
            }
            .font(Theme.mono)
            .accessibilityHidden(true)
            Text(card.grouped).font(Theme.mono).textSelection(.enabled)
                .accessibilityIdentifier("my-fingerprint")
            HStack {
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(model.me, forType: .string)
                }
                Button("Done") { model.sheet = nil }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
    }
}

/// How long a room keeps messages, in words.
enum Retention {
    static let choices: [(String, UInt64)] = [
        ("1 day", 86_400), ("7 days", 7 * 86_400), ("30 days", 30 * 86_400),
        ("1 year", 365 * 86_400), ("forever", 0),
    ]

    static func words(_ seconds: UInt64) -> String {
        choices.first { $0.1 == seconds }?.0 ?? "\(seconds) seconds"
    }
}

/// Retention, saying what it does before it is set (E-5); the identity passphrase always.
private struct RetentionSheet: View {
    @ObservedObject var model: NodeModel
    @State private var seconds: UInt64 = 30 * 86_400
    @State private var field = SecureFieldHolder()

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Retention").font(Theme.heading)
            Picker("Keep messages", selection: $seconds) {
                ForEach(Retention.choices, id: \.1) { Text($0.0).tag($0.1) }
            }
            Text(seconds == 0 ? "Every member keeps every message's text for good."
                : "Every member deletes a message's text \(Retention.words(seconds)) after it was "
                    + "sent, and older ones at once. Deleted text cannot be read again.")
                .secondaryText()
            Text("Your identity passphrase:").secondaryText()
            SecureInput(holder: field) { submit() }.frame(width: 320)
            if let said = model.said { StateMark(kind: .danger, words: said).textSelection(.enabled) }
            HStack {
                Button("Cancel") { model.sheet = nil }.keyboardShortcut(.cancelAction)
                Button("Set") { submit() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 440)
    }

    private func submit() {
        let bytes = field.take()
        let s = seconds
        Task { if await model.setRetention(s, passphrase: bytes) { model.sheet = nil } }
    }
}

/// The room's admins: its creator first, then those it made admins.
private struct AdminsSheet: View {
    @ObservedObject var model: NodeModel
    @State private var admins: [String] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Admins").font(Theme.heading)
            Text("An admin may end the room and set its retention.").secondaryText()
            ForEach(model.members) { member in
                Toggle(isOn: Binding(get: { admins.contains(member.id) }, set: { on in
                    Task {
                        await model.setAdmin(member.id, on)
                        admins = await model.admins()
                    }
                })) {
                    TrustMark(name: member.name, trust: member.trust)
                }
                .disabled(admins.first == member.id)
            }
            if let said = model.said { StateMark(kind: .danger, words: said).textSelection(.enabled) }
            Button("Done") { model.sheet = nil }.keyboardShortcut(.defaultAction)
        }
        .padding(24)
        .frame(width: 440)
        .task { admins = await model.admins() }
    }
}

/// Leave, or End for Everyone, each saying what it does first (E-5).
private struct LeaveSheet: View {
    @ObservedObject var model: NodeModel
    let ending: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(ending ? "End this room for everyone?" : "Leave this room?").font(Theme.heading)
            Text(ending
                ? "Every member's copy of the room is deleted, and no one can post in it again. "
                    + "Only its creator or an admin can do this."
                : "This node stops reading and posting here, and the room is deleted here. "
                    + "The others go on; to come back you need its link and passphrase again.")
            if let said = model.said { StateMark(kind: .danger, words: said).textSelection(.enabled) }
            HStack {
                Button("Cancel") { model.sheet = nil }.keyboardShortcut(.cancelAction)
                Button(ending ? "End for Everyone" : "Leave", role: .destructive) {
                    Task {
                        await model.leaveRoom(endingIt: ending)
                        model.sheet = nil
                    }
                }
            }
        }
        .padding(24)
        .frame(width: 440)
    }
}
