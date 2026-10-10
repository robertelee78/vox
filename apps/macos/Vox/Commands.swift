// Menus, keys and the command palette (ADR-014 M-19–M-21): every action is listed once, here,
// and the menus, the M-20 keys and the palette (⌘K) all come from that one list.

import AppKit
import SwiftUI

extension Notification.Name {
    /// Put the keyboard on the room's timeline (View > Focus Timeline).
    static let voxFocusTimeline = Notification.Name("us.vox.focusTimeline")
}

/// A sheet a menu, key or palette action opens.
enum NodeSheet: String, Identifiable {
    case palette, newRoom, joinRoom, fingerprint, rename, retention, admins, leave, end
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
        // A detached node acts on nothing until it is attached again.
        let live = node != nil && node?.ended == nil
        let inRoom = live && node?.roomOnScreen != nil
        // What the room's commands act on: the Session on screen, when one is, never the room
        // behind it (D2).
        let inSession = node?.showingSession ?? false
        let driven = node?.shownSession.flatMap { $0.canDrive && $0.open ? $0 : nil }
        // A keyring row selected, in the keyring view: what Compare, Rename and Remove act on.
        let picked = node?.selection == .keyring && node?.keyringSelected != nil
        let digits: [VoxAction] = (1...9).map { n in
            VoxAction("View", "Room \(n)", KeyEquivalent(Character("\(n)")), enabled: live) {
                Task { await node?.showRoom(at: n) }
            }
        }
        return [
            // In the Room menu, first, whether a room is on screen or not (the decider, v0.4.1).
            VoxAction("Room", "New Room…", "n", enabled: live) { node?.sheet = .newRoom },
            VoxAction("Room", "Join Room…", "j", [.command, .shift], enabled: live) {
                node?.sheet = .joinRoom
            },
            inSession
                ? VoxAction("File", "Attach File to \(driven?.label ?? "the Session")…", "o",
                            enabled: inRoom && driven != nil) { node?.sessionAttachAsked += 1 }
                : VoxAction("File", "Attach File to the Room…", "o", enabled: inRoom) {
                    node?.attachAsked += 1
                },
            VoxAction("File", "Share Service…", enabled: live) {
                Task { await node?.show(.services) }
            },
            VoxAction("Room", "Copy Room Link", "l", enabled: inRoom) {
                Task { await node?.copyRoomLink() }
            },
            VoxAction("Room", "Rename…", enabled: inRoom) { node?.sheet = .rename },
            VoxAction("Room", "Retention…", enabled: inRoom) { node?.sheet = .retention },
            VoxAction("Room", "Admins…", enabled: inRoom) { node?.sheet = .admins },
            VoxAction("Room", "Reply to Selected Message", "r",
                      enabled: inRoom && node?.messages.contains { $0.id == node?.selectedMessage } == true) {
                node?.replyTo = node?.messages.first { $0.id == node?.selectedMessage }
            },
            // The room's composer only: never while a Session is shown (D2).
            VoxAction("Room", "Send Urgent", .return, enabled: inRoom && !inSession) {
                node?.urgentAsked += 1
            },
            // The keyboard's way into the messages (WCAG 2.1.1): ↑/↓ then move through them.
            // ⌃⌘T: ⇧⌘T is the system's View > Show Tab Bar, and ⌥⌘T its Show Toolbar.
            VoxAction("View", "Focus Timeline", "t", [.command, .control], enabled: inRoom) {
                NotificationCenter.default.post(name: .voxFocusTimeline, object: nil)
            },
            // The room's inspector, hidden or shown again; ⌥⌘I, as in the Finder.
            VoxAction("View", node?.inspectorShown == false ? "Show Inspector" : "Hide Inspector", "i",
                      [.command, .option], enabled: inRoom) { node?.inspectorShown.toggle() },
            // On the selected request of the Session on screen (P1). ⌥⌘Y and ⌥⌘N: ⌘Y is the
            // system's history and ⌘N New Room.
            VoxAction("Room", "Approve Request", "y", [.command, .option],
                      enabled: node?.selectedApproval != nil) {
                Task { await node?.answerSelected(approve: true) }
            },
            VoxAction("Room", "Reject Request", "n", [.command, .option],
                      enabled: node?.selectedApproval != nil) {
                Task { await node?.answerSelected(approve: false) }
            },
            VoxAction("Room", "Copy Selected Service's Address", "c", [.command, .shift],
                      enabled: node?.selectedService != nil) { node?.copyServiceCommand() },
            VoxAction("Room", "Next Room That Needs You", "j", enabled: live) {
                Task { await node?.nextNeedingYou() }
            },
            VoxAction("Room", "Leave…", enabled: inRoom) { node?.sheet = .leave },
            VoxAction("Room", "End for Everyone…", enabled: inRoom) { node?.sheet = .end },
            VoxAction("Node", "Show Fingerprint", "i", enabled: live) { node?.sheet = .fingerprint },
            VoxAction("Keyring", "Add…", enabled: live) { node?.askKeyring(.add) },
            VoxAction("Keyring", "Compare…", enabled: picked) { node?.askKeyring(.compare) },
            VoxAction("Keyring", "Rename…", enabled: picked) { node?.askKeyring(.rename) },
            VoxAction("Keyring", "Remove…", enabled: picked) { node?.askKeyring(.remove) },
            VoxAction("View", "Command Palette", "k", enabled: live) { node?.sheet = .palette },
            VoxAction("View", "Keyring", "k", [.command, .shift], enabled: live) {
                Task { await node?.show(.keyring) }
            },
            VoxAction("View", "Services", "s", [.command, .shift], enabled: live) {
                Task { await node?.show(.services) }
            },
            VoxAction("View", "Decision Record", "d", [.command, .shift], enabled: live) {
                Task { await node?.show(.decisions) }
            },
            // The app's own text size (WCAG 1.4.4): macOS has none for the whole system.
            VoxAction("View", "Bigger", "+") { AppModel.shared.stepTextSize(1) },
            VoxAction("View", "Smaller", "-") { AppModel.shared.stepTextSize(-1) },
            VoxAction("View", "Actual Size", "0") { AppModel.shared.stepTextSize(0) },
        ] + digits
    }
}

/// The menu bar's menus (M-21), from the one action list.
struct VoxCommands: Commands {
    @ObservedObject var app: AppModel

    var body: some Commands {
        // Keep Running, reachable while Vox runs (#571): its title says what choosing it does.
        CommandGroup(after: .appSettings) {
            Button(app.keepRunning ? "Turn Keep Running Off" : "Keep Running While Logged In") {
                Task { await app.setKeepRunning(!app.keepRunning) }
            }
        }
        CommandGroup(replacing: .newItem) { items("File") }
        CommandMenu("Room") { items("Room") }
        CommandMenu("Node") {
            Button("Attach…") { Task { await app.start() } }
                .disabled(app.node != nil)
            Button("Detach") { Task { await app.detachNode() } }
                .disabled(app.node == nil)
            Hairline()
            // E-4: the one way to act as another node: sign out, then sign in.
            Button("Sign Out…") { app.signingOut = true }
                .disabled(app.signedInAs == nil)
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
        VStack(alignment: .leading, spacing: Space.s8) {
            TextField("Type a command", text: $query)
                .accessibilityLabel("Command")
                .onSubmit { if let first = found.first { done(first) } }
                .accessibilityIdentifier("palette-query")
            ScrollView {
                VStack(alignment: .leading, spacing: Space.s4) {
                    ForEach(found) { action in
                        Button { done(action) } label: {
                            HStack {
                                Text(action.title)
                                Spacer()
                                Text(action.menu).eyebrow().secondaryText()
                            }
                        }
                        .buttonStyle(.plain)
                        .accessibilityIdentifier("palette-\(action.title)")
                    }
                }
            }
            .frame(height: 280)
        }
        .padding(Space.s16)
        .frame(width: Theme.scaled(420))
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
        Group {
            switch sheet {
            case .palette: Palette(model: model)
            case .newRoom: RoomForm(model: model, joining: false)
            case .joinRoom: RoomForm(model: model, joining: true)
            case .fingerprint: FingerprintSheet(model: model)
            case .rename: RenameSheet(model: model)
            case .retention: RetentionSheet(model: model)
            case .admins: AdminsSheet(model: model)
            case .leave: LeaveSheet(model: model, ending: false)
            case .end: LeaveSheet(model: model, ending: true)
            }
        }
        .panelSurface()
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
    /// Whether the passphrase field is empty: a room may have none (ADR-005 J-2 as amended).
    @State private var noPassphrase = true
    /// A create or join under way: Return and the button may both ask.
    @State private var submitting = false

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s12) {
            Text(joining ? "Join a room" : "New room").title()
            if joining {
                TextField("Room link (vox://…)", text: $link).font(Theme.mono)
                    .accessibilityLabel("Room link")
                    .accessibilityIdentifier("room-form-link")
            } else {
                TextField("Its name, as every member sees it", text: $name)
                    .accessibilityLabel("Room name")
                    .accessibilityIdentifier("room-form-name")
            }
            Text(joining ? "The room's passphrase, sent to you another way than its link."
                : "A passphrase for the room: send it another way than its link.").secondaryText()
            SecureInput(holder: field, onEmpty: { noPassphrase = $0 }) { submit() }
                .frame(width: Theme.scaled(320))
                .accessibilityLabel(joining ? "Room passphrase" : "Passphrase for the new room")
                .accessibilityIdentifier("room-form-passphrase")
            if noPassphrase {
                // Allowed, and said (D16): a room without one is open to anyone with its link.
                Text("No passphrase: anyone with the link can join.")
                    .accessibilityIdentifier("room-form-no-passphrase")
            }
            OutcomeMark(outcome: model.failure(of: operation))
            HStack {
                Button("Cancel") { model.sheet = nil }.keyboardShortcut(.cancelAction)
                Button(joining ? "Join" : "Create") { submit() }.keyboardShortcut(.defaultAction)
                    .buttonStyle(.voxPrimary)
                    .disabled(submitting || (joining ? link.isEmpty : name.isEmpty))
                    .accessibilityIdentifier("room-form-submit")
            }
        }
        .padding(Space.s24)
        .frame(width: Theme.scaled(440))
        .onAppear {
            model.clearOutcome(of: operation)
            // A link the system opened the app with fills the field; nothing is joined until the
            // person types the passphrase and clicks Join.
            if joining, let given = model.joinLink {
                link = given
                model.joinLink = nil
            }
        }
    }

    private var operation: String { joining ? "join-room" : "create-room" }

    private func submit() {
        // Return and the button may both ask: the second finds one under way. An empty field is
        // a room with no passphrase, never nothing done (D16).
        guard !submitting, joining ? !link.isEmpty : !name.isEmpty else { return }
        submitting = true
        let secret = field.takeAllowingEmpty()
        noPassphrase = true
        let (l, n) = (link, name)
        Task {
            let ok = joining ? await model.joinRoom(l, passphrase: secret)
                : await model.createRoom(n, passphrase: secret)
            submitting = false
            if ok { model.sheet = nil }
        }
    }
}

/// This node's fingerprint, grouped with its art (K-1).
private struct FingerprintSheet: View {
    @ObservedObject var model: NodeModel

    var body: some View {
        let card = fingerprintCard(fingerprint: model.me)
        VStack(alignment: .leading, spacing: Space.s12) {
            Text("Node \(model.node)").title()
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
                .accessibilityLabel("Copy this node's fingerprint")
                Button("Done") { model.sheet = nil }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(Space.s24)
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

/// Retention, saying what it does before it is set (E-5); no passphrase (ADR-028 K-11).
///
/// **It opens at what the room keeps, and Return never sets it** (D14): it opened at 30 days
/// whatever the room kept, with Set as the default, so Return on a room kept forever shortened
/// it. Set waits for a choice that differs, and a shorter retention deletes files and previews
/// too (F-5), which it says.
private struct RetentionSheet: View {
    @ObservedObject var model: NodeModel
    @State private var seconds: UInt64 = 0
    @State private var opened = false

    /// What the room keeps now, `nil` until it is known.
    private var current: UInt64? { model.retentionSecs }

    /// The choices, with the room's own value among them when it is none of the usual ones.
    private var choices: [(String, UInt64)] {
        guard let current, !Retention.choices.contains(where: { $0.1 == current }) else {
            return Retention.choices
        }
        return Retention.choices + [(model.retention.isEmpty ? "\(current) seconds" : model.retention,
                                     current)]
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s12) {
            Text("Retention").title()
            Picker("Keep messages", selection: $seconds) {
                ForEach(choices, id: \.1) { Text($0.0).tag($0.1) }
            }
            .disabled(current == nil)
            .accessibilityIdentifier("retention-choice")
            Text(effect)
                .secondaryText()
                .accessibilityIdentifier("retention-effect")
            OutcomeMark(outcome: model.failure(of: "retention"), id: "retention-said")
            HStack {
                Button("Cancel") { model.sheet = nil }.keyboardShortcut(.cancelAction)
                // Never the Return default (A9): a retention deletes text, so Set is pressed on
                // purpose, and only once another retention is chosen (D14).
                Button("Set", role: seconds == 0 ? nil : .destructive) { submit() }
                    .disabled(current == nil || seconds == current)
                    .accessibilityIdentifier("retention-submit")
            }
        }
        .padding(Space.s24)
        .frame(width: Theme.scaled(440))
        .onAppear {
            model.clearOutcome(of: "retention")
            open()
        }
        .onChange(of: model.retentionSecs) { _ in open() }
    }

    /// What the choice does, said before it is set: the text, the files it shared and their
    /// previews go together (F-5).
    private var effect: String {
        if current != nil, seconds == current {
            return seconds == 0 ? "This room keeps every message for good. Choose another to change it."
                : "This room keeps messages for \(Retention.words(seconds)). Choose another to change it."
        }
        if seconds == 0 {
            return "Every member keeps every message, the files it shared and their previews, for good."
        }
        return "Every member deletes each message, with the files it shared and their previews, "
            + "\(Retention.words(seconds)) after it was sent, and older ones at once. What is "
            + "deleted cannot be read or opened again."
    }

    /// The sheet starts at what the room keeps, once that is known.
    private func open() {
        guard !opened, let current else { return }
        seconds = current
        opened = true
    }

    private func submit() {
        let s = seconds
        Task { if await model.setRetention(s) { model.sheet = nil } }
    }
}

/// Rename the room: its one name, as every member sees it, said before it is set (E-5); no
/// passphrase (ADR-028 K-11), as `vox room rename` asks none.
private struct RenameSheet: View {
    @ObservedObject var model: NodeModel
    @State private var name = ""

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s12) {
            Text("Rename the room").title()
            TextField("Its new name", text: $name).onSubmit { submit() }
                .accessibilityLabel("New room name")
                .accessibilityIdentifier("rename-name")
            Text("Every member sees the new name, in their sidebar and in every address of the "
                + "room's services. Only the room's creator or an admin may rename it.")
                .secondaryText()
                .accessibilityIdentifier("rename-effect")
            OutcomeMark(outcome: model.failure(of: "rename"), id: "rename-said")
            HStack {
                Button("Cancel") { model.sheet = nil }.keyboardShortcut(.cancelAction)
                Button("Rename") { submit() }.keyboardShortcut(.defaultAction)
                    .buttonStyle(.voxPrimary)
                    .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
                    .accessibilityIdentifier("rename-submit")
            }
        }
        .padding(Space.s24)
        .frame(width: Theme.scaled(440))
        .onAppear { model.clearOutcome(of: "rename") }
    }

    private func submit() {
        let n = name.trimmingCharacters(in: .whitespaces)
        guard !n.isEmpty else { return }
        Task { if await model.renameRoom(to: n) { model.sheet = nil } }
    }
}

/// The room's admins: its creator first, then those it made admins.
private struct AdminsSheet: View {
    @ObservedObject var model: NodeModel
    @State private var admins: [String] = []
    /// The member about to be made an admin, asked first: an admin can end the room for everyone
    /// (E-5). Taking adminship away goes through at once.
    @State private var asking: NodeModel.MemberRow?

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s12) {
            Text("Admins").title()
            Text("An admin may end the room and set its retention.").secondaryText()
            ForEach(model.members) { member in
                Toggle(isOn: Binding(get: { admins.contains(member.id) }, set: { on in
                    if on {
                        asking = member
                        return
                    }
                    Task {
                        await model.setAdmin(member.id, false)
                        admins = await model.admins()
                    }
                })) {
                    TrustMark(name: member.name, trust: member.trust)
                }
                .disabled(admins.first == member.id || asking != nil)
                .accessibilityIdentifier("admin-\(member.name)")
                .accessibilityLabel(admins.contains(member.id) ? "\(member.name), admin"
                                                               : "\(member.name), not an admin")
            }
            if let member = asking {
                VStack(alignment: .leading, spacing: 8) {
                    StateMark(kind: .attention,
                              words: "Make \(member.name) an admin? An admin can end this room for "
                                  + "everyone and change its retention.")
                        .accessibilityIdentifier("admin-confirm")
                    HStack {
                        Spacer()
                        Button("Cancel") { asking = nil }
                            .keyboardShortcut(.cancelAction)
                            .accessibilityIdentifier("admin-confirm-cancel")
                        Button("Make Admin") {
                            asking = nil
                            Task {
                                await model.setAdmin(member.id, true)
                                admins = await model.admins()
                            }
                        }
                        .accessibilityIdentifier("admin-confirm-make")
                    }
                }
            }
            OutcomeMark(outcome: model.failure(of: "admins"))
            if asking == nil {
                Button("Done") { model.sheet = nil }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(Space.s24)
        .frame(width: Theme.scaled(440))
        .onAppear { model.clearOutcome(of: "admins") }
        .task { admins = await model.admins() }
    }
}

/// Leave, or End for Everyone, each saying what it does first (E-5).
private struct LeaveSheet: View {
    @ObservedObject var model: NodeModel
    let ending: Bool
    /// Why the last try did not leave: the sheet stays open and says so (D19).
    @State private var failed: String?
    @State private var working = false

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s12) {
            Text(ending ? "End this room for everyone?" : "Leave this room?").title()
            Text(ending
                ? "Every member's copy of the room is deleted, and no one can post in it again. "
                    + "Only its creator or an admin can do this."
                : "This node stops reading and posting here, and the room is deleted here. "
                    + "The others go on; to come back you need its link and passphrase again.")
            HStack {
                Button("Cancel") { model.sheet = nil }.keyboardShortcut(.cancelAction)
                Button(ending ? "End for Everyone" : "Leave", role: .destructive) {
                    working = true
                    failed = nil
                    Task {
                        // Closed only once it is done; a failure stays, with its reason.
                        if let why = await model.leaveRoom(endingIt: ending) {
                            failed = why
                        } else {
                            model.sheet = nil
                        }
                        working = false
                    }
                }
                .disabled(working)
                .accessibilityIdentifier("leave-confirm")
            }
            if let failed {
                StateMark(kind: .danger, words: failed).textSelection(.enabled)
                    .accessibilityIdentifier("leave-failed")
            }
        }
        .padding(Space.s24)
        .frame(width: Theme.scaled(440))
    }
}
