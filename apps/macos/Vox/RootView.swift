// The window: reaching the daemon, choosing the node at first run and its passphrase, then the
// main window once the node is attached.

import AppKit
import ServiceManagement
import SwiftUI

struct RootView: View {
    @ObservedObject var model: AppModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Group {
            if case .attached = model.phase, let node = model.node {
                MainWindow(model: node)
                    .font(Theme.text)
            } else {
                setup
            }
        }
        // Node › Sign Out…: what it does, said first (E-5), done only when confirmed.
        .sheet(isPresented: $model.signingOut) {
            if let node = model.signedInAs {
                SignOutSheet(node: node, model: model)
                    .padding(Space.s24)
                    .font(Theme.text)
                    .panelSurface()
            }
        }
        // Keep Running turned on with a node attached: keep it now, with its passphrase.
        .sheet(isPresented: Binding(get: { model.keepNodeAsk != nil },
                                    set: { if !$0, let n = model.keepNodeAsk { model.declineToKeepNode(n) } })) {
            if let node = model.keepNodeAsk {
                KeepNodeOffer(node: node, model: model)
                    .padding(Space.s24)
                    .font(Theme.text)
                    .panelSurface()
            }
        }
        // ON THIS MACHINE's Attach…: a node that waits for its passphrase (#666).
        .sheet(isPresented: Binding(get: { model.attachNodeAsk != nil },
                                    set: { if !$0 { model.attachNodeAsk = nil } })) {
            if let node = model.attachNodeAsk {
                AttachNodeSheet(node: node, model: model)
                    .padding(Space.s24)
                    .font(Theme.text)
                    .panelSurface()
            }
        }
        // Turning Keep Running on or off from the Vox menu, refused: macOS's or the daemon's words.
        .alert("Keep Running", isPresented: Binding(get: { model.keepRunningSaid != nil },
                                                    set: { if !$0 { model.keepRunningSaid = nil } })) {
            Button("OK") {}
        } message: {
            Text(model.keepRunningSaid ?? "")
        }
    }

    private var setup: some View {
        VStack(alignment: .leading, spacing: Space.s16) {
            switch model.phase {
            case .askingLoginItem:
                LoginItemQuestion(model: model)
            case let .loginItemApproval(said):
                LoginItemApproval(said: said, model: model)
            case .starting:
                ProgressView("Reaching the vox daemon…")
            case let .unreachable(failure):
                // A plain headline, one line of cause, then what can help; the sentence said under
                // Details, selectable and copyable (P4).
                Text(failure.headline)
                    .heading()
                    .accessibilityIdentifier("start-failure")
                Text(failure.cause).secondaryText()
                    .accessibilityIdentifier("start-failure-cause")
                if let why = model.loginItemSaid {
                    // The login item's daemon ended on a refusal no retry changes: said here,
                    // with the way out (ADR-014 M-8).
                    Text("Vox's login item did not start: \(why)")
                        .secondaryText()
                        .textSelection(.enabled)
                        .accessibilityIdentifier("login-item-said")
                    Button("Turn Keep Running Off") { Task { await model.stopKeepingRunning() } }
                        .accessibilityIdentifier("login-item-off")
                }
                HStack {
                    Button("Try Again") { Task { await model.start() } }
                        .keyboardShortcut(.defaultAction)
                        .accessibilityIdentifier("retry")
                    if model.loginItemSaid != nil {
                        Button("Show Log in Finder") {
                            let home = ProcessInfo.processInfo.environment["HOME"] ?? NSHomeDirectory()
                            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: home)
                                .appendingPathComponent("Library/Logs/Vox/login-item.log")])
                        }
                        .accessibilityIdentifier("start-failure-log")
                    }
                }
                Text("DETAILS").eyebrow().secondaryText()
                Said(text: failure.said)
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(failure.said, forType: .string)
                }
                .accessibilityIdentifier("start-failure-copy")
            case let .oldLayout(dirs, said):
                OldLayout(dirs: dirs, said: said, model: model)
            case let .welcome(said):
                Welcome(said: said, model: model)
            case let .creating(node):
                ProgressView("Making node \(node)…")
            case let .choosing(nodes):
                Chooser(nodes: nodes, model: model)
            case let .passphrase(node, said):
                PassphraseForm(node: node, said: said, model: model)
            case let .attaching(node):
                ProgressView("Attaching node \(node)…")
            case .attached:
                ProgressView("Opening the node…")
            case let .detached(node):
                // E-4: this window is node <node>'s, attached or not. Attach it again, or quit.
                Text("Node \(node) is detached.").heading()
                Text("This window acts only as node \(node). Attach it again to go on, or quit Vox.")
                    .secondaryText()
                    .accessibilityIdentifier("detached-why")
                HStack {
                    Button("Attach \(node) Again") { Task { await model.attachAgain() } }
                        .keyboardShortcut(.defaultAction)
                        .accessibilityIdentifier("attach-again")
                    Button("Quit Vox") { NSApp.terminate(nil) }
                        .accessibilityIdentifier("detached-quit")
                }
            }
        }
        .padding(Space.s24)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .font(Theme.text)
        // Every word shown can be selected and copied (the decider, v0.4.1).
        .textSelection(.enabled)
        .contentSurface()
        .animation(Theme.motion(reduced: reduceMotion), value: model.phase)
    }
}

/// A sentence the daemon said, where the action was taken (M-7).
private struct Said: View {
    let text: String

    var body: some View {
        StateMark(kind: .danger, words: text)
            .textSelection(.enabled)
            .accessibilityIdentifier("said")
            .accessibilityLabel("Failed: \(text)")
    }
}

/// First run: whether the daemon keeps running while the person is logged in (ADR-014 M-8).
private struct LoginItemQuestion: View {
    @ObservedObject var model: AppModel

    var body: some View {
        Text("Keep Vox running while you're logged in?").heading()
        Text("Keep Running keeps Vox running in the background while you're logged in, even with "
            + "the app closed, so your rooms stay reachable. It adds Vox to Login Items, and macOS "
            + "may ask you to allow it. You can turn this off in Settings or the Vox menu.")
            .secondaryText()
            .accessibilityIdentifier("login-item-why")
        // M-22: offered here, at first run, and off unless the person turns it on.
        Toggle("Show Vox in the menu bar", isOn: Binding(get: { model.menuBar },
                                                         set: { model.showMenuBar($0) }))
            .accessibilityIdentifier("menu-bar-offer")
        // Neither is the default: Return must not add a login item (#571, proposal 2).
        HStack {
            Button("Keep Running") { Task { await model.answerLoginItem(keep: true) } }
                .accessibilityIdentifier("login-item-keep")
            Button("Not Now") { Task { await model.answerLoginItem(keep: false) } }
                .accessibilityIdentifier("login-item-not-now")
        }
    }
}

/// Keep Running turned on while node `node` is attached: keep it now, its passphrase stored in the
/// Keychain (M-6, ADR-028 K-10), or not, said plainly.
private struct KeepNodeOffer: View {
    let node: String
    @ObservedObject var model: AppModel
    @State private var field = SecureFieldHolder()
    /// Set while one Store is being asked: one key press may ask twice.
    @State private var submitted = false

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s12) {
            Text("Keep node \(node) attached?").title()
            Text("Keep Running is on. To keep node \(node) attached when Vox is closed and after a "
                + "restart, Vox stores its passphrase in the Keychain. Anyone who can unlock this "
                + "Mac's login keychain can then attach node \(node). Without it, node \(node) stays "
                + "attached only while Vox is open, and after a restart it needs its passphrase.")
                .secondaryText()
                .accessibilityIdentifier("keep-node-why")
            SecureInput(holder: field) { store() }
                .frame(width: Theme.scaled(320))
                .accessibilityIdentifier("keep-node-passphrase")
                .accessibilityLabel("Identity passphrase for node \(node)")
            if let said = model.keepNodeSaid {
                Said(text: said)
            }
            HStack {
                Button("Store in Keychain") { store() }
                    .accessibilityIdentifier("keep-node-store")
                Button("Not Now") { model.declineToKeepNode(node) }
                    .accessibilityIdentifier("keep-node-not-now")
            }
        }
    }

    private func store() {
        // A node may have no passphrase (ADR-005 J-2): an empty field keeps none.
        guard !submitted else { return }
        submitted = true
        DispatchQueue.main.async { submitted = false }
        let secret = field.takeAllowingEmpty()
        Task { await model.keepNode(node, passphrase: secret) }
    }
}

/// Attach a node on this Mac that waits for its passphrase, and remember it (#666): the passphrase
/// is stored in the Keychain, so the node attaches again by itself after every restart.
private struct AttachNodeSheet: View {
    let node: String
    @ObservedObject var model: AppModel
    @State private var field = SecureFieldHolder()
    /// Set while one Attach is being asked: one key press may ask twice.
    @State private var submitted = false

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s12) {
            Text("Attach node \(node)").title()
            Text("Type node \(node)'s identity passphrase, or leave it empty for a node made with "
                + "none. Vox stores it in the Keychain, so node \(node) attaches again by itself "
                + "after a restart; anyone who can unlock this Mac's login keychain can then attach "
                + "node \(node). `vox node forget-passphrase \(node)` forgets it.")
                .secondaryText()
                .accessibilityIdentifier("attach-node-why")
            SecureInput(holder: field) { attach() }
                .frame(width: Theme.scaled(320))
                .accessibilityIdentifier("attach-node-passphrase")
                .accessibilityLabel("Identity passphrase for node \(node)")
            if let said = model.keepNodeSaid {
                Said(text: said)
            }
            HStack {
                Button("Attach") { attach() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.voxPrimary)
                    .accessibilityIdentifier("attach-node")
                Button("Cancel") { model.attachNodeAsk = nil }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("attach-node-cancel")
            }
        }
    }

    private func attach() {
        guard !submitted else { return }
        submitted = true
        DispatchQueue.main.async { submitted = false }
        let secret = field.takeAllowingEmpty()
        Task { await model.keepNode(node, passphrase: secret) }
    }
}

/// The login item waits for the person in System Settings; the app opens it and goes on.
private struct LoginItemApproval: View {
    let said: String?
    @ObservedObject var model: AppModel

    var body: some View {
        Text("Allow Vox in Login Items").heading()
        Text("To keep running while you're logged in, Vox needs your approval in System Settings, "
            + "General, Login Items. Until then Vox runs while it is open.")
            .secondaryText()
        if let said {
            Said(text: said)
        }
        HStack {
            Button("Open Login Items") { Daemon.openLoginItems() }
                .accessibilityIdentifier("login-item-settings")
            Button("Continue") { Task { await model.reach() } }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.voxPrimary)
                .accessibilityIdentifier("login-item-continue")
        }
    }
}

/// The data root holds an earlier release's node directories, which this version does not read
/// (#576): said plainly, with the way on, not the daemon's sentence alone.
private struct OldLayout: View {
    let dirs: [String]
    let said: String?
    @ObservedObject var model: AppModel

    var body: some View {
        Text("This Mac has a node from an earlier Vox").heading()
        Text("This version of Vox cannot read "
            + dirs.map { URL(fileURLWithPath: $0).lastPathComponent }.joined(separator: ", ")
            + ", kept the way an earlier release kept its nodes. Vox can move it aside, whole and "
            + "untouched, and start fresh: you make a new node next. Nothing in it is deleted.")
            .secondaryText()
            .accessibilityIdentifier("old-layout-why")
        ForEach(dirs, id: \.self) { dir in
            Text(dir).font(Theme.mono).secondaryText().textSelection(.enabled)
        }
        Text("Your new node is a new identity: people you shared rooms with add it to their keyring "
            + "again.")
            .secondaryText()
        if let said {
            Said(text: said)
        }
        HStack {
            Button("Move It Aside and Start Fresh") { Task { await model.moveAside() } }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.voxPrimary)
                .accessibilityIdentifier("old-move-aside")
            Button("Try Again") { Task { await model.start() } }
                .accessibilityIdentifier("retry")
        }
    }
}

/// First run on a Mac with no node yet: the node is made here, in the window, as `vox node create`
/// makes it (a name, and its identity passphrase typed twice), then attached. Nothing on the way
/// sends the person anywhere else.
private struct Welcome: View {
    let said: String?
    @ObservedObject var model: AppModel
    @State private var name = Welcome.suggestedName
    @State private var first = SecureFieldHolder()
    @State private var again = SecureFieldHolder()
    /// Whether the passphrase field is empty now: a node may have none (ADR-005 J-2), said here.
    @State private var noPassphrase = true
    /// Set while one Make Node is being asked: Return and the button may both ask at one key
    /// press, and an empty passphrase no longer tells the second from the first.
    @State private var submitted = false

    var body: some View {
        Text("Welcome to Vox").heading()
        Text("To start, make your node: who you are in every room. Everything you post, trust and "
            + "share is your node's.")
            .secondaryText()
            .accessibilityIdentifier("welcome-why")
        TextField("Name", text: $name)
            .frame(width: Theme.scaled(320))
            .accessibilityIdentifier("new-node-name")
            .accessibilityLabel("Node name")
        Text("Lowercase letters, digits, dots, dashes and underscores.").secondaryText()
        SecureInput(holder: first, onEmpty: { noPassphrase = $0 }) {
            again.field.becomeFirstResponder()
        }
            .frame(width: Theme.scaled(320))
            .accessibilityIdentifier("new-node-passphrase")
            .accessibilityLabel("Identity passphrase")
        SecureInput(holder: again) { submit() }
            .frame(width: Theme.scaled(320))
            .accessibilityIdentifier("new-node-passphrase-again")
            .accessibilityLabel("Identity passphrase again")
        Text("The identity passphrase unlocks your node on this Mac. Nobody can recover it for you: "
            + "keep it somewhere safe.")
            .secondaryText()
            .accessibilityIdentifier("new-node-passphrase-why")
        if noPassphrase {
            // Allowed, and said (ADR-005 J-2, V030-36): a node with none keeps its key unencrypted.
            Text(Welcome.capitalized(noPassphraseNotice()))
                .accessibilityIdentifier("new-node-no-passphrase")
        }
        Text(Welcome.capitalized(noBackupNotice()))
            .secondaryText()
            .accessibilityIdentifier("new-node-no-backup")
        ForEach(model.movedAside, id: \.to) { moved in
            Text("Moved aside, untouched: \(moved.from) is now \(moved.to).")
                .secondaryText()
                .textSelection(.enabled)
                .accessibilityIdentifier("moved-aside-note")
        }
        if let said {
            Said(text: said)
        }
        Button("Make Node") { submit() }
            .keyboardShortcut(.defaultAction)
            .buttonStyle(.voxPrimary)
            .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
            .accessibilityIdentifier("new-node-make")
    }

    private func submit() {
        // Return and the button may both ask: the second does nothing.
        guard !submitted else { return }
        submitted = true
        // One key press fires both at once; the next press is a new ask.
        DispatchQueue.main.async { submitted = false }
        let secret = first.takeAllowingEmpty()
        let repeated = again.takeAllowingEmpty()
        let node = name.trimmingCharacters(in: .whitespaces)
        Task { await model.createNode(node, passphrase: secret, again: repeated) }
    }

    /// The Mac's own name, in the letters a node name may have: a start the person may change.
    static var suggestedName: String {
        let raw = (Host.current().localizedName ?? "").lowercased()
        var name = ""
        for c in raw {
            if c.isASCII && (c.isLetter || c.isNumber || c == "." || c == "_" || c == "-") {
                name.append(c)
            } else if c == " " && !name.hasSuffix("-") && !name.isEmpty {
                name.append("-")
            }
        }
        while name.hasSuffix("-") { name.removeLast() }
        return String(name.prefix(32))
    }

    static func capitalized(_ sentence: String) -> String {
        sentence.prefix(1).uppercased() + sentence.dropFirst() + "."
    }
}

/// First run with several nodes on this Mac: which one is you here (ADR-028 E-4).
private struct Chooser: View {
    let nodes: [String]
    @ObservedObject var model: AppModel

    var body: some View {
        Text("Which node are you?").heading()
        Text("Pick the node you post, trust and share as here, or make a new one. Vox acts as it "
            + "until you sign out.")
            .secondaryText()
        ForEach(nodes, id: \.self) { node in
            let fp = model.nodeList.first { $0.name == node }?.fingerprint ?? ""
            // Each node with its fingerprint art and its fingerprint, and what choosing it means
            // (P8).
            HStack(alignment: .top, spacing: Space.s16) {
                if !fp.isEmpty {
                    VStack(spacing: 0) {
                        ForEach(Array(fingerprintCard(fingerprint: fp).art.enumerated()),
                                id: \.offset) { Text($0.element) }
                    }
                    .font(Theme.mono)
                    .accessibilityHidden(true)
                }
                VStack(alignment: .leading, spacing: Space.s4) {
                    Button {
                        Task { await model.choose(node) }
                    } label: {
                        Text(node).fontWeight(.bold)
                    }
                    .accessibilityIdentifier("node-\(node)")
                    .accessibilityLabel(fp.isEmpty ? "Act as node \(node)"
                        : "Act as node \(node), fingerprint \(fingerprintCard(fingerprint: fp).grouped)")
                    Text(fp.isEmpty ? "Its fingerprint is known once this node has been attached."
                                    : fingerprintCard(fingerprint: fp).grouped)
                        .font(Theme.mono).secondaryText().textSelection(.enabled)
                        .accessibilityIdentifier("node-fingerprint-\(node)")
                    Text("Everything you post, trust and share will be as \(node).")
                        .secondaryText()
                        .accessibilityIdentifier("node-acting-as-\(node)")
                }
            }
            .padding(.vertical, Space.s8)
        }
        Button("New Node…") { model.newNode() }
            .accessibilityIdentifier("new-node")
    }
}

/// Node › Sign Out…: what signing out does, then Sign Out or Cancel.
private struct SignOutSheet: View {
    let node: String
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s16) {
            Text("Sign out of node \(node)?").title()
            Text("Vox detaches node \(node), stops keeping it attached, and forgets its passphrase "
                + "in the Keychain and that this app opens it. Node \(node), its rooms and its "
                + "messages stay on this Mac. Then you choose a node to sign in as, or make a new "
                + "one.")
                .accessibilityIdentifier("sign-out-effect")
            HStack {
                Button("Cancel") { model.signingOut = false }
                    .keyboardShortcut(.cancelAction)
                Button("Sign Out") { Task { await model.signOut() } }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("sign-out-confirm")
            }
        }
        .frame(width: Theme.scaled(440))
    }
}

/// The node's identity passphrase, typed straight into a secure field whose bytes go to the
/// client and are wiped (M-5).
private struct PassphraseForm: View {
    let node: String
    let said: String?
    @ObservedObject var model: AppModel
    @State private var field = SecureFieldHolder()
    /// ADR-028 K-10 as amended (#666): on until the person turns it off, for this node.
    @State private var keepInKeychain = true
    /// Set while one Attach is being asked: Return and the button may both ask at one key press,
    /// and an empty passphrase no longer tells the second from the first.
    @State private var submitted = false

    var body: some View {
        Text("Attach node \(node)").heading()
        Text("Type node \(node)'s identity passphrase, or leave it empty for a node made with none.")
            .secondaryText()
        SecureInput(holder: field) { submit() }
            .frame(width: Theme.scaled(320))
            .accessibilityIdentifier("passphrase")
            .accessibilityLabel("Identity passphrase for node \(node)")
        Toggle("Remember the passphrase in the Keychain, so node \(node) attaches again by "
            + "itself after Vox quits or the Mac restarts", isOn: $keepInKeychain)
            .accessibilityIdentifier("keep-in-keychain")
        Text(keepInKeychain
            ? "Anyone who can unlock this Mac's login keychain can then attach node \(node)."
            : "Without it, your rooms are reachable only while Vox is open, and node \(node) "
                + "asks for its passphrase again after a restart.")
            .secondaryText()
            .accessibilityIdentifier("keep-in-keychain-why")
        if let said {
            Said(text: said)
        }
        Button("Attach") { submit() }
            .keyboardShortcut(.defaultAction)
            .buttonStyle(.voxPrimary)
            .accessibilityIdentifier("attach")
    }

    private func submit() {
        // Return and the Attach button may both ask at one key press: the second does nothing.
        guard !submitted else { return }
        submitted = true
        DispatchQueue.main.async { submitted = false }
        // A node may have no passphrase (ADR-005 J-2): an empty field attaches it with none.
        let secret = field.takeAllowingEmpty()
        let keep = keepInKeychain
        Task { await model.attach(node, passphrase: secret, keepInKeychain: keep) }
    }
}

/// Typed passphrase bytes with one owner, so wiping them wipes the only copy the app made (M-5).
/// They are wiped as soon as they become a `Passphrase`, and when dropped.
final class Secret: @unchecked Sendable {
    private var bytes: Data

    init(_ bytes: Data) { self.bytes = bytes }

    /// A `Passphrase` of the bytes, which are wiped at once, whether or not it could be made.
    func passphrase() throws -> Passphrase {
        defer { wipe() }
        return try Passphrase(bytes: bytes)
    }

    func wipe() { bytes.resetBytes(in: 0..<bytes.count) }

    /// Nothing was typed.
    var isEmpty: Bool { bytes.isEmpty }

    /// Whether `other` holds the same bytes, compared without stopping at the first difference.
    func matches(_ other: Secret) -> Bool {
        guard bytes.count == other.bytes.count else { return false }
        var diff: UInt8 = 0
        for (a, b) in zip(bytes, other.bytes) { diff |= a ^ b }
        return diff == 0
    }

    deinit { wipe() }
}

/// Holds the secure field, so its bytes are taken and the field cleared at once.
@MainActor
final class SecureFieldHolder {
    let field = NSSecureTextField()

    /// The typed bytes, the field emptied; nil when nothing was typed (or it was already taken).
    func take() -> Secret? {
        let text = field.stringValue
        field.stringValue = ""
        guard !text.isEmpty else { return nil }
        return Secret(Data(text.utf8))
    }

    /// The typed bytes, the field emptied: empty when nothing was typed. For a passphrase a room
    /// or a node may go without (ADR-005 J-2).
    func takeAllowingEmpty() -> Secret {
        let text = field.stringValue
        field.stringValue = ""
        return Secret(Data(text.utf8))
    }

    /// Whether nothing is typed now.
    var isEmpty: Bool { field.stringValue.isEmpty }
}

/// An `NSSecureTextField`, read only by `SecureFieldHolder.take`. What M-5 leaves: AppKit holds
/// the typed text in the field until it is emptied, and `take` reads it once as a Swift `String`,
/// which cannot be wiped and is freed, not cleared. The bytes the app hands on are a `Secret`,
/// wiped in place once used.
struct SecureInput: NSViewRepresentable {
    let holder: SecureFieldHolder
    /// Told whether the field is empty as it changes (never what it holds).
    var onEmpty: ((Bool) -> Void)? = nil
    let onSubmit: () -> Void

    func makeNSView(context: Context) -> NSSecureTextField {
        holder.field.target = context.coordinator
        holder.field.action = #selector(Coordinator.submit)
        holder.field.delegate = context.coordinator
        return holder.field
    }

    func updateNSView(_ view: NSSecureTextField, context: Context) {
        context.coordinator.onSubmit = onSubmit
        context.coordinator.onEmpty = onEmpty
    }

    func makeCoordinator() -> Coordinator { Coordinator(onSubmit: onSubmit, onEmpty: onEmpty) }

    final class Coordinator: NSObject, NSTextFieldDelegate {
        var onSubmit: () -> Void
        var onEmpty: ((Bool) -> Void)?
        init(onSubmit: @escaping () -> Void, onEmpty: ((Bool) -> Void)?) {
            self.onSubmit = onSubmit
            self.onEmpty = onEmpty
        }
        @objc func submit() { onSubmit() }
        func controlTextDidChange(_ note: Notification) {
            guard let field = note.object as? NSTextField else { return }
            onEmpty?(field.stringValue.isEmpty)
        }
    }
}
