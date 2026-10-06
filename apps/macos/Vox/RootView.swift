// The window: reaching the daemon, choosing the node at first run and its passphrase, then the
// main window once the node is attached.

import AppKit
import ServiceManagement
import SwiftUI

struct RootView: View {
    @ObservedObject var model: AppModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        if case .attached = model.phase, let node = model.node {
            MainWindow(model: node)
                .font(Theme.text)
        } else {
            setup
        }
    }

    private var setup: some View {
        VStack(alignment: .leading, spacing: 16) {
            switch model.phase {
            case .askingLoginItem:
                LoginItemQuestion(model: model)
            case let .loginItemApproval(said):
                LoginItemApproval(said: said, model: model)
            case .starting:
                ProgressView("Reaching the vox daemon…")
            case let .unreachable(said):
                Text("Vox could not reach the vox daemon.")
                    .font(Theme.heading)
                Said(text: said)
                Button("Try Again") { Task { await model.start() } }
                    .accessibilityIdentifier("retry")
            case let .choosing(nodes):
                Chooser(nodes: nodes, model: model)
            case let .passphrase(node, said):
                PassphraseForm(node: node, said: said, model: model)
            case let .attaching(node):
                ProgressView("Attaching node \(node)…")
            case .attached:
                ProgressView("Opening the node…")
            }
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .font(Theme.text)
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
    let model: AppModel

    var body: some View {
        Text("Keep Vox running while you're logged in?").font(Theme.heading)
        Text("Vox keeps your rooms reachable while you are logged in, even with the app closed.")
            .secondaryText()
            .accessibilityIdentifier("login-item-why")
        // M-22: offered here, at first run, and off unless the person turns it on.
        Toggle("Show Vox in the menu bar", isOn: Binding(get: { model.menuBar },
                                                         set: { model.showMenuBar($0) }))
            .accessibilityIdentifier("menu-bar-offer")
        HStack {
            Button("Keep Running") { Task { await model.answerLoginItem(keep: true) } }
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("login-item-keep")
            Button("Not Now") { Task { await model.answerLoginItem(keep: false) } }
                .accessibilityIdentifier("login-item-not-now")
        }
    }
}

/// The login item waits for the person in System Settings; the app opens it and goes on.
private struct LoginItemApproval: View {
    let said: String?
    let model: AppModel

    var body: some View {
        Text("Allow Vox in Login Items").font(Theme.heading)
        Text("To keep running while you're logged in, Vox needs your approval in System Settings, "
            + "General, Login Items. Until then Vox runs while it is open.")
            .secondaryText()
        if let said {
            Said(text: said)
        }
        HStack {
            Button("Open Login Items") { SMAppService.openSystemSettingsLoginItems() }
                .accessibilityIdentifier("login-item-settings")
            Button("Continue") { Task { await model.reach() } }
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("login-item-continue")
        }
    }
}

/// First run: which node this app acts as (ADR-028 E-4).
private struct Chooser: View {
    let nodes: [String]
    let model: AppModel

    var body: some View {
        Text("Which node is this app?").font(Theme.heading)
        Text(
            "Vox acts as one node on this Mac: everything you post, trust and share is that node's."
        )
        .secondaryText()
        if nodes.isEmpty {
            Text("There is no node on this Mac yet. Make one in Terminal with `vox node create <name>`, then try again.")
            Button("Try Again") { Task { await model.start() } }
                .accessibilityIdentifier("retry")
        } else {
            ForEach(nodes, id: \.self) { node in
                Button(node) { Task { await model.choose(node) } }
                    .accessibilityIdentifier("node-\(node)")
                    .accessibilityLabel("Act as node \(node)")
            }
        }
    }
}

/// The node's identity passphrase, typed straight into a secure field whose bytes go to the
/// client and are wiped (M-5).
private struct PassphraseForm: View {
    let node: String
    let said: String?
    let model: AppModel
    @State private var field = SecureFieldHolder()
    /// ADR-028 K-10: off until the person turns it on, for this node.
    @State private var keepInKeychain = false

    var body: some View {
        Text("Attach node \(node)").font(Theme.heading)
        Text("Type node \(node)'s identity passphrase.").secondaryText()
        SecureInput(holder: field) { submit() }
            .frame(width: 320)
            .accessibilityIdentifier("passphrase")
            .accessibilityLabel("Identity passphrase for node \(node)")
        if model.keepRunning {
            Toggle("Store the passphrase in the Keychain, so node \(node) stays attached when "
                + "Vox quits", isOn: $keepInKeychain)
                .accessibilityIdentifier("keep-in-keychain")
            Text(keepInKeychain
                ? "Anyone who can unlock this Mac's login keychain can then attach node \(node)."
                : "Without it, your rooms are reachable only while Vox is open.")
                .secondaryText()
                .accessibilityIdentifier("keep-in-keychain-why")
        }
        if let said {
            Said(text: said)
        }
        Button("Attach") { submit() }
            .keyboardShortcut(.defaultAction)
            .accessibilityIdentifier("attach")
    }

    private func submit() {
        let bytes = field.take()
        let keep = keepInKeychain
        Task { await model.attach(node, passphrase: bytes, keepInKeychain: keep) }
    }
}

/// Holds the secure field, so its bytes are taken and the field cleared at once.
@MainActor
final class SecureFieldHolder {
    let field = NSSecureTextField()

    /// The typed bytes; the field is emptied.
    func take() -> Data {
        let bytes = Data(field.stringValue.utf8)
        field.stringValue = ""
        return bytes
    }
}

/// An `NSSecureTextField`: its text is read only by `SecureFieldHolder.take`, never bound to a
/// Swift `String` that outlives the keystroke.
struct SecureInput: NSViewRepresentable {
    let holder: SecureFieldHolder
    let onSubmit: () -> Void

    func makeNSView(context: Context) -> NSSecureTextField {
        holder.field.target = context.coordinator
        holder.field.action = #selector(Coordinator.submit)
        return holder.field
    }

    func updateNSView(_ view: NSSecureTextField, context: Context) {
        context.coordinator.onSubmit = onSubmit
    }

    func makeCoordinator() -> Coordinator { Coordinator(onSubmit: onSubmit) }

    final class Coordinator: NSObject {
        var onSubmit: () -> Void
        init(onSubmit: @escaping () -> Void) { self.onSubmit = onSubmit }
        @objc func submit() { onSubmit() }
    }
}
