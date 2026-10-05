// The window until the main window (#440) takes over: reaching the daemon, choosing the node at
// first run, its passphrase, and the node attached.

import AppKit
import SwiftUI

struct RootView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            switch model.phase {
            case .starting:
                ProgressView("Reaching the vox daemon…")
            case let .unreachable(said):
                Text("Vox could not reach the vox daemon.")
                    .font(.headline)
                Said(text: said)
                Button("Try Again") { Task { await model.start() } }
                    .accessibilityIdentifier("retry")
            case let .choosing(nodes):
                Chooser(nodes: nodes, model: model)
            case let .passphrase(node, said):
                PassphraseForm(node: node, said: said, model: model)
            case let .attaching(node):
                ProgressView("Attaching node \(node)…")
            case let .attached(node, fingerprint):
                Attached(node: node, fingerprint: fingerprint)
            }
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

/// A sentence the daemon said, where the action was taken (M-7).
private struct Said: View {
    let text: String

    var body: some View {
        Label(text, systemImage: "exclamationmark.triangle")
            .textSelection(.enabled)
            .accessibilityIdentifier("said")
            .accessibilityLabel("Failed: \(text)")
    }
}

/// First run: which node this app acts as (ADR-028 E-4).
private struct Chooser: View {
    let nodes: [String]
    let model: AppModel

    var body: some View {
        Text("Which node is this app?").font(.headline)
        Text(
            "Vox acts as one node on this Mac: everything you post, trust and share is that node's."
        )
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

    var body: some View {
        Text("Attach node \(node)").font(.headline)
        Text("Type node \(node)'s identity passphrase.")
        SecureInput(holder: field) { submit() }
            .frame(width: 320)
            .accessibilityIdentifier("passphrase")
            .accessibilityLabel("Identity passphrase for node \(node)")
        if let said {
            Said(text: said)
        }
        Button("Attach") { submit() }
            .keyboardShortcut(.defaultAction)
            .accessibilityIdentifier("attach")
    }

    private func submit() {
        let bytes = field.take()
        Task { await model.attach(node, passphrase: bytes) }
    }
}

/// The node this app acts as.
private struct Attached: View {
    let node: String
    let fingerprint: String

    var body: some View {
        Label("Node \(node) — attached", systemImage: "checkmark.circle")
            .font(.headline)
            .accessibilityIdentifier("attached")
            .accessibilityLabel("Node \(node), attached")
        Text(fingerprint)
            .font(.system(.body, design: .monospaced))
            .textSelection(.enabled)
            .accessibilityIdentifier("fingerprint")
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
private struct SecureInput: NSViewRepresentable {
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
