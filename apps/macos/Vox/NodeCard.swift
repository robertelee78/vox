// A node's card (ADR-028 K-5, R-5; D4): opened from a member in the member pane, from a message's
// author, and from a decision row. Its fingerprint grouped with its art, who trusts whom in plain
// words, and the keyring actions: Trust… (read, the same flow as an offer), Compare…, and Remove…
// for a node in the keyring. Every change passes the passphrase gate as every keyring change does
// (K-11 to K-13, K-16): through NodeModel's keyring change, never around it.

import AppKit
import SwiftUI

/// The node a card is open for, and the action it opens on (a context menu's choice).
struct NodeCardFor: Identifiable, Equatable {
    enum Act: Equatable {
        case trust, compare, remove
    }

    let fingerprint: String
    let name: String
    var act: Act?
    var id: String { fingerprint }
}

/// The same actions a card offers, as a context menu on a row that names a node.
struct NodeActions: ViewModifier {
    @ObservedObject var model: NodeModel
    let fingerprint: String
    let name: String

    func body(content: Content) -> some View {
        content.contextMenu {
            let trust = model.trust(of: fingerprint)
            Button("Show Node…") { model.openCard(fingerprint, name: name) }
            if !trust.inKeyring {
                Button("Trust…") { model.openCard(fingerprint, name: name, act: .trust) }
            }
            Button("Compare…") { model.openCard(fingerprint, name: name, act: .compare) }
            if trust.inKeyring {
                Button("Remove…", role: .destructive) {
                    model.openCard(fingerprint, name: name, act: .remove)
                }
            }
        }
    }
}

extension View {
    /// Open `fingerprint`'s card on a click, with its actions in a context menu (D4).
    func nodeCard(_ model: NodeModel, _ fingerprint: String, name: String) -> some View {
        self.contentShape(Rectangle())
            .onTapGesture { model.openCard(fingerprint, name: name) }
            .modifier(NodeActions(model: model, fingerprint: fingerprint, name: name))
            .accessibilityAddTraits(.isButton)
            .accessibilityAction { model.openCard(fingerprint, name: name) }
    }
}

struct NodeCard: View {
    @ObservedObject var model: NodeModel
    let node: NodeCardFor
    let done: () -> Void
    @State private var act: NodeCardFor.Act?
    @State private var alias = ""
    @State private var drive = false
    @State private var other = ""

    var body: some View {
        let card = fingerprintCard(fingerprint: node.fingerprint)
        let trust = model.trust(of: node.fingerprint)
        let entry = model.trusted.first { $0.fingerprint == node.fingerprint }
        // Its alias once the keyring holds it, else as the room named it.
        let name = entry?.name ?? node.name
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text(name).heading()
                HStack(alignment: .top, spacing: 16) {
                    VStack(spacing: 0) {
                        ForEach(Array(card.art.enumerated()), id: \.offset) { Text($0.element) }
                    }
                    .font(Theme.mono)
                    .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 6) {
                        Text(card.grouped).font(Theme.mono).textSelection(.enabled)
                            .accessibilityIdentifier("card-fingerprint")
                        Button("Copy") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(card.grouped, forType: .string)
                        }
                        .accessibilityIdentifier("card-copy")
                    }
                }
                TrustMark(name: name, trust: trust)
                    .accessibilityIdentifier("card-trust")
                Text(trust.sentence(name))
                    .accessibilityIdentifier("card-directions")
                if let entry {
                    Text("Your keyring grants \(entry.name) \(Capability.words(entry.drive)).")
                        .secondaryText()
                }
                HStack {
                    if !trust.inKeyring {
                        Button("Trust…") { act = .trust }
                            .accessibilityIdentifier("card-trust-open")
                    }
                    Button("Compare…") { act = .compare; other = "" }
                        .accessibilityIdentifier("card-compare-open")
                    if trust.inKeyring {
                        Button("Remove…", role: .destructive) { act = .remove }
                            .accessibilityIdentifier("card-remove-open")
                    }
                    Spacer()
                    Button("Close", action: done).keyboardShortcut(.cancelAction)
                        .accessibilityIdentifier("card-close")
                }
                Divider()
                switch act {
                case .trust? where !trust.inKeyring:
                    trusting
                case .compare?:
                    comparing(entry)
                case .remove?:
                    if let entry { removing(entry) }
                default:
                    EmptyView()
                }
                if model.keyringNeedsPassphrase {
                    KeyringPassphrase(model: model)
                }
                if let failed = model.keyringFailed {
                    StateMark(kind: .danger, words: failed).textSelection(.enabled)
                        .accessibilityIdentifier("card-failed")
                }
                if let did = model.keyringDid {
                    Text(did).accessibilityIdentifier("card-did")
                }
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(width: Theme.scaled(520), height: Theme.scaled(520))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("node-card")
        .onAppear { act = node.act }
    }

    /// Trust it: an alias and read or read + drive, read the default, what it does said first
    /// (E-5), as an offer is accepted (K-16).
    @ViewBuilder private var trusting: some View {
        TextField("Alias", text: $alias)
            .accessibilityLabel("Alias")
            .frame(width: Theme.scaled(320))
            .accessibilityIdentifier("card-alias")
        Picker("Grants", selection: $drive) {
            Text(Capability.words(false)).tag(false)
            Text(Capability.words(true)).tag(true)
        }
        .pickerStyle(.segmented)
        .fixedSize()
        .accessibilityIdentifier("card-capability")
        if !alias.isEmpty {
            Text(Effects.trusting(alias) + " " + Effects.granting(alias, drive: drive))
                .secondaryText()
        }
        Button("Trust") {
            let (name, grant, fp) = (alias, drive, node.fingerprint)
            Task { _ = await model.trust(fp, as: name, drive: grant) }
        }
        .disabled(alias.isEmpty)
        .accessibilityIdentifier("card-trust-confirm")
    }

    /// Compare a fingerprint pasted or typed with this node's; a mismatch is its own action, which
    /// says not to trust it (K-5).
    @ViewBuilder private func comparing(_ entry: TrustedNode?) -> some View {
        TextField("Their fingerprint, pasted or typed", text: $other).font(Theme.mono)
            .accessibilityLabel("Their fingerprint, to compare with \(node.name)'s")
            .accessibilityIdentifier("card-compare")
        if !other.isEmpty {
            if Compare.same(other, node.fingerprint) {
                StateMark(kind: .plain, words: "Matches \(node.name)'s fingerprint.")
                    .accessibilityIdentifier("card-compare-said")
            } else {
                StateMark(kind: .danger,
                          words: "Does not match. This is not the node you were given as "
                              + "\(node.name): do not trust it.")
                    .accessibilityIdentifier("card-compare-said")
                if entry != nil {
                    Button("Remove \(node.name)…", role: .destructive) { act = .remove }
                }
            }
        }
    }

    /// Remove it from the keyring: what that does said first (E-5), done only when confirmed.
    @ViewBuilder private func removing(_ entry: TrustedNode) -> some View {
        Text("Removing \(entry.name): it reads nothing you write from now on, and you read nothing "
            + "it writes. What it already read stays read. Its live sessions into your services are "
            + "cut. Your sender key is rotated, and everyone you still trust is re-keyed.")
            .accessibilityIdentifier("card-remove-effect")
        Button("Remove", role: .destructive) {
            Task { await model.untrust(entry) }
        }
        .accessibilityIdentifier("card-remove-confirm")
    }
}
