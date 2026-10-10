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
            Button("Copy Name") { copyWords(name) }
            Button("Copy Fingerprint") { copyWords(fingerprint) }
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
    ///
    /// A plain button, not a tap gesture: on macOS a tap gesture on a row in a scroll view lets a
    /// click through unanswered now and then (as it did on a service card, f12e1f77), and the card
    /// never opened (4 of 7 runs of step 15 on the v0.4.1 merged build). A button takes the
    /// click as AppKit does, and VoiceOver presses it.
    func nodeCard(_ model: NodeModel, _ fingerprint: String, name: String) -> some View {
        Button { model.openCard(fingerprint, name: name) } label: {
            self.contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .modifier(NodeActions(model: model, fingerprint: fingerprint, name: name))
    }
}

struct NodeCard: View {
    @ObservedObject var model: NodeModel
    let node: NodeCardFor
    let done: () -> Void
    @State private var act: NodeCardFor.Act?
    @State private var alias = ""

    var body: some View {
        let card = fingerprintCard(fingerprint: node.fingerprint)
        let trust = model.trust(of: node.fingerprint)
        let entry = model.trusted.first { $0.fingerprint == node.fingerprint }
        // Its alias once the keyring holds it, else as the room named it.
        let name = entry?.name ?? node.name
        ScrollView {
            VStack(alignment: .leading, spacing: Space.s12) {
                Text(name).title()
                HStack(alignment: .top, spacing: Space.s16) {
                    VStack(spacing: 0) {
                        ForEach(Array(card.art.enumerated()), id: \.offset) { Text($0.element) }
                    }
                    .font(Theme.mono)
                    .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: Space.s8) {
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
                    Button("Compare…") { act = .compare }
                        .accessibilityIdentifier("card-compare-open")
                    if trust.inKeyring {
                        Button("Remove…", role: .destructive) { act = .remove }
                            .accessibilityIdentifier("card-remove-open")
                    }
                    Spacer()
                    Button("Close", action: done).keyboardShortcut(.cancelAction)
                        .accessibilityIdentifier("card-close")
                }
                Hairline()
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
                KeyringReplaceAsk(model: model)
                // The prompt only for this node's change; another waiting is one line (D1).
                if let pending = model.keyringPending {
                    if pending.fingerprint == node.fingerprint {
                        KeyringPassphrase(model: model, pending: pending)
                    } else {
                        KeyringWaitingLine(model: model, pending: pending)
                    }
                }
                if let failed = model.keyringFailed {
                    StateMark(kind: .danger, words: failed).textSelection(.enabled)
                        .accessibilityIdentifier("card-failed")
                }
                if let did = model.keyringDid {
                    Text(did).accessibilityIdentifier("card-did")
                }
            }
            .padding(Space.s24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(width: Theme.scaled(520), height: Theme.scaled(520))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("node-card")
        .onAppear { act = node.act }
    }

    /// Trust it: an alias, and it is given read, the only grant here (the decider, v0.4.1: no
    /// drive choice when trusting); what it does said first (E-5), as an offer is accepted (K-16).
    @ViewBuilder private var trusting: some View {
        TextField("Alias", text: $alias)
            .accessibilityLabel("Alias")
            .frame(width: Theme.scaled(320))
            .accessibilityIdentifier("card-alias")
        if !alias.isEmpty {
            Text(Effects.trusting(alias) + " " + Effects.granting(alias, drive: false))
                .secondaryText()
                .accessibilityIdentifier("card-trust-effect")
        }
        Button("Trust") {
            let (name, fp) = (alias, node.fingerprint)
            Task { _ = await model.trust(fp, as: name, drive: false) }
        }
        .disabled(alias.isEmpty)
        .accessibilityIdentifier("card-trust-confirm")
    }

    /// Compare a fingerprint pasted or typed with this node's, group by group (K-5, #624): only a
    /// real mismatch says not to trust it, and only then is Remove offered.
    @ViewBuilder private func comparing(_ entry: TrustedNode?) -> some View {
        CompareField(fingerprint: node.fingerprint, name: entry?.name ?? node.name, id: "card",
                     remove: entry == nil ? nil : { act = .remove })
    }

    /// Remove it from the keyring: what that does said first (E-5), done only when confirmed.
    @ViewBuilder private func removing(_ entry: TrustedNode) -> some View {
        Text(Effects.removing(entry.name))
            .accessibilityIdentifier("card-remove-effect")
        Button("Remove", role: .destructive) {
            Task { await model.untrust(entry) }
        }
        .accessibilityIdentifier("card-remove-confirm")
    }
}

/// Puts words on the pasteboard (the member row's Copy Name / Copy Fingerprint, #577).
private func copyWords(_ words: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(words, forType: .string)
}
