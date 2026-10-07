// The keyring view (ADR-014 M-16; ADR-028 K-1–K-6, E-5): the nodes this node trusts, by alias with
// fingerprint art and the grouped fingerprint; add (paste or type), rename, compare and remove, each
// saying its effect before it acts and what it did after.

import SwiftUI

/// What a Keyring menu action asks the keyring view to open (M-21): the add form, or the
/// selected row's compare, rename or remove.
struct KeyringAsk: Equatable {
    enum Kind { case add, compare, rename, remove }
    let kind: Kind
    /// The row it is for; nil for add.
    let fingerprint: String?
    /// Each ask is new, so asking the same twice opens it twice.
    let id = UUID()
}

struct KeyringView: View {
    @ObservedObject var model: NodeModel
    @State private var fingerprint = ""
    @State private var alias = ""
    @State private var removing: TrustedNode?
    @FocusState private var adding: Bool

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Keyring").heading()
                Text(model.keyring).font(Theme.mono).secondaryText()
                if let did = model.keyringDid {
                    StateMark(kind: .plain, words: did)
                        .textSelection(.enabled)
                        .accessibilityIdentifier("keyring-did")
                }
                if let failed = model.keyringFailed {
                    StateMark(kind: .danger, words: failed)
                        .textSelection(.enabled)
                        .accessibilityIdentifier("keyring-said")
                }
                if model.keyringNeedsPassphrase {
                    KeyringPassphrase(model: model)
                }
                addForm
                Divider()
                if model.trusted.isEmpty {
                    Text("This node trusts no one yet: nobody can read what you write until you "
                        + "trust them.").secondaryText()
                }
                ForEach(model.trusted, id: \.fingerprint) { node in
                    KeyringRow(model: model, node: node) { removing = node }
                        .selectable(model.keyringSelected == node.fingerprint) {
                            model.keyringSelected = node.fingerprint
                        }
                }
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .sheet(item: Binding(get: { removing.map(Removal.init) }, set: { removing = $0?.node })) {
            RemoveSheet(model: model, node: $0.node) { removing = nil }
        }
        .onChange(of: model.keyringAsk) { ask in
            guard let ask else { return }
            switch ask.kind {
            case .add: adding = true
            case .remove:
                removing = model.trusted.first { $0.fingerprint == ask.fingerprint }
            case .compare, .rename: break // the row opens its own
            }
        }
    }

    /// Add: the fingerprint pasted or typed, an alias (K-3), and what trusting does, before it is
    /// done (E-5).
    private var addForm: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("ADD A NODE").eyebrow().secondaryText()
            TextField("Fingerprint (paste or type)", text: $fingerprint)
                .font(Theme.mono)
                .focused($adding)
                .accessibilityIdentifier("keyring-add-fingerprint")
            TextField("Alias", text: $alias)
                .accessibilityIdentifier("keyring-add-alias")
            if !fingerprint.isEmpty && !alias.isEmpty {
                Text(Effects.trusting(alias))
                    .secondaryText()
                    .accessibilityIdentifier("keyring-add-effect")
            }
            Button("Trust") {
                let (fp, name) = (fingerprint, alias)
                Task {
                    if await model.trust(fp, as: name) {
                        fingerprint = ""
                        alias = ""
                    }
                }
            }
            .disabled(fingerprint.isEmpty || alias.isEmpty)
            .accessibilityIdentifier("keyring-trust")
        }
    }
}

/// What each keyring change does, in words, said before it acts (ADR-028 E-5).
enum Effects {
    static func trusting(_ alias: String) -> String {
        "Trusting \(alias): it may read what you write in every room you share, now and later; you "
            + "read what it writes once it trusts you too; and it reaches every service you bind "
            + "to a room you are both in. Untrusting it undoes this."
    }

    static func untrusting(_ alias: String) -> String {
        "Untrusting \(alias): it reads nothing you write from now on, and you read nothing it "
            + "writes. What it already read stays read. Its live sessions into your services are "
            + "cut. Your sender key is rotated, and everyone you still trust is re-keyed."
    }

    static func renaming(_ alias: String) -> String {
        "Renamed, it is shown as \(alias) everywhere, and its services are reachable as "
            + "<service>.\(alias).<room>.vox."
    }
}

/// One node in the keyring: its alias, art and grouped fingerprint (K-1), and its actions.
private struct KeyringRow: View {
    @ObservedObject var model: NodeModel
    let node: TrustedNode
    let remove: () -> Void
    @State private var renaming = false
    @State private var newAlias = ""
    @State private var comparing = false
    @State private var other = ""

    var body: some View {
        let card = fingerprintCard(fingerprint: node.fingerprint)
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 16) {
                VStack(spacing: 0) {
                    ForEach(Array(card.art.enumerated()), id: \.offset) { Text($0.element) }
                }
                .font(Theme.mono)
                .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 4) {
                    // ⇄ once it trusts this node back, → until then (L-4).
                    TrustMark(name: node.name,
                              trust: model.trustsBack.contains(node.fingerprint) ? .mutual : .oneWay)
                    Text(card.grouped).font(Theme.mono).textSelection(.enabled)
                        .accessibilityIdentifier("keyring-fingerprint-\(node.name)")
                }
            }
            HStack {
                Button("Rename…") { renaming.toggle(); newAlias = node.name }
                Button("Compare…") { comparing.toggle(); other = "" }
                Button("Remove…", role: .destructive, action: remove)
                    .accessibilityIdentifier("keyring-remove-\(node.name)")
            }
            if renaming {
                HStack {
                    TextField("New alias", text: $newAlias)
                    Button("Rename") {
                        let name = newAlias
                        Task { if await model.rename(node.fingerprint, to: name) { renaming = false } }
                    }
                    .disabled(newAlias.isEmpty || newAlias == node.name)
                }
                if !newAlias.isEmpty && newAlias != node.name {
                    Text(Effects.renaming(newAlias)).secondaryText()
                }
            }
            if comparing {
                TextField("Their fingerprint, pasted or typed", text: $other).font(Theme.mono)
                    .accessibilityIdentifier("keyring-compare-\(node.name)")
                if !other.isEmpty {
                    if Compare.same(other, node.fingerprint) {
                        StateMark(kind: .plain, words: "Matches \(node.name)'s fingerprint.")
                    } else {
                        // K-5: a mismatch is its own action, which says not to trust the node.
                        StateMark(kind: .danger,
                                  words: "Does not match. This is not the node you trusted as "
                                      + "\(node.name): do not trust it.")
                        Button("Untrust \(node.name)…", role: .destructive, action: remove)
                    }
                }
            }
        }
        .padding(.vertical, 8)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("keyring-row-\(node.name)")
        .onChange(of: model.keyringAsk) { ask in
            guard let ask, ask.fingerprint == node.fingerprint else { return }
            switch ask.kind {
            case .compare: comparing = true; other = ""
            case .rename: renaming = true; newAlias = node.name
            case .add, .remove: break
            }
        }
    }
}

/// Fingerprints compared as a person types them: case, spaces and dashes do not count.
enum Compare {
    static func same(_ a: String, _ b: String) -> Bool {
        normal(a) == normal(b)
    }

    private static func normal(_ s: String) -> String {
        s.lowercased().filter { !$0.isWhitespace && $0 != "-" && $0 != "·" }
    }
}

/// A node about to be removed, as a sheet item.
private struct Removal: Identifiable {
    let node: TrustedNode
    var id: String { node.fingerprint }
}

/// Remove: what untrusting does, said first (E-5), then done only when the person confirms.
private struct RemoveSheet: View {
    @ObservedObject var model: NodeModel
    let node: TrustedNode
    let done: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Untrust \(node.name)?").heading()
            Text(Effects.untrusting(node.name))
                .accessibilityIdentifier("keyring-remove-effect")
            HStack {
                Button("Cancel", action: done).keyboardShortcut(.cancelAction)
                Button("Untrust", role: .destructive) {
                    Task {
                        await model.untrust(node)
                        done()
                    }
                }
                .accessibilityIdentifier("keyring-untrust-confirm")
            }
        }
        .padding(24)
        .frame(width: 440)
    }
}

/// The identity passphrase, asked for when the keyring window has closed (ADR-026 N-2): the
/// change waiting for it is made with it.
private struct KeyringPassphrase: View {
    @ObservedObject var model: NodeModel
    @State private var field = SecureFieldHolder()

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Changing who you trust needs your identity passphrase again.").secondaryText()
            SecureInput(holder: field) { submit() }
                .frame(width: 320)
                .accessibilityIdentifier("keyring-passphrase")
            Button("Continue") { submit() }
                .accessibilityIdentifier("keyring-passphrase-continue")
        }
    }

    private func submit() {
        guard let secret = field.take() else { return }
        Task { await model.retryKeyring(with: secret) }
    }
}
