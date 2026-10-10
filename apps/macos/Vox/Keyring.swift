// The keyring view (ADR-014 M-16; ADR-028 K-1–K-6, E-5): the nodes this node trusts, by alias with
// fingerprint art and the grouped fingerprint; add (paste or type), rename, compare and remove, each
// saying its effect before it acts and what it did after.

import SwiftUI

/// What a Keyring menu action asks the keyring view to open (M-21): the add form, or the
/// selected row's compare, rename or remove.
struct KeyringAsk: Equatable {
    enum Kind { case add, compare, rename, remove }
    let kind: Kind
    /// The row it is for; for add, a fingerprint to fill in (a file card's Trust…), or nil.
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
            VStack(alignment: .leading, spacing: Space.s16) {
                Text("Keyring").title()
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
                KeyringReplaceAsk(model: model)
                // A change for a node not in the keyring yet (an add) is asked for here; one for
                // a node in it, beside its row (D1).
                if let pending = model.keyringPending,
                   !model.trusted.contains(where: { $0.fingerprint == pending.fingerprint }) {
                    KeyringPassphrase(model: model, pending: pending)
                }
                addForm
                Hairline()
                if model.trusted.isEmpty {
                    Text("This node trusts no one yet: nobody can read what you write until you "
                        + "trust them.").secondaryText()
                }
                ForEach(model.trusted, id: \.fingerprint) { node in
                    KeyringRow(model: model, node: node, remove: { removing = node })
                        .selectable(model.keyringSelected == node.fingerprint) {
                            model.keyringSelected = node.fingerprint
                        }
                    // The selected entry's card (G2): each direction, the rooms, what removing it
                    // would change.
                    if model.keyringSelected == node.fingerprint {
                        KeyringCard(model: model, node: node)
                    }
                }
            }
            .padding(Space.s24)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .sheet(item: Binding(get: { removing.map(Removal.init) }, set: { removing = $0?.node })) {
            RemoveSheet(model: model, node: $0.node) { removing = nil }.textSelection(.enabled)
                .panelSurface()
        }
        .onChange(of: model.keyringAsk) { ask in
            guard let ask else { return }
            switch ask.kind {
            case .add:
                if let given = ask.fingerprint { fingerprint = given }
                adding = true
            case .remove:
                removing = model.trusted.first { $0.fingerprint == ask.fingerprint }
            case .compare, .rename: break // the row opens its own
            }
        }
    }

    /// Add: the fingerprint pasted or typed, an alias (K-3), and what trusting does, before it is
    /// done (E-5).
    private var addForm: some View {
        VStack(alignment: .leading, spacing: Space.s8) {
            Text("ADD A NODE").eyebrow().secondaryText().accessibilityAddTraits(.isHeader)
            TextField("Fingerprint (paste or type)", text: $fingerprint)
                .accessibilityLabel("Fingerprint")
                .font(Theme.mono)
                .focused($adding)
                .accessibilityIdentifier("keyring-add-fingerprint")
            TextField("Alias", text: $alias)
                .accessibilityLabel("Alias")
                .accessibilityIdentifier("keyring-add-alias")
            // Read is the only grant the app gives (K-16; the decider, v0.4.1: no drive in the app).
            AliasClash(model: model, alias: alias)
            if !fingerprint.isEmpty && !alias.isEmpty {
                Text(Effects.trusting(alias) + " " + Effects.granting(alias, drive: false))
                    .secondaryText()
                    .accessibilityIdentifier("keyring-add-effect")
            }
            Button("Trust") {
                let (fp, name) = (fingerprint, alias)
                Task {
                    if await model.trust(fp, as: name, drive: false) {
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

/// What a keyring entry grants, in the words `vox trust list` and the TUI use (ADR-028 K-14).
enum Capability {
    static func words(_ drive: Bool) -> String { drive ? "read + drive" : "read" }
}

/// What each keyring change does, in words, said before it acts (ADR-028 E-5).
enum Effects {
    /// What drive adds to read (ADR-029 DR-1), or what read alone leaves out (SC-3).
    static func granting(_ alias: String, drive: Bool) -> String {
        drive
            ? "With drive, \(alias) also sees inside your Sessions and may type into them, "
                + "interrupt or stop them, answer their approvals and questions, and send and "
                + "receive their files."
            : "With read only, \(alias) sees each of your Sessions' name and whether it is open, "
                + "and nothing inside it."
    }

    static func trusting(_ alias: String) -> String {
        "Trusting \(alias): it may read what you write in every room you share, now and later; you "
            + "read what it writes once it trusts you too; and it reaches every service you bind "
            + "to a room you are both in. Removing it undoes this."
    }

    static func untrusting(_ alias: String) -> String {
        "Removing \(alias): it reads nothing you write from now on, and you read nothing it "
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
    @State private var changing = false

    var body: some View {
        let card = fingerprintCard(fingerprint: node.fingerprint)
        VStack(alignment: .leading, spacing: Space.s8) {
            HStack(alignment: .top, spacing: Space.s16) {
                VStack(spacing: 0) {
                    ForEach(Array(card.art.enumerated()), id: \.offset) { Text($0.element) }
                }
                .font(Theme.mono)
                .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: Space.s4) {
                    // ⇄ once it trusts this node back, → until then (L-4).
                    TrustMark(name: node.name,
                              trust: model.trustsBack.contains(node.fingerprint) ? .mutual : .oneWay)
                    Text(Capability.words(node.drive)).secondaryText()
                        .accessibilityIdentifier("keyring-capability-\(node.name)")
                    Text(card.grouped).font(Theme.mono).textSelection(.enabled)
                        .accessibilityIdentifier("keyring-fingerprint-\(node.name)")
                }
            }
            HStack {
                // The app grants no drive (the decider, v0.4.1: it has no Sessions to drive). An
                // entry given drive from the CLI says so above, and can be made read only here.
                if node.drive {
                    Button("Make Read Only…") { changing.toggle() }
                        .accessibilityIdentifier("keyring-change-\(node.name)")
                }
                Button("Rename…") { renaming.toggle(); newAlias = node.name }
                Button("Compare…") { comparing.toggle(); other = "" }
                Button("Remove…", role: .destructive, action: remove)
                    .accessibilityIdentifier("keyring-remove-\(node.name)")
            }
            if let pending = model.keyringPending, pending.fingerprint == node.fingerprint {
                KeyringPassphrase(model: model, pending: pending)
            }
            if changing && node.drive {
                // Lowering stays inline, said before it is made (E-5).
                Text(Effects.granting(node.name, drive: false)).secondaryText()
                    .accessibilityIdentifier("keyring-change-effect-\(node.name)")
                Button("Make Read Only") {
                    Task { if await model.setCapability(node, drive: false) { changing = false } }
                }
                .accessibilityIdentifier("keyring-change-confirm-\(node.name)")
            }
            if renaming {
                HStack {
                    TextField("New alias", text: $newAlias)
                        .accessibilityLabel("New alias for \(node.name)")
                    Button("Rename") {
                        let name = newAlias
                        Task { if await model.rename(node.fingerprint, to: name) { renaming = false } }
                    }
                    .disabled(newAlias.isEmpty || newAlias == node.name)
                }
                if !newAlias.isEmpty && newAlias != node.name {
                    Text(Effects.renaming(newAlias)).secondaryText()
                    AliasClash(model: model, alias: newAlias, except: node.fingerprint)
                }
            }
            if comparing {
                // Group by group (#624): only a real mismatch says not to trust it (K-5).
                CompareField(fingerprint: node.fingerprint, name: node.name,
                             id: "keyring-\(node.name)", remove: remove)
            }
        }
        .padding(.vertical, Space.s8)
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

/// Remove: what removing does, said first (E-5), then done only when the person confirms.
private struct RemoveSheet: View {
    @ObservedObject var model: NodeModel
    let node: TrustedNode
    let done: () -> Void
    /// Why the last try did not remove it: the sheet stays open and says so (D19).
    @State private var failed: String?
    /// The change is waiting for the identity passphrase, asked for here.
    @State private var asking = false
    @State private var working = false

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s16) {
            Text("Remove \(node.name)?").title()
            Text(Effects.untrusting(node.name))
                .accessibilityIdentifier("keyring-remove-effect")
            HStack {
                Button("Cancel", action: done).keyboardShortcut(.cancelAction)
                Button("Remove", role: .destructive) {
                    working = true
                    failed = nil
                    Task {
                        // Closed only once it is done; a failure stays, with its reason.
                        if await model.untrust(node) {
                            done()
                        } else if model.keyringPending?.fingerprint == node.fingerprint
                                    || model.keyringReplacing?.fingerprint == node.fingerprint {
                            // This removal waits for the passphrase, or asks first whether to
                            // replace another change waiting (D1).
                            asking = true
                        } else {
                            failed = model.keyringFailed
                        }
                        working = false
                    }
                }
                .disabled(working || asking)
                .accessibilityIdentifier("keyring-remove-confirm")
            }
            if asking {
                KeyringReplaceAsk(model: model)
                if let pending = model.keyringPending, pending.fingerprint == node.fingerprint {
                    KeyringPassphrase(model: model, pending: pending)
                }
            }
            if let failed {
                StateMark(kind: .danger, words: failed).textSelection(.enabled)
                    .accessibilityIdentifier("keyring-remove-failed")
            }
        }
        .padding(Space.s24)
        .frame(width: Theme.scaled(440))
        // The passphrase given: done once the change is made, else why not, here. Cancelled, or
        // the other change kept, nothing was removed and the sheet stays.
        .onChange(of: model.keyringPending?.id) { _ in
            guard asking, model.keyringPending?.fingerprint != node.fingerprint,
                  model.keyringReplacing?.fingerprint != node.fingerprint else { return }
            asking = false
            if model.keyringFailed == nil, model.keyringDid != nil { done() }
        }
        .onChange(of: model.keyringReplacing?.id) { _ in
            guard asking, model.keyringReplacing == nil,
                  model.keyringPending?.fingerprint != node.fingerprint else { return }
            asking = false
        }
        .onChange(of: model.keyringFailed) { why in
            if asking, let why { failed = why }
        }
    }
}

/// A keyring change waiting for the identity passphrase (ADR-026 N-2), bound to what it changes
/// (D1): the node, the alias, the change in words, and the action that makes it. It holds no
/// passphrase; `run` makes the change with the one typed for it.
struct KeyringPending: Identifiable {
    let id = UUID()
    let fingerprint: String
    let alias: String
    /// The change, said in the prompt: "give bo read + drive".
    let words: String
    /// What its button says: "Give Drive".
    let action: String
    let run: (Passphrase?) async throws -> String
}

/// The identity passphrase for the change `pending` names, asked for beside what it changes (D1):
/// made only for that change; Cancel drops it.
struct KeyringPassphrase: View {
    @ObservedObject var model: NodeModel
    let pending: KeyringPending
    @State private var field = SecureFieldHolder()

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s8) {
            Text("Type your identity passphrase to \(pending.words).").secondaryText()
                .accessibilityIdentifier("keyring-passphrase-why")
            SecureInput(holder: field) { submit() }
                .accessibilityLabel("Identity passphrase, to \(pending.words)")
                .frame(width: Theme.scaled(320))
                .accessibilityIdentifier("keyring-passphrase")
            HStack {
                Button(pending.action) { submit() }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("keyring-passphrase-continue")
                Button("Cancel") { model.cancelKeyring() }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("keyring-passphrase-cancel")
            }
        }
    }

    private func submit() {
        guard let secret = field.take() else { return }
        let change = pending
        Task { await model.retryKeyring(change, with: secret) }
    }
}

/// A keyring change waiting somewhere else: one line, with Show and Cancel (D1).
struct KeyringWaitingLine: View {
    @ObservedObject var model: NodeModel
    let pending: KeyringPending

    var body: some View {
        HStack {
            Text("A keyring change is waiting for your passphrase: \(pending.words).").secondaryText()
                .accessibilityIdentifier("keyring-waiting")
            Button("Show") { model.select(.keyring) }
                .accessibilityIdentifier("keyring-waiting-show")
            Button("Cancel") { model.cancelKeyring() }
                .accessibilityIdentifier("keyring-waiting-cancel")
        }
    }
}

/// A second change needing the passphrase while one waits: replaced only if the person says so
/// (D1).
struct KeyringReplaceAsk: View {
    @ObservedObject var model: NodeModel

    var body: some View {
        if let next = model.keyringReplacing, let waiting = model.keyringPending {
            VStack(alignment: .leading, spacing: Space.s8) {
                Text("Replace the waiting change? \(waiting.words.prefix(1).uppercased() + waiting.words.dropFirst()) "
                    + "is waiting for your passphrase; \(next.words) would take its place.")
                    .secondaryText()
                    .accessibilityIdentifier("keyring-replace-ask")
                HStack {
                    Button("Replace") { model.replaceKeyring(true) }
                        .accessibilityIdentifier("keyring-replace-yes")
                    Button("Keep Waiting Change") { model.replaceKeyring(false) }
                        .keyboardShortcut(.cancelAction)
                        .accessibilityIdentifier("keyring-replace-no")
                }
            }
        }
    }
}
