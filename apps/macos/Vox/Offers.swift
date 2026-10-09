// Trust offers (ADR-028 K-15 to K-18): a node that joined a room this node is in, or that trusts
// this node, offered under "needs you" until it is trusted, dismissed, or leaves. The words are the
// TUI's (CL-1); what is said of the node is the node's own sentence (`said`).

import SwiftUI

extension OfferInfo {
    /// Its fingerprint grouped, cut to the first nine characters, as the sidebar names it.
    var short: String {
        String(fingerprintCard(fingerprint: fingerprint).grouped.prefix(9))
    }

    /// Why it is offered, in a word: it trusts this node, or it joined.
    var whyWords: String { why.contains(.trustsYou) ? "trusts you" : "joined" }
}

/// An offer in the sidebar, under needs you: "offer: <fingerprint>… joined".
struct OfferRow: View {
    let offer: OfferInfo

    var body: some View {
        Text("offer: \(offer.short)… \(offer.whyWords)")
            .font(Theme.mono)
            .accessibilityIdentifier("offer-\(offer.fingerprint.prefix(12))")
            .accessibilityLabel("trust offer: \(offer.short)… \(offer.whyWords)")
    }
}

/// The offer selected: the node's fingerprint grouped with its art, what is said of it, its rooms,
/// and the two things to do with it. Trusting asks an alias and read or read + drive (read the
/// default), says what it does first, and asks no fingerprint comparison (K-16); it passes the
/// passphrase gate as every keyring change does. Dismissing is this node's alone (K-18).
struct OfferView: View {
    @ObservedObject var model: NodeModel
    let fingerprint: String
    @State private var alias = ""
    @State private var drive = false
    @State private var comparing = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Trust offer").heading()
                if let offer = model.offers.first(where: { $0.fingerprint == fingerprint }) {
                    card(offer)
                } else {
                    // Trusted, dismissed, or gone from the room: say what was done, if this did it.
                    if let did = model.keyringDid {
                        Text(did).accessibilityIdentifier("offer-did")
                    } else {
                        Text("This offer is no longer waiting.").secondaryText()
                    }
                }
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder private func card(_ offer: OfferInfo) -> some View {
        let card = fingerprintCard(fingerprint: offer.fingerprint)
        HStack(alignment: .top, spacing: 16) {
            VStack(spacing: 0) {
                ForEach(Array(card.art.enumerated()), id: \.offset) { Text($0.element) }
            }
            .font(Theme.mono)
            .accessibilityHidden(true)
            Text(card.grouped).font(Theme.mono).textSelection(.enabled)
                .accessibilityIdentifier("offer-fingerprint")
        }
        Text(offer.said).accessibilityIdentifier("offer-said")
        // The same compare as the keyring's, collapsed until asked for (#624): nothing to remove
        // here.
        Button(comparing ? "Hide Compare" : "Compare…") { comparing.toggle() }
            .accessibilityIdentifier("offer-compare-open")
        if comparing {
            CompareField(fingerprint: offer.fingerprint, name: offer.short, id: "offer")
        }
        Text("In: \(offer.rooms.map(\.name).joined(separator: ", "))")
            .accessibilityIdentifier("offer-rooms")
        Text("It is not in your keyring. Trusting it lets it read what you write in every room "
            + "you share, now and later; you are asked for a name, and for read or read + drive.")
            .secondaryText()
        Text("Dismissing it is yours alone: it is not told, and stays out of your keyring.")
            .secondaryText()
        Divider()
        TextField("Alias", text: $alias)
            .accessibilityLabel("Alias")
            .frame(width: 320)
            .accessibilityIdentifier("offer-alias")
        Picker("Grants", selection: $drive) {
            Text(Capability.words(false)).tag(false)
            Text(Capability.words(true)).tag(true)
        }
        .pickerStyle(.segmented)
        .fixedSize()
        .accessibilityIdentifier("offer-capability")
        if !alias.isEmpty {
            Text(Effects.trusting(alias) + " " + Effects.granting(alias, drive: drive))
                .secondaryText()
                .accessibilityIdentifier("offer-effect")
        }
        if model.keyringNeedsPassphrase {
            KeyringPassphrase(model: model)
        }
        if let failed = model.keyringFailed {
            StateMark(kind: .danger, words: failed).textSelection(.enabled)
                .accessibilityIdentifier("offer-failed")
        }
        HStack {
            Button("Trust") {
                let (name, grant) = (alias, drive)
                Task { _ = await model.accept(offer, as: name, drive: grant) }
            }
            .disabled(alias.isEmpty)
            .accessibilityIdentifier("offer-accept")
            Button("Dismiss") { Task { await model.dismiss(offer) } }
                .accessibilityIdentifier("offer-dismiss")
        }
    }
}
