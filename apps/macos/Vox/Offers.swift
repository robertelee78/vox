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
/// and the two things to do with it. Trusting asks an alias and gives read, the only grant here
/// (K-16; drive is its own step in the keyring, P5), says what it does first, and asks no
/// fingerprint comparison (K-16); it passes the
/// passphrase gate as every keyring change does. Dismissing is this node's alone (K-18).
struct OfferView: View {
    @ObservedObject var model: NodeModel
    let fingerprint: String
    @State private var alias = ""
    @State private var comparing = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Space.s12) {
                Text("Trust offer").title()
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
            .padding(Space.s24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder private func card(_ offer: OfferInfo) -> some View {
        let card = fingerprintCard(fingerprint: offer.fingerprint)
        HStack(alignment: .top, spacing: Space.s16) {
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
            + "you share, now and later. You are asked for a name, and it is given read; drive is "
            + "a separate step in the keyring.")
            .secondaryText()
        Text("Dismissing it is yours alone: it is not told, and stays out of your keyring.")
            .secondaryText()
        Hairline()
        TextField("Alias", text: $alias)
            .accessibilityLabel("Alias")
            .frame(width: 320)
            .accessibilityIdentifier("offer-alias")
        AliasClash(model: model, alias: alias)
        if !alias.isEmpty {
            Text(Effects.trusting(alias) + " " + Effects.granting(alias, drive: false))
                .secondaryText()
                .accessibilityIdentifier("offer-effect")
        }
        KeyringReplaceAsk(model: model)
        // The prompt only for this offer's change; another waiting is one line (D1).
        if let pending = model.keyringPending {
            if pending.fingerprint == offer.fingerprint {
                KeyringPassphrase(model: model, pending: pending)
            } else {
                KeyringWaitingLine(model: model, pending: pending)
            }
        }
        if let failed = model.keyringFailed {
            StateMark(kind: .danger, words: failed).textSelection(.enabled)
                .accessibilityIdentifier("offer-failed")
        }
        HStack {
            Button("Trust") {
                let name = alias
                Task { _ = await model.accept(offer, as: name, drive: false) }
            }
            .disabled(alias.isEmpty)
            .accessibilityIdentifier("offer-accept")
            Button("Dismiss") { Task { await model.dismiss(offer) } }
                .accessibilityIdentifier("offer-dismiss")
        }
    }
}
