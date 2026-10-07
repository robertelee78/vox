// The composer's To: and urgent (ADR-014 M-15): who a message is addressed to, and whether it may
// interrupt their agents mid-turn.

import SwiftUI

/// To: and urgent for what the composer posts (M-15): the members ticked are written into `to` as
/// whole fingerprints; urgent may interrupt their agents mid-turn.
struct ComposerAddress: View {
    @ObservedObject var model: NodeModel
    @Binding var to: Set<String>
    @Binding var urgent: Bool

    var body: some View {
        HStack(spacing: 8) {
            Menu {
                ForEach(model.members) { member in
                    Toggle(member.name, isOn: Binding(
                        get: { to.contains(member.id) },
                        set: { on in if on { to.insert(member.id) } else { to.remove(member.id) } }))
                }
            } label: {
                Text(addressed).lineLimit(1).truncationMode(.tail)
            }
            // At least wide enough for "To: the room": with no minimum the label collapsed and
            // only the menu's chevron showed.
            .frame(minWidth: 110, maxWidth: 160)
            .accessibilityLabel(addressedInFull)
            .accessibilityIdentifier("compose-to")
            Toggle("Urgent", isOn: $urgent)
                .fixedSize()
                .accessibilityIdentifier("compose-urgent")
                .accessibilityLabel(urgent ? "Urgent, on" : "Urgent, off")
        }
        .eyebrow()
    }

    private var names: [String] { model.members.filter { to.contains($0.id) }.map(\.name) }

    /// Short enough for the composer's row at the window's narrowest: one name, or how many.
    private var addressed: String {
        switch names.count {
        case 0: return "To: the room"
        case 1: return "To: \(names[0])"
        default: return "To: \(names.count) members"
        }
    }

    /// Every name, for VoiceOver and the proofs.
    private var addressedInFull: String {
        names.isEmpty ? "To: the room" : "To: " + names.joined(separator: ", ")
    }
}
