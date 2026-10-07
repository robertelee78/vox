// The composer's To: and urgent (ADR-014 M-15): who a message is addressed to, and whether it may
// interrupt their agents mid-turn.

import SwiftUI

/// To: and urgent for what the composer posts (M-15): the members ticked are written into `to` as
/// whole fingerprints; urgent may interrupt their agents mid-turn.
struct ComposerAddress: View {
    @ObservedObject var model: NodeModel
    @Binding var to: Set<String>
    @Binding var urgent: Bool
    @State private var choosing = false

    var body: some View {
        HStack(spacing: 8) {
            // A button that opens the members to tick, not a menu: macOS draws a menu's label in
            // its own fixed size, and To: must follow the app's text size (WCAG 1.4.4).
            Button { choosing.toggle() } label: {
                Text(addressed).lineLimit(1).truncationMode(.tail)
            }
            // As wide as what it says ("To: the room", one name, or how many): a fixed width
            // cut it ("TO: THE…").
            .fixedSize()
            .accessibilityLabel(addressedInFull)
            .accessibilityIdentifier("compose-to")
            .popover(isPresented: $choosing, arrowEdge: .top) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("To").eyebrow().secondaryText().accessibilityAddTraits(.isHeader)
                    if model.members.isEmpty { Text("No other members yet").secondaryText() }
                    ForEach(model.members) { member in
                        Toggle(isOn: Binding(
                            get: { to.contains(member.id) },
                            set: { on in if on { to.insert(member.id) } else { to.remove(member.id) } }
                        )) { Text(member.name) }
                            .accessibilityIdentifier("to-\(member.name)")
                    }
                }
                .font(Theme.text)
                .padding(12)
            }
            Toggle(isOn: $urgent) { Text("Urgent") }
                .fixedSize()
                .accessibilityIdentifier("compose-urgent")
                .accessibilityLabel(urgent ? "Urgent, on" : "Urgent, off")
        }
        .caption()
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
