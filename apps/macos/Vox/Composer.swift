// The composer's To: and urgent (ADR-014 M-15): who a message is addressed to, and whether it may
// interrupt their agents mid-turn.

import AppKit
import SwiftUI

/// **⇧↩ adds a line** in a composer (P19), as ⌥↩ does, while the field has the keyboard; Return
/// still sends. ⌥↩ alone was not enough: on a Mac where a global hotkey takes ⌥↩ (the decider's
/// brings Alacritty forward), the composer never sees it. ⇧↩ is the common convention.
struct ShiftReturnAddsLine: ViewModifier {
    /// Whether the composer has the keyboard: only then is ⇧↩ taken.
    let focused: Bool
    @State private var monitor: Any?

    func body(content: Content) -> some View {
        content
            .onAppear { watch(focused) }
            .onChange(of: focused) { watch($0) }
            .onDisappear { watch(false) }
    }

    private func watch(_ on: Bool) {
        if let monitor { NSEvent.removeMonitor(monitor) }
        monitor = nil
        guard on else { return }
        monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            let held = event.modifierFlags.intersection([.shift, .command, .option, .control])
            guard held == .shift, event.keyCode == 36 || event.keyCode == 76 else { return event }
            // The line goes in where the insertion point is, as ⌥↩ puts it.
            NSApp.sendAction(#selector(NSResponder.insertNewlineIgnoringFieldEditor(_:)), to: nil, from: nil)
            return nil
        }
    }
}

extension View {
    /// ⇧↩ adds a line while `focused` (see `ShiftReturnAddsLine`).
    func shiftReturnAddsLine(_ focused: Bool) -> some View { modifier(ShiftReturnAddsLine(focused: focused)) }
}

/// To: and urgent for what the composer posts (M-15): the members ticked are written into `to` as
/// whole fingerprints, and a member's open Session as `<fingerprint>/<session id>`, the addressing
/// `vox room post --to <member>/<session>` sends (MADR W-4, ADR-029 TA-1); urgent may interrupt
/// their agents mid-turn.
struct ComposerAddress: View {
    @Environment(\.voxTextScale) private var scale
    @ObservedObject var model: NodeModel
    @Binding var to: Set<String>
    @Binding var urgent: Bool
    @State private var choosing = false

    var body: some View {
        HStack(spacing: Space.s8 * scale) {
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
                VStack(alignment: .leading, spacing: Space.s8 * scale) {
                    Text("To").eyebrow().secondaryText().accessibilityAddTraits(.isHeader)
                    if model.members.isEmpty { Text("No other members yet").secondaryText() }
                    ForEach(model.members) { member in
                        tick(member.id, member.name, id: "to-\(member.name)")
                        // Its open Sessions, under it: one of them alone can be written to.
                        ForEach(openSessions(of: member.id), id: \.sessionId) { s in
                            tick("\(member.id)/\(s.sessionId)", s.title,
                                 id: "to-\(member.name)-\(s.shortId)")
                                .voxPadding(.leading, Space.s20)
                        }
                    }
                }
                // Part of the composer, so at the conversation's text size (L-1b).
                .conversationScale(Theme.scale)
                .voxPadding(Space.s12)
            }
            Toggle(isOn: $urgent) { Text("Urgent") }
                .fixedSize()
                .accessibilityIdentifier("compose-urgent")
                .accessibilityLabel(urgent ? "Urgent, on" : "Urgent, off")
        }
        .caption()
    }

    /// A line of the To: list: ticked, it is in `to` as `address`.
    private func tick(_ address: String, _ name: String, id: String) -> some View {
        Toggle(isOn: Binding(
            get: { to.contains(address) },
            set: { on in if on { to.insert(address) } else { to.remove(address) } }
        )) { Text(name) }
            .accessibilityIdentifier(id)
    }

    /// A member's Sessions open in the room on screen.
    private func openSessions(of member: String) -> [FfiSession] {
        model.sessions.filter { $0.open && $0.nodeFingerprint == member }
    }

    /// What is ticked, by name: each member, and each Session by its label.
    private var names: [String] {
        model.members.flatMap { member -> [String] in
            (to.contains(member.id) ? [member.name] : [])
                + openSessions(of: member.id)
                .filter { to.contains("\(member.id)/\($0.sessionId)") }
                .map(\.title)
        }
    }

    /// Short enough for the composer's row at the window's narrowest: one name, or how many.
    private var addressed: String {
        switch names.count {
        case 0: return "To: the room"
        case 1: return "To: \(names[0])"
        default: return "To: \(names.count) addressees"
        }
    }

    /// Every name, for VoiceOver and the proofs.
    private var addressedInFull: String {
        names.isEmpty ? "To: the room" : "To: " + names.joined(separator: ", ")
    }
}
