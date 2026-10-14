// The slim room composer's address/urgency tokens and field menu (ADR-033 CO-1, CO-2).

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
        Button { choosing.toggle() } label: {
            Image(systemName: "ellipsis.circle")
        }
        .buttonStyle(.borderless)
        .help("Message options: To and Urgent")
        .accessibilityLabel(addressedInFull)
        .accessibilityIdentifier("compose-to")
        .popover(isPresented: $choosing, arrowEdge: .top) {
            VStack(alignment: .leading, spacing: Space.s8 * scale) {
                Toggle(isOn: $urgent) { Text("Urgent") }
                    .accessibilityIdentifier("compose-urgent")
                    .accessibilityLabel(urgent ? "Urgent, on" : "Urgent, off")
                Hairline()
                ScrollView {
                    VStack(alignment: .leading, spacing: Space.s8 * scale) {
                        Text("To").eyebrow().secondaryText().accessibilityAddTraits(.isHeader)
                        if model.members.isEmpty { Text("No other members yet").secondaryText() }
                        ForEach(model.members) { member in
                            tick(member.id, member.name, id: "to-\(member.name)")
                            // Its open Sessions, under it: one of them alone can be written to.
                            ForEach(openSessions(of: member.id), id: \.sessionId) { s in
                                tick("\(member.id)/\(s.sessionId)", s.label,
                                     id: "to-\(member.name)-\(s.shortId)")
                                    .voxPadding(.leading, Space.s20)
                            }
                        }
                    }
                }
                .frame(maxHeight: 280 * scale)
            }
            .conversationScale(Theme.scale)
            .voxPadding(Space.s12)
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
    private var names: [String] { to.sorted().map { Self.name($0, model: model) } }

    /// Every name, for VoiceOver and the proofs.
    private var addressedInFull: String {
        names.isEmpty ? "To: the room" : "To: " + names.joined(separator: ", ")
    }

    /// A saved target never silently disappears when its member or Session leaves the roster.
    static func name(_ address: String, model: NodeModel) -> String {
        let parts = address.split(separator: "/", maxSplits: 1).map(String.init)
        guard let member = parts.first else { return address }
        let name = model.members.first { $0.id == member }?.name ?? String(member.prefix(12))
        guard parts.count == 2 else { return name }
        let session = model.sessions.first { $0.nodeFingerprint == member && $0.sessionId == parts[1] }
        return "\(name) / \(session?.label ?? String(parts[1].prefix(8)))"
    }
}

/// Tokens are the selected effects, not a second copy of syntax that send could parse again.
struct ComposerTokens: View {
    @Environment(\.voxTextScale) private var scale
    @ObservedObject var model: NodeModel
    @Binding var to: Set<String>
    @Binding var urgent: Bool

    var body: some View {
        if urgent || !to.isEmpty {
            ScrollView(.horizontal) {
                HStack(spacing: Space.s4 * scale) {
                    if urgent {
                        token("! Urgent", id: "compose-remove-urgent", help: "Remove urgency") { urgent = false }
                    }
                    ForEach(to.sorted(), id: \.self) { address in
                        let name = ComposerAddress.name(address, model: model)
                        token("@\(name)", id: "compose-remove-to-\(address)", help: "Remove address to \(name)") {
                            to.remove(address)
                        }
                    }
                }
            }
            .scrollIndicators(.hidden)
            // Keep a usable viewport beside the elastic text field, even in a narrow room.
            .frame(minWidth: 96 * scale, idealWidth: 160 * scale, maxWidth: 160 * scale)
            .frame(height: Space.s24 * scale)
        }
    }

    private func token(_ title: String, id: String, help: String, remove: @escaping () -> Void) -> some View {
        Button(action: remove) {
            HStack(spacing: Space.s4 * scale) {
                Text(title).lineLimit(1)
                Image(systemName: "xmark")
            }
            .caption()
            .voxPadding(.horizontal, Space.s8)
            .voxPadding(.vertical, Space.s4)
            .background(RoundedRectangle(cornerRadius: Radius.control * scale).fill(VoxTokens.Colors.bgPanel))
            .cardOutline()
        }
        .buttonStyle(.plain)
        .help(help)
        .accessibilityLabel(help)
        .accessibilityIdentifier(id)
    }
}

/// Convert completed person-input syntax to exact targets. A partial alias stays editable;
/// submission also completes the final word. Unknown or ambiguous names remain ordinary text.
enum ComposerInput {
    static func tokens(_ input: String, members: [NodeModel.MemberRow], finish: Bool)
        -> (text: String, to: Set<String>, urgent: Bool) {
        var text = input, urgent = false, leading = true
        let aliases = Dictionary(grouping: members, by: { $0.name.lowercased() })
        var addressed: Set<String> = [], removed: [Range<String.Index>] = []
        var start = text.startIndex
        while start < text.endIndex {
            if text[start].isWhitespace { start = text.index(after: start); continue }
            let end = text[start...].firstIndex(where: \.isWhitespace) ?? text.endIndex
            var content = start
            // Consume the complete leading syntax once. After removing its token, sending
            // must not find another leading ! left behind by a pasted "!! @name message".
            if leading {
                while content < end, text[content] == "!" {
                    urgent = true
                    content = text.index(after: content)
                }
            }
            let word = text[content..<end]
            if (end < text.endIndex || finish), word.first == "@" {
                let alias = word.dropFirst().trimmingCharacters(in: .punctuationCharacters.subtracting(["#"]))
                if let matches = aliases[alias.lowercased()], matches.count == 1 {
                    addressed.insert(matches[0].id)
                    removed.append(start..<end)
                    start = end
                    continue
                }
            }
            if content != start { removed.append(start..<content) }
            if content < end { leading = false }
            start = end
        }
        for range in removed.reversed() { text.removeSubrange(range) }
        return (text, addressed, urgent)
    }
}
