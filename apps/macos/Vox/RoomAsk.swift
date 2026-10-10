// A repo with no room (ADR-029 RB-5 to RB-7): a harness session started in a directory the room
// map does not name works in no room, and Vox asks the person, not only the agent in its session:
// one banner across the top of the window (the decider's sidebar ruling, v0.4.3: no NEEDS YOU
// section). The words are the TUI's and `vox agent status`'s (CL-1); the sentence is the daemon's
// own. The room's passphrase is typed here, never given to an agent (RB-6).

import SwiftUI

/// Every ask, one line each, across the window; and what the last answer did, until dismissed.
/// Nothing when there is neither.
struct RoomAskBanner: View {
    @ObservedObject var model: NodeModel

    var body: some View {
        if !model.roomAsks.isEmpty || model.roomAskSaid != nil {
            VStack(alignment: .leading, spacing: Space.s8) {
                ForEach(model.roomAsks, id: \.dir) { ask in
                    RoomAskLine(model: model, ask: ask).id(ask.dir)
                }
                if let said = model.roomAskSaid {
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: Space.s4) {
                            ForEach(Array(said.said.enumerated()), id: \.offset) { _, line in
                                if said.done {
                                    Text(line)
                                } else {
                                    StateMark(kind: .danger, words: line)
                                }
                            }
                        }
                        .accessibilityElement(children: .combine)
                        .accessibilityIdentifier(said.done ? "room-ask-said" : "room-ask-failed")
                        Spacer()
                        Button("Dismiss") { model.clearRoomAskSaid() }
                            .accessibilityIdentifier("room-ask-dismiss")
                    }
                }
                OutcomeMark(outcome: model.failure(of: "bind-room")
                    ?? model.failure(of: "decline-room"))
            }
            .padding(.horizontal, Space.s16)
            .padding(.vertical, Space.s8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .raisedSurface()
            .textSelection(.enabled)
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("room-ask-banner")
            Divider()
        }
    }
}

/// One ask: "Claude Code in /opt/vox has no room", and the two answers. Choose a room… binds the
/// directory to a room this node holds, or to one by its pasted link, with the room's passphrase
/// typed here: what `vox room join <link> --node <node> --bind <dir>` does, and every session
/// waiting there is put in that room. Not this repo records a no, as `vox agent room --none` does.
private struct RoomAskLine: View {
    @ObservedObject var model: NodeModel
    let ask: RoomAskInfo
    @State private var choosing = false
    /// The room chosen from this node's, by id; nil when a link is pasted instead.
    @State private var room: String?
    @State private var link = ""
    @State private var field = SecureFieldHolder()
    @State private var noPassphrase = true
    @State private var submitting = false

    private var dir: String { ask.dir }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s8) {
            HStack {
                Text(ask.sentence)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .accessibilityIdentifier("room-ask-sentence")
                Spacer()
                if !choosing {
                    Button("Choose a room…") { choosing = true }
                        .buttonStyle(.voxPrimary)
                        .accessibilityIdentifier("room-ask-choose")
                    Button("Not this repo") { Task { await model.declineRoom(dir) } }
                        .help("No session started here is asked again.")
                        .accessibilityIdentifier("room-ask-decline")
                }
            }
            if choosing { chooser(ask) }
        }
    }

    @ViewBuilder private func chooser(_ ask: RoomAskInfo) -> some View {
        Hairline()
        Text("One of your rooms").eyebrow()
        let open = model.rooms.filter(\.open)
        if open.isEmpty { Text("You hold no open room.").secondaryText() }
        if !open.isEmpty {
            Picker("Room", selection: $room) {
                ForEach(open) { r in Text(r.name).tag(Optional(r.id)) }
            }
            .pickerStyle(.radioGroup)
            .labelsHidden()
            .accessibilityIdentifier("room-ask-rooms")
            .onChange(of: room) { if $0 != nil { link = "" } }
        }
        Text("Or its link").eyebrow()
        TextField("Room link (vox://…)", text: $link).font(Theme.mono)
            .accessibilityLabel("Room link")
            .accessibilityIdentifier("room-ask-link")
            .onChange(of: link) { if !$0.isEmpty { room = nil } }
        Text(passphraseWords(ask)).secondaryText()
        SecureInput(holder: field, onEmpty: { noPassphrase = $0 }) { submit() }
            .frame(width: Theme.scaled(320))
            .accessibilityLabel("Room passphrase")
            .accessibilityIdentifier("room-ask-passphrase")
        if noPassphrase {
            Text("No passphrase: for a room that has none.").secondaryText()
        }
        HStack {
            Button("Cancel") { choosing = false }
            Button("Bind") { submit() }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.voxPrimary)
                .disabled(submitting || (room == nil && link.isEmpty))
                .accessibilityIdentifier("room-ask-bind")
        }
    }

    /// What is said of the passphrase before it is typed (ADR-028 E-5): who can read it once saved.
    private func passphraseWords(_ ask: RoomAskInfo) -> String {
        let nodes = ask.nodes.joined(separator: ", ")
        return "The room's passphrase. It is saved for this repo in the room map, which every "
            + "node on this Mac can read, so \(nodes) can join the room with it. No agent is "
            + "asked for it."
    }

    private func submit() {
        guard !submitting, room != nil || !link.isEmpty else { return }
        submitting = true
        let secret = field.takeAllowingEmpty()
        noPassphrase = true
        let (r, l) = (room, link)
        Task {
            if await model.bindRoom(dir, room: r, link: r == nil ? l : nil, passphrase: secret) {
                choosing = false
            }
            submitting = false
        }
    }
}
