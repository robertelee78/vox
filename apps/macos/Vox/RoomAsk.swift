// A repo with no room (ADR-031 RM-1–RM-5): one dialog per canonical repository, naming the
// harnesses waiting there. The room passphrase is typed here, never given to an agent. Creation
// uses the app's selected node; bind checks the passphrase before saving the room map.

import SwiftUI

struct RoomAskDialog: View {
    @ObservedObject var model: NodeModel
    let ask: RoomAskInfo
    private enum Choice { case choosing, creating }
    @State private var choice: Choice?
    @State private var name = ""
    /// A held room by id, or nil when a link is pasted.
    @State private var room: String?
    @State private var link = ""
    @State private var field = SecureFieldHolder()
    @State private var noPassphrase = true
    @State private var submitting = false

    /// One DNS label (ADR-028 R-2), with an editable name when the directory has no such letters.
    private var suggestedName: String {
        let directory = URL(fileURLWithPath: ask.dir).lastPathComponent
        let letters = directory.lowercased().unicodeScalars.map { c -> String in
            (c.value >= 97 && c.value <= 122) || (c.value >= 48 && c.value <= 57)
                ? String(c) : "-"
        }.joined()
        let folded = letters.split(separator: "-").joined(separator: "-")
        let capped = String(folded.prefix(63)).trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return capped.isEmpty ? "repo" : capped
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s12) {
            Text(ask.sentence).title()
                .accessibilityIdentifier("room-ask-sentence")
            if choice == nil {
                if ask.room.isEmpty {
                    Button("Create Room \"\(suggestedName)\"") {
                        name = suggestedName
                        choose(.creating)
                    }
                    .buttonStyle(.voxPrimary)
                    .accessibilityIdentifier("room-ask-create")
                } else {
                    Button("Join It") { joinBound() }
                        .buttonStyle(.voxPrimary)
                        .accessibilityIdentifier("room-ask-join")
                }
                Button(ask.room.isEmpty ? "Choose a Room…" : "Choose Another Room…") {
                    choose(.choosing)
                }
                .accessibilityIdentifier("room-ask-choose")
                if ask.room.isEmpty {
                    Button("Not This Repo") { decline() }
                        .help("No session started in this repository is asked again.")
                        .accessibilityIdentifier("room-ask-decline")
                }
            } else {
                form
            }
            if submitting { ProgressView("Binding the room…") }
            if let answer = model.roomAskSaid, !answer.done {
                Text(answer.said.joined(separator: "\n"))
                    .accessibilityIdentifier("room-ask-failed")
            }
            OutcomeMark(outcome: model.failure(of: "bind-room")
                ?? model.failure(of: "decline-room"))
        }
        .padding(Space.s24)
        .frame(width: Theme.scaled(480))
        .disabled(submitting)
        .interactiveDismissDisabled()
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("room-ask-dialog")
        .onDisappear { field.clear() }
    }

    @ViewBuilder private var form: some View {
        Hairline()
        if choice == .creating {
            TextField("Room name", text: $name)
                .accessibilityIdentifier("room-ask-name")
            Text("Create this room as \(model.node).").secondaryText()
        } else {
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
        }
        Text("The room's passphrase. It is saved for this repo in the room map, which every "
             + "node on this Mac can read, so \(ask.nodes.joined(separator: ", ")) can join "
             + "the room with it. No agent is asked for it.").secondaryText()
        SecureInput(holder: field, onEmpty: { noPassphrase = $0 }) { submit() }
            .frame(width: Theme.scaled(320))
            .accessibilityLabel("Room passphrase")
            .accessibilityIdentifier("room-ask-passphrase")
        if noPassphrase {
            Text(choice == .creating ? "No passphrase: anyone with the link can join."
                 : "No passphrase: for a room that has none.").secondaryText()
        }
        HStack {
            Button("Back") { choose(nil) }
                .accessibilityIdentifier("room-ask-back")
            Button(choice == .creating ? "Create Room" : "Bind") { submit() }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.voxPrimary)
                .disabled(choice == .creating ? name.isEmpty : (room == nil && link.isEmpty))
                .accessibilityIdentifier("room-ask-bind")
        }
    }

    private func choose(_ next: Choice?) {
        field.clear()
        noPassphrase = true
        choice = next
        model.clearRoomAskFailure()
    }

    private func submit() {
        guard !submitting, choice == .creating ? !name.isEmpty : (room != nil || !link.isEmpty) else { return }
        submitting = true
        let secret = field.copyAllowingEmpty()
        let (r, l, n, creating) = (room, link, name, choice == .creating)
        Task {
            let done: Bool
            if creating {
                let made = await model.createRepoRoom(ask.dir, name: n, passphrase: secret)
                done = made.bound
                if !done, let created = made.room {
                    // If joining a waiting node failed, retry that bind; do not create a second room.
                    room = created
                    choice = .choosing
                }
            } else {
                done = await model.bindRoom(ask.dir, room: r, link: r == nil ? l : nil, passphrase: secret)
            }
            submitting = false
            if done { field.clear(); model.finishRoomAsk() }
        }
    }

    private func joinBound() {
        guard !submitting else { return }
        submitting = true
        Task {
            let done = await model.joinBoundRoom(ask.dir)
            submitting = false
            if done { model.finishRoomAsk() }
        }
    }

    private func decline() {
        guard !submitting else { return }
        submitting = true
        Task {
            let done = await model.declineRoom(ask.dir)
            submitting = false
            if done { model.finishRoomAsk() }
        }
    }
}
