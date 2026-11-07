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
    @State private var deciding = false
    @State private var bindingDecision: RoomDecisionInfo?
    @State private var decisionError: String?

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
                Button("Not This Repo") { deciding = true }
                    .help("Review the scope before changing the repository decision.")
                    .accessibilityIdentifier("room-ask-decline")
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
        .sheet(isPresented: $deciding) {
            RepoDecisionView(model: model, directory: ask.dir, decline: true) {
                deciding = false
                model.finishRoomAsk()
                Task { await model.readRoomAsks() }
            }
        }
    }

    @ViewBuilder private var form: some View {
        Hairline()
        if !ask.room.isEmpty {
            if let decision = bindingDecision {
                Text("Repository: \(decision.target)")
                Text("Current room: \(decision.room); source: \(decision.source)")
                Text(decision.source == decision.target ? "Exact binding." : "Inherited binding; the parent remains unchanged.")
                    .secondaryText()
            } else if let decisionError {
                Text(decisionError)
            } else {
                ProgressView("Inspecting repository decision…")
            }
        }
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
                .disabled((!ask.room.isEmpty && bindingDecision == nil) ||
                          (choice == .creating ? name.isEmpty : (room == nil && link.isEmpty)))
                .accessibilityIdentifier("room-ask-bind")
        }
    }

    private func choose(_ next: Choice?) {
        field.clear()
        noPassphrase = true
        choice = next
        model.clearRoomAskFailure()
        bindingDecision = nil
        decisionError = nil
        if next == .choosing && !ask.room.isEmpty {
            Task {
                do { bindingDecision = try await model.inspectRoomDecision(ask.dir) }
                catch { decisionError = sentence(error) }
            }
        }
    }

    private func submit() {
        guard !submitting, (ask.room.isEmpty || bindingDecision != nil),
              choice == .creating ? !name.isEmpty : (room != nil || !link.isEmpty) else { return }
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
                done = await model.bindRoom(ask.dir, room: r, link: r == nil ? l : nil,
                                            passphrase: secret, decision: bindingDecision)
            }
            submitting = false
            if !done && !ask.room.isEmpty {
                bindingDecision = nil
                decisionError = "The decision must be inspected again. Choose Back to review it."
            }
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

}

/// An explicitly inspected, stale-safe repository decision, independent of any pending ask.
struct RepoDecisionView: View {
    @ObservedObject var model: NodeModel
    let directory: String
    let decline: Bool
    let finished: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var decision: RoomDecisionInfo?
    @State private var error: String?
    @State private var answer: RoomAnswerInfo?
    @State private var room: String?
    @State private var link = ""
    @State private var field = SecureFieldHolder()
    @State private var empty = true
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s12) {
            Text(decline ? "Not This Repo" : "Rebind Repository").title()
            if let decision {
                Text("Repository: \(decision.target)")
                Text("Resolved decision: \(decision.room.isEmpty ? "unbound" : decision.room)")
                Text(decision.source.isEmpty ? "No source block." :
                     "Source: \(decision.source)" + (decision.source == decision.target ? " (exact)" : " (inherited)"))
                Text("This affects future sessions across all nodes and harnesses in this data root. Existing sessions do not move; no room is left and trust does not change. More-specific overrides remain effective. Replacing an exact block discards its saved link and passphrase; these are needed again to rebind.")
                    .secondaryText()
                if !decline {
                    let open = model.rooms.filter(\.open)
                    if !open.isEmpty {
                        Picker("Room", selection: $room) {
                            Text("Use a link").tag(Optional<String>.none)
                            ForEach(open) { r in Text(r.name).tag(Optional(r.id)) }
                        }
                    }
                    if room == nil { TextField("Room link (vox://…)", text: $link) }
                    Text("The passphrase is saved in the room map, readable by every node in this data root; agents are not given it.").secondaryText()
                    SecureInput(holder: field, onEmpty: { empty = $0 }) { submit() }
                        .accessibilityLabel("Room passphrase")
                }
                HStack {
                    Button("Cancel") { dismiss() }
                    Button(decline ? "Confirm Not This Repo" : "Rebind") { submit() }
                        .buttonStyle(.voxPrimary)
                        .disabled(busy || (!decline && room == nil && link.isEmpty))
                }
            } else {
                Button("Cancel") { dismiss() }
                if error != nil { Button("Inspect Again") { inspect() } }
            }
            if busy { ProgressView("Updating repository decision…") }
            if let error { Text(error) }
            if let answer { Text(answer.said.joined(separator: "\n")) }
        }
        .padding(Space.s24)
        .frame(width: Theme.scaled(500))
        .task { inspect() }
        .onDisappear { field.clear() }
    }
    private func inspect() {
        error = nil
        Task {
            do { decision = try await model.inspectRoomDecision(directory) }
            catch { self.error = sentence(error) }
        }
    }


    private func submit() {
        guard let decision, !busy else { return }
        busy = true
        let secret = decline ? Secret(Data()) : field.copyAllowingEmpty()
        Task {
            do {
                let result = try await model.replaceRoomDecision(decision, room: decline ? nil : room,
                                                                  link: decline ? "" : link, secret: secret)
                answer = result
                if result.done { field.clear(); finished(); dismiss() }
                else { self.decision = nil; error = "The decision must be inspected again before retrying." }
            } catch { self.decision = nil; self.error = sentence(error) }
            busy = false
        }
    }
}
