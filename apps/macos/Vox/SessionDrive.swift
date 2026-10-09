// Driving a Session from the app (ADR-029 DR-1, CL-1, #554): its composer, Interrupt and Stop, a
// file sent in, and an approval or a question answered, each said in the TUI's and the CLI's words.
// Whether the input is taken is the session's node's to say (DR-2); the app shows what it said.

import SwiftUI

extension NodeModel {
    /// Send `action` to the Session `s` of the room on screen, and say what came of it (DR-6), as
    /// `vox room session` and the TUI say it.
    func drive(_ s: FfiSession, _ action: DriveAction) async -> String {
        guard s.canDrive else {
            return "you cannot drive this Session: \(s.nodeAlias) has not given you drive"
        }
        guard let room = roomOnScreen else { return "not sent to \(s.label): no room is on screen" }
        do {
            let answer = try await drive(room: room, session: s.sessionId, action: action)
            switch answer.delivery {
            case .answered:
                return answer.ok ? "\(s.label): \(answer.said)" : "not delivered to \(s.label): \(answer.said)"
            case .unreachable:
                // A file the node could not serve says "not sent: …" already.
                let why = answer.said.hasPrefix("not sent: ") ? String(answer.said.dropFirst(10)) : answer.said
                return "not sent to \(s.label): \(why)"
            case .noAnswer:
                return "no answer from \(s.label): it may or may not have been delivered"
            }
        } catch {
            return sentence(error)
        }
    }
}

/// A Session's composer, to a member with drive (DR-1): what is typed goes to the session as its
/// operator's input, a line starting with "/" as a slash command; Interrupt (Esc), Stop (Ctrl-C),
/// and a file sent in. What came of the last of them is said under it.
struct SessionComposer: View {
    @Environment(\.voxTextScale) private var scale
    @ObservedObject var model: NodeModel
    let session: FfiSession
    @State private var draft = ""
    @State private var said = ""
    @State private var busy = false

    init(model: NodeModel, session: FfiSession) {
        self.model = model
        self.session = session
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s8 * scale) {
            HStack(spacing: Space.s8 * scale) {
                Button {
                    if let url = chooseFile() {
                        act(.file(path: url.path, note: nil))
                    }
                } label: {
                    Image(systemName: "paperclip")
                }
                .buttonStyle(.borderless)
                .help("Send the session a file")
                .accessibilityLabel("Send the session a file")
                .accessibilityIdentifier("session-attach")
                TextField("Composer — to \(session.label)", text: $draft)
                    .accessibilityLabel("Message to \(session.label)")
                    .textFieldStyle(.plain)
                    .frame(minWidth: Theme.scaled(160), maxWidth: .infinity)
                    .layoutPriority(1)
                    .onSubmit(send)
                    .accessibilityIdentifier("session-compose")
                Button("Interrupt") { act(.interrupt) }
                    .fixedSize()
                    .help("Interrupt the turn it is running (Esc)")
                    .accessibilityIdentifier("session-interrupt")
                Button("Stop") { act(.stop) }
                    .fixedSize()
                    .help("Stop it (Ctrl-C)")
                    .accessibilityIdentifier("session-stop")
            }
            .disabled(busy)
            if !said.isEmpty {
                Text(said)
                    .secondaryText()
                    .lineLimit(3)
                    .textSelection(.enabled)
                    .accessibilityIdentifier("session-said")
            }
        }
        .voxPadding(Space.s12)
    }

    /// Type the draft, or send it as a slash command when it starts with "/".
    private func send() {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        draft = ""
        act(text.hasPrefix("/") ? .slash(command: text) : .text(text: text))
    }

    private func act(_ action: DriveAction) {
        busy = true
        Task {
            said = await model.drive(session, action)
            busy = false
        }
    }
}

/// An approval or a question a Session asked (DR-4), in its entry's row: Approve and Reject, or
/// each part's options, while it waits on the reader; once it is settled, what became of it.
struct RequestView: View {
    @Environment(\.voxTextScale) private var scale
    @ObservedObject var model: NodeModel
    let session: FfiSession
    let request: FfiRequest
    /// What the request asks, as its entry's line says it: its buttons name it to VoiceOver.
    let about: String
    @State private var why = ""
    /// Each part's chosen option, by its index, for a question of several parts.
    @State private var chosen: [Int: String] = [:]
    @State private var said = ""
    @State private var busy = false

    init(model: NodeModel, session: FfiSession, request: FfiRequest, about: String = "") {
        self.model = model
        self.session = session
        self.request = request
        self.about = about
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s8 * scale) {
            if let state = request.state {
                Text(state).secondaryText()
                    .accessibilityIdentifier("request-state-\(request.reference)")
            } else if session.canDrive {
                if request.isQuestion { question } else { approval }
                if !said.isEmpty {
                    Text(said).secondaryText().lineLimit(3).textSelection(.enabled)
                        .accessibilityIdentifier("request-said-\(request.reference)")
                }
            }
        }
        .disabled(busy)
    }

    private var approval: some View {
        HStack(spacing: Space.s8 * scale) {
            Button("Approve") { act(.approve(reference: request.reference)) }
                .accessibilityIdentifier("request-approve-\(request.reference)")
                .accessibilityLabel(about.isEmpty ? "Approve" : "Approve: \(about)")
            Button("Reject") {
                let reason = why.trimmingCharacters(in: .whitespacesAndNewlines)
                act(.reject(reference: request.reference, why: reason.isEmpty ? nil : reason))
            }
            .accessibilityIdentifier("request-reject-\(request.reference)")
            .accessibilityLabel(about.isEmpty ? "Reject" : "Reject: \(about)")
            TextField("Why (optional, told to the model)", text: $why)
                .accessibilityLabel("Why you reject it (optional, told to the model)")
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: Theme.scaled(260))
                .accessibilityIdentifier("request-why-\(request.reference)")
        }
    }

    /// One row of options per part. A question of one part is answered by its option alone; one of
    /// several is answered once every part has a choice.
    private var question: some View {
        let parts = request.questions
        // Numbered across the parts, so each option's id is one of a kind in the request.
        let offsets = parts.indices.map { i in parts[..<i].reduce(0) { $0 + $1.options.count } }
        return VStack(alignment: .leading, spacing: Space.s8 * scale) {
            ForEach(parts.indices, id: \.self) { i in
                VStack(alignment: .leading, spacing: Space.s4 * scale) {
                    Text(parts[i].text)
                    HStack(spacing: Space.s8 * scale) {
                        ForEach(parts[i].options.indices, id: \.self) { n in
                            let option = parts[i].options[n]
                            Button(option) { pick(part: i, option) }
                                .selectionMark(chosen[i] == option)
                                .accessibilityIdentifier("request-option-\(request.reference)-\(offsets[i] + n + 1)")
                                .accessibilityLabel("\(option), answer to \(parts[i].text)")
                                .accessibilityAddTraits(chosen[i] == option ? .isSelected : [])
                        }
                    }
                }
            }
            if parts.count > 1 {
                Button("Send answers") { answer() }
                    .disabled(chosen.count < parts.count)
                    .accessibilityIdentifier("request-send-\(request.reference)")
            }
        }
    }

    private func pick(part: Int, _ option: String) {
        chosen[part] = option
        if request.questions.count == 1 { answer() }
    }

    /// Each part's answer under its text, as the node takes it.
    private func answer() {
        var answers: [String: String] = [:]
        for (i, q) in request.questions.enumerated() {
            guard let a = chosen[i] else { return }
            answers[q.text] = a
        }
        act(.answer(reference: request.reference, answers: answers))
    }

    private func act(_ action: DriveAction) {
        busy = true
        Task {
            said = await model.drive(session, action)
            busy = false
        }
    }
}
