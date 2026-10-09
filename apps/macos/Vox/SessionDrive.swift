// Driving a Session from the app (ADR-029 DR-1, CL-1, #554): its composer, Interrupt and Stop, a
// file sent in, and an approval or a question answered, each said in the TUI's and the CLI's words.
// Whether the input is taken is the session's node's to say (DR-2); the app shows what it said.

import SwiftUI

/// What came of driving a Session: taken, refused (not delivered or not sent), or not known
/// (no answer: it may or may not have arrived), with what to say of it (D13).
enum DriveResult {
    case taken(String)
    case refused(String)
    case unknown(String)

    var said: String {
        switch self {
        case let .taken(s), let .refused(s), let .unknown(s): return s
        }
    }
}

extension NodeModel {
    /// Send `action` to the Session `s` of `room`, the destination its control was drawn for (D3),
    /// and say what came of it (DR-6), as `vox room session` and the TUI say it.
    func drive(_ s: FfiSession, in room: String, _ action: DriveAction) async -> String {
        await driveResult(s, in: room, action).said
    }

    /// `drive`, telling a send that was taken from one refused or not known (D13).
    func driveResult(_ s: FfiSession, in room: String, _ action: DriveAction) async -> DriveResult {
        guard s.canDrive else {
            return .refused("you cannot drive this Session: \(s.nodeAlias) has not given you drive")
        }
        do {
            let answer = try await drive(room: room, session: s.sessionId, action: action)
            switch answer.delivery {
            case .answered:
                return answer.ok ? .taken("\(s.label): \(answer.said)")
                    : .refused("not delivered to \(s.label): \(answer.said)")
            case .unreachable:
                // A file the node could not serve says "not sent: …" already.
                let why = answer.said.hasPrefix("not sent: ") ? String(answer.said.dropFirst(10)) : answer.said
                return .refused("not sent to \(s.label): \(why)")
            case .noAnswer:
                return .unknown("no answer from \(s.label): it may or may not have been delivered")
            }
        } catch {
            return .refused(sentence(error))
        }
    }
}

/// A Session's composer, to a member with drive (DR-1): what is typed goes to the session as its
/// operator's input, a line starting with "/" as a slash command; Interrupt (Esc), Stop (Ctrl-C),
/// and a file sent in. What came of the last of them is said under it.
struct SessionComposer: View {
    @ObservedObject var model: NodeModel
    /// The room it was drawn in: what it sends goes there and to `session` only (D3).
    let room: String
    let session: FfiSession
    @State private var draft = ""
    @State private var said = ""
    /// A send (or a file) waiting for its answer: only sending and the paperclip wait on it; Interrupt
    /// and Stop stay live (D13).
    @State private var sending = false
    @State private var interrupting = false
    @State private var stopping = false
    /// Asked before Stop (⌃C): it ends the session.
    @State private var confirmStop = false

    init(model: NodeModel, room: String, session: FfiSession) {
        self.model = model
        self.room = room
        self.session = session
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
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
                .disabled(sending)
                // Who types, into which Session (E-4, CL-1): never read as the room's composer.
                Text("\(model.node) ▸ \(session.label)").font(Theme.mono).secondaryText()
                    .lineLimit(1).truncationMode(.middle)
                    .accessibilityLabel("typing as \(model.node) into \(session.label)")
                    .accessibilityIdentifier("session-compose-as")
                TextField("Composer — to \(session.label)", text: $draft)
                    .accessibilityLabel("Message to \(session.label), as \(model.node)")
                    .textFieldStyle(.plain)
                    .frame(minWidth: Theme.scaled(160), maxWidth: .infinity)
                    .layoutPriority(1)
                    .onSubmit(send)
                    // Esc interrupts the turn it is running, as the tooltip says (D13).
                    .onExitCommand { interrupt() }
                    .disabled(sending)
                    .accessibilityIdentifier("session-compose")
                Button("Interrupt") { interrupt() }
                    .fixedSize()
                    .help("Interrupt the turn it is running (Esc)")
                    .disabled(interrupting)
                    .accessibilityIdentifier("session-interrupt")
                Button("Stop") { confirmStop = true }
                    .fixedSize()
                    .help("Stop it (Ctrl-C)")
                    .keyboardShortcut("c", modifiers: .control)
                    .disabled(stopping)
                    .accessibilityIdentifier("session-stop")
            }
            .confirmationDialog("Stop \(session.label)? It ends the session.", isPresented: $confirmStop) {
                Button("Stop the Session", role: .destructive) { stop() }
                    .accessibilityIdentifier("session-stop-confirm")
                Button("Cancel", role: .cancel) {}
            }
            if !said.isEmpty {
                Text(said)
                    .secondaryText()
                    .lineLimit(3)
                    .textSelection(.enabled)
                    .accessibilityIdentifier("session-said")
            }
        }
        .padding(12)
        // Its draft, kept per Session while the app runs, in memory only (D12).
        .onAppear { draft = model.sessionDrafts[key] ?? "" }
        .onChange(of: draft) { model.sessionDrafts[key] = $0 }
        // ⌘O while this Session is shown: a file sent to it, not the room (D2).
        .onChange(of: model.sessionAttachAsked) { _ in
            DispatchQueue.main.async {
                if let url = chooseFile() { act(.file(path: url.path, note: nil)) }
            }
        }
    }

    /// The Session's destination, which its draft is kept under.
    private var key: String { "\(room)/\(session.nodeFingerprint)/\(session.sessionId)" }

    /// Type the draft, or send it as a slash command when it starts with "/". The text stays
    /// until the session's node has taken it (D13): refused, it is back as typed; with no answer,
    /// it is back marked "delivery unknown", and never sent again by itself.
    private func send() {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, !sending else { return }
        sending = true
        let action: DriveAction = text.hasPrefix("/") ? .slash(command: text) : .text(text: text)
        Task {
            let result = await model.driveResult(session, in: room, action)
            switch result {
            case .taken:
                if draft.trimmingCharacters(in: .whitespacesAndNewlines) == text { draft = "" }
                said = result.said
            case .refused:
                said = result.said
            case .unknown:
                said = result.said + " (delivery unknown: your text is kept; send it again if it did not arrive)"
            }
            sending = false
        }
    }

    /// Interrupt the turn it is running (Esc or the button), live while a send waits (D13).
    private func interrupt() {
        guard !interrupting else { return }
        interrupting = true
        Task {
            said = await model.drive(session, in: room, .interrupt)
            interrupting = false
        }
    }

    /// Stop the session, once asked (⌃C or the button).
    private func stop() {
        guard !stopping else { return }
        stopping = true
        Task {
            said = await model.drive(session, in: room, .stop)
            stopping = false
        }
    }

    /// A file sent in: it waits as a send does.
    private func act(_ action: DriveAction) {
        sending = true
        Task {
            said = await model.drive(session, in: room, action)
            sending = false
        }
    }
}

/// An approval or a question a Session asked (DR-4), in its entry's row: Approve and Reject, or
/// each part's options, while it waits on the reader; once it is settled, what became of it.
struct RequestView: View {
    @ObservedObject var model: NodeModel
    /// The room it was drawn in: Approve, Reject and an answer go there and to `session` (D3).
    let room: String
    let session: FfiSession
    let request: FfiRequest
    /// What the request asks, as its entry's line says it: its buttons name it to VoiceOver.
    let about: String
    @State private var why = ""
    /// Each part's chosen option, by its index, for a question of several parts.
    @State private var chosen: [Int: String] = [:]
    @State private var said = ""
    @State private var busy = false

    init(model: NodeModel, room: String, session: FfiSession, request: FfiRequest, about: String = "") {
        self.model = model
        self.room = room
        self.session = session
        self.request = request
        self.about = about
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
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
        HStack(spacing: 8) {
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
        return VStack(alignment: .leading, spacing: 6) {
            ForEach(parts.indices, id: \.self) { i in
                VStack(alignment: .leading, spacing: 4) {
                    Text(parts[i].text)
                    HStack(spacing: 6) {
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
            said = await model.drive(session, in: room, action)
            busy = false
        }
    }
}
