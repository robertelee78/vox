// ADR-033 PA-1/2/4/6: one bounded, captured room selection and explicit per-node outcomes.
// Persistent Session pause badges belong to PA-5; this sheet reports the person's action.
import SwiftUI

@MainActor
struct RoomPauseSheet: View {
    @ObservedObject var model: NodeModel
    let pausing: Bool
    @State private var capture: RoomPauseSelection?
    @State private var context = ""
    @State private var members: [String] = []
    @State private var selected: Set<String> = []
    @State private var states: [String: RoomPauseState] = [:]
    @State private var stateErrors: [String: String] = [:]
    @State private var outcomes: [String: PauseOutcome] = [:]
    @State private var failure: String?
    @State private var loading = false
    @State private var working = false
    @State private var statusEpoch = UUID()
    @State private var action = UUID()
    @State private var operation: Task<Void, Never>?

    private struct PauseOutcome {
        var state: RoomPauseState?
        var interrupted: UInt64 = 0
        var unconfirmed: UInt64 = 0
        var incomplete = false
        var finished = false
        var issue = ""
        var phase = "Waiting"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s12) {
            Text(pausing ? "Pause room agents" : "Resume room agents").font(.headline)
            Text(pausing
                 ? "Pause holds this room’s news and wakes, and interrupts the selected nodes’ sessions. Your own input still reaches them."
                 : "Resume releases held news at each session’s next turn. It does not start an ordinary turn; an urgent addressed message may wake it.")
                .fixedSize(horizontal: false, vertical: true)
            if loading { ProgressView("Reading the room’s current members…") }
            if !members.isEmpty {
                HStack {
                    Button("All \(members.count) captured nodes") { selected = Set(members) }
                    Button("None") { selected = [] }
                    Spacer()
                    Text("\(selected.count) selected").secondaryText()
                }.disabled(working || capture == nil)
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: Space.s12) {
                        ForEach(members, id: \.self) { member in
                            VStack(alignment: .leading, spacing: Space.s4) {
                                Toggle(model.roomPauseName(member), isOn: Binding(
                                    get: { selected.contains(member) },
                                    set: { if $0 { selected.insert(member) } else { selected.remove(member) } }))
                                    .disabled(working || capture == nil)
                                    .accessibilityIdentifier("pause-target-\(member)")
                                Text(stateText(member)).secondaryText()
                                    .accessibilityIdentifier("pause-state-\(member)")
                                if let outcome = outcomes[member] {
                                    Text(outcomeText(outcome)).textSelection(.enabled)
                                        .fixedSize(horizontal: false, vertical: true)
                                        .accessibilityIdentifier("pause-outcome-\(member)")
                                }
                            }
                            .task(id: statusEpoch) { await readState(member) }
                        }
                    }
                }.frame(minHeight: 140, maxHeight: 340)
            }
            if let failure {
                StateMark(kind: .danger, words: failure).textSelection(.enabled)
                    .accessibilityIdentifier("pause-failed")
            }
            HStack {
                Button("Reload targets") { Task { await load() } }.disabled(working || loading)
                Button("Refresh state") { statusEpoch = UUID() }.disabled(working || capture == nil)
                Spacer()
                Button("Done") { model.sheet = nil }.keyboardShortcut(.cancelAction).disabled(working)
                Button(pausing ? "Pause selected" : "Resume selected") { begin() }
                    .disabled(working || loading || capture == nil || selected.isEmpty)
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("pause-confirm")
            }
            if working { ProgressView(pausing ? "Pausing selected nodes…" : "Resuming selected nodes…") }
        }
        .padding(Space.s24)
        .frame(width: Theme.scaled(600))
        .task { await load() }
        .onChange(of: model.roomPauseContext) { _, value in
            guard !context.isEmpty, value != context else { return }
            invalidate()
            failure = "The room or node connection changed. Showing last known state; reload targets before another action."
        }
        .onDisappear { invalidate() }
        .interactiveDismissDisabled(working)
        .accessibilityIdentifier("room-pause-sheet")
    }

    private func invalidate() {
        if working {
            for member in outcomes.keys {
                guard var outcome = outcomes[member], !outcome.finished else { continue }
                if outcome.phase == "Waiting" {
                    outcome.phase = "Not sent: the room or node selection changed"
                } else if outcome.phase == "Pausing" || outcome.phase == "Resuming" {
                    outcome.phase = "Outcome unknown: the room or node selection changed during the request"
                } else if outcome.phase == "Pause saved" {
                    outcome.incomplete = true
                    outcome.phase = "Pause was saved; the room or node selection changed before completion was confirmed"
                }
                outcomes[member] = outcome
            }
        }
        action = UUID()
        statusEpoch = UUID()
        operation?.cancel()
        operation = nil
        working = false
        capture = nil
    }

    private func load() async {
        guard !working else { return }
        invalidate()
        context = model.roomPauseContext
        let reading = context
        loading = true
        failure = nil
        defer { if context == reading { loading = false } }
        do {
            let value = try await model.captureRoomPause(context: reading)
            guard context == reading, model.roomPauseContext == reading, !Task.isCancelled else { return }
            capture = value
            members = value.members()
            selected = Set(members)
            states = [:]
            stateErrors = [:]
            outcomes = [:]
            statusEpoch = UUID()
        } catch {
            guard context == reading, model.roomPauseContext == reading, !Task.isCancelled else { return }
            failure = sentence(error)
        }
    }

    private func readState(_ member: String) async {
        guard let capture, !working else { return }
        let reading = context, epoch = statusEpoch
        do {
            let value = try await model.readRoomPause(capture, member: member, context: reading)
            guard context == reading, statusEpoch == epoch, !working else { return }
            states[member] = value
            stateErrors.removeValue(forKey: member)
        } catch {
            guard context == reading, statusEpoch == epoch, !working else { return }
            // Keep an observed pause when a later read fails. Failure never means Resume.
            stateErrors[member] = sentence(error)
        }
    }

    private func stateText(_ member: String) -> String {
        let stale = stateErrors[member] != nil || capture == nil
        var words = "Current pause state not yet read"
        if let state = states[member] {
            if state.atMillis == 0 {
                words = "No pause recorded"
            } else {
                let when = Date(timeIntervalSince1970: Double(state.atMillis) / 1000)
                    .formatted(date: .abbreviated, time: .shortened)
                words = "\(state.paused ? "Paused" : "Resumed") by \(model.roomPauseName(state.by)) at \(when)"
            }
            if stale { words = "Last known: \(words)" }
        }
        if let error = stateErrors[member] { words += ". State unavailable: \(error)" }
        return words
    }

    private func outcomeText(_ outcome: PauseOutcome) -> String {
        var words = outcome.phase
        if let state = outcome.state, state.paused {
            words += ". \(outcome.interrupted) session interruptions confirmed"
            if outcome.unconfirmed > 0 { words += "; \(outcome.unconfirmed) not confirmed" }
            if outcome.incomplete { words += "; interruption pass incomplete" }
        }
        if !outcome.issue.isEmpty { words += ". First interruption issue: \(outcome.issue)" }
        return words
    }

    private func current(_ token: UUID, _ captured: String) -> Bool {
        action == token && context == captured && model.roomPauseContext == captured && !Task.isCancelled
    }

    private func begin() {
        guard let capture, !working, !selected.isEmpty, context == model.roomPauseContext else { return }
        let targets = members.filter { selected.contains($0) }
        let captured = context, token = UUID()
        action = token
        statusEpoch = UUID() // Retire any status read begun before this mutation.
        outcomes = Dictionary(uniqueKeysWithValues: targets.map { ($0, PauseOutcome()) })
        working = true
        failure = nil
        operation = Task { @MainActor in
            // Four in-flight targets at most. Every continuation stays with its exact capture;
            // one aggregate per target remains, regardless of how many Sessions it interrupts.
            for start in stride(from: 0, to: targets.count, by: 4) {
                guard current(token, captured) else { break }
                let workers = targets[start..<min(start + 4, targets.count)].map { member in
                    Task { @MainActor in await change(capture, member: member, token: token, context: captured) }
                }
                for worker in workers { await worker.value }
            }
            guard current(token, captured) else { return }
            working = false
            operation = nil
            statusEpoch = UUID() // Read current state; never reapply an uncertain action.
        }
    }

    private func change(_ capture: RoomPauseSelection, member: String, token: UUID, context captured: String) async {
        var outcome = PauseOutcome()
        outcome.phase = pausing ? "Pausing" : "Resuming"
        var next: RoomPauseContinuation?
        while current(token, captured) {
            outcomes[member] = outcome
            do {
                let page = try await model.changeRoomPause(capture, member: member, paused: pausing,
                                                           next: next, context: captured)
                guard current(token, captured) else { return }
                switch page.delivery {
                case .confirmed:
                    outcome.state = page.state
                    outcome.interrupted += UInt64(page.interrupted)
                    outcome.unconfirmed += UInt64(page.unconfirmed)
                    if outcome.issue.isEmpty { outcome.issue = page.interruptionError ?? page.said }
                    outcome.incomplete = outcome.incomplete || page.interruptionError != nil
                    if let state = page.state { states[member] = state; stateErrors.removeValue(forKey: member) }
                    outcome.phase = pausing ? "Pause saved" : "Resumed; held news will arrive at the next turn"
                    next = page.next
                    if next == nil { outcome.finished = true; outcomes[member] = outcome; return }
                case .refused, .notSent, .unknown:
                    let label: String
                    switch page.delivery {
                    case .refused: label = "Refused"
                    case .notSent: label = "Not sent"
                    default: label = "Outcome unknown"
                    }
                    outcome.incomplete = outcome.state != nil
                    outcome.finished = true
                    outcome.phase = "\(outcome.state == nil ? "" : "Pause was saved; continuation ")\(label): \(page.said)"
                    outcomes[member] = outcome
                    return
                }
            } catch {
                guard current(token, captured) else { return }
                outcome.incomplete = outcome.state != nil
                outcome.finished = true
                outcome.phase = "\(outcome.state == nil ? "" : "Pause was saved; continuation ")Outcome unknown: \(sentence(error))"
                outcomes[member] = outcome
                return
            }
        }
    }
}
