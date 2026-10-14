// The daemon owns the machine's anchors. Settings changes only manual sources; a room's
// inspector reads its signed room endpoints separately from machine-wide identity reach.
// Neither presentation grants dialing authority.
import SwiftUI

@MainActor
final class AnchorNetworkModel: ObservableObject {
    @Published private(set) var anchors: [AnchorSummary] = []
    @Published private(set) var loaded = false
    @Published private(set) var reachable = false
    @Published private(set) var busy = false
    @Published private(set) var problem: String?
    @Published private(set) var actionProblem: String?
    private var client: VoxClient?

    @discardableResult
    func perform(refreshing: Bool = false, _ request: (VoxClient) async throws -> [AnchorSummary]) async -> Bool {
        guard !busy else { return false }
        busy = true
        if !refreshing { actionProblem = nil }
        defer { busy = false }
        do {
            let connection: VoxClient
            if let client { connection = client }
            else { connection = try await VoxClient.open(dataRoot: ""); client = connection }
            anchors = try await request(connection)
            loaded = true
            reachable = true
            problem = nil
            return true
        } catch {
            reachable = false
            if refreshing { problem = sentence(error) }
            else { actionProblem = sentence(error) }
            client = nil
            return false
        }
    }

    func follow() async {
        while !Task.isCancelled {
            await perform(refreshing: true) { try await $0.anchors() }
            do { try await Task.sleep(for: .seconds(3)) }
            catch { return }
        }
    }
}

/// One row's source and reach wording is shared by Settings and the room inspector.
struct AnchorNetworkRow: View {
    let anchor: AnchorSummary
    let reachable: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s4) {
            Text(String(anchor.fingerprint.prefix(12))).font(Theme.mono)
            Text(anchor.addresses.joined(separator: ", ")).font(Theme.mono)
                .fixedSize(horizontal: false, vertical: true)
            Text(anchor.sources.map { source in
                if source.kind == "added-by-hand" { return "added by hand" }
                let name = source.name.flatMap { $0.isEmpty ? nil : $0 }
                    ?? String((source.room ?? "").prefix(12))
                return "from room \(name)" + (source.stale ? " (last known)" : "")
            }.joined(separator: "; ")).secondaryText()
            Text(reachable ? anchor.reachText : "Reach unavailable; showing last known sources.")
                .secondaryText().accessibilityIdentifier("anchor-reach-\(anchor.fingerprint)")
        }
        .textSelection(.enabled)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("anchor-row-\(anchor.fingerprint)")
    }
}

struct NetworkSettingsView: View {
    @Environment(\.dismiss) private var dismiss
    @StateObject private var model = AnchorNetworkModel()
    @State private var input = ""

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s16) {
            Text("Network").font(.title2)
            Text("Anchors help peers that cannot connect directly. An anchor added here is kept for this machine.")
                .secondaryText().fixedSize(horizontal: false, vertical: true)
            HStack {
                TextField("fingerprint@address or host:port", text: $input)
                    .accessibilityIdentifier("network-anchor-input")
                    .onSubmit { add() }
                Button("Add Anchor") { add() }
                    .disabled(model.busy || input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    .accessibilityIdentifier("network-anchor-add")
            }
            ScrollView {
                VStack(alignment: .leading, spacing: Space.s16) {
                    if model.loaded && model.reachable && model.anchors.isEmpty {
                        Text("No manual or saved-room anchors on this machine.").secondaryText()
                    }
                    ForEach(model.anchors, id: \.fingerprint) { anchor in
                        HStack(alignment: .top) {
                            AnchorNetworkRow(anchor: anchor, reachable: model.reachable)
                            Spacer()
                            if anchor.sources.contains(where: { $0.kind == "added-by-hand" }) {
                                Button("Remove") {
                                    Task { await model.perform { try await $0.removeAnchor(fingerprint: anchor.fingerprint) } }
                                }
                                .disabled(model.busy)
                                .accessibilityIdentifier("network-anchor-remove-\(anchor.fingerprint)")
                            }
                        }
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            if model.busy { ProgressView("Checking with Vox…") }
            if let problem = model.actionProblem ?? model.problem {
                Text(problem).foregroundStyle(VoxTokens.Colors.danger)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("network-anchor-problem")
            }
            Text("Removing an anchor here removes only its manual source. A room's creator or admin changes that room's anchors.")
                .secondaryText().fixedSize(horizontal: false, vertical: true)
            HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.defaultAction) }
        }
        .padding(Space.s24)
        .frame(width: Theme.scaled(560), height: Theme.scaled(480))
        .contentSurface()
        .task { await model.follow() }
    }

    private func add() {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return }
        Task { if await model.perform({ try await $0.addAnchor(input: value) }) { input = "" } }
    }
}

/// The selected room's signed endpoints, with separately labelled machine identity reach
/// and honest last-known configuration when an authoritative refresh is unavailable.
struct RoomAnchorsView: View {
    @ObservedObject var model: NodeModel
    let room: String

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s8) {
            if model.roomOnScreen == room {
                if model.roomAnchorLoading { ProgressView("Reading anchors…") }
                if model.roomAnchorSnapshotCurrent, !model.roomAnchorLoading,
                   model.roomAnchorEntries.isEmpty {
                    Text("This room has no anchors.").secondaryText()
                }
                ForEach(model.roomAnchorSnapshotKnown ? model.roomAnchorEntries : [], id: \.fingerprint) { anchor in
                    VStack(alignment: .leading, spacing: Space.s4) {
                        Text(String(anchor.fingerprint.prefix(12))).font(Theme.mono)
                        // Addresses come only from this room's authenticated configuration;
                        // the machine inventory's union is never presented as its endpoints.
                        Text(anchor.addresses.joined(separator: ", ")).font(Theme.mono)
                            .fixedSize(horizontal: false, vertical: true)
                        Text("from room " + model.roomName(room)
                             + (model.roomAnchorSnapshotCurrent ? "" : " (last known configuration)"))
                            .secondaryText()
                        Text("Identity reach across this machine's sources: "
                             + (model.roomAnchorSnapshotCurrent && model.roomAnchorReachError == nil
                                ? (model.roomAnchorReach[anchor.fingerprint] ?? "No current observation.")
                                : "unavailable; last known: " + (model.roomAnchorReach[anchor.fingerprint] ?? "none")))
                            .secondaryText().accessibilityIdentifier("anchor-reach-" + anchor.fingerprint)
                    }
                    .textSelection(.enabled)
                    .accessibilityElement(children: .contain)
                    .accessibilityIdentifier("anchor-row-" + anchor.fingerprint)
                }
                if !model.roomAnchorSnapshotCurrent && model.roomAnchorSnapshotKnown {
                    Text("Room configuration unavailable; showing last known configuration.").secondaryText()
                }
                if !model.roomAnchorSnapshotKnown && !model.roomAnchorLoading,
                   (!model.daemonReachable || model.ended != nil) {
                    Text("Room configuration unavailable; no saved snapshot for this room.").secondaryText()
                }
                if let problem = model.roomAnchorError ?? model.roomAnchorReachError {
                    Text(problem).secondaryText().fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("room-anchors-problem")
                }
            }
        }
        .accessibilityIdentifier("room-anchors")
        .task(id: model.me + "/" + room) {
            // Use the selected node's held client and its room/actor/request fences. No
            // independent account client can leak another actor's inventory into this room.
            while !Task.isCancelled, model.roomOnScreen == room, model.ended == nil {
                await model.loadRoomAnchorState()
                do { try await Task.sleep(for: .seconds(3)) }
                catch { return }
            }
        }
    }
}


/// One explicit input field is reusable by New Room once its authenticated search/creation
/// handoff (#782) exists. Typing here alone never dials or writes a manual anchor.
struct RoomAnchorInput: View {
    @Binding var input: String
    let busy: Bool
    let allowed: Bool
    let add: () -> Void
    var body: some View {
        HStack {
            TextField("fingerprint@address or host:port", text: $input)
                .disabled(busy)
                .accessibilityIdentifier("room-anchor-input")
                .onSubmit { if allowed && !busy { add() } }
            Button("Add Anchor", action: add)
                .disabled(!allowed || busy || input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .accessibilityIdentifier("room-anchor-add")
        }
    }
}

/// Only selected-room signed governance is changed; machine manual sources remain independent.
struct RoomAnchorEditor: View {
    @ObservedObject var model: NodeModel
    @Environment(\.dismiss) private var dismiss
    @State private var input = ""
    @StateObject private var choices = RoomAnchorChoices()
    var body: some View {
        VStack(alignment: .leading, spacing: Space.s16) {
            Text("Room Anchors").font(.title2)
            Text("Anchors bridge peers that cannot connect directly. Changes apply to this room's members only; direct connections do not need one.")
                .secondaryText().fixedSize(horizontal: false, vertical: true)
            RoomAnchorSearch(model: model, choices: choices, applyingToRoom: true)
            RoomAnchorInput(input: $input, busy: model.roomAnchorChanging,
                            allowed: model.canManageRoomAnchors) {
                let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !value.isEmpty else { return }
                Task { if await model.changeRoomAnchor(input: value) { input = "" } }
            }
            ScrollView {
                VStack(alignment: .leading, spacing: Space.s16) {
                    if model.roomAnchorEntries.isEmpty && model.roomAnchorError == nil && !model.roomAnchorLoading {
                        Text("This room has no anchors.").secondaryText()
                    }
                    ForEach(model.roomAnchorEntries, id: \.fingerprint) { anchor in
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: Space.s4) {
                                Text(anchor.fingerprint).font(Theme.mono).textSelection(.enabled)
                                Text(anchor.addresses.joined(separator: ", ")).font(Theme.mono)
                                    .fixedSize(horizontal: false, vertical: true)
                                Text(model.roomAnchorError == nil
                                     ? "From this room's configuration."
                                     : "Room configuration unavailable; showing last known configuration.")
                                    .secondaryText()
                                Text("Identity reach across this machine's sources: "
                                     + (model.roomAnchorReachError == nil
                                        ? (model.roomAnchorReach[anchor.fingerprint] ?? "No current observation.")
                                        : "unavailable; last known: " + (model.roomAnchorReach[anchor.fingerprint] ?? "none")))
                                    .secondaryText()
                                    .accessibilityIdentifier("room-anchor-reach-" + anchor.fingerprint)
                            }
                            Spacer()
                            Button("Remove from Room") {
                                Task { await model.changeRoomAnchor(removing: anchor.fingerprint) }
                            }
                            .disabled(!model.canManageRoomAnchors || model.roomAnchorChanging)
                            .accessibilityIdentifier("room-anchor-remove-" + anchor.fingerprint)
                        }
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            if model.roomAnchorChanging || model.roomAnchorLoading { ProgressView("Checking with Vox…") }
            if let problem = model.roomAnchorError {
                Text(problem).foregroundStyle(VoxTokens.Colors.danger)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("room-anchor-problem")
            }
            HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.defaultAction) }
        }
        .padding(Space.s24)
        .frame(width: Theme.scaled(600), height: Theme.scaled(480))
        .contentSurface()
        .accessibilityIdentifier("room-anchor-editor")
        .task { await model.loadRoomAnchorState() }
    }
}

/// Optional, explicit discovery shared by New Room and the authorized room editor.
@MainActor
final class RoomAnchorChoices: ObservableObject {
    @Published private(set) var found: [RoomAnchorEndpoint] = []
    @Published private(set) var kept: [RoomAnchorEndpoint] = []
    @Published private(set) var busy = false
    @Published private(set) var searched = false
    @Published private(set) var noSearchAnswers = false
    @Published private(set) var problem: String?
    private var generation = UUID()
    func retire() {
        generation = UUID(); found = []; kept = []; busy = false; searched = false; noSearchAnswers = false; problem = nil
    }
    func request(_ model: NodeModel, input: String? = nil) async {
        guard !busy else { return }
        let request = UUID(), context = model.anchorChoiceContext
        generation = request; busy = true; problem = nil
        defer { if generation == request { busy = false } }
        do {
            let result: [RoomAnchorEndpoint]
            if let input { result = [try await model.resolveRoomAnchorChoice(input, context: context)] }
            else { result = try await model.searchRoomAnchorChoices(context: context) }
            guard !Task.isCancelled, generation == request, model.anchorChoiceContext == context else { return }
            if input == nil {
                searched = true
                noSearchAnswers = result.isEmpty
                found = kept
            }
            for endpoint in result {
                found.removeAll { $0.fingerprint == endpoint.fingerprint }
                if let existing = kept.first(where: { $0.fingerprint == endpoint.fingerprint }),
                   Set(endpoint.addresses).subtracting(existing.addresses).isEmpty {
                    // No extra address was offered. Show the full kept chip, so Remove
                    // describes the actual creation snapshot rather than a smaller answer.
                    found.append(existing)
                } else { found.append(endpoint) }
            }
        } catch {
            guard !Task.isCancelled, generation == request, model.anchorChoiceContext == context else { return }
            problem = sentence(error)
        }
    }
    func keep(_ endpoint: RoomAnchorEndpoint) {
        // A newly resolved address for a kept identity is offered, never silently applied
        // or ignored. Only this explicit Keep merges it into the creation snapshot.
        let previous = kept.first { $0.fingerprint == endpoint.fingerprint }
        let merged = RoomAnchorEndpoint(fingerprint: endpoint.fingerprint,
            addresses: Array(Set((previous?.addresses ?? []) + endpoint.addresses)).sorted())
        kept.removeAll { $0.fingerprint == endpoint.fingerprint }; kept.append(merged)
        found.removeAll { $0.fingerprint == endpoint.fingerprint }; found.append(merged)
    }
    func remove(_ endpoint: RoomAnchorEndpoint) { kept.removeAll { $0.fingerprint == endpoint.fingerprint } }
}

struct RoomAnchorSearch: View {
    @ObservedObject var model: NodeModel
    @ObservedObject var choices: RoomAnchorChoices
    var applyingToRoom = false
    @State private var input = ""
    var body: some View {
        VStack(alignment: .leading, spacing: Space.s8) {
            Text("Anchors (optional)").fontWeight(.semibold)
            Text("Directly reachable peers need no anchor. Search nearby only when you ask; keep only the fingerprints and addresses you want this room to use.")
                .secondaryText().fixedSize(horizontal: false, vertical: true)
            Button("Search Nearby Now") { Task { await choices.request(model) } }
                .disabled(choices.busy || (applyingToRoom && !model.canManageRoomAnchors))
                .accessibilityIdentifier("room-anchor-search")
            HStack {
                TextField("fingerprint@address or host:port", text: $input)
                    .disabled(choices.busy || (applyingToRoom && !model.canManageRoomAnchors))
                    .accessibilityIdentifier("room-anchor-choice-input")
                Button("Resolve") {
                    let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !value.isEmpty else { return }
                    Task { await choices.request(model, input: value) }
                }.disabled(choices.busy || input.isEmpty || (applyingToRoom && !model.canManageRoomAnchors))
            }
            if choices.busy { ProgressView("Looking for anchors…") }
            if choices.searched && !choices.busy && choices.noSearchAnswers {
                Text(applyingToRoom ? "No anchors found. This room's configuration is unchanged."
                     : "No anchors found. You can create without one.").secondaryText()
            }
            ScrollView {
                VStack(alignment: .leading, spacing: Space.s8) {
                    ForEach(choices.found, id: \.fingerprint) { endpoint in
                        VStack(alignment: .leading, spacing: Space.s4) {
                            Text(endpoint.fingerprint).font(Theme.mono).textSelection(.enabled)
                            Text(endpoint.addresses.joined(separator: ", ")).font(Theme.mono).textSelection(.enabled)
                            if !applyingToRoom && choices.kept.contains(where: {
                                $0.fingerprint == endpoint.fingerprint && Set($0.addresses) == Set(endpoint.addresses)
                            }) {
                                Button("Remove") { choices.remove(endpoint) }
                            } else {
                                Button(applyingToRoom ? "Keep for This Room"
                                       : (choices.kept.contains(where: { $0.fingerprint == endpoint.fingerprint })
                                          ? "Keep Additional Addresses" : "Keep")) {
                                    if applyingToRoom {
                                        let context = model.anchorChoiceContext
                                        Task {
                                            for address in endpoint.addresses {
                                                guard !Task.isCancelled, model.anchorChoiceContext == context else { return }
                                                guard await model.changeRoomAnchor(input: endpoint.fingerprint + "@" + address) else { return }
                                                guard !Task.isCancelled, model.anchorChoiceContext == context else { return }
                                            }
                                        }
                                    } else { choices.keep(endpoint) }
                                }.disabled(applyingToRoom && (!model.canManageRoomAnchors || model.roomAnchorChanging))
                            }
                        }.accessibilityIdentifier("room-anchor-choice-" + endpoint.fingerprint)
                    }
                }
            }.frame(maxHeight: 140)
            if let problem = choices.problem { Text(problem).foregroundStyle(VoxTokens.Colors.danger) }
            if !applyingToRoom {
                Text(choices.kept.isEmpty ? "The room link will carry no anchors."
                     : "The room link will carry: " + choices.kept.map { $0.fingerprint + "@" + $0.addresses.joined(separator: ", ") }.joined(separator: "; "))
                    .secondaryText().fixedSize(horizontal: false, vertical: true)
            }
        }
        .onChange(of: model.anchorChoiceContext) { _ in choices.retire() }
        .onDisappear { choices.retire() }
    }
}
