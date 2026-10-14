// The daemon owns the machine's anchors. Settings changes only manual sources; a room's
// inspector reads its source from that same inventory and never grants dialing authority.
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

/// The selected room's source in the same machine list, including its honest stale/unknown state.
struct RoomAnchorsView: View {
    let room: String
    @StateObject private var model = AnchorNetworkModel()

    var body: some View {
        let anchors = model.anchors.filter { $0.sources.contains { $0.room == room } }
        VStack(alignment: .leading, spacing: Space.s8) {
            if !model.loaded && model.busy { ProgressView("Reading anchors…") }
            if model.loaded && model.reachable && anchors.isEmpty { Text("This room has no anchors.").secondaryText() }
            ForEach(anchors, id: \.fingerprint) { anchor in
                AnchorNetworkRow(anchor: anchor, reachable: model.reachable)
            }
            if let problem = model.actionProblem ?? model.problem {
                Text(problem).secondaryText().fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("room-anchors-problem")
            }
        }
        .accessibilityIdentifier("room-anchors")
        .task { await model.follow() }
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
    var body: some View {
        VStack(alignment: .leading, spacing: Space.s16) {
            Text("Room Anchors").font(.title2)
            Text("Anchors bridge peers that cannot connect directly. Changes apply to this room's members only; direct connections do not need one.")
                .secondaryText().fixedSize(horizontal: false, vertical: true)
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
