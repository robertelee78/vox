// Computer pairing is account-wide. The daemon authenticates the peer, owns the one-time code
// and approves the exact displayed operation; this view holds no node or room authority.
import AppKit
import SwiftUI

@MainActor
private final class ComputerTrustModel: ObservableObject {
    @Published private(set) var status: ComputerStatus?
    @Published private(set) var busy = false
    @Published private(set) var reachable = false
    @Published private(set) var problem: String?
    @Published private(set) var actionProblem: String?
    private var client: VoxClient?
    private var working = false
    /// One operator action may wait behind the active refresh; refreshes never queue.
    private var waitingOperator: CheckedContinuation<Void, Never>?

    func perform(refreshing: Bool = false, _ request: (VoxClient) async throws -> ComputerStatus) async {
        if working {
            if refreshing { return }
            guard waitingOperator == nil else {
                actionProblem = "Another computer change is already waiting. Try again when it finishes."
                return
            }
            busy = true
            await withCheckedContinuation { waitingOperator = $0 }
            // The prior operation keeps ownership while handing it directly to us.
        } else {
            working = true
        }
        if !refreshing {
            busy = true
            actionProblem = nil
        }
        defer {
            if let next = waitingOperator {
                waitingOperator = nil
                next.resume()
            } else {
                working = false
                if busy { busy = false }
            }
        }
        do {
            let connection: VoxClient
            if let client { connection = client }
            else {
                connection = try await VoxClient.open(dataRoot: "")
                client = connection
            }
            status = try await request(connection)
            reachable = true
            problem = nil
        } catch {
            // Keep last-known facts visible, but never offer approval or claim current success
            // after losing the daemon. A new connection is tried on the next refresh.
            reachable = false
            if refreshing { problem = sentence(error) }
            else { actionProblem = sentence(error) }
            client = nil
        }
    }

    func refresh() async {
        await perform(refreshing: true) { try await $0.computerStatus() }
    }
}

private enum ComputerTrustFocus: Hashable {
    case policyDetails, computerDetails(String), remove(String), exchangeDetails(String)
    case managementDetails, transfer(String), binding(String), retirement
    case conflictCloseCommand, conflictFreshCommand, replace, closeConflict, conflictInput, reviewConflict
    case otherApproval, approve, thisApproval, copyCode, copyCommand, begin, input, preview
    case handoffClose, handoffInvite, cancel
}

struct ComputerTrustView: View {
    @Environment(\.dismiss) private var dismiss
    @StateObject private var model = ComputerTrustModel()
    @State private var link = ""
    @State private var copied: String?
    @State private var removal: RemovalChoice?
    @State private var bindingChoice: BindingChoice?
    @State private var replacement: ComputerGroupConflict?
    @State private var handoff: ComputerGroupConflict?
    @State private var retirement: ComputerGroupRetirement?
    @FocusState private var focused: ComputerTrustFocus?

    private struct BindingChoice {
        let binding: ComputerBindingAction
        let destination: String
        let frontier: String
    }

    private struct RemovalChoice {
        let computer: ComputerIdentity
        let frontier: String
        let nodes: [ComputerNode]
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s16) {
            Text("My Computers").font(.title2)
            if let problem = model.actionProblem {
                StateMark(kind: .danger, words: problem)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("computer-action-problem")
            }
            if let problem = model.problem {
                StateMark(kind: .danger, words: problem)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("computer-connection-problem")
            }
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: Space.s16) {
                        if let status = model.status {
                            identity(status.thisComputer, title: "This computer")
                            Text("Computer trust covers this Vox installation and its nodes.")
                                .secondaryText()
                            Text(status.policy)
                                .fixedSize(horizontal: false, vertical: true)
                                .accessibilityIdentifier("computer-trust-policy")
                            DisclosureGroup("Identity and policy details") {
                                Text("Policy revision \(status.revision)")
                                    .font(Theme.mono).secondaryText()
                                    .accessibilityIdentifier("computer-policy-revision")
                            }
                            .focused($focused, equals: .policyDetails)
                            .id(ComputerTrustFocus.policyDetails)
                            if !model.reachable {
                                Text("Last known state. Checking with Vox…").secondaryText()
                            }
                            if let problem = status.problem {
                                StateMark(kind: .danger, words: problem)
                                    .accessibilityIdentifier("computer-pairing-problem")
                            }
                            ForEach(status.topology, id: \.self) { line in
                                Text(line).fixedSize(horizontal: false, vertical: true)
                            }
                            VStack(alignment: .leading, spacing: Space.s16) {
                                pairing(status)
                            }
                            .focusSection()
                            if !status.pendingNodes.isEmpty {
                                Text("Waiting for these nodes to become Ready or apply computer trust:")
                                    .secondaryText()
                                Text(status.pendingNodes.joined(separator: ", "))
                                    .textSelection(.enabled)
                                    .accessibilityIdentifier("computer-pending-nodes")
                            }
                            if !status.computers.isEmpty {
                                Divider()
                                Text("Enrolled computers").eyebrow()
                                ForEach(status.applications, id: \.computer.fingerprint) { application in
                                    VStack(alignment: .leading, spacing: Space.s4) {
                                        Text(application.computer.name).font(.headline)
                                        DisclosureGroup("Identity and node details") {
                                            identity(application.computer, title: application.computer.name)
                                            ForEach(status.nodes.filter { $0.computer == application.computer.fingerprint }, id: \.fingerprint) { node in
                                                VStack(alignment: .leading, spacing: Space.s4) {
                                                    Text(node.name).font(.headline)
                                                    Text(node.fingerprint).font(Theme.mono).textSelection(.enabled)
                                                        .fixedSize(horizontal: false, vertical: true)
                                                    Text(node.personal ? "Personal node · can drive non-personal nodes" : "Managed node · read access")
                                                        .secondaryText()
                                                    if let revision = node.bindingRevision, let derived = node.bindingDerivedMs {
                                                        Text("Binding derived at policy revision \(revision) · Unix ms \(derived)")
                                                            .font(Theme.mono).secondaryText()
                                                            .accessibilityIdentifier("computer-binding-evidence-" + node.fingerprint)
                                                    }
                                                }
                                            }
                                        }
                                        .focused($focused, equals: .computerDetails(application.computer.fingerprint))
                                        .id(ComputerTrustFocus.computerDetails(application.computer.fingerprint))
                                        Button(application.computer.fingerprint == status.thisComputer.fingerprint
                                               ? "Remove This Computer" : "Remove Computer") {
                                            removal = RemovalChoice(computer: application.computer, frontier: status.frontier,
                                                nodes: status.nodes.filter { $0.computer == application.computer.fingerprint })
                                        }
                                        .disabled(model.busy || !model.reachable || status.state == "removed" || status.state == "quarantined")
                                        .accessibilityIdentifier("computer-remove-" + application.computer.fingerprint)
                                        .focused($focused, equals: .remove(application.computer.fingerprint))
                                        .id(ComputerTrustFocus.remove(application.computer.fingerprint))
                                        Text(applicationState(application, status: status))
                                            .secondaryText()
                                            .accessibilityIdentifier("computer-application-" + application.computer.fingerprint)
                                        Text(application.computer.fingerprint == status.thisComputer.fingerprint
                                             ? "Connectivity: this computer"
                                             : application.exchangeInFlight
                                             ? "Connectivity: exchange in progress; current reachability unknown"
                                             : application.exchangeFailures > 0
                                             ? "Connectivity: last exchange failed; current reachability unknown"
                                             : "Connectivity: current reachability unknown")
                                            .secondaryText()
                                        DisclosureGroup("Exchange diagnostics") {
                                        Text("Exchanged \(application.exchanges) time(s) in \(application.exchangeAttempts) attempt(s) · \(application.exchangeFailures) failed in a row")
                                            .font(Theme.mono).secondaryText()
                                            .accessibilityIdentifier("computer-exchange-counts-" + application.computer.fingerprint)
                                        Text(convergenceEvidence(application))
                                            .font(Theme.mono).secondaryText()
                                            .accessibilityIdentifier("computer-convergence-" + application.computer.fingerprint)
                                        if let exchange = application.lastStartedExchange {
                                            Text("Last started exchange: sent revision \(exchange.sentRevision), merged revision \(exchange.mergedRevision), Unix ms \(exchange.atMs)")
                                                .font(Theme.mono).secondaryText()
                                        }
                                        if let exchange = application.lastAnsweredExchange {
                                            Text("Last answered exchange: sent revision \(exchange.sentRevision), merged revision \(exchange.mergedRevision), Unix ms \(exchange.atMs)")
                                                .font(Theme.mono).secondaryText()
                                        }
                                        }
                                        .focused($focused, equals: .exchangeDetails(application.computer.fingerprint))
                                        .id(ComputerTrustFocus.exchangeDetails(application.computer.fingerprint))
                                    }
                                    .focusSection()
                                }
                            }
                            if !status.bindingActions.isEmpty {
                                Divider()
                                DisclosureGroup("Optional node management") {
                                ForEach(status.bindingActions, id: \.node) { binding in
                                    VStack(alignment: .leading, spacing: Space.s4) {
                                        Text(binding.name).font(.headline)
                                        Text(binding.node).font(Theme.mono).textSelection(.enabled)
                                        Text("Manager: " + binding.computer).font(Theme.mono).secondaryText()
                                        if binding.action == "release" {
                                            Menu("Transfer Node To…") {
                                                ForEach(status.computers.filter { $0.fingerprint != status.thisComputer.fingerprint }, id: \.fingerprint) { destination in
                                                    Button(destination.name + " · " + destination.fingerprint) {
                                                        bindingChoice = BindingChoice(binding: binding, destination: destination.fingerprint, frontier: status.frontier)
                                                    }
                                                }
                                            }
                                            .disabled(model.busy || !model.reachable)
                                            .focused($focused, equals: .transfer(binding.node))
                                            .id(ComputerTrustFocus.transfer(binding.node))
                                        } else {
                                            Button(binding.action == "transfer" ? "Accept Transfer Here" : "Recover Node Here") {
                                                bindingChoice = BindingChoice(binding: binding, destination: "", frontier: status.frontier)
                                            }
                                            .disabled(model.busy || !model.reachable)
                                            .focused($focused, equals: .binding(binding.node))
                                            .id(ComputerTrustFocus.binding(binding.node))
                                        }
                                    }
                                }
                                Text("A transfer needs a signed release from its previous manager. Recovery needs retained removal or fault evidence. After approving here, unlock the node's local vault normally to sign its new binding. A copied name or fingerprint is never proof of management.")
                                    .secondaryText()
                                }
                                .focused($focused, equals: .managementDetails)
                                .id(ComputerTrustFocus.managementDetails)
                            }
                            if !status.removed.isEmpty {
                                Divider()
                                Text("Removed computers").eyebrow()
                                ForEach(status.removed, id: \.fingerprint) { computer in
                                    identity(computer, title: computer.name)
                                }
                                Text("Removal stops new read and drive access when each remaining computer applies it. Unreachable computers remain pending; already received data is not erased. Rejoining requires a new approval. You can deliberately trust an individual node afterward.")
                                    .secondaryText()
                            }
                        } else if model.problem == nil {
                            ProgressView("Reading computer trust…")
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .focusSection()
                .onChange(of: focused) { target in
                    if let target { proxy.scrollTo(target) }
                }
            }
            HStack {
                Button("Refresh") { Task { await model.refresh() } }
                    .disabled(model.busy)
                    .accessibilityIdentifier("computer-refresh")
                if model.busy { ProgressView().controlSize(.small) }
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("computer-done")
            }
            .focusSection()
        }
        .padding(Space.s24)
        .frame(width: Theme.scaled(600), height: Theme.scaled(600))
        .contentSurface()
        // A container of its own: without it SwiftUI puts this identifier on every direct child
        // (the title, both problems, Refresh and Done), and theirs are lost.
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("computer-trust-sheet")
        .task {
            await model.refresh()
            while !Task.isCancelled {
                do { try await Task.sleep(nanoseconds: 2_000_000_000) }
                catch { break }
                guard !Task.isCancelled else { break }
                await model.refresh()
            }
        }
        .sheet(isPresented: Binding(get: { replacement != nil }, set: { if !$0 { replacement = nil } })) {
            if let choice = replacement {
                ComputerTrustConfirmation(
                    title: "Replace This Computer's Group?",
                    message: "Retire the reviewed old group on this computer? Covered Read, Drive and individual grants are revoked locally. Identities, data and signed history remain. Unreachable computers may retain access and data.",
                    affected: choice.affected,
                    confirmLabel: "Retire Old Group Locally",
                    confirmIdentifier: "computer-replacement-confirm",
                    cancelIdentifier: "computer-replacement-decline",
                    cancel: { replacement = nil },
                    confirm: {
                        replacement = nil
                        Task {
                            await model.perform {
                                try await $0.changeComputerBinding(action: "replace-group", node: choice.reviewId,
                                                                   destination: "", frontier: choice.frontier)
                            }
                            if model.status?.state == "individual", model.actionProblem == nil { handoff = choice }
                        }
                    }
                )
            }
        }
        .sheet(isPresented: Binding(get: { retirement != nil }, set: { if !$0 { retirement = nil } })) {
            if let choice = retirement {
                ComputerTrustConfirmation(
                    title: "Finish Local Group Retirement?",
                    message: "Retire the old group and its covered local grants? Identities, data and signed history remain. Unreachable computers may retain access and data.",
                    affected: choice.affected,
                    confirmLabel: "Retire Group Locally",
                    cancel: { retirement = nil },
                    confirm: {
                        retirement = nil
                        Task { await model.perform {
                            try await $0.changeComputerBinding(action: "recover-group", node: choice.reviewId,
                                                               destination: "", frontier: choice.frontier)
                        } }
                    }
                )
            }
        }
        .sheet(isPresented: Binding(get: { removal != nil }, set: { if !$0 { removal = nil } })) {
            if let choice = removal {
                ComputerTrustConfirmation(
                    title: "Remove Computer?",
                    message: "Remove \(choice.computer.name) (\(choice.computer.fingerprint)) and all trust in its nodes, including individual grants made before pairing?",
                    affected: choice.nodes.isEmpty ? ["No authenticated nodes are currently listed."] : choice.nodes.map { "\($0.name) · \($0.fingerprint)" },
                    footnote: "Offline computers remain pending until they apply this removal. Data already received is not erased.",
                    confirmLabel: "Remove Computer",
                    cancel: { removal = nil },
                    confirm: {
                        let computer = choice.computer.fingerprint
                        let frontier = choice.frontier
                        removal = nil
                        Task { await model.perform { try await $0.removeComputer(computer: computer, frontier: frontier) } }
                    }
                )
            }
        }
        .alert("Change Node Management?", isPresented: Binding(get: { bindingChoice != nil }, set: { if !$0 { bindingChoice = nil } }), presenting: bindingChoice) { choice in
            Button(choice.binding.action == "release" ? "Release Node" : "Approve Here") {
                bindingChoice = nil
                Task { await model.perform {
                    try await $0.changeComputerBinding(action: choice.binding.action, node: choice.binding.node,
                        destination: choice.destination, frontier: choice.frontier)
                } }
            }
            Button("Cancel", role: .cancel) { bindingChoice = nil }
        } message: { choice in
            Text("Node: \(choice.binding.name)\n\(choice.binding.node)\nPrevious manager: \(choice.binding.computer)\n"
                 + (choice.binding.action == "release"
                    ? "Release only to \(choice.destination). This computer relinquishes the binding and automatic policy for this node. The destination must approve and unlock it."
                    : "Approve \(choice.binding.action) to this computer using the retained signed evidence. No trust is applied until the node signs with its unlocked local vault. If its key was compromised, create a fresh node instead."))
        }
        .onDisappear { link = ""; copied = nil; removal = nil; bindingChoice = nil; replacement = nil; retirement = nil; handoff = nil }
    }

    @ViewBuilder private func pairing(_ status: ComputerStatus) -> some View {
        if status.state == "removed" {
            Text("This computer was removed. Its automatic group trust is being revoked. To rejoin, use a new pairing code from a remaining member and approve again.")
                .accessibilityIdentifier("computer-trust-removed")
        } else if status.state == "quarantined" {
            Text("Computer trust is suspended.")
                .accessibilityIdentifier("computer-trust-quarantined")
        } else if status.state == "confirmed", model.reachable {
            Text("Computer trust is confirmed.")
                .accessibilityIdentifier("computer-trust-confirmed")
        } else if status.state == "applying" {
            Text("Computer trust was approved. Waiting for it to be applied across the group.")
                .accessibilityIdentifier("computer-trust-applying")
        }
        if let review = status.retirement {
            Text("This computer was removed from its previous group. Review the remaining local retirement before starting a fresh pairing.")
                .secondaryText()
            ForEach(review.affected, id: \.self) { Text($0).textSelection(.enabled) }
            Button("Review Local Retirement…") { retirement = review }
                .disabled(model.busy || !model.reachable)
                .accessibilityIdentifier("computer-retirement-review")
                .focused($focused, equals: .retirement)
                .id(ComputerTrustFocus.retirement)
        } else if let conflict = status.conflict, status.state != "quarantined" {
            Divider()
            identity(conflict.peer, title: "Authenticated computer in a different group")
            Text("Current group: \(conflict.currentGroup)\nProposed group: \(conflict.proposedGroup)")
                .font(Theme.mono).textSelection(.enabled)
            Text("Replacing locally revokes covered Read, personal-to-managed-node Drive and covered individual grants. Identities, local data and signed history remain. Unreachable computers may retain access and data.")
                .fixedSize(horizontal: false, vertical: true)
            ForEach(conflict.affected, id: \.self) { Text($0).textSelection(.enabled) }
            if conflict.inviterApproved {
                Text("The proposal is already signed on \(conflict.peer.name). Wait until \(Date(timeIntervalSince1970: Double(conflict.expiresMs) / 1_000).formatted()) before closing it there. Closing does not withdraw a signature already retained elsewhere.")
                    .secondaryText()
            }
            if expired(conflict.expiresMs) {
                Text("This proposal has expired. Close it on the inviting computer and review a fresh invitation before replacing this group.")
                    .secondaryText()
                Button("Copy Close Command for \(conflict.peer.name)") {
                    copy(shellCommand(words: ["vox", "computer", "cancel", conflict.operationId]),
                         said: "Close command copied for \(conflict.peer.name).")
                }
                .focused($focused, equals: .conflictCloseCommand)
                .id(ComputerTrustFocus.conflictCloseCommand)
                Button("Copy Fresh Invitation Command") {
                    copy(shellCommand(words: ["vox", "computer", "invite"]), said: "Invitation command copied.")
                }
                .focused($focused, equals: .conflictFreshCommand)
                .id(ComputerTrustFocus.conflictFreshCommand)
            }
            Button("Review Group Replacement…") { replacement = conflict }
                .disabled(model.busy || !model.reachable || expired(conflict.expiresMs))
                .accessibilityIdentifier("computer-replace-group")
                .focused($focused, equals: .replace)
                .id(ComputerTrustFocus.replace)
            Button("Keep Current Group and Close This Review") {
                let operation = conflict.operationId
                Task { await model.perform { try await $0.cancelComputerPairing(operationId: operation) } }
            }
            .disabled(model.busy || !model.reachable)
            .accessibilityIdentifier("computer-conflict-close")
            .focused($focused, equals: .closeConflict)
            .id(ComputerTrustFocus.closeConflict)
            Text("This closes the review only on this computer. It cannot withdraw an invitation or signature recorded on \(conflict.peer.name).")
                .secondaryText()
            TextField("Pairing code to review again", text: $link)
                .textFieldStyle(.roundedBorder)
                .privacySensitive()
                .accessibilityIdentifier("computer-conflict-input")
                .focused($focused, equals: .conflictInput)
                .id(ComputerTrustFocus.conflictInput)
            Button("Review Code Again") {
                let code = link.trimmingCharacters(in: .whitespacesAndNewlines)
                link = ""
                Task { await model.perform { try await $0.previewComputerPairing(link: code) } }
            }
            .disabled(model.busy || !model.reachable || link.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            .accessibilityIdentifier("computer-conflict-review-again")
            .focused($focused, equals: .reviewConflict)
            .id(ComputerTrustFocus.reviewConflict)
        } else if let preview = status.pairing, status.state != "quarantined" {
            Divider()
            identity(preview.peer, title: "Computer to add")
            Text("Operation: \(preview.operationId)")
                .font(Theme.mono).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("computer-pairing-operation")
            if let group = preview.proposedGroup {
                Text("Joins existing computer group: \(group)")
                    .font(Theme.mono).textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("computer-pairing-proposed-group")
            } else {
                Text("Creates a new computer group.")
                    .accessibilityIdentifier("computer-pairing-proposed-group")
            }
            if expired(preview.expiresMs), !preview.approvedHere || !preview.approvedThere {
                Text(preview.approvedHere
                     ? "The approval window has ended. You can close this attempt here. The other computer may have recorded approval; closing here does not remove its trust."
                     : "This pairing code expired before both computers approved. Cancel it and create a new one.")
                    .secondaryText()
                    .accessibilityIdentifier("computer-pairing-expired")
            } else if preview.approvedHere {
                Text(preview.approvedThere
                     ? "Both computers approved. Waiting for applied confirmation."
                     : "Approved here. Confirm on \(preview.peer.name) (\(preview.peer.fingerprint)) to continue.")
                    .accessibilityIdentifier("computer-pairing-waiting")
                if !preview.approvedThere {
                    Button("Copy Other Computer's Approval Command") {
                        copy(shellCommand(words: ["vox", "computer", "approve", preview.operationId]),
                             said: "Approval command copied for \(preview.peer.name).")
                    }
                    .focused($focused, equals: .otherApproval)
                    .id(ComputerTrustFocus.otherApproval)
                }
            } else {
                Text("Confirm this computer and the permissions above.")
                Button("Trust This Computer") {
                    // Capture the peer the person actually saw, even if a refresh arrives before
                    // the task starts. The daemon rejects an expired or replaced operation.
                    let operation = preview.operationId
                    Task { await model.perform { try await $0.approveComputerPairing(operationId: operation) } }
                }
                .buttonStyle(.voxPrimary)
                .disabled(model.busy || !model.reachable || expired(preview.expiresMs))
                .accessibilityIdentifier("computer-pairing-approve")
                .focused($focused, equals: .approve)
                .id(ComputerTrustFocus.approve)
                Button("Copy This Computer's Approval Command") {
                    copy(shellCommand(words: ["vox", "computer", "approve", preview.operationId]),
                         said: "Approval command copied for this computer.")
                }
                .focused($focused, equals: .thisApproval)
                .id(ComputerTrustFocus.thisApproval)
            }
        } else if let invitation = status.inviteLink, status.state != "quarantined" {
            Divider()
            Text("On your other Mac, open Add Computer and paste this pairing code.")
            Text(invitation).font(Theme.mono).textSelection(.enabled)
                .lineLimit(4).privacySensitive()
                .accessibilityIdentifier("computer-pairing-code")
            HStack {
                Button("Copy Pairing Code") { copy(invitation, said: "Pairing code copied.") }
                    .accessibilityIdentifier("computer-copy-code")
                    .focused($focused, equals: .copyCode)
                    .id(ComputerTrustFocus.copyCode)
                Button("Copy Terminal Command") {
                    copy(shellCommand(words: ["vox", "computer", "pair", invitation]), said: "Terminal command copied.")
                }
                .accessibilityIdentifier("computer-copy-command")
                .focused($focused, equals: .copyCommand)
                .id(ComputerTrustFocus.copyCommand)
            }
            Text("For a computer without the app, paste the terminal command into its own terminal.")
                .secondaryText()
            if let expiry = status.inviteExpiresMs {
                Text(expired(expiry) ? "This pairing code has expired."
                     : "Expires at \(Date(timeIntervalSince1970: Double(expiry) / 1_000).formatted(date: .omitted, time: .shortened)).")
                    .secondaryText()
            }
            if let copied { Text(copied).secondaryText() }
        } else if status.state != "quarantined" {
            Divider()
            Text(status.computers.isEmpty
                 ? "Individual node trust is active until you approve computer trust."
                 : "Add another computer to My Computers. Existing members will learn about it when they reconnect.")
                .secondaryText()
            Button("Create Pairing Code") {
                Task { await model.perform { try await $0.beginComputerPairing() } }
            }
            .buttonStyle(.voxPrimary)
            .disabled(model.busy || !model.reachable)
            .disabled(status.state == "removed")
            .accessibilityIdentifier("computer-pairing-begin")
            .focused($focused, equals: .begin)
            .id(ComputerTrustFocus.begin)
            Text("Or use a code from your other computer").eyebrow()
            TextField("Pairing code", text: $link)
                .textFieldStyle(.roundedBorder)
                .privacySensitive()
                .accessibilityIdentifier("computer-pairing-input")
                .focused($focused, equals: .input)
                .id(ComputerTrustFocus.input)
            Button("Review Computer") {
                let code = link.trimmingCharacters(in: .whitespacesAndNewlines)
                link = ""
                Task { await model.perform { try await $0.previewComputerPairing(link: code) } }
            }
            .disabled(model.busy || !model.reachable || link.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            .accessibilityIdentifier("computer-pairing-preview")
            .focused($focused, equals: .preview)
            .id(ComputerTrustFocus.preview)
        }
        if let handoff, status.state == "individual" {
            Text("On \(handoff.peer.name), \(handoff.inviterApproved && !expired(handoff.expiresMs) ? "wait until the signed proposal expires, then " : "")close the old proposal and create a fresh invitation. If it was signed after review, wait for expiry before closing. Bring the fresh invitation here and approve on both computers. Closing cannot withdraw a signature already recorded elsewhere.")
                .fixedSize(horizontal: false, vertical: true)
            Button("Copy Command to Close Old Proposal") {
                copy(shellCommand(words: ["vox", "computer", "cancel", handoff.operationId]), said: "Close command copied for \(handoff.peer.name).")
            }
            .focused($focused, equals: .handoffClose)
            .id(ComputerTrustFocus.handoffClose)
            Button("Copy Command to Create Fresh Invitation") {
                copy(shellCommand(words: ["vox", "computer", "invite"]), said: "Invitation command copied for \(handoff.peer.name).")
            }
            .focused($focused, equals: .handoffInvite)
            .id(ComputerTrustFocus.handoffInvite)
        }
        let approvedHere = status.pairing?.approvedHere == true
        let closeExpired = approvedHere && status.pairing?.approvedThere != true
            && status.pairing.map { expired($0.expiresMs) } == true
        if status.state != "quarantined", !approvedHere || closeExpired,
           let operation = status.pairing?.operationId ?? status.inviteId {
            Button(closeExpired ? "Close Expired Attempt" : "Cancel Pairing") {
                Task { await model.perform { try await $0.cancelComputerPairing(operationId: operation) } }
            }
            .disabled(model.busy || !model.reachable)
            .accessibilityIdentifier("computer-pairing-cancel")
            .focused($focused, equals: .cancel)
            .id(ComputerTrustFocus.cancel)
            Text(closeExpired
                 ? "Closing this attempt lets you start a new pairing here. It cannot withdraw the approval already sent to the other computer."
                 : "Closing this window leaves the pairing pending. Cancel Pairing cancels this unused code.")
                .secondaryText()
        } else if approvedHere, status.state != "quarantined" {
            Text("Your approval has been sent and cannot be withdrawn here. You can close this window while pairing finishes.")
                .secondaryText()
        }
    }

    private func applicationState(_ application: ComputerApplication, status: ComputerStatus) -> String {
        var states: [String] = []
        if status.state == "quarantined" { states.append("Trust suspended") }
        let confirmation = application.confirmed ? "Application confirmed" : "Awaiting application confirmation"
        states.append(model.reachable ? confirmation : "Last known: \(confirmation.lowercased())")
        if application.convergenceState == "repaired-late" {
            states.append("Repaired late")
        } else if application.convergenceState == "expired" {
            states.append("Expired before convergence")
        } else if application.convergenceState == "replaced" {
            states.append("Expired revision replaced")
        }
        return states.joined(separator: "; ")
    }

    private func convergenceEvidence(_ application: ComputerApplication) -> String {
        guard let revision = application.missedRevision else {
            return "Convergence: \(application.convergenceState)"
        }
        let repaired = application.repairedLate ? "yes" : "no"
        return "Convergence: \(application.convergenceState) · missed revision \(revision) · repaired late \(repaired)"
    }

    private func identity(_ computer: ComputerIdentity, title: String) -> some View {
        VStack(alignment: .leading, spacing: Space.s4) {
            Text(title).eyebrow()
            Text(computer.name).font(.headline)
            Text(computer.fingerprint).font(Theme.mono).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            Text("Installation \(computer.installation)").font(Theme.mono)
                .secondaryText().textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .contain)
    }

    private func expired(_ millis: UInt64) -> Bool {
        Double(millis) / 1_000 <= Date().timeIntervalSince1970
    }

    private func copy(_ text: String, said: String) {
        NSPasteboard.general.clearContents()
        if NSPasteboard.general.setString(text, forType: .string) { copied = said }
        else { copied = "The clipboard could not be updated. Select and copy the code." }
    }
}

private struct ComputerTrustConfirmation: View {
    let title: String
    let message: String
    let affected: [String]
    var footnote: String? = nil
    let confirmLabel: String
    var confirmIdentifier = "computer-confirm"
    var cancelIdentifier = "computer-confirm-cancel"
    let cancel: () -> Void
    let confirm: () -> Void
    @State private var inspected: Int?
    @State private var copyNotice: String?

    init(title: String, message: String, affected: [String], footnote: String? = nil,
         confirmLabel: String, confirmIdentifier: String = "computer-confirm",
         cancelIdentifier: String = "computer-confirm-cancel",
         cancel: @escaping () -> Void, confirm: @escaping () -> Void) {
        self.title = title
        self.message = message
        self.affected = affected
        _inspected = State(initialValue: affected.indices.first)
        self.footnote = footnote
        self.confirmLabel = confirmLabel
        self.confirmIdentifier = confirmIdentifier
        self.cancelIdentifier = cancelIdentifier
        self.cancel = cancel
        self.confirm = confirm
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s16) {
            Text(title).title()
            Text(message).fixedSize(horizontal: false, vertical: true)
            List(selection: $inspected) {
                ForEach(affected.indices, id: \.self) { index in
                    Text(affected[index])
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .fixedSize(horizontal: false, vertical: true)
                        .tag(index)
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            .frame(height: Theme.scaled(200))
            if let footnote {
                Text(footnote).fixedSize(horizontal: false, vertical: true)
            }
            Button("Copy Selected Identity") {
                guard let inspected, affected.indices.contains(inspected) else { return }
                NSPasteboard.general.clearContents()
                if NSPasteboard.general.setString(affected[inspected], forType: .string) {
                    copyNotice = "Copied selected identity."
                } else {
                    copyNotice = "The clipboard could not be updated."
                }
            }
            .buttonStyle(VoxButtonStyle())
            .disabled(inspected.map { affected.indices.contains($0) } != true)
            .accessibilityIdentifier("computer-confirm-copy")
            if let copyNotice {
                Text(copyNotice).secondaryText().fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Button("Cancel", role: .cancel, action: cancel)
                    .keyboardShortcut(.cancelAction)
                    .accessibilityLabel("Cancel")
                    .accessibilityIdentifier(cancelIdentifier)
                Button(confirmLabel, role: .destructive, action: confirm)
                    .accessibilityLabel(confirmLabel)
                    .accessibilityIdentifier(confirmIdentifier)
            }
            .buttonStyle(VoxButtonStyle())
        }
        .padding(Space.s24)
        .frame(width: Theme.scaled(440))
        .font(Theme.text)
        .panelSurface()
        .onChange(of: inspected) { _ in copyNotice = nil }
    }
}
