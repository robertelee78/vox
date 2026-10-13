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

    func perform(refreshing: Bool = false, _ request: (VoxClient) async throws -> ComputerStatus) async {
        guard !busy else { return }
        busy = true
        if !refreshing { actionProblem = nil }
        defer { busy = false }
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

struct ComputerTrustView: View {
    @Environment(\.dismiss) private var dismiss
    @StateObject private var model = ComputerTrustModel()
    @State private var link = ""
    @State private var copied: String?

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s16) {
            Text("My Computers").font(.title2)
            ScrollView {
                VStack(alignment: .leading, spacing: Space.s16) {
                    if let status = model.status {
                        identity(status.thisComputer, title: "This computer")
                        Text("Computer trust covers this Vox installation and its nodes.")
                            .secondaryText()
                        Text(status.policy)
                            .fixedSize(horizontal: false, vertical: true)
                            .accessibilityIdentifier("computer-trust-policy")
                        if !model.reachable {
                            Text("Last known state. Checking with Vox…").secondaryText()
                        }
                        if let problem = status.problem {
                            StateMark(kind: .danger, words: problem)
                                .accessibilityIdentifier("computer-pairing-problem")
                        }
                        pairing(status)
                        if !status.pendingNodes.isEmpty {
                            Text("Waiting for these nodes to attach or apply computer trust:")
                                .secondaryText()
                            Text(status.pendingNodes.joined(separator: ", "))
                                .textSelection(.enabled)
                                .accessibilityIdentifier("computer-pending-nodes")
                        }
                        if !status.computers.isEmpty {
                            Divider()
                            Text("Enrolled computers").eyebrow()
                            ForEach(status.computers, id: \.fingerprint) { computer in
                                identity(computer, title: computer.name)
                            }
                        }
                    } else if model.busy {
                        ProgressView("Reading computer trust…")
                    }
                    if let problem = model.actionProblem {
                        StateMark(kind: .danger, words: problem)
                            .accessibilityIdentifier("computer-action-problem")
                    }
                    if let problem = model.problem {
                        StateMark(kind: .danger, words: problem)
                            .accessibilityIdentifier("computer-connection-problem")
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
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
        }
        .padding(Space.s24)
        .frame(width: Theme.scaled(600), height: Theme.scaled(600))
        .contentSurface()
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
        .onDisappear { link = ""; copied = nil }
    }

    @ViewBuilder private func pairing(_ status: ComputerStatus) -> some View {
        if status.state == "quarantined" {
            Text("Computer trust is suspended.")
                .accessibilityIdentifier("computer-trust-quarantined")
        } else if status.state == "confirmed", model.reachable {
            Text("Computer trust is confirmed.")
                .accessibilityIdentifier("computer-trust-confirmed")
        } else if status.state == "applying" {
            Text("Computer trust was approved. Waiting for it to be applied on both computers.")
                .accessibilityIdentifier("computer-trust-applying")
        }
        if let preview = status.pairing, status.state != "confirmed", status.state != "quarantined" {
            Divider()
            identity(preview.peer, title: "Computer to add")
            if expired(preview.expiresMs), !preview.approvedHere || !preview.approvedThere {
                Text(preview.approvedHere
                     ? "The approval window has ended. You can close this attempt here. The other computer may have recorded approval; closing here does not remove its trust."
                     : "This pairing code expired before both computers approved. Cancel it and create a new one.")
                    .secondaryText()
                    .accessibilityIdentifier("computer-pairing-expired")
            } else if preview.approvedHere {
                Text(preview.approvedThere
                     ? "Both computers approved. Waiting for applied confirmation."
                     : "Approved here. Confirm on the other computer to continue.")
                    .accessibilityIdentifier("computer-pairing-waiting")
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
            }
        } else if let invitation = status.inviteLink, status.state == "waiting" {
            Divider()
            Text("On your other Mac, open Add Computer and paste this pairing code.")
            Text(invitation).font(Theme.mono).textSelection(.enabled)
                .lineLimit(4).privacySensitive()
                .accessibilityIdentifier("computer-pairing-code")
            HStack {
                Button("Copy Pairing Code") { copy(invitation, said: "Pairing code copied.") }
                    .accessibilityIdentifier("computer-copy-code")
                Button("Copy Terminal Command") {
                    copy("vox computer pair " + shellQuote(invitation), said: "Terminal command copied.")
                }
                .accessibilityIdentifier("computer-copy-command")
            }
            Text("For a computer without the app, paste the terminal command into its own terminal.")
                .secondaryText()
            if let expiry = status.inviteExpiresMs {
                Text(expired(expiry) ? "This pairing code has expired."
                     : "Expires at \(Date(timeIntervalSince1970: Double(expiry) / 1_000).formatted(date: .omitted, time: .shortened)).")
                    .secondaryText()
            }
            if let copied { Text(copied).secondaryText() }
        } else if status.state == "individual" {
            Divider()
            Text("Individual node trust is active until you approve computer trust.")
                .secondaryText()
            Button("Create Pairing Code") {
                Task { await model.perform { try await $0.beginComputerPairing() } }
            }
            .buttonStyle(.voxPrimary)
            .disabled(model.busy || !model.reachable)
            .accessibilityIdentifier("computer-pairing-begin")
            Text("Or use a code from your other computer").eyebrow()
            TextField("Pairing code", text: $link)
                .textFieldStyle(.roundedBorder)
                .privacySensitive()
                .accessibilityIdentifier("computer-pairing-input")
            Button("Review Computer") {
                let code = link.trimmingCharacters(in: .whitespacesAndNewlines)
                link = ""
                Task { await model.perform { try await $0.previewComputerPairing(link: code) } }
            }
            .disabled(model.busy || !model.reachable || link.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            .accessibilityIdentifier("computer-pairing-preview")
        }
        let approvedHere = status.pairing?.approvedHere == true
        let closeExpired = approvedHere && status.pairing?.approvedThere != true
            && status.pairing.map { expired($0.expiresMs) } == true
        if status.state != "confirmed", status.state != "applying", status.state != "quarantined",
           !approvedHere || closeExpired,
           let operation = status.pairing?.operationId ?? status.inviteId {
            Button(closeExpired ? "Close Expired Attempt" : "Cancel Pairing") {
                Task { await model.perform { try await $0.cancelComputerPairing(operationId: operation) } }
            }
            .disabled(model.busy || !model.reachable)
            .accessibilityIdentifier("computer-pairing-cancel")
            Text(closeExpired
                 ? "Closing this attempt lets you start a new pairing here. It cannot withdraw the approval already sent to the other computer."
                 : "Closing this window leaves the pairing pending. Cancel Pairing cancels this unused code.")
                .secondaryText()
        } else if approvedHere, status.state != "confirmed", status.state != "quarantined" {
            Text("Your approval has been sent and cannot be withdrawn here. You can close this window while pairing finishes.")
                .secondaryText()
        }
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

    private func shellQuote(_ text: String) -> String {
        "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private func copy(_ text: String, said: String) {
        NSPasteboard.general.clearContents()
        if NSPasteboard.general.setString(text, forType: .string) { copied = said }
        else { copied = "The clipboard could not be updated. Select and copy the code." }
    }
}
