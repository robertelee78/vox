// Node-free onboarding (ADR-031 HK-4, NC-2/3). These files contain names and answers only.
// The passphrase belongs to the app's secure fields and existing FFI calls, never this handoff.

import Foundation
import SwiftUI
import Darwin

struct AgentSetupRequest: Codable, Equatable, Identifiable {
    let harness: String
    let dir: String
    let node: String
    let request: String
    let sessions: [String]
    let explicit: Bool
    let ompAgentDir: String?
    var id: String { "\(harness)-\(request)" }
    var name: String {
        switch harness { case "claude": "Claude Code"; case "codex": "Codex"; case "opencode": "OpenCode"; case "omp": "Oh My Pi"; default: harness }
    }
    enum CodingKeys: String, CodingKey {
        case harness, dir, node, sessions, explicit
        case ompAgentDir = "omp_agent_dir"
        case request = "id"
    }

    func completionTarget() throws -> [String] {
        guard harness == "omp" else {
            guard ompAgentDir == nil else {
                throw VoxError.Failed(reason: "An OMP agent directory is not valid for this harness.")
            }
            return []
        }
        guard let target = ompAgentDir, target.hasPrefix("/"), target.utf8.count <= 4096,
              target.contains(where: { $0 != "/" }),
              !target.components(separatedBy: "/").contains(".."),
              target.rangeOfCharacter(from: .controlCharacters) == nil else {
            throw VoxError.Failed(reason: "The OMP agent directory is missing or invalid. Request setup again.")
        }
        return ["--omp-agent-dir", target]
    }
}

enum AgentSetupStore {
    /// The CLI uses this same flock. Hold it only while applying the person's choice, never
    /// while the sheet waits for input, so the approved request cannot be replaced mid-action.
    static func lock(_ request: AgentSetupRequest) throws -> FileHandle {
        let handle = try FileHandle(forUpdating: file(request.harness, ".lock"))
        guard flock(handle.fileDescriptor, LOCK_EX | LOCK_NB) == 0 else {
            try? handle.close()
            throw VoxError.Failed(reason: "Another setup request is being recorded. Try again.")
        }
        return handle
    }

    static func file(_ harness: String, _ suffix: String) throws -> URL {
        let config = try configDir(dataRoot: "")
        return URL(fileURLWithPath: config).appendingPathComponent("agent-setup/\(harness)\(suffix)")
    }

    static func requests() -> [AgentSetupRequest] {
        ["claude", "codex", "opencode", "omp"].compactMap { harness in
            guard let at = try? file(harness, ".json"), let bytes = try? Data(contentsOf: at),
                  bytes.count <= 16 * 1024,
                  let request = try? JSONDecoder().decode(AgentSetupRequest.self, from: bytes),
                  request.harness == harness else { return nil }
            return request
        }
    }

    static func declined(_ request: AgentSetupRequest) -> Bool {
        guard let at = try? file(request.harness, ".declined") else { return false }
        return FileManager.default.fileExists(atPath: at.path)
    }

    static func answered(_ request: AgentSetupRequest) -> Bool {
        guard let at = try? file(request.harness, ".answer.json"),
              let bytes = try? Data(contentsOf: at),
              let answer = try? JSONSerialization.jsonObject(with: bytes) as? [String: String]
        else { return false }
        return answer["request"] == request.request
    }

    static func madeNode(_ name: String) -> Bool {
        requests().contains { request in
            guard let at = try? file(request.harness, ".answer.json"),
                  let bytes = try? Data(contentsOf: at),
                  let answer = try? JSONSerialization.jsonObject(with: bytes) as? [String: String]
            else { return false }
            return answer["made_node"] == name
        }
    }

    static func write(_ value: [String: String], to at: URL) throws {
        try FileManager.default.createDirectory(at: at.deletingLastPathComponent(),
            withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try JSONSerialization.data(withJSONObject: value).write(to: at, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: at.path)
    }

    static func answer(_ request: AgentSetupRequest, outcome: String, node: String) throws {
        let muted = try file(request.harness, ".declined")
        if outcome == "declined" {
            try write(["outcome": "declined"], to: muted)
        }
        let at = try file(request.harness, ".answer.json")
        var answer = ["request": request.request, "outcome": outcome, "node": node]
        if outcome == "ready" { answer["made_node"] = node }
        else if let bytes = try? Data(contentsOf: at),
                let previous = try? JSONSerialization.jsonObject(with: bytes) as? [String: String] {
            answer["made_node"] = previous["made_node"]
        }
        try write(answer, to: at)
        if outcome == "ready", FileManager.default.fileExists(atPath: muted.path) {
            try FileManager.default.removeItem(at: muted)
        }
    }

    static func registerApp() {
        guard let config = try? configDir(dataRoot: "") else { return }
        try? write(["bundle": Bundle.main.bundleURL.path],
                   to: URL(fileURLWithPath: config).appendingPathComponent("app/bundle.json"))
    }
}

struct AgentSetupOffers: View {
    @ObservedObject var model: AppModel
    var body: some View {
        if let request = model.agentSetupOffers.first {
            HStack(alignment: .top, spacing: Space.s12) {
                VStack(alignment: .leading, spacing: Space.s4) {
                    Text("Set up \(request.name) for Vox").font(Theme.text)
                    Text("This harness has no Vox node on this machine.").secondaryText()
                }
                Spacer()
                Button("Set Up") { model.offerAgentSetup(request) }
                    .accessibilityIdentifier("agent-setup-offer-\(request.harness)")
                Button("Not Now") { model.declineAgentSetup(request) }
                    .accessibilityIdentifier("agent-setup-not-now-\(request.harness)")
            }
            .padding(Space.s16)
            .panelSurface()
        }
    }
}

/// A window owned by the app: the harness, directory, editable node name, and secure fields.
struct AgentSetupSheet: View {
    let request: AgentSetupRequest
    @ObservedObject var model: AppModel
    @State private var name: String
    @State private var first = SecureFieldHolder()
    @State private var again = SecureFieldHolder()
    @State private var empty = true

    init(request: AgentSetupRequest, model: AppModel) {
        self.request = request
        self.model = model
        _name = State(initialValue: request.node)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.s12) {
            Text("Set Up \(request.name)").heading()
                .accessibilityIdentifier("agent-setup-harness")
            Text(request.dir.isEmpty ? "No session directory yet." : "Directory: \(request.dir)")
                .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("agent-setup-directory")
            if request.harness == "omp" {
                Text("OMP agent directory: \(request.ompAgentDir ?? "missing")")
                    .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("agent-setup-omp-directory")
            }
            TextField("Node name", text: $name)
                .accessibilityIdentifier("agent-setup-name")
            Text("Lowercase letters, digits, dots, dashes and underscores.").secondaryText()
            SecureInput(holder: first, onEmpty: { empty = $0 }) { again.field.becomeFirstResponder() }
                .accessibilityIdentifier("agent-setup-passphrase")
                .accessibilityLabel("Agent node identity passphrase")
            SecureInput(holder: again) { submit() }
                .accessibilityIdentifier("agent-setup-passphrase-again")
                .accessibilityLabel("Agent node identity passphrase again")
            if empty {
                Text(asSentence(noPassphraseNotice())).secondaryText()
                    .accessibilityIdentifier("agent-setup-no-passphrase")
            }
            Text("Vox remembers this node on this Mac. A passphrase, if you choose one, is kept in "
                + "the Keychain so it is Ready after a restart; it is never sent to the agent.")
                .secondaryText()
            Text(asSentence(noBackupNotice())).secondaryText()
            if let said = model.agentSetupFailed {
                StateMark(kind: .danger, words: said).accessibilityIdentifier("agent-setup-failed")
            }
            HStack {
                Button("Not Now") { model.declineAgentSetup(request) }
                    .accessibilityIdentifier("agent-setup-decline")
                Spacer()
                if model.agentSetupBusy { ProgressView("Setting up…") }
                Button("Set Up") { submit() }
                    .keyboardShortcut(.defaultAction).buttonStyle(.voxPrimary)
                    .accessibilityIdentifier("agent-setup-make")
            }
        }
        .disabled(model.agentSetupBusy)
        .padding(Space.s24).font(Theme.text).panelSurface()
        .frame(width: Theme.scaled(480))
    }

    private func submit() {
        guard !model.agentSetupBusy else { return }
        let secret = first.takeAllowingEmpty()
        let repeated = again.takeAllowingEmpty()
        Task { await model.setUpAgent(request, name: name.trimmingCharacters(in: .whitespaces).lowercased(),
                                      passphrase: secret, again: repeated) }
    }
}
