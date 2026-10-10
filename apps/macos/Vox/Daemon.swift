// The account's vox daemon, as the app reaches it (ADR-014 M-8, M-9): the login item's daemon
// when the person kept it, else one started as `vox` starts it, never a second one.

import Foundation
import ServiceManagement

/// What the app asks of a background item it registers with macOS (the login item, the LAN
/// helper): registered, unregistered, and its status.
protocol BackgroundItem {
    var status: SMAppService.Status { get }
    func register() throws
    func unregister() async throws
}

extension SMAppService: BackgroundItem {}

#if VOX_PROOF_STUB_SERVICES
/// **Proof builds only** (`scripts/app-proofs.sh` compiles it in; a release never has it, and
/// scripts/assemble-macos-app.sh refuses a bundle that does): a background item that registers
/// nothing. A real login item runs the bundle's `vox daemon` under launchd with none of a proof's
/// scratch directories, on the person's real profile (#571, and the v0.4.0 #439 check); a real LAN
/// helper is a root daemon. This one keeps what the app asked for in `<config dir>/app/<file>`,
/// where the proof reads it.
struct ProofBackgroundItem: BackgroundItem {
    /// The marker app-proofs.sh and assemble look for in the executable.
    static let marker = "vox-proof-service-stand-in"
    /// `proof-login-item` or `proof-lan-helper`.
    let name: String

    private var file: URL? {
        guard let dir = try? configDir(dataRoot: "") else { return nil }
        return URL(fileURLWithPath: dir).appendingPathComponent("app/\(name)")
    }

    var status: SMAppService.Status {
        guard let file, let text = try? String(contentsOf: file, encoding: .utf8) else {
            return .notRegistered
        }
        if text.hasPrefix("registered") { return .enabled }
        if text.hasPrefix("awaiting-approval") { return .requiresApproval }
        return .notRegistered
    }

    /// Registered at once, as macOS does for an item it has approved; or, when
    /// `<config dir>/app/<name>.approval` says `ask`, left awaiting the person's approval, which
    /// the proof gives by writing `registered` itself, standing in for the switch in System
    /// Settings.
    func register() throws {
        let asks = file.flatMap { try? String(contentsOf: $0.appendingPathExtension("approval"),
                                              encoding: .utf8) }?
            .trimmingCharacters(in: .whitespacesAndNewlines) == "ask"
        write(asks ? "awaiting-approval" : "registered")
    }
    func unregister() async throws { write("unregistered") }

    private func write(_ state: String) {
        guard let file else { return }
        Self.write("\(state) \(Self.marker)\n", to: file)
    }

    static func write(_ text: String, to file: URL) {
        try? FileManager.default.createDirectory(
            at: file.deletingLastPathComponent(), withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try? Data(text.utf8).write(to: file, options: .atomic)
    }

    /// Opening System Settings' Login Items, recorded in `<config dir>/app/proof-opened-login-items`
    /// instead: no proof drives a System Settings pane.
    static func openLoginItems() {
        guard let dir = try? configDir(dataRoot: "") else { return }
        write("opened \(Date().timeIntervalSince1970) \(marker)\n",
              to: URL(fileURLWithPath: dir).appendingPathComponent("app/proof-opened-login-items"))
    }
}
#endif

enum Daemon {
    /// The login item: the bundle's launch agent, running the bundle's own `vox daemon` (M-8). In
    /// a proof build, a stand-in that registers nothing ([`ProofBackgroundItem`]).
    static var loginItem: any BackgroundItem {
        #if VOX_PROOF_STUB_SERVICES
        ProofBackgroundItem(name: "proof-login-item")
        #else
        SMAppService.agent(plistName: "us.vox.daemon.plist")
        #endif
    }

    /// The family LAN's root helper: the bundle's launch daemon (ADR-014 M-10). In a proof build,
    /// a stand-in that registers nothing: no proof can register a root daemon.
    static var lanHelper: any BackgroundItem {
        #if VOX_PROOF_STUB_SERVICES
        ProofBackgroundItem(name: "proof-lan-helper")
        #else
        SMAppService.daemon(plistName: "us.vox.lanhelper.plist")
        #endif
    }

    /// How long the login item's daemon, or one started here, is waited for (ADR-026 S-2).
    static let patience: TimeInterval = 15

    /// **The agent skill pack, installed or refreshed for every harness here** (#586): once per
    /// build of Vox.app, at launch, so a first run and every update of the app put the pack the
    /// bundle's `vox` carries in each harness's skills folder, as `install.sh` and `vox update` do.
    /// A file the operator changed is kept. `vox agent skill --install` does it, in the background;
    /// a launch where it fails tries again. In a proof build its HOME is
    /// `<config dir>/app/home` and no harness variable reaches it, so no proof touches the
    /// person's own harness folders, and it runs at every launch.
    static func refreshSkillPack() {
        let build = (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "")
            + " " + (Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "")
        let key = "skillPackInstalledFor"
        var env = ProcessInfo.processInfo.environment
        #if VOX_PROOF_STUB_SERVICES
        guard let dir = try? configDir(dataRoot: "") else { return }
        env["HOME"] = URL(fileURLWithPath: dir).appendingPathComponent("app/home").path
        for name in ["CLAUDE_CONFIG_DIR", "CODEX_HOME", "OPENCODE_CONFIG_DIR", "XDG_CONFIG_HOME"] {
            env[name] = nil
        }
        #else
        if UserDefaults.standard.string(forKey: key) == build { return }
        #endif
        let environment = env
        Task.detached {
            let p = Process()
            p.executableURL = vox
            p.arguments = ["agent", "skill", "--install"]
            p.environment = environment
            p.standardOutput = FileHandle.nullDevice
            p.standardError = FileHandle.nullDevice
            p.standardInput = FileHandle.nullDevice
            guard (try? p.run()) != nil else { return }
            p.waitUntilExit()
            if p.terminationStatus == 0 {
                UserDefaults.standard.set(build, forKey: key)
            }
        }
    }

    /// A client of the account's daemon. When none answers, the bundle's `vox` starts one as
    /// `vox` does (`vox daemon --detach`, ADR-026 S-2), which starts none if one runs: also with
    /// the login item on, whose daemon may not be running (stopped, refused, or not loaded yet),
    /// and with which it cannot make a second (D-1: one holds the account's lock).
    static func reach() async throws -> VoxClient {
        if let client = try? await VoxClient.open(dataRoot: "") {
            return client
        }
        try await startAsVoxDoes()
        let until = Date().addingTimeInterval(patience)
        var last: Error?
        while Date() < until {
            do {
                return try await VoxClient.open(dataRoot: "")
            } catch {
                last = error
                try await Task.sleep(nanoseconds: 250_000_000)
            }
        }
        throw StartFailure(kind: .notAnswering,
                           said: last.map(sentence) ?? "the vox daemon did not answer")
    }

    /// The bundle's `vox`, at Contents/Helpers/vox.
    static var vox: URL {
        Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/vox")
    }

    /// `vox daemon --detach`: started in the background, its output in `<data root>/.daemon/log`,
    /// returning once it answers. A failure is its own sentence (M-7).
    private static func startAsVoxDoes() async throws {
        let (status, said) = try await Task.detached { () throws -> (Int32, String) in
            let p = Process()
            p.executableURL = vox
            p.arguments = ["daemon", "--detach"]
            let out = Pipe()
            p.standardOutput = out
            p.standardError = out
            p.standardInput = FileHandle.nullDevice
            try p.run()
            let bytes = out.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            return (p.terminationStatus, String(decoding: bytes, as: UTF8.self))
        }.value
        guard status == 0 else {
            let text = said.trimmingCharacters(in: .whitespacesAndNewlines)
            throw StartFailure(kind: .exited, said: text.isEmpty
                ? "the vox daemon did not start (vox exited \(status))"
                : text.replacingOccurrences(of: "vox: ", with: ""))
        }
    }

    /// The login item's last word on why it would not start, with when: its daemon writes it to
    /// `~/Library/Logs/Vox/login-item.log` (as `<unix milliseconds> <reason>`) and ends, rather than
    /// being started again every ten seconds.
    static func loginItemSaid() -> String? {
        let home = ProcessInfo.processInfo.environment["HOME"] ?? NSHomeDirectory()
        let log = URL(fileURLWithPath: home).appendingPathComponent("Library/Logs/Vox/login-item.log")
        guard let text = try? String(contentsOf: log, encoding: .utf8),
              let last = text.split(separator: "\n").last(where: { !$0.isEmpty }) else { return nil }
        let parts = last.split(separator: " ", maxSplits: 1)
        guard parts.count == 2, let ms = Double(parts[0]) else { return String(last) }
        let when = Date(timeIntervalSince1970: ms / 1_000).formatted(date: .abbreviated, time: .shortened)
        return "\(parts[1]) (\(when))"
    }

    // ---- Keep Running: the one implementation the first run, the Vox menu and Settings use ----

    /// Keep Running on: the answer kept as Keep Running and the login item registered. Returns
    /// the login item's status after: `.enabled`, or `.requiresApproval` when macOS asks the person
    /// first (M-8). A refusal leaves the answer as Not Now and is thrown.
    static func startKeeping() throws -> SMAppService.Status {
        remember(kept: true)
        do {
            try loginItem.register()
        } catch {
            remember(kept: false)
            throw error
        }
        return loginItem.status
    }

    /// System Settings' Login Items, where the person approves the login item or the LAN helper;
    /// in a proof build, only recorded ([`ProofBackgroundItem.openLoginItems`]).
    static func openLoginItems() {
        #if VOX_PROOF_STUB_SERVICES
        ProofBackgroundItem.openLoginItems()
        #else
        SMAppService.openSystemSettingsLoginItems()
        #endif
    }

    /// Keep Running off: the login item unregistered (when it is registered), and the answer
    /// kept as Not Now.
    static func stopKeeping() async throws {
        if loginItem.status != .notRegistered {
            try await loginItem.unregister()
        }
        remember(kept: false)
    }

    // ---- the first run's answer, kept beside vox's own settings -----------------------------

    /// What the person answered at first run: keep the daemon running (`true`), not now
    /// (`false`), or not asked yet (`nil`).
    static func kept() -> Bool? {
        guard let file = answerFile(), let text = try? String(contentsOf: file, encoding: .utf8)
        else { return nil }
        switch text.trimmingCharacters(in: .whitespacesAndNewlines) {
        case "keep": return true
        case "no": return false
        default: return nil
        }
    }

    static func remember(kept: Bool) {
        guard let file = answerFile() else { return }
        try? FileManager.default.createDirectory(
            at: file.deletingLastPathComponent(), withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try? Data((kept ? "keep\n" : "no\n").utf8).write(to: file, options: .atomic)
    }

    /// `<config dir>/app/login-item`, or nil when the config directory cannot be found (then
    /// the daemon cannot be reached either, and the app says why).
    private static func answerFile() -> URL? {
        guard let dir = try? configDir(dataRoot: "") else { return nil }
        return URL(fileURLWithPath: dir).appendingPathComponent("app/login-item")
    }
}
