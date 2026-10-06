// The account's vox daemon, as the app reaches it (ADR-014 M-8, M-9): the login item's daemon
// when the person kept it, else one started as `vox` starts it, never a second one.

import Foundation
import ServiceManagement

enum Daemon {
    /// The login item: the bundle's launch agent, running the bundle's own `vox daemon` (M-8).
    static var loginItem: SMAppService { .agent(plistName: "us.vox.daemon.plist") }

    /// How long the login item's daemon, or one started here, is waited for (ADR-026 S-2).
    static let patience: TimeInterval = 15

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
        throw last ?? VoxError.Failed(reason: "the vox daemon did not answer")
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
            throw VoxError.Failed(reason: text.isEmpty
                ? "the vox daemon did not start (vox exited \(status))"
                : text.replacingOccurrences(of: "vox: ", with: ""))
        }
    }

    /// The login item's last word on why it would not start, with when: its daemon writes it to
    /// `~/Library/Logs/Vox/login-item.log` (as `<unix seconds> <reason>`) and ends, rather than
    /// being started again every ten seconds.
    static func loginItemSaid() -> String? {
        let home = ProcessInfo.processInfo.environment["HOME"] ?? NSHomeDirectory()
        let log = URL(fileURLWithPath: home).appendingPathComponent("Library/Logs/Vox/login-item.log")
        guard let text = try? String(contentsOf: log, encoding: .utf8),
              let last = text.split(separator: "\n").last(where: { !$0.isEmpty }) else { return nil }
        let parts = last.split(separator: " ", maxSplits: 1)
        guard parts.count == 2, let secs = Double(parts[0]) else { return String(last) }
        let when = Date(timeIntervalSince1970: secs).formatted(date: .abbreviated, time: .shortened)
        return "\(parts[1]) (\(when))"
    }

    /// Keep Running off: the login item unregistered (when it is registered), and the answer
    /// kept as Not Now.
    static func stopKeeping() throws {
        if loginItem.status != .notRegistered {
            try loginItem.unregister()
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
