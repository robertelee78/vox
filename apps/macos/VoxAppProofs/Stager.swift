// Apparatus: the client of scripts/app-proof-stager.py, which runs outside the UI-test runner's
// sandbox what the proofs stage — every `vox`, the files they write, the echo services — since a
// process this runner starts inherits its sandbox and cannot write its scratch data root.

import Foundation
import Network

final class Stager {
    private let conn: NWConnection
    private let token: String
    private var buffer = Data()

    /// The stager `scripts/app-proofs.sh` started, from VOX_PROOF_STAGER_PORT and _TOKEN.
    static func fromEnvironment() throws -> Stager {
        let env = ProcessInfo.processInfo.environment
        guard let port = env["VOX_PROOF_STAGER_PORT"].flatMap(UInt16.init),
              let token = env["VOX_PROOF_STAGER_TOKEN"] else {
            throw Apparatus("VOX_PROOF_STAGER_PORT and _TOKEN are set by scripts/app-proofs.sh")
        }
        return try Stager(port: port, token: token)
    }

    init(port: UInt16, token: String) throws {
        self.token = token
        conn = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
        let ready = DispatchSemaphore(value: 0)
        conn.stateUpdateHandler = { if case .ready = $0 { ready.signal() } }
        conn.start(queue: DispatchQueue(label: "stager"))
        guard ready.wait(timeout: .now() + 10) == .success else {
            throw Apparatus("the stager on 127.0.0.1:\(port) did not answer")
        }
    }

    /// One request, one answer.
    func ask(_ request: [String: Any], within seconds: Double = 330) throws -> [String: Any] {
        var req = request
        req["token"] = token
        var line = try JSONSerialization.data(withJSONObject: req)
        line.append(0x0A)
        conn.send(content: line, completion: .contentProcessed { _ in })
        let until = Date().addingTimeInterval(seconds)
        while true {
            if let nl = buffer.firstIndex(of: 0x0A) {
                let body = buffer[buffer.startIndex..<nl]
                buffer = Data(buffer[(nl + 1)...])
                guard let answer = try JSONSerialization.jsonObject(with: body) as? [String: Any] else {
                    throw Apparatus("the stager's answer is not an object")
                }
                if let error = answer["error"] as? String, answer["id"] == nil {
                    throw Apparatus("the stager could not \(request["op"] ?? "?"): \(error)")
                }
                return answer
            }
            guard Date() < until else { throw Apparatus("the stager did not answer in \(seconds) s") }
            let got = DispatchSemaphore(value: 0)
            conn.receive(minimumIncompleteLength: 1, maximumLength: 1 << 20) { data, _, _, _ in
                if let data { self.buffer.append(data) }
                got.signal()
            }
            _ = got.wait(timeout: .now() + max(0.1, until.timeIntervalSinceNow))
        }
    }

    /// Run `args` to its end with exactly `env`; its status and what it printed.
    func run(_ args: [String], env: [String: String], input: String? = nil) -> (status: Int32, out: String) {
        var req: [String: Any] = ["op": "run", "args": args, "env": env]
        if let input { req["stdin"] = input }
        do {
            let a = try ask(req)
            return (Int32(a["status"] as? Int ?? -1), a["out"] as? String ?? "")
        } catch {
            return (-1, "\(error)")
        }
    }

    /// Start `args` and wait until it prints a line starting with `until`.
    func start(_ args: [String], env: [String: String], until: String,
               within seconds: Double = 30) throws -> (id: Int, line: String?, out: String) {
        let a = try ask(["op": "start", "args": args, "env": env, "until": until, "within": seconds],
                        within: seconds + 30)
        return (a["id"] as? Int ?? -1, a["line"] as? String, a["out"] as? String ?? "")
    }

    func stop(_ id: Int) { _ = try? ask(["op": "stop", "id": id]) }

    /// Own an existing native harness apparatus speaking one JSON reply per stdin line.
    /// Its stderr remains separate from the protocol, in this journey's scratch log.
    func jsonHost(_ args: [String], env: [String: String], cwd: String,
                  stderr: String) throws -> StagedJSONHost {
        let reply = try ask(["op": "json-host-start", "args": args, "env": env,
                             "cwd": cwd, "stderr": stderr], within: 30)
        guard let handle = reply["handle"] as? String, !handle.isEmpty else {
            throw Apparatus("the stager returned no owned native host handle")
        }
        return StagedJSONHost(stager: self, handle: handle)
    }

    func write(_ data: Data, to path: String) throws {
        _ = try ask(["op": "write", "path": path, "base64": data.base64EncodedString()])
    }

    /// A loopback echo service; its port.
    func echo() throws -> UInt16 {
        guard let port = try ask(["op": "echo"])["port"] as? Int else {
            throw Apparatus("the stager started no echo service")
        }
        return UInt16(port)
    }
}

/// A process the stager started, stopped by it.
struct Started {
    let stager: Stager
    let id: Int
    func terminate() { stager.stop(id) }
    func waitUntilExit() {}
}

/// An opaque child owned by the stager, never an arbitrary process ID.
/// A failed or timed-out conversation is retired before any subsequent command.
final class StagedJSONHost {
    private let stager: Stager
    private let handle: String

    fileprivate init(stager: Stager, handle: String) {
        self.stager = stager
        self.handle = handle
    }

    func command(_ line: String, within seconds: Double = 30) throws -> [String: Any] {
        guard seconds.isFinite, seconds > 0, seconds <= 120 else {
            throw Apparatus("native host response bound must be between 0 and 120 seconds")
        }
        let answer = try stager.ask(["op": "json-host-command", "handle": handle,
                                     "command": line, "within": seconds], within: seconds + 10)
        guard let reply = answer["reply"] as? [String: Any] else {
            throw Apparatus("the native host's response is not a JSON object")
        }
        return reply
    }

    func terminate() {
        _ = try? stager.ask(["op": "json-host-stop", "handle": handle], within: 10)
    }

    deinit { terminate() }
}
