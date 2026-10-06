// Apparatus for the app proofs: an echo service on loopback (the stager's), standing in for a
// service a member shares, and a client that sends a line and reads it back through a forward.

import Foundation
import Network

/// Echoes every byte back, on 127.0.0.1: run by the stager, since this runner may not listen.
struct EchoServer {
    let port: UInt16
    init(_ stager: Stager) throws { port = try stager.echo() }
}

/// A TCP connection to `host:port` as a person's program makes one: send, read back, notice a cut.
final class Line {
    private let conn: NWConnection
    private let queue = DispatchQueue(label: "line")

    init?(_ address: String) {
        let parts = address.split(separator: ":")
        guard parts.count == 2, let port = NWEndpoint.Port(String(parts[1])) else { return nil }
        conn = NWConnection(host: NWEndpoint.Host(String(parts[0])), port: port, using: .tcp)
        let ready = DispatchSemaphore(value: 0)
        conn.stateUpdateHandler = { state in
            if case .ready = state { ready.signal() }
        }
        conn.start(queue: queue)
        guard ready.wait(timeout: .now() + 15) == .success else {
            conn.cancel()
            return nil
        }
    }

    /// Send `text` and read until as many bytes came back, or `seconds` passed. What came back.
    func roundTrip(_ text: String, seconds: Double = 30) -> String {
        let want = Data(text.utf8)
        conn.send(content: want, completion: .contentProcessed { _ in })
        var got = Data()
        let until = Date().addingTimeInterval(seconds)
        while got.count < want.count && Date() < until {
            let one = DispatchSemaphore(value: 0)
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { data, _, _, _ in
                if let data { got.append(data) }
                one.signal()
            }
            if one.wait(timeout: .now() + max(0.1, until.timeIntervalSinceNow)) == .timedOut { break }
        }
        return String(decoding: got, as: UTF8.self)
    }

    /// Whether the connection was cut within `seconds`: a read ends, or fails.
    func cut(within seconds: Double) -> Bool {
        let ended = DispatchSemaphore(value: 0)
        func wait() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { data, _, done, error in
                if done || error != nil || data == nil { ended.signal() } else { wait() }
            }
        }
        wait()
        return ended.wait(timeout: .now() + seconds) == .success
    }

    deinit { conn.cancel() }
}
