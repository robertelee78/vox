// A Swift program that embeds the Vox node the way an app does (PRD-001 R30/R31):
// linked against the macOS slice of VoxFFI.xcframework, calling only the generated
// bindings. `crates/vox-tui/tests/ffi_swift_proof.rs` builds and drives it.
//
//   harness <data-dir> <vox://link> <room-passphrase> <daemon-fingerprint>
//
// It prints one line per step, which the proof reads:
//   FP <fingerprint>        its identity, for the daemon to trust
//   JOINED <room>           joined the daemon's room
//   POSTED                  posted "hello from swift"
//   (waits for a line on stdin: the daemon now trusts it)
//   GOT <text>              a message arrived through the event stream
//   STREAM <n> <sha256>     the 1 MiB app-stream round trip came back
//   DGRAMS <n>              datagrams echoed back of 100 sent
//   DONE

import CryptoKit
import Foundation

let args = CommandLine.arguments
guard args.count == 5 else {
    FileHandle.standardError.write("usage: harness <dir> <link> <room-passphrase> <daemon-fp>\n".data(using: .utf8)!)
    exit(2)
}
let (dataDir, link, roomPassphrase, daemon) = (args[1], args[2], args[3], args[4])

func say(_ line: String) {
    print(line)
    fflush(stdout)
}

/// The app's side of the event stream: every message is announced as it arrives.
final class Listener: EventListener, @unchecked Sendable {
    func onMessage(room: String, message: Message) {
        say("GOT \(message.text)")
    }

    func onNotice(text: String) {}
}

/// The distinct datagrams that came back, counted across tasks.
final class Seen: @unchecked Sendable {
    private let lock = NSLock()
    private var set = Set<Data>()
    func add(_ d: Data) { lock.lock(); set.insert(d); lock.unlock() }
    var count: Int { lock.lock(); defer { lock.unlock() }; return set.count }
}

func hex(_ digest: SHA256.Digest) -> String {
    digest.map { String(format: "%02x", $0) }.joined()
}

do {
    let node = try await VoxNode.start(dataDir: dataDir, passphrase: "harness identity", listen: "127.0.0.1:0")
    say("FP \(node.fingerprint())")
    node.subscribe(listener: Listener())

    let room = try await node.joinRoom(link: link, name: "calls", passphrase: roomPassphrase)
    say("JOINED \(room)")
    try await node.trust(fingerprint: daemon, name: "daemon")
    try await node.post(room: room, text: "hello from swift")
    say("POSTED")

    // The proof trusts this identity on the daemon, and starts its listeners, then says go.
    _ = readLine()

    // A mebibyte to the daemon's `vox app listen`, which echoes it back.
    var payload = Data(count: 1 << 20)
    for i in 0..<payload.count {
        payload[i] = UInt8(truncatingIfNeeded: (i &* 2_654_435_761) >> 13)
    }
    let stream = try await node.appOpen(room: room, peer: daemon, labels: ["echo/v1"], datagrams: false)
    let writer = Task {
        var at = 0
        while at < payload.count {
            let end = min(at + 64 * 1024, payload.count)
            try await stream.write(data: payload.subdata(in: at..<end))
            at = end
        }
        await stream.finish()
    }
    var back = Data()
    while let chunk = try await stream.read(max: 64 * 1024) {
        back.append(chunk)
    }
    try await writer.value
    say("STREAM \(back.count) \(hex(SHA256.hash(data: back))) sent \(hex(SHA256.hash(data: payload)))")

    // A hundred datagrams to a second listener, which echoes each one back.
    let flow = try await node.appOpen(room: room, peer: daemon, labels: ["dgram/v1"], datagrams: true)
    let seen = Seen()
    Task {
        while let d = await flow.recvDatagram() {
            seen.add(d)
        }
    }
    for i in 0..<100 {
        try flow.sendDatagram(data: "datagram \(i)".data(using: .utf8)!)
        try await Task.sleep(nanoseconds: 5_000_000)
    }
    // Datagrams are not confirmed: count what came back within a generous window.
    for _ in 0..<200 where seen.count < 100 {
        try await Task.sleep(nanoseconds: 100_000_000)
    }
    let echoed = seen.count
    say("DGRAMS \(echoed)")

    // Hold on until the proof has its answer about the event stream.
    _ = readLine()
    say("DONE")
    await node.stop()
} catch {
    say("ERROR \(error)")
    exit(1)
}
