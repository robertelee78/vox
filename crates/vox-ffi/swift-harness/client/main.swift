// A Swift program that uses the account's vox daemon the way Vox.app does (ADR-014 M-2–M-6):
// linked against the macOS slice of VoxFFI.xcframework, calling only the generated bindings'
// VoxClient. It hosts no node. `crates/vox-tui/tests/ffi_swift_proof.rs` builds and drives it.
//
//   client-harness <data-root> <node> <identity-passphrase> <vox://link> <room-passphrase> <peer-fp>
//
// It prints one line per step, which the proof reads:
//   FP <fingerprint>        attached <node> through the daemon; its identity, for the peer to trust
//   JOINED <room>           joined the peer's room
//   POSTED <n>              posted "hello from swift"; n is how many of the room's messages,
//                           read back at once, are that post
//   (waits for a line on stdin: the peer now trusts it and has posted)
//   GOT <text>              a message arrived through the event listener
//   (waits for a line on stdin: a stand-in LAN helper's socket)
//   LAN_UP <line>           `lanUp`, allowing port 5000, answered with the daemon's first line
//   LAN_SAID <lines>        `lanSaid`: what the LAN has said, joined with " | "
//   LAN_DOWN                `lanDown` took it down
//   (waits for a line on stdin)
//   CLOSED                  the client has closed, letting go of the node
//
// Passphrases reach the client as `Passphrase` handles made from bytes, never kept as text.

import Foundation

let args = CommandLine.arguments
guard args.count == 7 else {
    FileHandle.standardError.write(
        "usage: client-harness <root> <node> <identity-pass> <link> <room-pass> <peer-fp>\n"
            .data(using: .utf8)!)
    exit(2)
}
let (dataRoot, node, link, peer) = (args[1], args[2], args[4], args[6])

func say(_ line: String) {
    print(line)
    fflush(stdout)
}

/// The app's side of the event stream: every message is announced as it arrives.
final class Listener: ClientListener, @unchecked Sendable {
    func onMessage(room: String, message: RoomMessage) {
        say("GOT \(message.text)")
    }

    func onNotice(text: String) {}

    func onEnded(text: String) {
        say("ENDED \(text)")
    }
}

do {
    let client = try await VoxClient.open(dataRoot: dataRoot)
    let identity = try Passphrase(bytes: Data(args[3].utf8))
    let me = try await client.attach(node: node, passphrase: identity)
    identity.wipe()
    say("FP \(me)")
    try await client.subscribe(listener: Listener())

    let room = try await client.joinRoom(
        link: link, name: "calls", passphrase: try Passphrase(bytes: Data(args[5].utf8)))
    say("JOINED \(room)")
    // Within the keyring window the attach opened: no passphrase is asked for.
    try await client.trustAdd(fingerprint: peer, name: "peer", identityPassphrase: nil)
    try await client.post(room: room, text: "hello from swift", to: [], re: "", urgent: false)
    // A post is answered once the node has it: the room read back at once holds it.
    let mine = try await client.read(room: room, after: "", limit: 0)
        .filter { $0.text == "hello from swift" }.count
    say("POSTED \(mine)")

    // The proof trusts this identity on the peer and posts there, then says go.
    _ = readLine()
    // The family LAN, through the helper the proof stands in for.
    let helper = readLine() ?? ""
    say("LAN_UP \(try await client.lanUp(room: room, allow: [5000], helperSocket: helper))")
    // The lines after the first arrive as the LAN says them: up to 10 s for the next two.
    var lanLines = try await client.lanSaid(room: room)
    let saidUntil = Date().addingTimeInterval(10)
    while lanLines.count < 3 && Date() < saidUntil {
        try await Task.sleep(nanoseconds: 100_000_000)
        lanLines = try await client.lanSaid(room: room)
    }
    say("LAN_SAID \(lanLines.joined(separator: " | "))")
    try await client.lanDown(room: room)
    say("LAN_DOWN")
    _ = readLine()
    await client.close()
    say("CLOSED")
} catch {
    say("ERROR \(error)")
    exit(1)
}
