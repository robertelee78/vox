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
//   (waits for a line on stdin: the peer now shares a service in the room)
//   SHARED <address> <by> <kind>
//                           one per service the peer shares, as `services` lists it, once the
//                           room's log has brought the peer's share (up to 120 s)
//   (waits for a line on stdin: the proof has compared the list with `vox service list`)
//   BOUND <ip:port>         `forward` to the first shared address bound there
//   (waits for a line on stdin: the bound address, once the proof has been through the forward)
//   STOPPED                 `stopForward` stopped it
//   STATUS <json>           `status`: the node's report, on one line
//   (waits for a line on stdin: the path of a file to share to the peer)
//   SHARED_FILE <name> <sha256>
//                           `share` to the peer, with a note, answered once the daemon serves it
//   LISTED_FILES <n> <name> `shares`: this node's shares in the room
//   (waits for a line on stdin: the peer has shared a file to this node)
//   PULLED <path>           `pulled`: the file this node pulled by itself (up to 90 s)
//   (waits for a line on stdin: the port a stand-in listens on, on every interface)
//   LISTENING <line> EVERY <true|false>
//                           `listening`: the stand-in, as one-step sharing lists it
//   MISSING <sentence>      what is said under the list
//   PREVIEW <tag> <ip:port> <warning | warning …>
//                           `servicePreview`: what sharing it would do, said before it is
//   OFFERED <tag>           `serviceAdd` with the preview's tag and endpoint: shared in the room
//   (waits for a line on stdin: the peer has posted a link)
//   CARD <title> | <description> | <n>
//                           the link card the peer's node fetched, as `read` gives it (up to 90 s);
//                           n is its image's size in bytes
//   IMAGE <w>x<h> JPEG <true|false> BLURHASH <hash>
//                           the image the peer's file share announced: dimensions, whether the
//                           thumbnail is a JPEG, its BlurHash
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
        link: link, passphrase: try Passphrase(bytes: Data(args[5].utf8)))
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
    // Once the proof has its answer about the event stream, the peer shares a service.
    _ = readLine()
    var shared: [SharedService] = []
    let until = Date().addingTimeInterval(120)
    while Date() < until {
        shared = try await client.services(room: room).shared.filter { $0.by != "you" }
        if !shared.isEmpty { break }
        try await Task.sleep(nanoseconds: 250_000_000)
    }
    for s in shared {
        say("SHARED \(s.address) \(s.by) \(s.kind)")
    }
    guard let first = shared.first else {
        say("ERROR the peer's share was never listed")
        exit(1)
    }
    _ = readLine()
    say("BOUND \(try await client.forward(address: first.address, local: ""))")
    let bound = readLine() ?? ""
    try await client.stopForward(local: bound)
    say("STOPPED")
    let report = try await client.status()
    say("STATUS \(report.replacingOccurrences(of: "\n", with: " "))")

    let file = readLine() ?? ""
    let fileShare = try await client.share(
        room: room, path: file, to: [peer], note: "from swift", re: "", urgent: false, count: 0,
        forSecs: 0)
    say("SHARED_FILE \(fileShare.name) \(fileShare.sha256)")
    let mineListed = try await client.shares(room: room)
    say("LISTED_FILES \(mineListed.count) \(mineListed.first?.name ?? "")")

    _ = readLine()
    var pulled: [PulledFile] = []
    // Within the proof's own wait for this line (120 s), so an empty answer is its to judge.
    let pullUntil = Date().addingTimeInterval(90)
    while pulled.isEmpty && Date() < pullUntil {
        pulled = try await client.pulled(room: room)
        if pulled.isEmpty { try await Task.sleep(nanoseconds: 250_000_000) }
    }
    say("PULLED \(pulled.first?.path ?? "")")

    // One-step sharing (ADR-028 S-4, #444): what listens here, what sharing it says, then share.
    let port = UInt16(readLine() ?? "") ?? 0
    let here = await client.listening()
    for s in here.services where s.port == port {
        say("LISTENING \(s.line) EVERY \(s.everyInterface)")
    }
    say("MISSING \(here.mayBeMissing)")
    let preview = try await client.servicePreview(port: port, udp: false)
    say("PREVIEW \(preview.tag) \(preview.local) \(preview.warnings.joined(separator: " | "))")
    try await client.serviceAdd(room: room, tag: preview.tag, local: preview.local)
    say("OFFERED \(preview.tag)")

    // What a message carries for showing (ADR-028 F-9, F-10).
    _ = readLine()
    var card: LinkCard? = nil
    let cardUntil = Date().addingTimeInterval(90)
    while card == nil && Date() < cardUntil {
        card = try await client.read(room: room, after: "", limit: 0).compactMap { $0.card }.first
        if card == nil { try await Task.sleep(nanoseconds: 250_000_000) }
    }
    say("CARD \(card?.title ?? "") | \(card?.description ?? "") | \(card?.image?.count ?? 0)")
    let image = try await client.read(room: room, after: "", limit: 0)
        .compactMap { $0.image }.first
    let jpeg = image.map { $0.thumb.starts(with: [0xFF, 0xD8]) } ?? false
    say("IMAGE \(image?.width ?? 0)x\(image?.height ?? 0) JPEG \(jpeg) BLURHASH \(image?.blurhash ?? "")")
    _ = readLine()
    await client.close()
    say("CLOSED")
} catch {
    say("ERROR \(error)")
    exit(1)
}
