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
//   COMMANDS <what>=<command> | …   the share's ready-to-copy commands (ADR-028 S-3)
//   NEEDS <need>=<yes|no> | …        what reaching it needs, and whether each holds
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
//   (waits for a line on stdin: a stand-in LAN helper's socket)
//   LAN_UP <line>           `lanUp`, allowing port 5000, answered with the daemon's first line
//   LAN_SAID <lines>        `lanSaid`: what the LAN has said, joined with " | "
//   LAN_DOWN                `lanDown` took it down
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
//   PULLED_BY <names> SAME <true|false>
//                           `pulledBy`: who pulled this node's file share whole (up to 90 s), and
//                           whether it names the share's own announcement
//   REFUSED <error>         `renameRoom` on the peer's room, which this node may not rename
//   CREATED <room> <link>   `createRoom` named "mine", and its link
//   (waits for a line on stdin: the peer has joined it)
//   RENAMED                 `renameRoom` gave it the name "renamed"
//   (waits for a line on stdin: the id of a session of this node's, staged through its hook)
//   SESSION <label> PENDING <n> DRIVE <bool>
//                           `sessions`: that Session, once one request in it waits (up to 90 s)
//   ENTRY <line>            `sessionRead`: one per entry, its line
//   REQUEST <ref> OPEN <bool>
//                           after an entry that is a request: its reference, and whether it is open
//   NOTE <note>             what `sessionRead` says besides; empty for nothing
//   HEARD <n> <m>           how many times the listener heard of an entry in that Session, and of
//                           the room's Sessions changing
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

/// The app's side of the event stream: every message is announced as it arrives; what it hears
/// of Sessions is counted, for the proof to ask.
final class Listener: ClientListener, @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [String: Int] = [:]
    private var rooms: [String: Int] = [:]

    func onMessage(room: String, message: RoomMessage) {
        say("GOT \(message.text)")
    }

    func onNotice(text: String) {}

    func onEnded(text: String) {
        say("ENDED \(text)")
    }

    func onSessions(room: String) {
        lock.lock()
        rooms[room, default: 0] += 1
        lock.unlock()
    }

    func onSessionEntry(room: String, node: String, sessionId: String) {
        lock.lock()
        entries[sessionId, default: 0] += 1
        lock.unlock()
    }

    func heard(session: String, room: String) -> (Int, Int) {
        lock.lock()
        defer { lock.unlock() }
        return (entries[session] ?? 0, rooms[room] ?? 0)
    }
}

do {
    let client = try await VoxClient.open(dataRoot: dataRoot)
    let identity = try Passphrase(bytes: Data(args[3].utf8))
    let me = try await client.attach(node: node, passphrase: identity)
    identity.wipe()
    say("FP \(me)")
    let listener = Listener()
    try await client.subscribe(listener: listener)

    let room = try await client.joinRoom(
        link: link, passphrase: try Passphrase(bytes: Data(args[5].utf8)))
    say("JOINED \(room)")
    // A keyring change takes the identity passphrase: attaching opened no window (ADR-028 K-12).
    let again = try Passphrase(bytes: Data(args[3].utf8))
    try await client.trustAdd(fingerprint: peer, name: "peer", identityPassphrase: again)
    again.wipe()
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
        say("COMMANDS " + s.commands.map { "\($0.what)=\($0.command)" }.joined(separator: " | "))
        say("NEEDS " + s.needs.map { "\($0.need)=\($0.holds ? "yes" : "no")" }.joined(separator: " | "))
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

    // What a message carries for showing (ADR-028 F-9, F-10), and a room's one name (R-1).
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
    var pulledBy: [PulledBy] = []
    let pulledByUntil = Date().addingTimeInterval(90)
    while pulledBy.isEmpty && Date() < pulledByUntil {
        pulledBy = try await client.pulledBy(room: room)
        if pulledBy.isEmpty { try await Task.sleep(nanoseconds: 250_000_000) }
    }
    let byNames = pulledBy.first?.names.joined(separator: ",") ?? ""
    say("PULLED_BY \(byNames) SAME \(pulledBy.first?.id == fileShare.entry)")
    // A rename asks for no passphrase (ADR-028 K-11).
    do {
        try await client.renameRoom(room: room, name: "taken")
        say("REFUSED nothing: the rename was answered")
    } catch {
        say("REFUSED \(error)")
    }
    let made = try await client.createRoom(
        name: "mine", passphrase: try Passphrase(bytes: Data("mine passphrase".utf8)))
    say("CREATED \(made) \(try await client.link(room: made).url)")
    _ = readLine()
    try await client.renameRoom(room: made, name: "renamed")
    say("RENAMED")

    // A Session of this node's own (ADR-029, #554), staged by the proof through `vox agent hook`.
    let sid = (readLine() ?? "").trimmingCharacters(in: .whitespaces)
    var row: FfiSession? = nil
    let sessionUntil = Date().addingTimeInterval(90)
    while row == nil && Date() < sessionUntil {
        row = try await client.sessions(room: room).first { $0.sessionId == sid && $0.pending > 0 }
        if row == nil { try await Task.sleep(nanoseconds: 250_000_000) }
    }
    say("SESSION \(row?.label ?? "") PENDING \(row?.pending ?? 0) DRIVE \(row?.canDrive ?? false)")
    let session = try await client.sessionRead(room: room, node: me, sessionId: sid)
    for e in session.entries {
        say("ENTRY \(e.line)")
        if let r = e.request {
            say("REQUEST \(r.reference) OPEN \(r.state == nil)")
        }
    }
    say("NOTE \(session.note ?? "")")
    let (heardEntries, heardRooms) = listener.heard(session: sid, room: room)
    say("HEARD \(heardEntries) \(heardRooms)")
    _ = readLine()
    await client.close()
    say("CLOSED")
} catch {
    say("ERROR \(error)")
    exit(1)
}
