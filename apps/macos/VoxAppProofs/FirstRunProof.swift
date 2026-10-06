// ADR-014 M-6, ADR-028 A-4 and M-7 — first run to an attached node, and quit detaching it, proved
// by real use of the built Vox.app (ADR-018, ADR-014 M-30).
//
// Run by `scripts/app-proofs.sh`, which builds the app, puts the release `vox` in it, and passes
// (through xcodebuild's TEST_RUNNER_ prefix):
//   VOX_PROOF_APP      the Vox.app under proof; its Contents/Helpers/vox runs the daemon
//   VOX_PROOF_SCRATCH  a scratch directory: the data root and config directory go there
//
// What must hold, as a person sees it:
// 1. At first run the app asks once whether to keep the daemon running while logged in, saying
//    what that does (ADR-014 M-8), and offers the menu bar extra, off until turned on; clicked,
//    the toggle shows it on (M-22; the item itself is looked at by a person in the notification
//    case: XCTest reads no menu bar items here). The person says Not Now. Then it lists the Mac's nodes; the person picks one and types its passphrase.
//    A wrong passphrase shows the daemon's own sentence where it was typed.
// 2. The right one attaches the node: the app says so, and `vox node list` says `attached`.
// 3. The main window (ADR-028 W-1, W-2; ADR-014 M-13): ⌘N makes the room and shows it; bob joins
//    and alice trusts him while it is on screen, and its inspector lists him in her keyring. Off
//    the room, once bob posts to it a message addressed to alice, the sidebar lists the room under "needs you (1)"; the
//    inspector lists bob with his trust glyph; the status bar says the node, its peers and the
//    keyring window.
// 4. Read each way (ADR-028 R-6, ADR-014 M-14, #441): bob's message, drawn in alice's timeline,
//    is read, and bob's `vox room read --json` says alice read it; one bob posts while alice's
//    app is hidden is not read, until she brings it back; a message alice posts, read by bob's
//    agent drain (`vox agent hook`), shows "read by bob" under it in her timeline.
// 5. The keyring view (ADR-014 M-16, ADR-028 K-3, E-5, #443): a pasted fingerprint with an alias
//    says what trusting does before it is done, and is listed, as `vox trust list` lists it;
//    removing it says what untrusting does first, and only then removes it.
// 6. Attaching a file (ADR-014 M-24, ADR-028 F-1, #449): chosen with Attach…, addressed To: bob
//    with a note, it is one share: bob's node pulls it by itself, byte for byte, and the note is
//    in the share's announcement, never a message of its own.
// 7. The lanes view (ADR-014 M-15, ADR-028 W-3, #442): bob posting `working` without a claim is
//    not working; once he claims a resource and posts `working`, his lane's chip says working;
//    ⌘O there opens the file panel, as on the timeline.
// 8. Notifications, a case of its own (testNotificationSaysWhoWroteNeverWhat), the one step that
//    needs a person at the Mac (ADR-014 M-23, ADR-028 R-10, #448): with the keyring on screen, bob's message
//    to alice posts one local notification, titled with the room, saying who wrote to her, and
//    never the message's text. Preconditions, not the proof's to arrange: Vox allowed to notify
//    (the app says "notifications off" otherwise, an APPARATUS red) and no Focus on.
// 9. Keys (ADR-014 M-20, #446): with quiet rooms aaa and bbb and mission needing alice, ⌘J from
//    aaa goes to mission, not to bbb, the next room in the sidebar's order; To: bob ticked in
//    mission is not carried into aaa; NEEDS-YOU-9, shown in mission and left at once, is recorded
//    read in mission; ⌘⇧C on a selected service card copies its canonical address. The services
//    view (⌘⇧S, M-17, #444) lists bob's share; its forward command, copied (canonical) and run,
//    reaches bob's service; a service listening here, shared from the view in one step after it
//    says bob can reach it, is reached by bob through his own `vox service list`.
// 10. The decision record (ADR-014 M-18, ADR-028 §7, #445): carol's join with a wrong passphrase,
//     refused by alice's node, is at the top of the view, above the trust changes of steps 3 and 5.
// 11. Untrust cuts a live forward (ADR-014 M-31, ADR-028 K-6, E-5): bob forwards to a service
//     alice shares and carries bytes through it; alice removes bob in the keyring view, and that
//     live connection is cut within 30 s.
// 12. Quitting the app (⌘Q) detaches it: `vox node list` says `detached`.
// 13. What came while the app was closed (ADR-028 R-8): alice's node, attached by hand, takes
//     bob's message to her while no app runs; opened again, the app lists mission under "needs
//     you (1)" at once, from what her node recorded as read.
//
// Mutants: the app attaches its node so that it outlives the app (the daemon's explicit attach in
// place of the app's hold), and quitting leaves it attached: (12) goes red. A room with a message
// addressed to this node grouped as quiet (`attention::group`): (3) goes red. An app that never
// reads the menu bar choice again (its delegate not observed): (1) goes red. An inspector
// that lists the members only when the room is opened: (3) goes red. The timeline drops
// the read-by line, or marks rows read while the window is hidden: (4) goes red. A read batch sent
// for the room on screen when it is flushed, not the room it was drawn in; To: kept across rooms;
// ⌘O on the timeline only: (9), (9) and (7) go red. A copy of the readable address, by ⌘⇧C or the
// services view's Copy: (9) goes red. Remove untrusts at once, saying nothing
// first: (5) goes red. The note is posted as a message
// of its own: (6) goes red. A lane derived working without a claim: (7) goes red.
// A notification that carries the message's text: (8) goes red. ⌘J bound to the next room in
// the sidebar's order: (9) goes red. The decision record oldest first: (10) goes red.
// Untrust that leaves a member's live sessions running: (11) goes red. An app that counts
// nothing from before it opened (no seeding from VoxClient.unread): (13) goes red.

// Every check on the window proves its own query first (ADR-018: a red names its side): Vox is in
// front and XCTest reads words in what it shows, else the red is APPARATUS; then a red is PRODUCT
// and quotes what the app showed. "Missing" is PRODUCT only once every container the app can show
// (windows with their sheets and popovers, dialogs such as the file panel, menus) was searched;
// found only outside them (the Touch Bar), it is APPARATUS. A case stops at its first red. A SwiftUI Text's words are its accessibility value, not its
// label: the read-by line, the keyring's effect sentences and a message's text are read there.

import XCTest

/// A red that is the product's, thrown where an assertion cannot be: what `vox` did, quoted.
struct Product: Error, CustomStringConvertible {
    let why: String
    init(_ why: String) { self.why = why }
    var description: String { "PRODUCT: \(why)" }
}

/// What an element says to VoiceOver: its label, else its value (a Text's words), else its title
/// (a menu button's).
func shown(_ element: XCUIElement) -> String {
    if !element.label.isEmpty { return element.label }
    if let value = element.value as? String, !value.isEmpty { return value }
    // A menu button's words are its title.
    return element.title
}

/// Refuse (APPARATUS) to launch the app with a data root or config directory outside this run's
/// scratch: a Vox started without them acts on the person's real profile.
func scratchOnly(_ env: [String: String], under scratch: String) throws {
    let root = URL(fileURLWithPath: scratch).standardizedFileURL.path + "/"
    for key in ["VOX_DATA_DIR", "VOX_CONFIG_DIR"] {
        guard let value = env[key],
              URL(fileURLWithPath: value).standardizedFileURL.path.hasPrefix(root) else {
            throw Apparatus("refusing to launch Vox.app: \(key) is \(env[key] ?? "unset"), not under this run's scratch \(scratch)")
        }
    }
}

/// What a check looks for in what the app shows: an element by its identifier, by the start of
/// its identifier, by the words it shows, a menu item by its title, or a button inside a control.
enum Key: ExpressibleByStringLiteral, CustomStringConvertible {
    case id(String)
    case idPrefix(String)
    case showing(String)
    case menuItem(String)
    case child(of: String, button: String)

    init(stringLiteral value: String) { self = .id(value) }

    var description: String {
        switch self {
        case let .id(i): return "\"\(i)\""
        case let .idPrefix(p): return "an element whose identifier starts \"\(p)\""
        case let .showing(w): return "an element showing \"\(w)\""
        case let .menuItem(t): return "the menu item \"\(t)\""
        case let .child(of, button): return "\"\(button)\" in \"\(of)\""
        }
    }

    /// The containers to search: a menu item only in menus, all else everywhere.
    func containers(_ ui: XCUIApplication, all: [XCUIElementQuery]) -> [XCUIElementQuery] {
        if case .menuItem = self { return [ui.menus] }
        return all
    }

    /// The containers themselves that `self` names (a dialog by its identifier, say): a search
    /// of a container's descendants never meets the container.
    func selves(in container: XCUIElementQuery) -> XCUIElementQuery? {
        switch self {
        case let .id(i): return container.matching(identifier: i)
        case let .idPrefix(p): return container.matching(NSPredicate(format: "identifier BEGINSWITH %@", p))
        default: return nil
        }
    }

    func query(in container: XCUIElementQuery) -> XCUIElementQuery {
        switch self {
        case let .id(i):
            return container.descendants(matching: .any).matching(identifier: i)
        case let .idPrefix(p):
            return container.descendants(matching: .any)
                .matching(NSPredicate(format: "identifier BEGINSWITH %@", p))
        case let .showing(w):
            return container.descendants(matching: .any)
                .matching(NSPredicate(format: "label CONTAINS %@ OR value CONTAINS %@", w, w))
        case let .menuItem(t):
            return container.descendants(matching: .menuItem)
                .matching(NSPredicate(format: "title == %@ OR label == %@", t, t))
        case let .child(of, button):
            // Any type: a segmented picker's segments are radio buttons on macOS, not buttons.
            return container.descendants(matching: .any).matching(identifier: of)
                .descendants(matching: .any).matching(NSPredicate(format: "title == %@ OR label == %@", button, button))
        }
    }
}

/// A red that is the apparatus's, not the product's: staging was not achieved.
struct Apparatus: Error, CustomStringConvertible {
    let why: String
    init(_ why: String) { self.why = why }
    var description: String { "APPARATUS: \(why)" }
}

final class FirstRunProof: XCTestCase {
    private var daemon: Started?
    /// Runs what the runner's sandbox forbids: every `vox`, the files, the echo services.
    private var stager: Stager!

    override func setUpWithError() throws {
        // A case stops at its first red: one red, with its side, and no cascade behind it.
        continueAfterFailure = false
        stager = try Stager.fromEnvironment()
    }

    override func tearDown() {
        daemon?.terminate()
        super.tearDown()
    }

    /// The login item's daemon ended on a refusal no retry changes (`vox daemon --login-item`
    /// writes why to ~/Library/Logs/Vox/login-item.log): with Keep Running chosen and the daemon
    /// unreachable, the app quotes that line and offers Turn Keep Running Off, which keeps the
    /// answer as Not Now (ADR-014 M-8). Staged in scratch: a data root of an earlier release, the
    /// Keep Running answer, and the log under a scratch HOME; no login item is registered.
    /// Mutation: the app not reading the log → red at the quoted line.
    func testALoginItemThatWillNotStartIsSaidWithAWayOut() throws {
        let env = ProcessInfo.processInfo.environment
        guard let appPath = env["VOX_PROOF_APP"], let scratchPath = env["VOX_PROOF_SCRATCH"] else {
            throw Apparatus("VOX_PROOF_APP and VOX_PROOF_SCRATCH are set by scripts/app-proofs.sh")
        }
        let root = URL(fileURLWithPath: scratchPath).appendingPathComponent("login-item")
        let data = root.appendingPathComponent("data").path
        let config = root.appendingPathComponent("config").path
        let home = root.appendingPathComponent("home").path
        // A data root as v0.2.x left it, which this version refuses; the answer Keep Running; and
        // the line the login item's daemon wrote as it ended.
        try stager.write(Data("an earlier release's vault".utf8), to: data + "/default/vault.cbor")
        try stager.write(Data("an earlier release's store".utf8), to: data + "/default/store.redb")
        try stager.write(Data("keep\n".utf8), to: config + "/app/login-item")
        let reason = "vox daemon will not start: STAGED-REASON is not a Vox data directory this version reads"
        try stager.write(Data("1791262600 \(reason)\n".utf8),
                         to: home + "/Library/Logs/Vox/login-item.log")

        let ui = XCUIApplication(url: URL(fileURLWithPath: appPath))
        ui.launchEnvironment = ["VOX_DATA_DIR": data, "VOX_CONFIG_DIR": config, "HOME": home,
                                "VOX_PROXY": "127.0.0.1:0"]
        try scratchOnly(ui.launchEnvironment, under: scratchPath)
        ui.launch()
        defer { ui.terminate() }
        let said = Key.id("login-item-said")
        let quoted = words(ui, said, timeout: 30,
                           "with Keep Running chosen and its daemon refusing for good, the app must quote the login item's own line",
                           until: { $0.contains("STAGED-REASON is not a Vox data directory this version reads") }) ?? ""
        tap(ui, Key.id("login-item-off"), "Turn Keep Running Off")
        if !el(ui, said).waitForNonExistence(timeout: 30) {
            XCTFail("PRODUCT: Turn Keep Running Off must leave Keep Running off; the login item's line is still shown: \(shown(el(ui, said)))")
        }
        let answer = stager.run(["/bin/cat", config + "/app/login-item"], env: [:]).out
        XCTAssertEqual(answer.trimmingCharacters(in: .whitespacesAndNewlines), "no",
                       "PRODUCT: Turn Keep Running Off must keep the answer as Not Now; the answer file says \(answer.debugDescription)")
        print("[proof] login item: quoted \"\(quoted)\"; after Turn Keep Running Off the answer is \(answer.debugDescription)")
    }

    /// (8) Notifications (ADR-014 M-23, ADR-028 R-10, #448), alone: the one step that needs a
    /// person at the Mac, so it is run by itself, in about a minute, with no replay of the
    /// journey. Staged by `vox` alone: alice and bob, a room of alice's that bob joined, each
    /// trusting the other, alice attached; the app opens as alice, chosen before (first run
    /// done). With the keyring on screen, bob's message to alice posts one local notification
    /// saying who wrote to her, and never the message's text. Vox not allowed to notify is said
    /// first, by the app's own status bar: APPARATUS, at once. The menu bar item, turned on at the
    /// first-run question, is looked at by the person (a pause of 20 s, said in the log).
    func testNotificationSaysWhoWroteNeverWhat() throws {
        let env = ProcessInfo.processInfo.environment
        guard let appPath = env["VOX_PROOF_APP"], let scratchPath = env["VOX_PROOF_SCRATCH"] else {
            throw Apparatus("VOX_PROOF_APP and VOX_PROOF_SCRATCH are set by scripts/app-proofs.sh")
        }
        let app = URL(fileURLWithPath: appPath)
        let vox = app.appendingPathComponent("Contents/Helpers/vox").path
        let root = URL(fileURLWithPath: scratchPath).appendingPathComponent("notify")
        let data = root.appendingPathComponent("data").path
        let config = root.appendingPathComponent("config").path
        let voxEnv = ["VOX_DATA_DIR": data, "VOX_CONFIG_DIR": config, "VOX_PROXY": "127.0.0.1:0"]
        let bobSession = voxEnv.merging(["VOX_SESSION": "bob-proof"]) { $1 }
        let pass = { (name: String) in root.appendingPathComponent("\(name).pass").path }
        try stager.write(Data("alice identity\n".utf8), to: pass("alice"))
        try stager.write(Data("bob identity\n".utf8), to: pass("bob"))
        try stager.write(Data("notify room\n".utf8), to: pass("room"))
        // The first-run question is left unanswered, so the menu bar toggle is clicked as a
        // person does (the path that once did nothing); the node is chosen before.
        try stager.write(Data("alice\n".utf8), to: config + "/app/node")
        daemon = try start(vox, ["daemon", "--listen", "127.0.0.1:0"], env: voxEnv,
                           until: "vox daemon: control socket")
        for (name, words) in [("alice", "alice identity"), ("bob", "bob identity")] {
            try staged(vox, ["node", "create", name],
                       env: voxEnv.merging(["VOX_IDENTITY_PASSPHRASE": words]) { $1 })
            try staged(vox, ["node", "attach", name, "--passphrase-file", pass(name)], env: voxEnv)
        }
        let aliceFp = try line(staged(vox, ["id", "--node", "alice"], env: voxEnv)) { $0.count == 52 }
        let bobFp = try line(staged(vox, ["id", "--node", "bob"], env: voxEnv)) { $0.count == 52 }
        try staged(vox, ["room", "create", "--node", "alice", "--passphrase-file", pass("room"),
                         "--name", "notify"], env: voxEnv)
        let room = try line(staged(vox, ["room", "list", "--node", "alice"], env: voxEnv)) {
            $0.contains(" notify")
        }.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? ""
        let link = try line(staged(vox, ["room", "link", "--node", "alice", room], env: voxEnv)) {
            $0.hasPrefix("vox://")
        }
        try staged(vox, ["room", "join", "--node", "bob", "--passphrase-file", pass("room"), link],
                   env: voxEnv)
        try staged(vox, ["trust", "add", "--node", "alice", bobFp, "--name", "bob",
                         "--identity-passphrase-file", pass("alice")], env: voxEnv)
        try staged(vox, ["trust", "add", "--node", "bob", aliceFp, "--name", "alice",
                         "--identity-passphrase-file", pass("bob")], env: voxEnv)
        // Forward-only keys: bob posts until one is readable to alice.
        var readable = false
        let staging = Date().addingTimeInterval(120)
        var n = 0
        while !readable && Date() < staging {
            n += 1
            try staged(vox, ["room", "post", "--node", "bob", room, "STAGE-\(n)"], env: voxEnv)
            Thread.sleep(forTimeInterval: 1)
            readable = run(vox, ["room", "read", "--node", "alice", room], env: voxEnv).out.contains("STAGE-")
        }
        guard readable else { throw Apparatus("alice never read a post of bob's in 120 s") }

        let ui = XCUIApplication(url: app)
        ui.launchEnvironment = voxEnv
        try scratchOnly(ui.launchEnvironment, under: scratchPath)
        ui.launch()
        defer {
            ui.terminate()
            _ = run(vox, ["node", "detach", "alice"], env: voxEnv)
        }
        // The menu bar item: turned on here, then looked at by the person at the Mac (XCTest reads
        // no menu bar items on this Mac).
        let offer = Key.id("menu-bar-offer")
        if present(ui, offer, timeout: 30, "the first run must offer \"Show Vox in the menu bar\"") {
            tap(ui, offer, "Show Vox in the menu bar")
            print("[proof] LOOK NOW at the menu bar: Vox's speech-bubble item must be there, just turned on (waiting 20 s)")
            Thread.sleep(forTimeInterval: 20)
        }
        tap(ui, Key.id("login-item-not-now"), "Not Now")
        present(ui, Key.id("attached"), timeout: 60,
                "the app, its node chosen before, must open attached as alice")
        tap(ui, Key.id("keyring"), "Keyring in the sidebar")
        // Asked first: whether the app may notify, in its own status bar.
        let statusNow = words(ui, Key.id("status"), timeout: 10,
                              "the window must have a status bar") ?? ""
        if statusNow.contains("notifications off") {
            throw Apparatus("Vox is not allowed to notify on this Mac: allow it in System Settings, Notifications, Vox, then run again; the app said \(statusNow)")
        }
        try staged(vox, ["room", "post", "--node", "bob", "--to", aliceFp, room, "SECRET-TEXT-8"],
                   env: bobSession)
        let centre = XCUIApplication(bundleIdentifier: "com.apple.notificationcenterui")
        let banner = centre.descendants(matching: .any)
            .matching(NSPredicate(format: "label CONTAINS %@ OR value CONTAINS %@", "bob wrote to you",
                                  "bob wrote to you")).firstMatch
        if !banner.waitForExistence(timeout: 30) {
            let there = centre.descendants(matching: .any).allElementsBoundByIndex.prefix(30).map(shown)
                .filter { !$0.isEmpty }
            if there.isEmpty {
                XCTFail("APPARATUS: XCTest reads nothing in Notification Center, so whether a banner showed cannot be told")
            } else {
                XCTFail("PRODUCT: bob's message to alice in a room off screen posted no notification saying \"bob wrote to you\" (Vox's status bar says it may notify: \(statusNow)); Notification Center shows: \(there)")
            }
        }
        let leaked = centre.descendants(matching: .any)
            .matching(NSPredicate(format: "label CONTAINS %@ OR value CONTAINS %@",
                                  "SECRET-TEXT-8", "SECRET-TEXT-8")).firstMatch
        // Only where the banner itself was read: a query that reads nothing in Notification Center
        // would pass this for nothing.
        if banner.exists && leaked.exists {
            XCTFail("PRODUCT: a notification must not carry the message's text; one said \(shown(leaked))")
        }
        print("[proof] notification: \(shown(banner))")
    }

    func testFirstRunAttachesTheNodeAndQuitDetachesIt() throws {
        let env = ProcessInfo.processInfo.environment
        guard let appPath = env["VOX_PROOF_APP"], let scratchPath = env["VOX_PROOF_SCRATCH"] else {
            throw Apparatus("VOX_PROOF_APP and VOX_PROOF_SCRATCH are set by scripts/app-proofs.sh")
        }
        let app = URL(fileURLWithPath: appPath)
        let vox = app.appendingPathComponent("Contents/Helpers/vox").path
        let scratch = URL(fileURLWithPath: scratchPath)
        let data = scratch.appendingPathComponent("data").path
        let config = scratch.appendingPathComponent("config").path
        // The daemon's .vox proxy on a free port, never another daemon's 1080.
        let voxEnv = ["VOX_DATA_DIR": data, "VOX_CONFIG_DIR": config, "VOX_PROXY": "127.0.0.1:0"]
        // `vox room post --to` speaks for an agent session, and refuses without one: bob's, named.
        let bobSession = voxEnv.merging(["VOX_SESSION": "bob-proof"]) { $1 }

        // The account's daemon, from the bundle, before any node exists, so nothing but the app
        // attaches the node.
        daemon = try start(vox, ["daemon", "--listen", "127.0.0.1:0"], env: voxEnv,
                           until: "vox daemon: control socket")
        let made = run(vox, ["node", "create", "alice"],
                       env: voxEnv.merging(["VOX_IDENTITY_PASSPHRASE": "alice identity"]) { $1 })
        XCTAssertEqual(made.status, 0, "APPARATUS: `vox node create alice` failed: \(made.out)")
        let bobEnv = voxEnv.merging(["VOX_IDENTITY_PASSPHRASE": "bob identity"]) { $1 }
        let roomPass = scratch.appendingPathComponent("room.pass").path
        let alicePass = scratch.appendingPathComponent("alice.pass").path
        let bobPass = scratch.appendingPathComponent("bob.pass").path
        try stager.write(Data("mission room\n".utf8), to: roomPass)
        try stager.write(Data("alice identity\n".utf8), to: alicePass)
        try stager.write(Data("bob identity\n".utf8), to: bobPass)
        // What steps 6 and on use from steps 1 to 5.
        var listed = ""
        var room = ""
        var aliceFp = ""
        var bobFp = ""

        // **Starting at step 6** (VOX_PROOF_FROM=6, for troubleshooting a later step without
        // steps 1 to 5): what they leave is staged by `vox` instead (alice attached, the room
        // mission with bob in it, each trusting the other, carol made), and the app opens as
        // alice, its first run answered.
        let from = Int(env["VOX_PROOF_FROM"] ?? "") ?? 1
        if from > 5 {
            try staged(vox, ["node", "create", "bob"], env: bobEnv)
            try staged(vox, ["node", "attach", "bob", "--passphrase-file", bobPass], env: voxEnv)
            try staged(vox, ["node", "attach", "alice", "--passphrase-file", alicePass], env: voxEnv)
            aliceFp = try line(staged(vox, ["id", "--node", "alice"], env: voxEnv)) { $0.count == 52 }
            bobFp = try line(staged(vox, ["id", "--node", "bob"], env: voxEnv)) { $0.count == 52 }
            try staged(vox, ["room", "create", "--node", "alice", "--passphrase-file", roomPass,
                             "--name", "mission"], env: voxEnv)
            room = try line(staged(vox, ["room", "list", "--node", "alice"], env: voxEnv)) {
                $0.contains(" mission")
            }.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? ""
            let stagedLink = try line(staged(vox, ["room", "link", "--node", "alice", room], env: voxEnv)) {
                $0.hasPrefix("vox://")
            }
            try staged(vox, ["room", "join", "--node", "bob", "--passphrase-file", roomPass, stagedLink],
                       env: voxEnv)
            try staged(vox, ["trust", "add", "--node", "alice", bobFp, "--name", "bob",
                             "--identity-passphrase-file", alicePass], env: voxEnv)
            try staged(vox, ["trust", "add", "--node", "bob", aliceFp, "--name", "alice",
                             "--identity-passphrase-file", bobPass], env: voxEnv)
            var readable = false
            let staging = Date().addingTimeInterval(120)
            var n = 0
            while !readable && Date() < staging {
                n += 1
                try staged(vox, ["room", "post", "--node", "bob", room, "STAGE-\(n)"], env: voxEnv)
                Thread.sleep(forTimeInterval: 1)
                readable = run(vox, ["room", "read", "--node", "alice", room], env: voxEnv).out.contains("STAGE-")
            }
            guard readable else { throw Apparatus("alice never read a post of bob's in 120 s") }
            try staged(vox, ["node", "create", "carol"],
                       env: voxEnv.merging(["VOX_IDENTITY_PASSPHRASE": "carol identity"]) { $1 })
            try stager.write(Data("no\n".utf8), to: config + "/app/login-item")
            try stager.write(Data("alice\n".utf8), to: config + "/app/node")
            // Only the app holds alice from here, as after step 2: `vox node attach` is an
            // explicit attach that outlives the app (step 12 checks the app's quit detaches her).
            try staged(vox, ["node", "detach", "alice"], env: voxEnv)
            print("[proof] started at step \(from): steps 1–5 NOT RUN; what they leave was staged by vox")
        }

        let ui = XCUIApplication(url: app)
        ui.launchEnvironment = voxEnv
        try scratchOnly(ui.launchEnvironment, under: scratchPath)
        ui.launch()

        if from > 5 {
            // The app attaches alice itself, her passphrase typed, as in step 2.
            let field = Key.id("passphrase")
            present(ui, field, timeout: 30, "the app must ask for node alice's passphrase")
            type(ui, field, "alice identity", "the passphrase field")
            tap(ui, Key.id("attach"), "Attach")
            present(ui, Key.id("attached"), timeout: 60, "the app, its first run answered, must open attached as alice")
            listed = run(vox, ["node", "list"], env: voxEnv).out
        } else {
        // (1) First run: the login item is asked about once, and declined here (approving it is
        // the manual check manual.login_item); then pick the node, and a wrong passphrase is the
        // daemon's sentence.
        words(ui, Key.id("login-item-why"), timeout: 30,
              "at first run the app must ask whether to keep the daemon running, saying what that does",
              until: { $0.contains("keeps your rooms reachable while you are logged in, even with the app closed") })
        // The menu bar extra, offered here, off until turned on (M-22): the toggle shows it is on
        // once clicked. Whether the item then shows in the menu bar XCTest cannot see on this
        // Mac (it reads no menu bar items); a person looks, in testNotificationSaysWhoWroteNeverWhat.
        let offer = Key.id("menu-bar-offer")
        if present(ui, offer, timeout: 10, "the first run must offer \"Show Vox in the menu bar\"") {
            tap(ui, offer, "Show Vox in the menu bar")
            switch el(ui, offer).value as? Int {
            case nil: XCTFail("APPARATUS: XCTest reads no value from the \"Show Vox in the menu bar\" checkbox")
            case 1?: break
            case let v?: XCTFail("PRODUCT: \"Show Vox in the menu bar\", clicked, must show it is on; its value is \(v)")
            }
        }
        tap(ui, Key.id("login-item-not-now"), "Not Now")
        let pick = Key.id("node-alice")
        present(ui, pick, timeout: 30, "at first run the app must offer node alice")
        tap(ui, pick, "node alice")
        let field = Key.id("passphrase")
        present(ui, field, timeout: 10, "the app must ask for node alice's passphrase")
        type(ui, field, "not the passphrase", "the passphrase field")
        tap(ui, Key.id("attach"), "Attach")
        words(ui, Key.id("said"), timeout: 30,
              "a wrong passphrase must show the daemon's own sentence where it was typed",
              until: { $0.contains("that passphrase does not open node alice's identity") })

        // (2) The right one attaches it.
        type(ui, field, "alice identity", "the passphrase field")
        tap(ui, Key.id("attach"), "Attach")
        present(ui, Key.id("attached"), timeout: 60,
                "the right passphrase must attach node alice")
        listed = run(vox, ["node", "list"], env: voxEnv).out
        XCTAssertTrue(nodeLine(listed, "alice")?.contains(" attached ") ?? false,
                      "PRODUCT: `vox node list` must say alice is attached; it said: \(listed)")

        // (3) The main window groups the room by what it needs from alice. Bob is a second node of
        // the same daemon: a member reached directly, no anchor.
        try staged(vox, ["node", "create", "bob"], env: bobEnv)
        try staged(vox, ["node", "attach", "bob", "--passphrase-file", bobPass], env: voxEnv)
        aliceFp = try line(staged(vox, ["id", "--node", "alice"], env: voxEnv)) { $0.count == 52 }
        bobFp = try line(staged(vox, ["id", "--node", "bob"], env: voxEnv)) { $0.count == 52 }
        // The app makes the room (⌘N, M-31: create) and copies its link (⌘L).
        ui.typeKey("n", modifierFlags: .command)
        let roomName = Key.id("room-form-name")
        present(ui, roomName, timeout: 10, "⌘N must open the New Room form")
        type(ui, roomName, "mission", "the room's name field")
        let roomSecret = Key.id("room-form-passphrase")
        type(ui, roomSecret, "mission room", "the room's passphrase field")
        tap(ui, Key.id("room-form-submit"), "Create")
        var rooms = ""
        let madeUntil = Date().addingTimeInterval(60)
        while Date() < madeUntil && !rooms.contains(" mission") {
            rooms = run(vox, ["room", "list", "--node", "alice"], env: voxEnv).out
            if !rooms.contains(" mission") { Thread.sleep(forTimeInterval: 0.5) }
        }
        guard let made = rooms.split(separator: "\n").first(where: { $0.contains(" mission") })?
            .split(whereSeparator: \.isWhitespace).first.map(String.init) else {
            throw Product("the app's New Room made no room alice's `vox room list` lists: \(rooms)")
        }
        room = made
        NSPasteboard.general.clearContents()
        ui.typeKey("l", modifierFlags: .command)
        var link = ""
        let linkUntil = Date().addingTimeInterval(15)
        while Date() < linkUntil && !link.hasPrefix("vox://") {
            link = NSPasteboard.general.string(forType: .string) ?? ""
            if !link.hasPrefix("vox://") { Thread.sleep(forTimeInterval: 0.25) }
        }
        XCTAssertTrue(link.hasPrefix("vox://"),
                      "PRODUCT: ⌘L in the room must copy its vox:// link; the pasteboard has \(link.debugDescription)")
        try staged(vox, ["room", "join", "--node", "bob", "--passphrase-file", roomPass, link],
                   env: voxEnv)
        try staged(vox, ["trust", "add", "--node", "alice", bobFp, "--name", "bob",
                         "--identity-passphrase-file", alicePass], env: voxEnv)
        try staged(vox, ["trust", "add", "--node", "bob", aliceFp, "--name", "alice",
                         "--identity-passphrase-file", bobPass], env: voxEnv)
        // Staged when alice reads a post of bob's: forward-only, so bob posts afresh until one is
        // readable to her.
        var readable = false
        let staging = Date().addingTimeInterval(120)
        var n = 0
        var seen = ""
        while !readable && Date() < staging {
            n += 1
            try staged(vox, ["room", "post", "--node", "bob", room, "STAGE-\(n)"], env: voxEnv)
            Thread.sleep(forTimeInterval: 1)
            seen = run(vox, ["room", "read", "--node", "alice", room], env: voxEnv).out
            readable = seen.contains("STAGE-")
        }
        guard readable else {
            throw Apparatus("alice never read a post of bob's in 120 s; `vox room read` said: \(seen)")
        }
        // The room has been on screen since ⌘N made it: bob, who joined meanwhile and whom alice
        // trusted meanwhile, is listed in its inspector without the room being opened again.
        words(ui, Key.id("member-bob"), timeout: 30,
              "bob joined and was trusted while the room was on screen: its inspector must list him in alice's keyring",
              until: { $0.hasPrefix("bob, in keyring") })
        // Off the room, so a message to alice is unread: a room on screen is read.
        tap(ui, Key.id("keyring"), "Keyring in the sidebar")
        try staged(vox, ["room", "post", "--node", "bob", "--to", aliceFp, room, "NEEDS-YOU"],
                   env: bobSession)
        words(ui, Key.id("group-needs you"), timeout: 60,
              "a message to alice must list the room under \"needs you (1)\"",
              until: { $0 == "needs you (1)" })
        let row = Key.id("room-mission")
        words(ui, row, timeout: 10, "the room's row must say it needs you",
              until: { $0.contains("needs you") })
        tap(ui, row, "mission in the sidebar")
        let bob = Key.id("member-bob")
        let bobWords = words(ui, bob, timeout: 30, "the inspector must list bob in alice's keyring",
                             until: { $0.hasPrefix("bob, in keyring") }) ?? ""
        let bar = words(ui, Key.id("status"), timeout: 10,
                        "the status bar must say the node, its peers and the keyring window",
                        until: { $0.contains("node alice") && $0.contains("peer") && $0.contains("keyring") }) ?? ""
        let regrouped = words(ui, Key.id("group-needs you"), timeout: 10,
                              "the room shown is read, so nothing needs alice: \"needs you (0)\"",
                              until: { $0 == "needs you (0)" }) ?? ""
        print("[proof] grouped: needs you (1), then \(regrouped); inspector: \(bobWords); status: \(bar)")

        // (4) Read each way. Bob's NEEDS-YOU is on alice's screen now: her node says she read it.
        var readByAlice: [String] = []
        let readUntil = Date().addingTimeInterval(60)
        while Date() < readUntil {
            let rows = run(vox, ["room", "read", "--node", "bob", "--json", room], env: voxEnv).out
            for line in rows.split(separator: "\n") {
                guard let row = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                      (row["text"] as? String)?.contains("NEEDS-YOU") == true else { continue }
                readByAlice = row["read_by"] as? [String] ?? []
            }
            if readByAlice.contains("alice") { break }
            Thread.sleep(forTimeInterval: 1)
        }
        XCTAssertTrue(readByAlice.contains("alice"),
                      "PRODUCT: bob's message drawn in alice's timeline must be read: bob's `vox room read --json` must say alice read it; it says read_by \(readByAlice)")
        // Hidden (⌘H), alice's app shows nobody bob's next message: it is not read.
        ui.typeKey("h", modifierFlags: .command)
        XCTAssertTrue(ui.wait(for: .runningBackground, timeout: 10),
                      "APPARATUS: ⌘H did not hide the app")
        try staged(vox, ["room", "post", "--node", "bob", room, "WHILE-HIDDEN"], env: voxEnv)
        func readBy(_ text: String) -> [String]? {
            let rows = run(vox, ["room", "read", "--node", "bob", "--json", room], env: voxEnv).out
            for line in rows.split(separator: "\n") {
                guard let row = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                      (row["text"] as? String)?.contains(text) == true else { continue }
                return row["read_by"] as? [String] ?? []
            }
            return nil
        }
        // Long enough for the message to reach alice's node and her app, and for a read record to
        // come back, had one been posted.
        var whileHidden: [String]? = nil
        let hiddenUntil = Date().addingTimeInterval(15)
        while Date() < hiddenUntil {
            whileHidden = readBy("WHILE-HIDDEN")
            if whileHidden?.contains("alice") == true { break }
            Thread.sleep(forTimeInterval: 1)
        }
        XCTAssertFalse(whileHidden?.contains("alice") ?? false,
                       "PRODUCT: a message that arrived while alice's app was hidden must not be read; bob's `vox room read --json` says read_by \(whileHidden ?? [])")
        ui.activate()
        var shownAgain: [String] = []
        let backUntil = Date().addingTimeInterval(60)
        while Date() < backUntil {
            shownAgain = readBy("WHILE-HIDDEN") ?? []
            if shownAgain.contains("alice") { break }
            Thread.sleep(forTimeInterval: 1)
        }
        XCTAssertTrue(shownAgain.contains("alice"),
                      "PRODUCT: once alice's app is in front again, the message on screen must be read; bob's `vox room read --json` says read_by \(shownAgain)")
        // Alice posts; bob's agent reads it in a drain, as a harness does before every prompt.
        let compose = Key.id("compose")
        present(ui, compose, timeout: 10, "the room must have a field to post")
        type(ui, compose, "FROM-ALICE\r", "the composer")
        var drained = ""
        let drainUntil = Date().addingTimeInterval(60)
        while Date() < drainUntil && !drained.contains("FROM-ALICE") {
            drained += run(vox, ["agent", "hook", "--node", "bob", "--room", room, "--format", "text"],
                           env: voxEnv,
                           input: "{\"hook_event_name\":\"UserPromptSubmit\",\"session_id\":\"bob-proof\"}").out
            Thread.sleep(forTimeInterval: 1)
        }
        guard drained.contains("FROM-ALICE") else {
            throw Apparatus("bob's agent drain never read alice's FROM-ALICE in 60 s: \(drained)")
        }
        // The read-by line is a Text: its words are its accessibility value.
        let readLine = Key.idPrefix("read-by-")
        let readWords = words(ui, readLine, timeout: 30,
                              "alice's message read by bob must show \"read by bob\" under it",
                              until: { $0 == "read by bob" }) ?? ""
        print("[proof] bob's message read by \(readByAlice); alice's message: \(readWords)")

        // (5) The keyring: carol, a node made here, added by her pasted fingerprint, then removed.
        try staged(vox, ["node", "create", "carol"],
                   env: voxEnv.merging(["VOX_IDENTITY_PASSPHRASE": "carol identity"]) { $1 })
        let carolFp = try line(staged(vox, ["id", "--node", "carol"], env: voxEnv)) { $0.count == 52 }
        tap(ui, Key.id("keyring"), "Keyring in the sidebar")
        let addFp = Key.id("keyring-add-fingerprint")
        present(ui, addFp, timeout: 10, "the keyring view must offer to add a node")
        type(ui, addFp, carolFp, "the fingerprint field")
        let addAlias = Key.id("keyring-add-alias")
        type(ui, addAlias, "carol", "the alias field")
        // The effect sentences are Texts: their words are their accessibility value.
        words(ui, Key.id("keyring-add-effect"), timeout: 10,
              "adding must say what trusting does before it is done",
              until: { $0.contains("it may read what you write") })
        tap(ui, Key.id("keyring-trust"), "Trust")
        let carolRow = Key.id("keyring-row-carol")
        present(ui, carolRow, timeout: 30, "carol, once trusted, must be listed in the keyring view")
        let trustList = run(vox, ["trust", "list", "--node", "alice"], env: voxEnv).out
        XCTAssertTrue(trustList.contains(carolFp),
                      "PRODUCT: `vox trust list` must list carol once the app trusted her; it said: \(trustList)")
        tap(ui, Key.id("keyring-remove-carol"), "Remove… on carol")
        words(ui, Key.id("keyring-remove-effect"), timeout: 10,
              "removing must say what untrusting does before it is done",
              until: { $0.contains("reads nothing you write from now on") })
        tap(ui, Key.id("keyring-untrust-confirm"), "Untrust")
        var after5 = ""
        let goneUntil = Date().addingTimeInterval(30)
        while Date() < goneUntil {
            after5 = run(vox, ["trust", "list", "--node", "alice"], env: voxEnv).out
            if !after5.contains(carolFp) && locate(ui, carolRow) == nil { break }
            Thread.sleep(forTimeInterval: 0.5)
        }
        if after5.contains(carolFp) {
            XCTFail("PRODUCT: once untrusted, carol must be gone from `vox trust list`; it said: \(after5)")
        }
        // Gone from the view: shown with the window read, so a missing row is not a lost query.
        if windowReadable(ui), let row = locate(ui, carolRow) {
            XCTFail("PRODUCT: once untrusted, carol must be gone from the keyring view; it still shows \"\(shown(row))\"")
        }
        print("[proof] keyring: added and listed carol, then removed her after saying what untrusting does")

        }

        // (6) Attach a file to the room, To: bob, with a note.
        tap(ui, Key.id("room-mission"), "mission in the sidebar")
        let file = scratch.appendingPathComponent("for-bob.bin")
        let bytes = Data((0..<150_000).map { UInt8(truncatingIfNeeded: $0 &* 31 % 253) })
        try stager.write(bytes, to: file.path)
        let attachButton = Key.id("attach")
        present(ui, attachButton, timeout: 10, "the room must offer Attach")
        tap(ui, attachButton, "Attach (the paperclip)")
        // The file panel (open-panel, a dialog of the app, found wherever it shows): go to the
        // file's path, then the panel's own Attach (OKButton), once the Go To sheet has closed and
        // it is enabled.
        if present(ui, Key.id("open-panel"), timeout: 10, "Attach must open the file panel") {
            ui.typeKey("g", modifierFlags: [.command, .shift])
            ui.typeText(file.path + "\r")
            let choose = el(ui, Key.id("open-panel")).buttons["OKButton"]
            let enabled = NSPredicate(format: "exists == true AND isEnabled == true AND isHittable == true")
            if XCTWaiter.wait(for: [expectation(for: enabled, evaluatedWith: choose)], timeout: 10) == .completed {
                choose.click()
            } else {
                XCTFail("APPARATUS: the file panel's Attach never became clickable after going to \(file.path): the Go To sheet did not take the path")
            }
        }
        let toBob = Key.id("attach-to-bob")
        present(ui, toBob, timeout: 10, "attaching a file must ask To:")
        tap(ui, toBob, "To: bob")
        let noteField = Key.id("attach-note")
        type(ui, noteField, "FOR-BOB-NOTE", "the note field")
        tap(ui, Key.id("attach-send"), "Send")
        // Premise: the share reached the room, as bob's own node reads it (the app's send is the
        // product's; a room that never carries it is the product's red too, said as that).
        var bobRows: [Substring] = []
        let sharedUntil = Date().addingTimeInterval(60)
        while Date() < sharedUntil && bobRows.isEmpty {
            bobRows = run(vox, ["room", "read", "--node", "bob", "--json", room], env: voxEnv).out
                .split(separator: "\n").filter { $0.contains("FOR-BOB-NOTE") }
            if bobRows.isEmpty { Thread.sleep(forTimeInterval: 0.5) }
        }
        if bobRows.isEmpty {
            let alices = run(vox, ["room", "read", "--node", "alice", "--json", room], env: voxEnv).out
            XCTFail("PRODUCT: the file attached in the app, with its note FOR-BOB-NOTE, never reached the room as bob's node reads it in 60 s; alice's node reads: \(alices.suffix(1500))")
        }
        XCTAssertTrue(bobRows.count == 1 && bobRows[0].contains("for-bob.bin"),
                      "PRODUCT: the note must travel in the share itself, as one message; bob's `vox room read --json` has \(bobRows.count) row(s) with it: \(bobRows)")
        // Bob's copy, read outside the runner's sandbox (by the stager): its size and SHA-256
        // against what was attached.
        // A pull is filed under the room's full ID; `room` is the short one `vox room list` prints.
        // The full ID opens the room's vox:// link.
        let roomLink = try line(staged(vox, ["room", "link", "--node", "alice", room], env: voxEnv)) {
            $0.hasPrefix("vox://")
        }
        let fullRoom = String(roomLink.dropFirst("vox://".count).prefix { $0 != "?" && $0 != "/" })
        guard fullRoom.count == 52 else {
            throw Apparatus("the room's full ID could not be read from its link \(roomLink)")
        }
        let bobCopy = URL(fileURLWithPath: data).appendingPathComponent("nodes/bob/files/\(fullRoom)/for-bob.bin")
        let want = stager.run(["/usr/bin/shasum", "-a", "256", file.path], env: [:]).out
            .split(separator: " ").first.map(String.init) ?? ""
        guard !want.isEmpty else { throw Apparatus("the proof could not hash the file it attached, \(file.path)") }
        var got = ""
        let pullUntil = Date().addingTimeInterval(120)
        while Date() < pullUntil && got != want {
            got = stager.run(["/usr/bin/shasum", "-a", "256", bobCopy.path], env: [:]).out
                .split(separator: " ").first.map(String.init) ?? ""
            if got != want { Thread.sleep(forTimeInterval: 0.5) }
        }
        if got != want {
            let there = stager.run(["/bin/ls", "-lR", URL(fileURLWithPath: data).appendingPathComponent("nodes/bob/files").path], env: [:]).out
            let pulls = run(vox, ["room", "read", "--node", "bob", room], env: voxEnv).out
            XCTFail("PRODUCT: the file attached To: bob must be pulled by bob's node, byte for byte, into \(bobCopy.path) within 120 s; it holds \(got.isEmpty ? "nothing" : "sha256 \(got)"); bob's files: \(there.isEmpty ? "none" : there.replacingOccurrences(of: "\n", with: " ⏎ ")); bob's room read: \(pulls.suffix(1200))")
        }
        let pulledBytes: Data? = got == want ? bytes : nil
        print("[proof] attached for-bob.bin To: bob; bob pulled \(pulledBytes?.count ?? 0) bytes; rows with the note: \(bobRows.count)")

        // (7) Lanes. Working without a claim is not working.
        // Coordination is owned per session: bob's posts and claims here are his session's.
        try staged(vox, ["room", "post", "--node", "bob", "--type", "working", room, "NO-CLAIM"],
                   env: bobSession)
        Thread.sleep(forTimeInterval: 10)
        let lanesToggle = Key.id("lanes-toggle")
        let bobLane = Key.id("lane-state-bob")
        if locate(ui, lanesToggle) != nil {
            tap(ui, Key.child(of: "lanes-toggle", button: "Lanes"), "Lanes")
            if windowReadable(ui), el(ui, bobLane).waitForExistence(timeout: 5),
               shown(el(ui, bobLane)) == "bob: working" {
                XCTFail("PRODUCT: bob posted `working` holding no claim; his lane must not say working, and it says \"\(shown(el(ui, bobLane)))\"")
            }
            tap(ui, Key.child(of: "lanes-toggle", button: "Timeline"), "Timeline")
        }
        try staged(vox, ["room", "claim", "--node", "bob", room, "ticket-1"], env: bobSession)
        try staged(vox, ["room", "post", "--node", "bob", "--type", "working", room, "ON-TICKET-1"],
                   env: bobSession)
        present(ui, lanesToggle, timeout: 30, "a room whose member works on a claim must offer the lanes view")
        tap(ui, Key.child(of: "lanes-toggle", button: "Lanes"), "Lanes")
        let laneWords = words(ui, bobLane, timeout: 30,
                              "bob, holding ticket-1 with a working post, must show working in his lane",
                              until: { $0 == "bob: working" }) ?? ""
        print("[proof] lanes: \(laneWords)")
        // ⌘O works with the lanes view shown, as with the timeline: the open panel shows.
        if windowReadable(ui) {
            ui.typeKey("o", modifierFlags: .command)
            if present(ui, Key.id("open-panel"), timeout: 10,
                       "⌘O in the lanes view must open the file panel to attach a file") {
                tap(ui, Key.id("CancelButton"), "the file panel's Cancel")
                _ = el(ui, Key.id("open-panel")).waitForNonExistence(timeout: 10)
            }
        }
        tap(ui, Key.child(of: "lanes-toggle", button: "Timeline"), "Timeline")

        // (8) Notifications are their own case, testNotificationSaysWhoWroteNeverWhat: the one
        // step that needs a person at the Mac (Vox allowed to notify, no Focus on), run alone.

        // (9) Keys. Two quiet rooms of alice's, made here; each takes a post of hers, so the app
        // learns of it, and her own posts are never unread.
        let roomPassFile = roomPass
        for name in ["aaa", "bbb"] {
            try staged(vox, ["room", "create", "--node", "alice", "--passphrase-file", roomPassFile,
                             "--name", name], env: voxEnv)
            let listing = try staged(vox, ["room", "list", "--node", "alice"], env: voxEnv)
            guard let id = listing.split(separator: "\n").first(where: { $0.contains(" \(name)") })?
                .split(whereSeparator: \.isWhitespace).first.map(String.init) else {
                throw Apparatus("`vox room list` does not list \(name): \(listing)")
            }
            try staged(vox, ["room", "post", "--node", "alice", id, "HELLO-\(name)"], env: voxEnv)
        }
        let aaa = Key.id("room-aaa")
        present(ui, aaa, timeout: 30, "room aaa must show in the sidebar")
        present(ui, Key.id("room-bbb"), timeout: 30,
                "room bbb must show in the sidebar")
        tap(ui, aaa, "aaa in the sidebar")
        try staged(vox, ["room", "post", "--node", "bob", "--to", aliceFp, room, "NEEDS-YOU-9"],
                   env: bobSession)
        words(ui, Key.id("group-needs you"), timeout: 60,
              "bob's message to alice must put mission under needs you",
              until: { $0 == "needs you (1)" })
        ui.typeKey("j", modifierFlags: .command)
        // A message's text is a Text: its words are its accessibility value.
        let landed = Key.showing("NEEDS-YOU-9")
        present(ui, landed, timeout: 15,
                "⌘J from room aaa must open mission, the room that needs alice, with its message NEEDS-YOU-9")
        // Shown means on screen (hittable), not only built: a lazy timeline builds rows beyond
        // its visible part too.
        let inViewUntil = Date().addingTimeInterval(10)
        while Date() < inViewUntil && !el(ui, landed).isHittable { Thread.sleep(forTimeInterval: 0.2) }
        if !el(ui, landed).isHittable {
            keepTree(ui, "NEEDS-YOU-9 was not in view")
            XCTFail("PRODUCT: ⌘J must open mission with its newest message, NEEDS-YOU-9, in view; it is in the timeline but not on screen")
        }
        // To: is the room's own: bob ticked in mission is not carried into aaa.
        let to = Key.id("compose-to")
        present(ui, to, timeout: 10, "the composer must offer To:")
        tap(ui, to, "To:")
        tap(ui, Key.menuItem("bob"), "bob in To:")
        words(ui, to, timeout: 10, "ticking bob in To: must say so", until: { $0 == "To: bob" })
        // Seen in mission, then at once another room: the read record names mission, the room the
        // message is in.
        tap(ui, aaa, "aaa in the sidebar")
        words(ui, to, timeout: 10, "To: set in mission must not carry into aaa",
              until: { $0 == "To: the room" })
        var nine: [String] = []
        let nineUntil = Date().addingTimeInterval(30)
        while Date() < nineUntil && !nine.contains("alice") {
            for line in run(vox, ["room", "read", "--node", "bob", "--json", room], env: voxEnv).out
                .split(separator: "\n") {
                guard let row = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                      (row["text"] as? String)?.contains("NEEDS-YOU-9") == true else { continue }
                nine = row["read_by"] as? [String] ?? []
            }
            if !nine.contains("alice") { Thread.sleep(forTimeInterval: 1) }
        }
        XCTAssertTrue(nine.contains("alice"),
                      "PRODUCT: NEEDS-YOU-9, shown in mission and left at once for aaa, must be recorded read in mission; bob's `vox room read --json` says read_by \(nine)")
        // ⌘⇧C: a service bob shares, selected, copies its address.
        let echo = try EchoServer(stager)
        try staged(vox, ["service", "add", "--node", "bob", room, "web", "127.0.0.1:\(echo.port)"],
                   env: voxEnv)
        // Its readable address (shown) and canonical one (copied), as alice's
        // `vox service list --json` gives them (ADR-028 S-1, S-3).
        var cliAddress = ""
        var canonical = ""
        let shareUntil = Date().addingTimeInterval(60)
        while Date() < shareUntil && canonical.isEmpty {
            let listed = run(vox, ["service", "list", "--node", "alice", "--json", room], env: voxEnv).out
            let json = (try? JSONSerialization.jsonObject(with: Data(listed.utf8))) as? [String: Any]
            let web = (json?["shared"] as? [[String: Any]] ?? []).first {
                ($0["readable"] as? String)?.hasPrefix("web.") == true
            }
            cliAddress = web?["readable"] as? String ?? ""
            canonical = web?["address"] as? String ?? ""
            if canonical.isEmpty { Thread.sleep(forTimeInterval: 1) }
        }
        guard !canonical.isEmpty else {
            throw Apparatus("alice's `vox service list --json` never listed bob's web share")
        }
        tap(ui, aaa, "aaa in the sidebar")
        tap(ui, Key.id("room-mission"), "mission in the sidebar")
        let card = Key.id("service-\(cliAddress)")
        present(ui, card, timeout: 30, "the room must show a card for bob's service \(cliAddress)")
        tap(ui, card, "the service card")
        // Clicked, the card is selected (it says so to VoiceOver), and enables Room > Copy
        // Selected Service's Address (⌘⇧C).
        let selectedUntil = Date().addingTimeInterval(5)
        while Date() < selectedUntil && !el(ui, card).isSelected { Thread.sleep(forTimeInterval: 0.2) }
        if !el(ui, card).isSelected {
            keepTree(ui, "the service card was not selected")
            XCTFail("PRODUCT: clicking bob's service card must select it; it does not say it is selected")
        }
        let copyItem = el(ui, Key.menuItem("Copy Selected Service's Address"))
        if !copyItem.exists {
            keepTree(ui, "the copy menu item was not found")
            XCTFail("APPARATUS: XCTest finds no menu item \"Copy Selected Service's Address\" in the app's menus")
        } else if !copyItem.isEnabled {
            keepTree(ui, "the copy menu item was disabled")
            XCTFail("PRODUCT: clicking bob's service card must select it, enabling Room > Copy Selected Service's Address; it is disabled")
        }
        let copied = copiedBy(ui) { ui.typeKey("c", modifierFlags: [.command, .shift]) }
        if copied != canonical {
            keepTree(ui, "⌘⇧C copied the wrong thing")
            XCTFail("PRODUCT: ⌘⇧C on the selected service must copy its canonical address, as `vox service list --json` gives it (\(canonical)), not the readable one shown (\(cliAddress)); the pasteboard holds \(copied.debugDescription)")
        }
        // ... and used: `vox forward` to what was copied carries bytes to bob's service and back.
        let forward = try start(vox, ["forward", "--node", "alice", copied, "127.0.0.1:0"],
                                env: voxEnv, until: "vox: forwarding ", product: true)
        let bound = startedLine.split(separator: " ").dropFirst(2).first.map(String.init) ?? ""
        let through = Line(bound)?.roundTrip("THROUGH-THE-COPY\n") ?? ""
        // Stopped now: a forward holds alice attached while it runs (step 12 checks the quit
        // detaches her).
        forward.terminate()
        forward.waitUntilExit()
        XCTAssertEqual(through, "THROUGH-THE-COPY\n",
                       "PRODUCT: a forward to the copied address \(copied), bound at \(bound), must carry bytes to bob's service and back")
        print("[proof] ⌘J opened mission; ⌘⇧C copied \(copied)")

        // The services view (⌘⇧S, ADR-014 M-17, #444): bob's web share with its commands, the
        // readable address shown and the canonical one copied; the forward command, copied and
        // run as a person pastes it, reaches bob's service.
        ui.typeKey("s", modifierFlags: [.command, .shift])
        let box = Key.id("service-box-\(cliAddress)")
        present(ui, box, timeout: 30, "the services view must list bob's web share \(cliAddress)")
        let pasted = copiedBy(ui) {
            tap(ui, Key.id("copy-forward-\(cliAddress)"), "Copy on the forward command")
        }
        if pasted != "vox forward \(canonical) 127.0.0.1:0" {
            keepTree(ui, "Copy on the forward command copied the wrong thing")
            XCTFail("PRODUCT: Copy on the forward command must copy it with the canonical address, as `vox service list` gives it; the pasteboard holds \(pasted.debugDescription)")
        }
        let pastedArgs = pasted.split(separator: " ").dropFirst().map(String.init)
        let pastedForward = try start(vox, Array(pastedArgs.prefix(1)) + ["--node", "alice"]
                                      + Array(pastedArgs.dropFirst()),
                                      env: voxEnv, until: "vox: forwarding ", product: true)
        let pastedAt = startedLine.split(separator: " ").dropFirst(2).first.map(String.init) ?? ""
        let pastedThrough = Line(pastedAt)?.roundTrip("PASTED-COMMAND\n") ?? ""
        pastedForward.terminate()
        pastedForward.waitUntilExit()
        XCTAssertEqual(pastedThrough, "PASTED-COMMAND\n",
                       "PRODUCT: the forward command copied from the services view, run, must carry bytes to bob's service and back")
        // One-step sharing (S-4): a service listening on this Mac, picked from the list, is shared
        // in mission with the name suggested, and bob reaches it by his own `vox service list`.
        let mine = try EchoServer(stager)
        let listedHere = Key.id("listening-\(mine.port)")
        present(ui, listedHere, timeout: 30,
                "the services view must list the service listening here on port \(mine.port)")
        tap(ui, listedHere, "the listening service")
        let shareRoom = Key.id("share-room")
        present(ui, shareRoom, timeout: 10, "picking a listening service must offer a room to share it in")
        tap(ui, shareRoom, "the room picker")
        tap(ui, Key.menuItem("mission"), "mission in the room picker")
        words(ui, Key.id("share-can"), timeout: 10,
              "before sharing, the view must say bob, whom alice trusts, can reach it",
              until: { $0.contains("bob") })
        tap(ui, Key.id("share-submit"), "Share")
        let sharedName = Key.idPrefix("service-mine-")
        present(ui, sharedName, timeout: 30, "the share made in one step must be under YOUR SHARES")
        var bobSees = ""
        let bobUntil = Date().addingTimeInterval(60)
        while Date() < bobUntil && bobSees.isEmpty {
            let theirs = run(vox, ["service", "list", "--node", "bob", "--json", room], env: voxEnv).out
            let json = (try? JSONSerialization.jsonObject(with: Data(theirs.utf8))) as? [String: Any]
            bobSees = (json?["shared"] as? [[String: Any]] ?? []).first {
                ($0["by"] as? String) != "you" && ($0["readable"] as? String)?.hasPrefix("web.") != true
            }?["address"] as? String ?? ""
            if bobSees.isEmpty { Thread.sleep(forTimeInterval: 1) }
        }
        XCTAssertFalse(bobSees.isEmpty, "PRODUCT: bob's `vox service list` never listed the service alice shared in one step")
        let oneStepForward = try start(vox, ["forward", "--node", "bob", bobSees, "127.0.0.1:0"],
                                   env: voxEnv, until: "vox: forwarding ", product: true)
        defer { oneStepForward.terminate(); oneStepForward.waitUntilExit() }
        let bobAt = startedLine.split(separator: " ").dropFirst(2).first.map(String.init) ?? ""
        XCTAssertEqual(Line(bobAt)?.roundTrip("ONE-STEP\n") ?? "", "ONE-STEP\n",
                       "PRODUCT: bob must reach the service alice shared in one step, through \(bobSees)")
        print("[proof] services view: copied \(pasted); shared port \(mine.port) in one step; bob reached it at \(bobSees)")

        // (10) A refused join, newest in the decision record.
        let carolPass = scratch.appendingPathComponent("carol.pass").path
        let wrongPass = scratch.appendingPathComponent("wrong.pass").path
        try stager.write(Data("carol identity\n".utf8), to: carolPass)
        try stager.write(Data("not the room passphrase\n".utf8), to: wrongPass)
        try staged(vox, ["node", "attach", "carol", "--passphrase-file", carolPass], env: voxEnv)
        let missionLink = try line(staged(vox, ["room", "link", "--node", "alice", room], env: voxEnv)) {
            $0.hasPrefix("vox://")
        }
        let refusedJoin = run(vox, ["room", "join", "--node", "carol", "--passphrase-file", wrongPass,
                                    missionLink], env: voxEnv)
        guard refusedJoin.status != 0 else {
            throw Apparatus("carol's join with a wrong passphrase was not refused: \(refusedJoin.out)")
        }
        tap(ui, Key.id("decisions"), "Decision record in the sidebar")
        let topWords = words(ui, Key.id("decision-0"), timeout: 30,
                             "carol's refused join must be at the top of the decision record",
                             until: { $0.hasPrefix("refused: to join a room") }) ?? ""
        present(ui, Key.id("decision-1"), timeout: 5,
                "the decision record must keep the older decisions (the trust changes) below")
        print("[proof] decision record top: \(topWords)")

        // (11) Untrust cuts a live forward into alice's service.
        let aliceEcho = try EchoServer(stager)
        try staged(vox, ["service", "add", "--node", "alice", room, "notes",
                         "127.0.0.1:\(aliceEcho.port)"], env: voxEnv)
        var bobsAddress = ""
        let listUntil = Date().addingTimeInterval(60)
        while Date() < listUntil && bobsAddress.isEmpty {
            let listed = run(vox, ["service", "list", "--node", "bob", room], env: voxEnv).out
            bobsAddress = listed.split(separator: "\n").first { $0.contains("notes.") && $0.contains(" by ") }?
                .split(whereSeparator: \.isWhitespace).first.map(String.init) ?? ""
            if bobsAddress.isEmpty { Thread.sleep(forTimeInterval: 1) }
        }
        guard !bobsAddress.isEmpty else {
            throw Apparatus("bob's `vox service list` never listed alice's notes share")
        }
        let bobForward = try start(vox, ["forward", "--node", "bob", bobsAddress, "127.0.0.1:0"],
                                   env: voxEnv, until: "vox: forwarding ", product: true)
        defer { bobForward.terminate(); bobForward.waitUntilExit() }
        let bobBound = startedLine.split(separator: " ").dropFirst(2).first.map(String.init) ?? ""
        guard let live = Line(bobBound), live.roundTrip("BEFORE-UNTRUST\n") == "BEFORE-UNTRUST\n" else {
            throw Apparatus("bob's forward at \(bobBound) carried nothing before the untrust")
        }
        tap(ui, Key.id("keyring"), "Keyring in the sidebar")
        tap(ui, Key.id("keyring-remove-bob"), "Remove… on bob")
        words(ui, Key.id("keyring-remove-effect"), timeout: 10,
              "removing bob must say what untrusting does first",
              until: { $0.contains("reads nothing you write from now on") })
        tap(ui, Key.id("keyring-untrust-confirm"), "Untrust")
        XCTAssertTrue(live.cut(within: 30),
                      "PRODUCT: alice untrusted bob in the keyring view; bob's live connection into her service must be cut within 30 s, and it was not")
        print("[proof] untrust cut bob's live forward into alice's notes service")

        // (12) Quitting detaches it.
        ui.typeKey("q", modifierFlags: .command)
        XCTAssertTrue(ui.wait(for: .notRunning, timeout: 30), "PRODUCT: ⌘Q did not quit the app")
        var after = ""
        let until = Date().addingTimeInterval(30)
        while Date() < until {
            after = run(vox, ["node", "list"], env: voxEnv).out
            if nodeLine(after, "alice")?.contains(" detached") ?? false { break }
            Thread.sleep(forTimeInterval: 0.25)
        }
        XCTAssertTrue(nodeLine(after, "alice")?.contains(" detached") ?? false,
                      "PRODUCT: once the app quit, node alice must be detached; `vox node list` said: \(after)")
        print("[proof] while attached: \(listed)[proof] after quit: \(after)")

        // (13) What came while the app was closed is counted when it opens (ADR-028 R-8). Alice's
        // node, attached by hand and trusting bob again, takes bob's message to her while no app
        // runs; opened again, the app lists mission under "needs you (1)" from what her node
        // recorded as read, with nothing arriving after it opened.
        try staged(vox, ["node", "attach", "alice", "--passphrase-file", alicePass], env: voxEnv)
        try staged(vox, ["trust", "add", "--node", "alice", bobFp, "--name", "bob",
                         "--identity-passphrase-file", alicePass], env: voxEnv)
        try staged(vox, ["room", "post", "--node", "bob", "--to", aliceFp, room, "WHILE-APP-CLOSED"],
                   env: bobSession)
        var held = ""
        let heldUntil = Date().addingTimeInterval(60)
        while Date() < heldUntil && !held.contains("WHILE-APP-CLOSED") {
            held = run(vox, ["room", "read", "--node", "alice", room], env: voxEnv).out
            if !held.contains("WHILE-APP-CLOSED") { Thread.sleep(forTimeInterval: 0.5) }
        }
        guard held.contains("WHILE-APP-CLOSED") else {
            throw Apparatus("alice's node never held bob's WHILE-APP-CLOSED in 60 s: \(held)")
        }
        try scratchOnly(ui.launchEnvironment, under: scratchPath)
        ui.launch()
        let reopened = words(ui, Key.id("group-needs you"), timeout: 30,
                             "bob's message to alice came while the app was closed; opened again, the app must count it from what her node recorded as read, mission under \"needs you (1)\"",
                             until: { $0 == "needs you (1)" }) ?? ""
        print("[proof] opened again: \(reopened)")
        ui.typeKey("q", modifierFlags: .command)
        _ = ui.wait(for: .notRunning, timeout: 30)
        _ = run(vox, ["node", "detach", "alice"], env: voxEnv)
    }

    // ---- every check on the window proves its own query first --------------------------------
    //
    // A red must say whose it is (ADR-018): one that cannot tell a broken app from a broken proof
    // is no proof. So before any check on what the window shows, the query is shown to work: Vox
    // is in front and XCTest reads words in its window, else the red is APPARATUS. Then a red is
    // PRODUCT and quotes what the app did show. A SwiftUI Text's words are its accessibility
    // value, not its label (the read-by line, the keyring's effect sentences, a message's text):
    // `shown` reads the label, else the value.

    /// The premise: Vox in front, with words XCTest reads in what it shows. APPARATUS otherwise.
    private func windowReadable(_ ui: XCUIApplication, file: StaticString = #filePath,
                                line: UInt = #line) -> Bool {
        if ui.state != .runningForeground {
            ui.activate()
            _ = ui.wait(for: .runningForeground, timeout: 5)
        }
        guard ui.state == .runningForeground else {
            XCTFail("APPARATUS: Vox is not in front (state \(ui.state.rawValue)), so what it shows cannot be checked",
                    file: file, line: line)
            return false
        }
        // One text read is the premise; the full listing is for a red's message only.
        let text = ui.windows.firstMatch.staticTexts.firstMatch
        guard ui.windows.firstMatch.waitForExistence(timeout: 5), text.exists, !shown(text).isEmpty else {
            XCTFail("APPARATUS: XCTest reads no words in what Vox shows, so nothing in it can be checked",
                    file: file, line: line)
            return false
        }
        return true
    }

    /// Everything the app can show a person: its windows (with their sheets and popovers), its
    /// dialogs (the file panel), and its open menus. Never the Touch Bar, which mirrors controls.
    private func containers(_ ui: XCUIApplication) -> [XCUIElementQuery] {
        [ui.windows, ui.dialogs, ui.sheets, ui.popovers, ui.menus]
    }

    /// The words in everything the app shows, each text's identifier with them: what a PRODUCT
    /// red quotes.
    private func onScreen(_ ui: XCUIApplication) -> String {
        containers(ui).flatMap { $0.staticTexts.allElementsBoundByIndex.prefix(40) }.map { e -> String in
            let words = shown(e)
            return e.identifier.isEmpty || words.isEmpty ? words : "\(e.identifier): \(words)"
        }
        .filter { !$0.isEmpty }.joined(separator: " | ")
    }

    /// Where `key` is now, looked for while waiting: the windows (with their sheets and
    /// popovers) and the dialogs, two queries a turn. A menu item, in the menus.
    private func locate(_ ui: XCUIApplication, _ key: Key) -> XCUIElement? {
        let quick: [XCUIElementQuery]
        if case .menuItem = key { quick = [ui.menus] } else { quick = [ui.windows, ui.dialogs] }
        for container in quick {
            if let found = find(key, in: container) { return found }
        }
        return nil
    }

    /// `key` as one of `container`'s elements themselves, else among their descendants.
    private func find(_ key: Key, in container: XCUIElementQuery) -> XCUIElement? {
        if let own = key.selves(in: container)?.firstMatch, own.exists { return own }
        let found = key.query(in: container).firstMatch
        return found.exists ? found : nil
    }

    /// Where `key` is, searched in every container the app can show: before any verdict that it
    /// is missing.
    private func locateEverywhere(_ ui: XCUIApplication, _ key: Key) -> XCUIElement? {
        for container in key.containers(ui, all: containers(ui)) {
            if let found = find(key, in: container) { return found }
        }
        return nil
    }

    /// The app's whole accessibility tree, attached to the result, so a red carries its own
    /// evidence.
    private func keepTree(_ ui: XCUIApplication, _ why: String) {
        let tree = XCTAttachment(string: ui.debugDescription)
        tree.name = "Vox's UI tree when \(why)"
        tree.lifetime = .keepAlways
        add(tree)
    }

    /// The element `key` names, where it is now (else a query that finds nothing): for reading
    /// its value or whether it is there.
    private func el(_ ui: XCUIApplication, _ key: Key) -> XCUIElement {
        locate(ui, key) ?? key.query(in: ui.windows).firstMatch
    }

    /// `key` shown within `timeout`, the premise holding. Not shown: PRODUCT only once every
    /// container the app can show was searched, quoting what they show; found only outside them
    /// (the Touch Bar), APPARATUS.
    @discardableResult
    private func present(_ ui: XCUIApplication, _ key: Key, timeout: TimeInterval, _ product: String,
                         file: StaticString = #filePath, line: UInt = #line) -> Bool {
        guard windowReadable(ui, file: file, line: line) else { return false }
        let end = Date().addingTimeInterval(timeout)
        repeat {
            if locate(ui, key) != nil { return true }
            Thread.sleep(forTimeInterval: 0.25)
        } while Date() < end
        if locateEverywhere(ui, key) != nil { return true }
        missing(ui, key, product, file: file, line: line)
        return false
    }

    /// The red for `key` not shown: APPARATUS when the app has it only outside what it shows a
    /// person, PRODUCT otherwise, quoting everything shown.
    private func missing(_ ui: XCUIApplication, _ key: Key, _ product: String, file: StaticString,
                         line: UInt) {
        keepTree(ui, "\(key) was not shown")
        let anywhere = key.query(in: ui.descendants(matching: .any)).firstMatch
        if anywhere.exists {
            XCTFail("APPARATUS: \(key) is in the app only outside its windows, dialogs, sheets, popovers and menus (\(anywhere.elementType.rawValue)); the proof's search missed it",
                    file: file, line: line)
        } else {
            XCTFail("PRODUCT: \(product); \(key) is in none of the app's windows, dialogs, sheets, popovers or menus, which show: \(onScreen(ui))",
                    file: file, line: line)
        }
    }

    /// `key`'s words once `holds` is true of them, within `timeout`, the premise holding: PRODUCT
    /// quoting them when it never is; `missing` when it never shows; APPARATUS when it shows and
    /// XCTest reads neither its label nor its value.
    @discardableResult
    private func words(_ ui: XCUIApplication, _ key: Key, timeout: TimeInterval, _ product: String,
                       until holds: (String) -> Bool = { _ in true },
                       file: StaticString = #filePath, line: UInt = #line) -> String? {
        guard windowReadable(ui, file: file, line: line) else { return nil }
        let end = Date().addingTimeInterval(timeout)
        var last = ""
        var seen = false
        repeat {
            if let e = locate(ui, key) {
                seen = true
                last = shown(e)
                if !last.isEmpty && holds(last) { return last }
            }
            Thread.sleep(forTimeInterval: 0.25)
        } while Date() < end
        if !seen, let e = locateEverywhere(ui, key) {
            seen = true
            last = shown(e)
            if !last.isEmpty && holds(last) { return last }
        }
        if !seen {
            missing(ui, key, product, file: file, line: line)
        } else if last.isEmpty {
            keepTree(ui, "\(key) could not be read")
            XCTFail("APPARATUS: \(key) is shown and XCTest reads neither its label nor its value",
                    file: file, line: line)
        } else {
            keepTree(ui, "\(key) showed the wrong words")
            XCTFail("PRODUCT: \(product); it shows \"\(last)\"", file: file, line: line)
        }
        return nil
    }

    /// What `act` puts on the pasteboard, within 3 s. Premise: the runner reads the pasteboard (a
    /// string it writes reads back), else APPARATUS.
    private func copiedBy(_ ui: XCUIApplication, _ act: () -> Void,
                          file: StaticString = #filePath, line: UInt = #line) -> String {
        let board = NSPasteboard.general
        board.clearContents()
        board.setString("PASTEBOARD-PREMISE", forType: .string)
        guard board.string(forType: .string) == "PASTEBOARD-PREMISE" else {
            XCTFail("APPARATUS: the proof cannot read back what it puts on the pasteboard", file: file, line: line)
            return ""
        }
        board.clearContents()
        act()
        let end = Date().addingTimeInterval(3)
        var got = ""
        while Date() < end && got.isEmpty {
            got = board.string(forType: .string) ?? ""
            if got.isEmpty { Thread.sleep(forTimeInterval: 0.1) }
        }
        return got
    }

    /// Click `key`, once it is shown and hittable: APPARATUS when XCTest cannot click it, never an
    /// exception that names no side.
    @discardableResult
    private func tap(_ ui: XCUIApplication, _ key: Key, _ what: String,
                     file: StaticString = #filePath, line: UInt = #line) -> Bool {
        let end = Date().addingTimeInterval(10)
        repeat {
            if let e = locate(ui, key) {
                // Shown but off screen in a scroll view: scrolled to, as a person does.
                if !e.isHittable { scrollTo(ui, e) }
                if e.isHittable {
                    e.click()
                    return true
                }
            }
            Thread.sleep(forTimeInterval: 0.25)
        } while Date() < end
        keepTree(ui, "\(what) could not be clicked")
        XCTFail("APPARATUS: XCTest cannot click \(what) (\(key)): \(locateEverywhere(ui, key) == nil ? "not shown" : "not hittable")",
                file: file, line: line)
        return false
    }

    /// Scroll the window's scroll view that holds `e` until `e` is on screen (or it moves no more).
    private func scrollTo(_ ui: XCUIApplication, _ e: XCUIElement) {
        let target = e.frame
        guard let view = ui.windows.firstMatch.scrollViews.allElementsBoundByIndex.first(where: {
            $0.frame.minX <= target.midX && target.midX <= $0.frame.maxX
        }) else { return }
        for _ in 0..<20 where !e.isHittable {
            let now = e.frame
            let down = now.midY > view.frame.maxY
            let up = now.midY < view.frame.minY
            guard down || up else { return }
            view.scroll(byDeltaX: 0, deltaY: down ? -200 : 200)
            if e.frame == now { return }
        }
    }

    /// Type `text` into `key`, only once it was clicked.
    private func type(_ ui: XCUIApplication, _ key: Key, _ text: String, _ what: String,
                      file: StaticString = #filePath, line: UInt = #line) {
        if tap(ui, key, what, file: file, line: line) { el(ui, key).typeText(text) }
    }

    /// A staging step: `vox` must succeed, else the staging was not achieved. Its output, trimmed.
    @discardableResult
    private func staged(_ vox: String, _ args: [String], env: [String: String]) throws -> String {
        let (status, out) = run(vox, args, env: env)
        guard status == 0 else {
            throw Apparatus("`vox \(args.joined(separator: " "))` exited \(status): \(out)")
        }
        return out.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// The line of `out` that `is` picks: `vox` prints its answer on a line of its own.
    private func line(_ out: String, _ is: (String) -> Bool) throws -> String {
        guard let found = out.split(separator: "\n").map({ $0.trimmingCharacters(in: .whitespaces) })
            .first(where: `is`) else {
            throw Apparatus("no line of `vox`'s answer was the one asked for: \(out)")
        }
        return found
    }

    private func nodeLine(_ list: String, _ node: String) -> String? {
        list.split(separator: "\n").map(String.init).first { $0.hasPrefix(node + " ") }
    }

    /// Run `vox` to its end, by the stager (outside the runner's sandbox); its exit status and
    /// what it printed, stdout and stderr.
    private func run(_ vox: String, _ args: [String], env: [String: String],
                     input: String? = nil) -> (status: Int32, out: String) {
        stager.run([vox] + args, env: env, input: input)
    }

    /// The line `start` waited for, as `vox` printed it.
    private var startedLine = ""

    /// Start `vox`, by the stager, and wait until it prints a line starting with `until`; that
    /// line is kept in `startedLine`. A `vox` that never says it is the apparatus's red, unless
    /// `product` (it is the product's to say, as `vox forward` saying where it forwards); either
    /// way the red quotes what it did say, stderr included.
    private func start(_ vox: String, _ args: [String], env: [String: String], until: String,
                       product: Bool = false) throws -> Started {
        let got = try stager.start([vox] + args, env: env, until: until)
        let started = Started(stager: stager, id: got.id)
        guard let line = got.line else {
            started.terminate()
            let why = "`vox \(args.joined(separator: " "))` never said \(until.debugDescription) in 30 s; it said: \(got.out)"
            if product { throw Product(why) }
            throw Apparatus(why)
        }
        startedLine = line
        return started
    }
}
