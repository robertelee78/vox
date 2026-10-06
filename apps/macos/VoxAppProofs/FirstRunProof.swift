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
//    what that does (ADR-014 M-8); the person says Not Now. Then it lists the Mac's nodes; the person picks one and types its passphrase.
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
//    not working; once he claims a resource and posts `working`, his lane's chip says working.
// 8. Notifications (ADR-014 M-23, ADR-028 R-10, #448): with the keyring on screen, bob's message
//    to alice posts one local notification, titled with the room, saying who wrote to her, and
//    never the message's text. Preconditions, not the proof's to arrange: Vox allowed to notify
//    (the app says "notifications off" otherwise, an APPARATUS red) and no Focus on.
// 9. Keys (ADR-014 M-20, #446): with quiet rooms aaa and bbb and mission needing alice, ⌘J from
//    aaa goes to mission, not to bbb, the next room in the sidebar's order; ⌘⇧C on a selected
//    service card copies the address `vox service list` gives.
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
// addressed to this node grouped as quiet (`attention::group`), or an inspector that lists the
// members only when the room is opened: (3) goes red. The timeline drops
// the read-by line, or marks rows read while the window is hidden: (4) goes red. Remove untrusts at once, saying nothing first: (5) goes red. The note is posted as a message
// of its own: (6) goes red. A lane derived working without a claim: (7) goes red.
// A notification that carries the message's text: (8) goes red. ⌘J bound to the next room in
// the sidebar's order: (9) goes red. The decision record oldest first: (10) goes red.
// Untrust that leaves a member's live sessions running: (11) goes red. An app that counts
// nothing from before it opened (no seeding from VoxClient.unread): (13) goes red.

import XCTest

/// A red that is the product's, thrown where an assertion cannot be: what `vox` did, quoted.
struct Product: Error, CustomStringConvertible {
    let why: String
    init(_ why: String) { self.why = why }
    var description: String { "PRODUCT: \(why)" }
}

/// What an element says to VoiceOver: its label, or, for text, its value (a status bar of combined
/// text reads as its value).
func shown(_ element: XCUIElement) -> String {
    element.label.isEmpty ? (element.value as? String ?? "") : element.label
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
        stager = try Stager.fromEnvironment()
    }

    override func tearDown() {
        daemon?.terminate()
        super.tearDown()
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

        let ui = XCUIApplication(url: app)
        ui.launchEnvironment = voxEnv
        ui.launch()

        // (1) First run: the login item is asked about once, and declined here (approving it is
        // the manual check manual.login_item); then pick the node, and a wrong passphrase is the
        // daemon's sentence.
        let why = ui.descendants(matching: .any)["login-item-why"]
        XCTAssertTrue(why.waitForExistence(timeout: 30),
                      "PRODUCT: the app never asked at first run whether to keep the daemon running")
        let whyWords = why.label.isEmpty ? (why.value as? String ?? "") : why.label
        XCTAssertTrue(whyWords.contains("keeps your rooms reachable while you are logged in, even with the app closed"),
                      "PRODUCT: the login item question must say what it does; it said: \(whyWords)")
        ui.buttons["login-item-not-now"].click()
        let pick = ui.buttons["node-alice"]
        XCTAssertTrue(pick.waitForExistence(timeout: 30),
                      "PRODUCT: the app never offered node alice at first run")
        pick.click()
        let field = ui.secureTextFields["passphrase"]
        XCTAssertTrue(field.waitForExistence(timeout: 10),
                      "PRODUCT: the app never asked for node alice's passphrase")
        field.click()
        field.typeText("not the passphrase")
        ui.buttons["attach"].click()
        let said = ui.descendants(matching: .any)["said"]
        XCTAssertTrue(said.waitForExistence(timeout: 30),
                      "PRODUCT: a wrong passphrase showed no sentence where it was typed")
        let words = said.label
        XCTAssertTrue(words.contains("that passphrase does not open node alice's identity"),
                      "PRODUCT: a wrong passphrase must show the daemon's own sentence; it showed: \(words)")

        // (2) The right one attaches it.
        field.click()
        field.typeText("alice identity")
        ui.buttons["attach"].click()
        let attached = ui.descendants(matching: .any)["attached"]
        XCTAssertTrue(attached.waitForExistence(timeout: 60),
                      "PRODUCT: the right passphrase did not attach node alice")
        let listed = run(vox, ["node", "list"], env: voxEnv).out
        XCTAssertTrue(nodeLine(listed, "alice")?.contains(" attached ") ?? false,
                      "PRODUCT: `vox node list` must say alice is attached; it said: \(listed)")

        // (3) The main window groups the room by what it needs from alice. Bob is a second node of
        // the same daemon: a member reached directly, no anchor.
        let bobEnv = voxEnv.merging(["VOX_IDENTITY_PASSPHRASE": "bob identity"]) { $1 }
        let roomPass = scratch.appendingPathComponent("room.pass").path
        let alicePass = scratch.appendingPathComponent("alice.pass").path
        let bobPass = scratch.appendingPathComponent("bob.pass").path
        try stager.write(Data("mission room\n".utf8), to: roomPass)
        try stager.write(Data("alice identity\n".utf8), to: alicePass)
        try stager.write(Data("bob identity\n".utf8), to: bobPass)
        try staged(vox, ["node", "create", "bob"], env: bobEnv)
        try staged(vox, ["node", "attach", "bob", "--passphrase-file", bobPass], env: voxEnv)
        let aliceFp = try line(staged(vox, ["id", "--node", "alice"], env: voxEnv)) { $0.count == 52 }
        let bobFp = try line(staged(vox, ["id", "--node", "bob"], env: voxEnv)) { $0.count == 52 }
        // The app makes the room (⌘N, M-31: create) and copies its link (⌘L).
        ui.typeKey("n", modifierFlags: .command)
        let roomName = ui.textFields["room-form-name"]
        XCTAssertTrue(roomName.waitForExistence(timeout: 10), "PRODUCT: ⌘N opened no New Room form")
        roomName.click()
        roomName.typeText("mission")
        let roomSecret = ui.secureTextFields["room-form-passphrase"]
        roomSecret.click()
        roomSecret.typeText("mission room")
        ui.buttons["room-form-submit"].click()
        var rooms = ""
        let madeUntil = Date().addingTimeInterval(60)
        while Date() < madeUntil && !rooms.contains(" mission") {
            rooms = run(vox, ["room", "list", "--node", "alice"], env: voxEnv).out
            if !rooms.contains(" mission") { Thread.sleep(forTimeInterval: 0.5) }
        }
        guard let room = rooms.split(separator: "\n").first(where: { $0.contains(" mission") })?
            .split(whereSeparator: \.isWhitespace).first.map(String.init) else {
            throw Product("the app's New Room made no room alice's `vox room list` lists: \(rooms)")
        }
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
        let joined = ui.descendants(matching: .any)["member-bob"]
        let inKeyring = NSPredicate(format: "exists == true AND label BEGINSWITH %@", "bob, in keyring")
        XCTAssertEqual(XCTWaiter.wait(for: [expectation(for: inKeyring, evaluatedWith: joined)],
                                      timeout: 30), .completed,
                       "PRODUCT: bob joined and was trusted while the room was on screen, and its inspector does not list him in alice's keyring; it said \"\(joined.exists ? joined.label : "no bob")\"")
        // Off the room, so a message to alice is unread: a room on screen is read.
        ui.descendants(matching: .any)["keyring"].click()
        try staged(vox, ["room", "post", "--node", "bob", "--to", aliceFp, room, "NEEDS-YOU"],
                   env: bobSession)
        let needsYou = ui.descendants(matching: .any)["group-needs you"]
        let grouped = NSPredicate(format: "exists == true AND label == %@", "needs you (1)")
        let met = XCTWaiter.wait(for: [expectation(for: grouped, evaluatedWith: needsYou)], timeout: 60)
        let row = ui.descendants(matching: .any)["room-mission"]
        XCTAssertEqual(met, .completed,
                       "PRODUCT: a message to alice must list the room under \"needs you (1)\"; the sidebar said \"\(needsYou.exists ? needsYou.label : "no needs-you group")\", the room's row \"\(row.exists ? row.label : "not listed")\"")
        XCTAssertTrue(row.exists && row.label.contains("needs you"),
                      "PRODUCT: the room's row must say it needs you; it said \"\(row.exists ? row.label : "not listed")\"")
        row.click()
        let bob = ui.descendants(matching: .any)["member-bob"]
        XCTAssertTrue(bob.waitForExistence(timeout: 30),
                      "PRODUCT: the inspector never listed bob")
        XCTAssertTrue(bob.label.hasPrefix("bob, in keyring"),
                      "PRODUCT: the inspector must show bob in alice's keyring; it said \"\(bob.label)\"")
        let status = ui.descendants(matching: .any)["status"]
        XCTAssertTrue(status.waitForExistence(timeout: 10), "PRODUCT: the window has no status bar")
        let bar = shown(status)
        XCTAssertTrue(bar.contains("node alice") && bar.contains("peer") && bar.contains("keyring"),
                      "PRODUCT: the status bar must say the node, its peers and the keyring window; it said \"\(bar)\"")
        let regrouped = ui.descendants(matching: .any)["group-needs you"].label
        XCTAssertEqual(regrouped, "needs you (0)",
                       "PRODUCT: the room shown is read, so nothing needs alice; the sidebar said \"\(regrouped)\"")
        print("[proof] grouped: needs you (1), then \(regrouped); inspector: \(bob.label); status: \(bar)")

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
        let compose = ui.textFields["compose"]
        XCTAssertTrue(compose.waitForExistence(timeout: 10), "PRODUCT: the room has no field to post")
        compose.click()
        compose.typeText("FROM-ALICE\r")
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
        let readLine = ui.descendants(matching: .any)
            .matching(NSPredicate(format: "identifier BEGINSWITH 'read-by-'")).firstMatch
        XCTAssertTrue(readLine.waitForExistence(timeout: 30) && readLine.label == "read by bob",
                      "PRODUCT: alice's message read by bob must show \"read by bob\" under it; the timeline shows \(readLine.exists ? readLine.label : "no read-by line")")
        print("[proof] bob's message read by \(readByAlice); alice's message: \(readLine.exists ? readLine.label : "none")")

        // (5) The keyring: carol, a node made here, added by her pasted fingerprint, then removed.
        try staged(vox, ["node", "create", "carol"],
                   env: voxEnv.merging(["VOX_IDENTITY_PASSPHRASE": "carol identity"]) { $1 })
        let carolFp = try line(staged(vox, ["id", "--node", "carol"], env: voxEnv)) { $0.count == 52 }
        ui.descendants(matching: .any)["keyring"].click()
        let addFp = ui.textFields["keyring-add-fingerprint"]
        XCTAssertTrue(addFp.waitForExistence(timeout: 10), "PRODUCT: the keyring view offers no add")
        addFp.click()
        addFp.typeText(carolFp)
        let addAlias = ui.textFields["keyring-add-alias"]
        addAlias.click()
        addAlias.typeText("carol")
        let addEffect = ui.descendants(matching: .any)["keyring-add-effect"]
        XCTAssertTrue(addEffect.waitForExistence(timeout: 10)
                          && addEffect.label.contains("it may read what you write"),
                      "PRODUCT: adding must say what trusting does before it is done; it said \(addEffect.exists ? addEffect.label : "nothing")")
        ui.buttons["keyring-trust"].click()
        let carolRow = ui.descendants(matching: .any)["keyring-row-carol"]
        XCTAssertTrue(carolRow.waitForExistence(timeout: 30), "PRODUCT: carol, once trusted, is not listed in the keyring view")
        let trustList = run(vox, ["trust", "list", "--node", "alice"], env: voxEnv).out
        XCTAssertTrue(trustList.contains(carolFp),
                      "PRODUCT: `vox trust list` must list carol once the app trusted her; it said: \(trustList)")
        ui.buttons["keyring-remove-carol"].click()
        let removeEffect = ui.descendants(matching: .any)["keyring-remove-effect"]
        XCTAssertTrue(removeEffect.waitForExistence(timeout: 10)
                          && removeEffect.label.contains("reads nothing you write from now on"),
                      "PRODUCT: removing must say what untrusting does before it is done; it said \(removeEffect.exists ? removeEffect.label : "nothing")")
        ui.buttons["keyring-untrust-confirm"].click()
        var after5 = ""
        let goneUntil = Date().addingTimeInterval(30)
        while Date() < goneUntil {
            after5 = run(vox, ["trust", "list", "--node", "alice"], env: voxEnv).out
            if !after5.contains(carolFp) && !carolRow.exists { break }
            Thread.sleep(forTimeInterval: 0.5)
        }
        XCTAssertFalse(after5.contains(carolFp) || carolRow.exists,
                       "PRODUCT: once untrusted, carol must be gone from the keyring view and from `vox trust list`; it said: \(after5)")
        print("[proof] keyring: added and listed carol, then removed her after saying what untrusting does")

        // (6) Attach a file to the room, To: bob, with a note.
        ui.descendants(matching: .any)["room-mission"].click()
        let file = scratch.appendingPathComponent("for-bob.bin")
        let bytes = Data((0..<150_000).map { UInt8(truncatingIfNeeded: $0 &* 31 % 253) })
        try stager.write(bytes, to: file.path)
        let attachButton = ui.buttons["attach"]
        XCTAssertTrue(attachButton.waitForExistence(timeout: 10), "PRODUCT: the room offers no Attach")
        attachButton.click()
        // The open panel: go to the file's path, then Attach.
        ui.typeKey("g", modifierFlags: [.command, .shift])
        ui.typeText(file.path + "\r")
        let choose = ui.buttons["Attach"].firstMatch
        XCTAssertTrue(choose.waitForExistence(timeout: 10), "APPARATUS: the open panel did not show")
        choose.click()
        let toBob = ui.descendants(matching: .any)["attach-to-bob"]
        XCTAssertTrue(toBob.waitForExistence(timeout: 10), "PRODUCT: attaching a file asks no To:")
        toBob.click()
        let noteField = ui.textFields["attach-note"]
        noteField.click()
        noteField.typeText("FOR-BOB-NOTE")
        ui.buttons["attach-send"].click()
        let bobCopy = URL(fileURLWithPath: data).appendingPathComponent("nodes/bob/files/\(room)/for-bob.bin")
        var pulledBytes: Data?
        let pullUntil = Date().addingTimeInterval(120)
        while Date() < pullUntil && pulledBytes == nil {
            pulledBytes = try? Data(contentsOf: bobCopy)
            if pulledBytes == nil { Thread.sleep(forTimeInterval: 0.5) }
        }
        XCTAssertEqual(pulledBytes, bytes,
                       "PRODUCT: a file attached To: bob must be pulled by bob's node, byte for byte, into \(bobCopy.path); it holds \(pulledBytes?.count ?? -1) bytes")
        let bobRows = run(vox, ["room", "read", "--node", "bob", "--json", room], env: voxEnv).out
            .split(separator: "\n").filter { $0.contains("FOR-BOB-NOTE") }
        XCTAssertTrue(bobRows.count == 1 && bobRows[0].contains("for-bob.bin"),
                      "PRODUCT: the note must travel in the share itself, as one message; bob's `vox room read --json` has \(bobRows.count) row(s) with it: \(bobRows)")
        print("[proof] attached for-bob.bin To: bob; bob pulled \(pulledBytes?.count ?? 0) bytes; rows with the note: \(bobRows.count)")

        // (7) Lanes. Working without a claim is not working.
        try staged(vox, ["room", "post", "--node", "bob", "--type", "working", room, "NO-CLAIM"],
                   env: voxEnv)
        Thread.sleep(forTimeInterval: 10)
        let lanesToggle = ui.descendants(matching: .any)["lanes-toggle"]
        let bobLane = ui.descendants(matching: .any)["lane-state-bob"]
        if lanesToggle.exists {
            lanesToggle.buttons["Lanes"].click()
            XCTAssertFalse(bobLane.waitForExistence(timeout: 5) && bobLane.label == "bob: working",
                           "PRODUCT: bob posted `working` holding no claim; his lane must not say working, and it said \(bobLane.label)")
            lanesToggle.buttons["Timeline"].click()
        }
        try staged(vox, ["room", "claim", "--node", "bob", room, "ticket-1"], env: voxEnv)
        try staged(vox, ["room", "post", "--node", "bob", "--type", "working", room, "ON-TICKET-1"],
                   env: voxEnv)
        XCTAssertTrue(lanesToggle.waitForExistence(timeout: 30),
                      "PRODUCT: a room whose member works on a claim must offer the lanes view")
        lanesToggle.buttons["Lanes"].click()
        let working = NSPredicate(format: "exists == true AND label == %@", "bob: working")
        XCTAssertEqual(XCTWaiter.wait(for: [expectation(for: working, evaluatedWith: bobLane)], timeout: 30),
                       .completed,
                       "PRODUCT: bob, holding ticket-1 with a working post, must show working in his lane; it said \(bobLane.exists ? bobLane.label : "no lane")")
        print("[proof] lanes: \(bobLane.label)")
        lanesToggle.buttons["Timeline"].click()

        // (8) Notifications: the room off screen, bob writes to alice.
        ui.descendants(matching: .any)["keyring"].click()
        let statusNow = shown(ui.descendants(matching: .any)["status"])
        if statusNow.contains("notifications off") {
            throw Apparatus("Vox is not allowed to notify on this Mac: allow it in System Settings, Notifications, Vox, then run again; the app said \(statusNow)")
        }
        try staged(vox, ["room", "post", "--node", "bob", "--to", aliceFp, room, "SECRET-TEXT-8"],
                   env: bobSession)
        let centre = XCUIApplication(bundleIdentifier: "com.apple.notificationcenterui")
        let banner = centre.descendants(matching: .any)
            .matching(NSPredicate(format: "label CONTAINS %@", "bob wrote to you")).firstMatch
        XCTAssertTrue(banner.waitForExistence(timeout: 30),
                      "PRODUCT: bob's message to alice in a room off screen posted no notification saying \"bob wrote to you\" (with Vox allowed to notify and no Focus on)")
        let leaked = centre.descendants(matching: .any)
            .matching(NSPredicate(format: "label CONTAINS %@ OR value CONTAINS %@",
                                  "SECRET-TEXT-8", "SECRET-TEXT-8")).firstMatch
        XCTAssertFalse(leaked.exists,
                       "PRODUCT: a notification must not carry the message's text; one said \(leaked.label)")
        print("[proof] notification: \(banner.label)")

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
        let aaa = ui.descendants(matching: .any)["room-aaa"]
        XCTAssertTrue(aaa.waitForExistence(timeout: 30), "PRODUCT: room aaa never showed in the sidebar")
        XCTAssertTrue(ui.descendants(matching: .any)["room-bbb"].waitForExistence(timeout: 30),
                      "PRODUCT: room bbb never showed in the sidebar")
        aaa.click()
        try staged(vox, ["room", "post", "--node", "bob", "--to", aliceFp, room, "NEEDS-YOU-9"],
                   env: bobSession)
        let needs = NSPredicate(format: "exists == true AND label == %@", "needs you (1)")
        XCTAssertEqual(XCTWaiter.wait(for: [expectation(for: needs, evaluatedWith:
            ui.descendants(matching: .any)["group-needs you"])], timeout: 60), .completed,
                       "PRODUCT: bob's message to alice must put mission under needs you")
        ui.typeKey("j", modifierFlags: .command)
        let landed = ui.descendants(matching: .any)
            .matching(NSPredicate(format: "label CONTAINS %@", "NEEDS-YOU-9")).firstMatch
        XCTAssertTrue(landed.waitForExistence(timeout: 15),
                      "PRODUCT: ⌘J from room aaa must open mission, the room that needs alice; its message NEEDS-YOU-9 is not on screen")
        // ⌘⇧C: a service bob shares, selected, copies its address.
        let echo = try EchoServer(stager)
        try staged(vox, ["service", "add", "--node", "bob", room, "web", "127.0.0.1:\(echo.port)"],
                   env: voxEnv)
        var cliAddress = ""
        let shareUntil = Date().addingTimeInterval(60)
        while Date() < shareUntil && cliAddress.isEmpty {
            let listed = run(vox, ["service", "list", "--node", "alice", room], env: voxEnv).out
            cliAddress = listed.split(separator: "\n").first { $0.contains(" by ") && $0.contains("web.") }?
                .split(whereSeparator: \.isWhitespace).first.map(String.init) ?? ""
            if cliAddress.isEmpty { Thread.sleep(forTimeInterval: 1) }
        }
        guard !cliAddress.isEmpty else {
            throw Apparatus("alice's `vox service list` never listed bob's web share")
        }
        aaa.click()
        ui.descendants(matching: .any)["room-mission"].click()
        let card = ui.descendants(matching: .any)["service-\(cliAddress)"]
        XCTAssertTrue(card.waitForExistence(timeout: 30),
                      "PRODUCT: the room shows no card for bob's service \(cliAddress)")
        card.click()
        NSPasteboard.general.clearContents()
        ui.typeKey("c", modifierFlags: [.command, .shift])
        Thread.sleep(forTimeInterval: 1)
        let copied = NSPasteboard.general.string(forType: .string) ?? ""
        XCTAssertEqual(copied, cliAddress,
                       "PRODUCT: ⌘⇧C on the selected service must copy its address as `vox service list` gives it")
        // ... and used: `vox forward` to what was copied carries bytes to bob's service and back.
        let forward = try start(vox, ["forward", "--node", "alice", copied, "127.0.0.1:0"],
                                env: voxEnv, until: "vox: forwarding ", product: true)
        defer { forward.terminate(); forward.waitUntilExit() }
        let bound = startedLine.split(separator: " ").dropFirst(2).first.map(String.init) ?? ""
        let through = Line(bound)?.roundTrip("THROUGH-THE-COPY\n") ?? ""
        XCTAssertEqual(through, "THROUGH-THE-COPY\n",
                       "PRODUCT: a forward to the copied address \(copied), bound at \(bound), must carry bytes to bob's service and back")
        print("[proof] ⌘J opened mission; ⌘⇧C copied \(copied)")

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
        ui.descendants(matching: .any)["decisions"].click()
        let top = ui.descendants(matching: .any)["decision-0"]
        let refusedFirst = NSPredicate(format: "exists == true AND label BEGINSWITH %@",
                                       "refused: to join a room")
        XCTAssertEqual(XCTWaiter.wait(for: [expectation(for: refusedFirst, evaluatedWith: top)],
                                      timeout: 30), .completed,
                       "PRODUCT: carol's refused join must be at the top of the decision record; the top says \(top.exists ? top.label : "nothing")")
        XCTAssertTrue(ui.descendants(matching: .any)["decision-1"].exists,
                      "PRODUCT: the decision record must keep the older decisions (the trust changes) below")
        print("[proof] decision record top: \(top.label)")

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
        ui.descendants(matching: .any)["keyring"].click()
        ui.buttons["keyring-remove-bob"].click()
        let untrustEffect = ui.descendants(matching: .any)["keyring-remove-effect"]
        XCTAssertTrue(untrustEffect.waitForExistence(timeout: 10),
                      "PRODUCT: removing bob must say what untrusting does first")
        ui.buttons["keyring-untrust-confirm"].click()
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
        ui.launch()
        let reopened = ui.descendants(matching: .any)["group-needs you"]
        let counted = NSPredicate(format: "exists == true AND label == %@", "needs you (1)")
        XCTAssertEqual(XCTWaiter.wait(for: [expectation(for: counted, evaluatedWith: reopened)],
                                      timeout: 30), .completed,
                       "PRODUCT: bob's message to alice came while the app was closed; opened again, the app must count it from what her node recorded as read, mission under \"needs you (1)\"; the sidebar says \(reopened.exists ? reopened.label : "no needs-you group")")
        print("[proof] opened again: \(reopened.label)")
        ui.typeKey("q", modifierFlags: .command)
        _ = ui.wait(for: .notRunning, timeout: 30)
        _ = run(vox, ["node", "detach", "alice"], env: voxEnv)
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
