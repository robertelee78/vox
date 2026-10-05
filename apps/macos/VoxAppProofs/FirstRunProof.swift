// ADR-014 M-6, ADR-028 A-4 and M-7 — first run to an attached node, and quit detaching it, proved
// by real use of the built Vox.app (ADR-018, ADR-014 M-30).
//
// Run by `scripts/app-proofs.sh`, which builds the app, puts the release `vox` in it, and passes
// (through xcodebuild's TEST_RUNNER_ prefix):
//   VOX_PROOF_APP      the Vox.app under proof; its Contents/Helpers/vox runs the daemon
//   VOX_PROOF_SCRATCH  a scratch directory: the data root and config directory go there
//
// What must hold, as a person sees it:
// 1. At first run the app lists the Mac's nodes; the person picks one and types its passphrase.
//    A wrong passphrase shows the daemon's own sentence where it was typed.
// 2. The right one attaches the node: the app says so, and `vox node list` says `attached`.
// 3. The main window (ADR-028 W-1, W-2; ADR-014 M-13): once bob, a member alice trusts, posts to
//    the room a message addressed to alice, the sidebar lists the room under "needs you (1)"; the
//    inspector lists bob with his trust glyph; the status bar says the node, its peers and the
//    keyring window.
// 4. Quitting the app (⌘Q) detaches it: `vox node list` says `detached`.
//
// Mutants: the app attaches its node so that it outlives the app (the daemon's explicit attach in
// place of the app's hold), and quitting leaves it attached: (4) goes red. A room with a message
// addressed to this node grouped as quiet (`attention::group`): (3) goes red.

import XCTest

/// A red that is the apparatus's, not the product's: staging was not achieved.
struct Apparatus: Error, CustomStringConvertible {
    let why: String
    init(_ why: String) { self.why = why }
    var description: String { "APPARATUS: \(why)" }
}

final class FirstRunProof: XCTestCase {
    private var daemon: Process?

    override func tearDown() {
        daemon?.terminate()
        daemon?.waitUntilExit()
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
        let voxEnv = ["VOX_DATA_DIR": data, "VOX_CONFIG_DIR": config]

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

        // (1) First run: pick the node, and a wrong passphrase is the daemon's sentence.
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
        try "mission room\n".write(toFile: roomPass, atomically: true, encoding: .utf8)
        try "alice identity\n".write(toFile: alicePass, atomically: true, encoding: .utf8)
        try "bob identity\n".write(toFile: bobPass, atomically: true, encoding: .utf8)
        try staged(vox, ["node", "create", "bob"], env: bobEnv)
        try staged(vox, ["node", "attach", "bob", "--passphrase-file", bobPass], env: voxEnv)
        let aliceFp = try line(staged(vox, ["id", "--node", "alice"], env: voxEnv)) { $0.count == 52 }
        let bobFp = try line(staged(vox, ["id", "--node", "bob"], env: voxEnv)) { $0.count == 52 }
        try staged(vox, ["room", "create", "--node", "alice", "--passphrase-file", roomPass,
                         "--name", "mission"], env: voxEnv)
        let rooms = try staged(vox, ["room", "list", "--node", "alice"], env: voxEnv)
        guard let room = rooms.split(whereSeparator: \.isWhitespace).first.map(String.init) else {
            throw Apparatus("`vox room list --node alice` listed no room: \(rooms)")
        }
        let link = try line(staged(vox, ["room", "link", "--node", "alice", room], env: voxEnv)) {
            $0.hasPrefix("vox://")
        }
        try staged(vox, ["room", "join", "--node", "bob", "--passphrase-file", roomPass, link,
                         "--name", "mission"], env: voxEnv)
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
        try staged(vox, ["room", "post", "--node", "bob", "--to", aliceFp, room, "NEEDS-YOU"],
                   env: voxEnv)
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
        let bar = status.label
        XCTAssertTrue(bar.contains("node alice") && bar.contains("peer") && bar.contains("keyring"),
                      "PRODUCT: the status bar must say the node, its peers and the keyring window; it said \"\(bar)\"")
        let regrouped = ui.descendants(matching: .any)["group-needs you"].label
        XCTAssertEqual(regrouped, "needs you (0)",
                       "PRODUCT: the room shown is read, so nothing needs alice; the sidebar said \"\(regrouped)\"")
        print("[proof] grouped: needs you (1), then \(regrouped); inspector: \(bob.label); status: \(bar)")

        // (4) Quitting detaches it.
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

    /// Run `vox` to its end; its exit status and what it printed.
    private func run(_ vox: String, _ args: [String], env: [String: String]) -> (status: Int32, out: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: vox)
        p.arguments = args
        p.environment = env
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch {
            return (-1, "APPARATUS: could not start \(vox): \(error)")
        }
        let bytes = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: bytes, as: UTF8.self))
    }

    /// Start `vox` and wait until it prints a line starting with `until`.
    private func start(_ vox: String, _ args: [String], env: [String: String], until: String) throws -> Process {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: vox)
        p.arguments = args
        p.environment = env
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        p.standardInput = FileHandle.nullDevice
        try p.run()
        let seen = expectation(description: until)
        let lock = NSLock()
        var buffer = ""
        var met = false
        out.fileHandleForReading.readabilityHandler = { handle in
            let chunk = String(decoding: handle.availableData, as: UTF8.self)
            lock.lock()
            defer { lock.unlock() }
            buffer += chunk
            if !met, buffer.split(separator: "\n").contains(where: { $0.hasPrefix(until) }) {
                met = true
                seen.fulfill()
            }
        }
        if XCTWaiter.wait(for: [seen], timeout: 30) != .completed {
            p.terminate()
            throw Apparatus("the daemon never said \(until.debugDescription); it said: \(buffer)")
        }
        return p
    }
}
