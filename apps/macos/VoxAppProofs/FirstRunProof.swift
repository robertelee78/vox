// ADR-014 M-6, ADR-028 A-4 and M-7 — first run to an attached node, and quit detaching it, proved
// by real use of the built Vox.app (ADR-018, ADR-014 M-30).
//
// Run by `scripts/app-proofs.sh`, which builds the app, puts the release `vox` in it, and passes
// (through xcodebuild's TEST_RUNNER_ prefix):
//   VOX_PROOF_APP      the Vox.app under proof; its Contents/Helpers/vox runs the daemon
//   VOX_PROOF_SCRATCH  a scratch directory: the data root and config directory go there
//   VOX_PROOF_CONTINUE 1 for a combined mutant build: a case goes on past a red (its
//                      closing [proof] line then holds nothing)
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
//    A reply quotes what it answers (ADR-028 R-9, D6): bob's reply to FROM-ALICE shows "re you:
//    FROM-ALICE" above it, and its quote, clicked, or ⌘↑ with the reply selected, selects FROM-ALICE.
//    To: offers bob's open Session under him (MADR W-4, ADR-029 TA-1, D7): ticked, alice's post is
//    addressed to that Session alone, <bob>/<session>, as bob's node holds it.
//    @alias (ADR-028 K-4, D8): "@b" offers @bob, and picked, it addresses bob. Step 5 warns of an
//    alias the same as bob's but for case before it is given, and (5b) with carol trusted as "Bob",
//    bob is told apart in mission's members as bob#<his fingerprint's first 6>.
// 5. The keyring view (ADR-014 M-16, ADR-028 K-3, E-5, #443): a pasted fingerprint with an alias
//    says what trusting does before it is done, and is listed, as `vox trust list` lists it;
//    removing it says what removing does first, and only then removes it.
// 6. Attaching a file (ADR-014 M-24, ADR-028 F-1, #449): chosen with Attach…, addressed To: bob
//    with a note, it is one share: bob's node pulls it by itself, byte for byte, and the note is
//    in the share's announcement, never a message of its own.
// 7. (The lanes view: removed, ADR-029.)
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
// 14. The keyboard (WCAG 2.1.1, 2.4.7; #450), run with Full Keyboard Access on (set around the
//     pass, never by the proof): View > Focus Timeline (⌃⌘T) puts the keyboard on mission's
//     timeline with its newest message selected; ↑ and ↓ move the selection, as Reply to Selected
//     Message (⌘R) then says; Space and Return on a row whose file alice pulled open it in Quick
//     Look; Tab from the timeline reaches the composer.
// 15. Who trusts whom (ADR-028 K-5, K-7, R-5, R-6, E-4). Dave, whom bob trusts, joins mission
//     while it is on screen: its timeline says "<dave> (not in keyring) joined. bob trusts it."
//     (D10). Dave trusts alice; her member pane says he is "not in keyring, trusts you", the room
//     names him as not yet reading each other with her, and his card says both directions; Trust…
//     there, with his alias, makes him "trusted both ways" and puts him in her keyring, through
//     the passphrase gate if the keyring window has closed (D4). With bob's and dave's nodes
//     detached, a message she posts says "only on this machine"; once bob's node is back, "on 1 of
//     2 members' nodes" (D9). Node > Detach then offers only to attach alice again, never another
//     node of this Mac's, and attaching again makes the window hers (D17).
//     Compare goes group by group (#624): four groups of dave's fingerprint on his offer say "So
//     far matches 4 of 13 groups."; on his card two say 2 of 13, a wrong third is named as group 3
//     with no Remove (he is not in the keyring), and the whole of it is marked a match.
//     The keyring's card for dave (G2) heads "dave ⇄ you", says he trusts alice too, names
//     mission as a shared room, and its disclosure says what removing him would change.
// 16. What an operation comes to (#608, #611, #615), run after step 5, or alone with
//     VOX_PROOF_FROM=16: New Room with an empty passphrase says what that means and makes the
//     room; a refused End for Everyone keeps its sheet open with the reason; that refusal is the
//     status bar's, never another sheet's, and dismissed it goes. And G3 (ADR-017 S-1): a service
//     bob shares in mission, in the services view, shows its address broken into its parts, each
//     labelled (service, your node alias, your room alias, Vox address), and Copy Address copies
//     it whole, canonical.
//
// Mutants for (15), one each: the member rows drop a node's trust in alice unless she trusts it
// (D4: the row reads "not in keyring"); the timeline drops the whereabouts line (D9); the join
// line leaves out who trusts the newcomer (D10); Detach goes back to the chooser of every node
// (D17); a compare that calls any partial entry a mismatch (#624); the keyring card saying a node
// that trusts alice back is still waiting (G2). Each turns (15) red on its own assertion.
// Mutants: the app attaches its node so that it outlives the app (the daemon's explicit attach in
// place of the app's hold), and quitting leaves it attached: (12) goes red. A room with a message
// addressed to this node grouped as quiet (`attention::group`): (3) goes red. An app that never
// reads the menu bar choice again (its delegate not observed): (1) goes red. An inspector
// that lists the members only when the room is opened: (3) goes red. The timeline drops
// the read-by line, or marks rows read while the window is hidden: (4) goes red. A read batch sent
// for the room on screen when it is flushed, not the room it was drawn in; To: kept across rooms;
// (9) and (9) go red. A copy of the readable address, by ⌘⇧C or the
// services view's Copy: (9) goes red. Remove untrusts at once, saying nothing
// first: (5) goes red. The note is posted as a message
// of its own: (6) goes red.
// A notification that carries the message's text: (8) goes red. ⌘J bound to the next room in
// the sidebar's order: (9) goes red. The decision record oldest first: (10) goes red.
// Untrust that leaves a member's live sessions running: (11) goes red. An app that counts
// nothing from before it opened (no seeding from VoxClient.unread): (13) goes red. ↑/↓ that do not
// move the selection, or Space and Return that open nothing: (14) goes red.
// A quote that goes nowhere (MessageRow's quote button not calling `jump`): (4) goes red.
// To: that ticks the member for one of its Sessions (the Session's tick inserting the member's
// fingerprint alone): (4) goes red.
// An @alias picked that is only written, not addressed: (4) goes red. The FFI's names() without
// the clash suffix: (5) goes red.

// Every check on the window proves its own query first (ADR-018: a red names its side): Vox is in
// front and XCTest reads words in what it shows, else the red is APPARATUS; then a red is PRODUCT
// and quotes what the app showed. "Missing" is PRODUCT only once every container the app can show
// (windows with their sheets and popovers, dialogs such as the file panel, menus) was searched;
// found only outside them (the Touch Bar), it is APPARATUS. A case stops at its first red. A SwiftUI Text's words are its accessibility value, not its
// label: the read-by line, the keyring's effect sentences and a message's text are read there.

import XCTest

/// The app under proof's bundle identifier: app-proofs.sh builds it as "Vox Proof", never as
/// us.vox.app, so the person's own Vox, which may be installed and running, is never the one the
/// proof launches, watches or drives (#571).
let proofAppID = "us.vox.app.proof"

/// A red that is the product's, thrown where an assertion cannot be: what `vox` did, quoted.
struct Product: Error, CustomStringConvertible {
    let why: String
    init(_ why: String) { self.why = why }
    var description: String { "PRODUCT: \(why)" }
}

/// A timeline row saying `sentence` ("bob: COPY ONE"): its author first, then what it says, with
/// whatever the row adds around them (", to you", ", at 12:05", ", read by …"), as VoiceOver reads it.
func rowSays(_ sentence: String) -> NSPredicate {
    guard let colon = sentence.range(of: ": ") else { return NSPredicate(format: "label == %@", sentence) }
    let author = String(sentence[..<colon.lowerBound]), words = String(sentence[colon.lowerBound...])
    return NSPredicate(format: "label == %@ OR (label BEGINSWITH %@ AND label CONTAINS %@)",
                       sentence, author + ", ", words)
}

/// What an element says to VoiceOver: its label, else its value (a Text's words), else its title
/// (a menu button's).
func shown(_ element: XCUIElement) -> String {
    if !element.label.isEmpty { return element.label }
    if let value = element.value as? String, !value.isEmpty { return value }
    // A menu button's words are its title.
    return element.title
}

/// What is typed in a text field: its value, never its label (a composer's label names it, as
/// "Message to the room", whatever is typed). Empty when nothing is.
func typed(_ field: XCUIElement) -> String {
    (field.value as? String) ?? ""
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

    /// Something of the same kind that is always shown while the main window is (the status
    /// bar by identifier and by its words; Quit Vox among the menus): what the same search must
    /// find before anything it does not find is called missing.
    var sibling: Key {
        switch self {
        case .id, .idPrefix, .child: return .id("status")
        case .showing: return .showing("node ")
        case .menuItem: return .menuItem("Quit Vox")
        }
    }

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

/// What the daemon holds that an element is drawn from (a member, a keyring entry, a room), read
/// when the element is not shown: held, the app failed to show it (PRODUCT); not held, the staging
/// was not achieved (APPARATUS). Either way the red quotes what the daemon said.
struct Premise {
    let what: String
    let read: () -> (holds: Bool, said: String)
    init(_ what: String, _ read: @escaping () -> (holds: Bool, said: String)) {
        self.what = what
        self.read = read
    }
}

final class FirstRunProof: XCTestCase {
    private var daemon: Started?
    /// Dora's daemon, a peer whose clock is behind (step 3d): apparatus, stopped with the case.
    private var peer: Started?
    /// Runs what the runner's sandbox forbids: every `vox`, the files, the echo services.
    private var stager: Stager!
    /// When another app took the foreground from a running Vox, and which: a display change or a
    /// person at the Mac, never the walkthrough (it quits Vox, and Vox's own panels are its own).
    private var lostForeground: [(at: Date, to: String)] = []
    private var watchingForeground: NSObjectProtocol?
    private var watchingVox: NSObjectProtocol?
    /// Set while the proof itself has hidden or quit Vox (⌘H, ⌘Q), until Vox is active again:
    /// what takes the foreground meanwhile was handed it by the proof, not taken.
    private var handedOff = false
    /// The person's clipboard as it was before the case: every item, every type, restored exactly
    /// in tearDown, red or green (app-proofs.sh restores it too, should the runner itself die).
    private var keptPasteboard: [[NSPasteboard.PasteboardType: Data]] = []

    override func setUpWithError() throws {
        // A case stops at its first red: one red, with its side, and no cascade behind it. A
        // combined mutant build (VOX_PROOF_CONTINUE=1) goes on, so each mutated claim says its own
        // red; whoever runs it keeps out any mutant whose red could follow from another's. A
        // case's closing `[proof]` line still prints there, and holds only in a run with no red.
        continueAfterFailure = ProcessInfo.processInfo.environment["VOX_PROOF_CONTINUE"] == "1"
        keptPasteboard = (NSPasteboard.general.pasteboardItems ?? []).map { item in
            Dictionary(uniqueKeysWithValues: item.types.compactMap { t in item.data(forType: t).map { (t, $0) } })
        }
        stager = try Stager.fromEnvironment()
        let workspace = NSWorkspace.shared
        watchingVox = workspace.notificationCenter.addObserver(
            forName: NSWorkspace.didActivateApplicationNotification, object: nil, queue: .main
        ) { [weak self] note in
            if (note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication)?
                .bundleIdentifier == proofAppID { self?.handedOff = false }
        }
        watchingForeground = workspace.notificationCenter.addObserver(
            forName: NSWorkspace.didActivateApplicationNotification, object: nil, queue: .main
        ) { [weak self] note in
            guard self?.handedOff == false,
                  let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
                  app.bundleIdentifier != proofAppID,
                  app.processIdentifier != ProcessInfo.processInfo.processIdentifier,
                  // Vox's own file panel and previews run in system services of its own.
                  !(app.bundleIdentifier ?? "").hasPrefix("com.apple.appkit.xpc."),
                  !(app.bundleIdentifier ?? "").hasPrefix("com.apple.quicklook.") else { return }
            let at = Date()
            let to = app.localizedName ?? app.bundleIdentifier ?? "pid \(app.processIdentifier)"
            // Taken from a Vox that is still running a second later: not Vox quitting.
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                let voxRunning = NSRunningApplication.runningApplications(withBundleIdentifier: proofAppID)
                    .contains { !$0.isTerminated }
                if voxRunning, self?.handedOff == false {
                    self?.lostForeground.append((at, to))
                    print("[foreground] Vox lost the foreground to \(to) (\(app.bundleIdentifier ?? "?"))")
                }
            }
        }
    }

    override func tearDown() {
        // A red stops a case without running its `defer`s (continueAfterFailure is false), so the
        // Vox it started would still run into the next case: quit here each Vox this case started.
        for ui in launched where ui.state != .notRunning { ui.terminate() }
        launched = []
        if let watchingForeground { NSWorkspace.shared.notificationCenter.removeObserver(watchingForeground) }
        if let watchingVox { NSWorkspace.shared.notificationCenter.removeObserver(watchingVox) }
        peer?.terminate()
        daemon?.terminate()
        // The person's clipboard back, exactly as it was.
        let board = NSPasteboard.general
        board.clearContents()
        let items = keptPasteboard.map { kept -> NSPasteboardItem in
            let item = NSPasteboardItem()
            for (type, data) in kept { item.setData(data, forType: type) }
            return item
        }
        if !items.isEmpty { board.writeObjects(items) }
        super.tearDown()
    }

    /// A PRODUCT red within 30 s of another app taking the foreground from a running Vox is the
    /// environment's, not the product's: a popover or a sheet closes when Vox loses the
    /// foreground, and a click or key in that time went elsewhere. It is recorded as APPARATUS,
    /// naming when and to what, with the read it would have been.
    override func record(_ issue: XCTIssue) {
        let words = issue.compactDescription
        let product = words.range(of: "PRODUCT")
        let apparatus = words.range(of: "APPARATUS")
        guard let product, apparatus.map({ product.lowerBound < $0.lowerBound }) ?? true else {
            super.record(issue)
            return
        }
        var moved = issue
        if let cover = coveredBy() {
            moved.compactDescription = "APPARATUS: Vox's window is covered by \(cover), so a click or a read on it cannot be the product's; it read: \(words)"
        } else if let lost = lostForeground.last(where: { Date().timeIntervalSince($0.at) < 30 }) {
            let ago = String(format: "%.1f", Date().timeIntervalSince(lost.at))
            moved.compactDescription = "APPARATUS: Vox lost the foreground to \(lost.to) \(ago) s before this red, so what it read cannot be the product's; it read: \(words)"
        } else {
            super.record(issue)
            return
        }
        super.record(moved)
    }

    /// Another app's window in front of Vox's main window and over a quarter of it (a person's
    /// window, a system overlay such as the screenshot tool's), by the window list's owner, layer
    /// and bounds only: never an image. Nil when nothing covers it, or Vox has no window.
    /// A window of the system's over the screen point `at` that takes clicks there and is no part
    /// of Vox: a Notification Center banner or panel, or the screenshot overlay (screencaptureui,
    /// "Screenshot"), which may be the person's own. By the window list's owner, layer and bounds
    /// only, never an image. Its owner, layer and bounds, else nil. Never stopped: waited out.
    private func systemOverlayOver(_ at: CGPoint) -> String? {
        let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements],
                                                 kCGNullWindowID) as? [[String: Any]] ?? []
        for w in windows {
            guard let owner = w[kCGWindowOwnerName as String] as? String,
                  owner == "Notification Center" || owner == "Screenshot",
                  (w[kCGWindowLayer as String] as? Int ?? -1) >= 0,
                  (w[kCGWindowAlpha as String] as? Double ?? 1) > 0,
                  let b = w[kCGWindowBounds as String] as? NSDictionary,
                  let r = CGRect(dictionaryRepresentation: b as CFDictionary), r.contains(at) else { continue }
            return "\(owner), layer \(w[kCGWindowLayer as String] ?? "?"), \(Int(r.width))×\(Int(r.height)) at \(Int(r.minX)),\(Int(r.minY))"
        }
        return nil
    }

    private func coveredBy() -> String? {
        guard let vox = NSRunningApplication.runningApplications(withBundleIdentifier: proofAppID)
            .first(where: { !$0.isTerminated && ($0.bundleURL?.path.contains("/target/xcode/") ?? false) })
        else { return nil }
        let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements],
                                                 kCGNullWindowID) as? [[String: Any]] ?? []
        func bounds(_ w: [String: Any]) -> CGRect {
            guard let b = w[kCGWindowBounds as String] as? NSDictionary else { return .null }
            return CGRect(dictionaryRepresentation: b as CFDictionary) ?? .null
        }
        func pid(_ w: [String: Any]) -> pid_t { (w[kCGWindowOwnerPID as String] as? Int).map(pid_t.init) ?? 0 }
        func layer(_ w: [String: Any]) -> Int { w[kCGWindowLayer as String] as? Int ?? 0 }
        // Front to back: Vox's largest normal window, and what is listed before it.
        guard let mine = windows.enumerated()
            .filter({ pid($0.element) == vox.processIdentifier && layer($0.element) == 0 })
            .max(by: { bounds($0.element).width * bounds($0.element).height
                       < bounds($1.element).width * bounds($1.element).height }) else { return nil }
        let area = bounds(mine.element)
        for w in windows.prefix(mine.offset) {
            let owner = w[kCGWindowOwnerName as String] as? String ?? "?"
            // The menu bar, and the overlay macOS shows while XCTest drives the Mac, which takes
            // no clicks, are always in front.
            // Notification Center is left to tap(), which waits out a banner over what it clicks:
            // its host window spans the screen's side whenever any app's banner shows (the
            // person's own Vox's too), so its being there says nothing about this red.
            guard pid(w) != vox.processIdentifier, owner != "Window Server", owner != "AutomationModeUI",
                  owner != "Notification Center",
                  layer(w) >= 0, (w[kCGWindowAlpha as String] as? Double ?? 1) > 0 else { continue }
            let over = bounds(w).intersection(area)
            if !over.isNull, over.width * over.height > area.width * area.height / 4 {
                return "\(owner) (layer \(layer(w)), \(Int(over.width))×\(Int(over.height)) of Vox's \(Int(area.width))×\(Int(area.height)))"
            }
        }
        return nil
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
        // A data root no daemon can serve (a file where its directory would be), so the daemon
        // Vox starts stops as it starts; the answer Keep Running; and the line the login item's
        // daemon wrote as it ended. (An earlier release's data root is the welcome's to move
        // aside, #576, not this screen's.)
        try stager.write(Data("not a data directory".utf8), to: data)
        try stager.write(Data("keep\n".utf8), to: config + "/app/login-item")
        let reason = "vox daemon will not start: STAGED-REASON is not a Vox data directory this version reads"
        try stager.write(Data("1791262600000 \(reason)\n".utf8),
                         to: home + "/Library/Logs/Vox/login-item.log")

        let ui = voxApp(appPath)
        ui.launchEnvironment = ["VOX_DATA_DIR": data, "VOX_CONFIG_DIR": config, "HOME": home,
                                "VOX_PROXY": "127.0.0.1:0"]
        try launchVox(ui, appPath, env: ui.launchEnvironment, scratch: scratchPath)
        defer { ui.terminate() }
        let said = Key.id("login-item-said")
        let quoted = words(ui, said, timeout: 30,
                           "with Keep Running chosen and its daemon refusing for good, the app must quote the login item's own line",
                           until: { $0.contains("STAGED-REASON is not a Vox data directory this version reads") }) ?? ""
        // P4: the failure is said as what it is, with the daemon's own sentence under Details,
        // copyable, never as the bare sentence alone.
        words(ui, Key.id("start-failure"), timeout: 10,
              "a daemon that stops as it starts must be said plainly, as a background service that cannot start",
              until: { $0 == "Vox can't start its background service" })
        present(ui, Key.id("start-failure-copy"), timeout: 5,
                "the failure's own sentence must be under Details, with Copy")
        tap(ui, Key.id("login-item-off"), "Turn Keep Running Off")
        if !el(ui, said).waitForNonExistence(timeout: 30) {
            XCTFail("PRODUCT: Turn Keep Running Off must leave Keep Running off; the login item's line is still shown: \(shown(el(ui, said)))")
        }
        let answer = stager.run(["/bin/cat", config + "/app/login-item"], env: [:]).out
        XCTAssertEqual(answer.trimmingCharacters(in: .whitespacesAndNewlines), "no",
                       "PRODUCT: Turn Keep Running Off must keep the answer as Not Now; the answer file says \(answer.debugDescription)")
        print("[proof] login item: quoted \"\(quoted)\"; after Turn Keep Running Off the answer is \(answer.debugDescription)")
    }

    /// The first-run question (proposal 2): it says what Keep Running does and where to turn it
    /// off, and Return answers nothing, so only choosing Keep Running adds a login item.
    /// Keep Running is reachable while Vox runs (#571), not only on the screen shown when the
    /// daemon is unreachable: with Keep Running chosen at first run and the node attached (and
    /// kept, M-6), the Vox menu offers Turn Keep Running Off; chosen, the answer is kept as Not
    /// Now, the login item is unregistered, and the node is no longer kept, still attached while
    /// the app acts as it; the menu then offers Keep Running While Logged In, which turns it on.
    ///
    /// **No login item is ever registered here.** A real one runs the bundle's `vox daemon` under
    /// launchd without this run's scratch directories, on the person's real profile. The app under
    /// proof is built by app-proofs.sh with its login item replaced by a stand-in that registers
    /// nothing and records what was asked (`ProofBackgroundItem`, `<config>/app/proof-login-item`); the
    /// case refuses to start unless the executable carries that stand-in, and checks no login item
    /// is loaded at the end. Approving a real login item stays the manual check manual.login_item.
    /// Its own case: the other cases answer Not Now, and the unreachable case never reaches a
    /// running app. Mutations: Keep Running the first run's default button again → red at "Return at
    /// the first-run question must answer nothing"; the Vox menu without the item → red at "Turn
    /// Keep Running Off"; Off without unkeeping the node → red at "must stop keeping node alice";
    /// On without offering to keep the attached node → red at "must offer to keep her".
    /// On, with the node attached and not kept, offers to keep it at once (its passphrase stored
    /// in the Keychain, M-6); declined here, and the app must say what that leaves.
    func testKeepRunningCanBeTurnedOffAndOnWhileVoxRuns() throws {
        let env = ProcessInfo.processInfo.environment
        guard let appPath = env["VOX_PROOF_APP"], let scratchPath = env["VOX_PROOF_SCRATCH"] else {
            throw Apparatus("VOX_PROOF_APP and VOX_PROOF_SCRATCH are set by scripts/app-proofs.sh")
        }
        let exe = appPath + "/Contents/MacOS/Vox"
        guard stager.run(["/usr/bin/grep", "-q", "vox-proof-service-stand-in", exe], env: [:]).status == 0 else {
            throw Apparatus("\(exe) carries no stand-in background items (VOX_PROOF_STUB_SERVICES): it would register a real login item, which runs on the real profile; build it with scripts/app-proofs.sh")
        }
        let vox = URL(fileURLWithPath: appPath).appendingPathComponent("Contents/Helpers/vox").path
        let root = URL(fileURLWithPath: scratchPath).appendingPathComponent("keep-running")
        let data = root.appendingPathComponent("data").path
        let config = root.appendingPathComponent("config").path
        let home = root.appendingPathComponent("home").path
        let voxEnv = ["VOX_DATA_DIR": data, "VOX_CONFIG_DIR": config, "VOX_PROXY": "127.0.0.1:0"]
        // The account's daemon, from the bundle, stopped by this case; node alice kept as Keep
        // Running keeps a node (`--keep`, its passphrase from a scratch file: the Keychain is the
        // person's, never a proof's), and chosen; the first-run question not answered yet.
        daemon = try start(vox, ["daemon", "--listen", "127.0.0.1:0"], env: voxEnv,
                           until: "vox daemon: control socket")
        let pass = root.appendingPathComponent("alice.pass").path
        try stager.write(Data("alice identity\n".utf8), to: pass)
        try staged(vox, ["node", "create", "alice", "--passphrase-file", pass], env: voxEnv)
        try staged(vox, ["node", "attach", "alice", "--keep", "--passphrase-file", pass], env: voxEnv)
        try stager.write(Data("alice\n".utf8), to: config + "/app/node")
        // A file's words, or "" when there is none (its absence is what Return must leave).
        func read(_ name: String) -> String {
            stager.run(["/bin/sh", "-c", "cat \"$0\" 2>/dev/null", config + "/app/" + name], env: [:]).out
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }
        func settle(_ name: String, _ want: (String) -> Bool) -> String {
            var got = read(name)
            let until = Date().addingTimeInterval(10)
            while !want(got) && Date() < until {
                Thread.sleep(forTimeInterval: 0.25)
                got = read(name)
            }
            return got
        }

        let ui = voxApp(appPath)
        ui.launchEnvironment = voxEnv.merging(["HOME": home]) { $1 }
        try launchVox(ui, appPath, env: ui.launchEnvironment, scratch: scratchPath)
        defer { ui.terminate() }
        // First run (proposal 2): the question says what Keep Running does and where to turn it
        // off, and Return answers nothing: neither button is the default, so a login item is
        // added only by choosing Keep Running.
        let why = Key.id("login-item-why")
        words(ui, why, timeout: 30,
              "at first run the app must say what Keep Running does and where to turn it off",
              until: { $0.contains("keeps Vox running in the background while you're logged in, even with the app closed")
                  && $0.contains("You can turn this off in Settings or the Vox menu") })
        ui.typeKey(.return, modifierFlags: [])
        Thread.sleep(forTimeInterval: 3)
        let afterReturn = (read("login-item"), read("proof-login-item"))
        XCTAssertTrue(afterReturn.0.isEmpty && afterReturn.1.isEmpty && el(ui, why).exists,
                      "PRODUCT: Return at the first-run question must answer nothing (no default button): the answer file says \(afterReturn.0.debugDescription), the login item was left \(afterReturn.1.debugDescription), and the question is \(el(ui, why).exists ? "still shown" : "gone")")
        tap(ui, Key.id("login-item-keep"), "Keep Running at first run")
        let answerFirst = settle("login-item") { $0 == "keep" }
        let itemFirst = settle("proof-login-item") { $0.hasPrefix("registered") }
        XCTAssertTrue(answerFirst == "keep" && itemFirst.hasPrefix("registered"),
                      "PRODUCT: Keep Running at first run must keep the answer and register the login item; the answer is \(answerFirst.debugDescription), the login item was left \(itemFirst.debugDescription)")
        present(ui, Key.id("attached"), timeout: 60,
                "with Keep Running chosen and alice kept and attached, the app must open acting as alice")

        // The node as `vox node list` shows it: " (kept)" when the daemon keeps it (M-6).
        func aliceLine() -> String {
            run(vox, ["node", "list"], env: voxEnv).out.split(separator: "\n")
                .map(String.init).first { $0.hasPrefix("alice") } ?? ""
        }
        let keptBefore = aliceLine()
        guard keptBefore.hasSuffix("(kept)") else {
            throw Apparatus("staging not achieved: node alice is not kept before the case; `vox node list` says \(keptBefore.debugDescription)")
        }

        let voxMenu = ui.menuBars.menuBarItems["Vox"]
        guard voxMenu.waitForExistence(timeout: 10) else {
            throw Apparatus("XCTest finds no Vox menu in the menu bar")
        }
        // Off: the answer, the login item and the node (M-6: Not Now keeps no node).
        voxMenu.click()
        tap(ui, Key.menuItem("Turn Keep Running Off"), "Vox > Turn Keep Running Off while Vox runs")
        let answerOff = settle("login-item") { $0 == "no" }
        let itemOff = settle("proof-login-item") { $0.hasPrefix("unregistered") }
        var nodeOff = aliceLine()
        let until = Date().addingTimeInterval(10)
        while nodeOff.hasSuffix("(kept)") && Date() < until {
            Thread.sleep(forTimeInterval: 0.25)
            nodeOff = aliceLine()
        }
        let keepFile = stager.run(["/bin/cat", data + "/.daemon/attach"], env: [:]).out
        XCTAssertTrue(answerOff == "no" && itemOff.hasPrefix("unregistered"),
                      "PRODUCT: Vox > Turn Keep Running Off must keep the answer as Not Now and unregister the login item; the answer is \(answerOff.debugDescription), the login item was left \(itemOff.debugDescription)")
        XCTAssertTrue(nodeOff.contains("attached") && !nodeOff.hasSuffix("(kept)")
                        && !keepFile.split(separator: "\n").contains { $0.hasPrefix("alice\t") },
                      "PRODUCT: Vox > Turn Keep Running Off must stop keeping node alice, as Not Now does (M-6), while the app still acts as her: `vox node list` says \(nodeOff.debugDescription), and the daemon's attach file says \(keepFile.debugDescription)")
        // On again.
        voxMenu.click()
        tap(ui, Key.menuItem("Keep Running While Logged In"),
            "after Turn Keep Running Off, Vox > Keep Running While Logged In")
        let answerOn = settle("login-item") { $0 == "keep" }
        let itemOn = settle("proof-login-item") { $0.hasPrefix("registered") }
        XCTAssertTrue(answerOn == "keep" && itemOn.hasPrefix("registered"),
                      "PRODUCT: Vox > Keep Running While Logged In must keep the answer as Keep Running and register the login item; the answer is \(answerOn.debugDescription), the login item was left \(itemOn.debugDescription)")
        // On with alice attached and not kept: the app offers to keep her at once, with her
        // passphrase in the Keychain, saying what declining leaves. Declined here: the Keychain is
        // the person's, never a proof's (storing is manual.keep_running).
        let offer = Key.id("keep-node-why")
        words(ui, offer, timeout: 10,
              "turning Keep Running on with node alice attached and not kept must offer to keep her, saying what that takes and what declining leaves",
              until: { $0.contains("node alice") && $0.contains("Keychain")
                  && $0.contains("after a restart it needs its passphrase") })
        tap(ui, Key.id("keep-node-not-now"), "Not Now in the offer to keep node alice")
        words(ui, Key.showing("node alice is not kept"), timeout: 10,
              "declining must say plainly that node alice is not kept and needs her passphrase after a restart",
              until: { $0.contains("after a restart Vox asks for its passphrase again") })
        // The alert's own OK, in its sheet or dialog: `ui.buttons["OK"]` also finds the Touch Bar's
        // copy of it, which XCTest cannot click (rooms2's run, APPARATUS).
        let okUntil = Date().addingTimeInterval(5)
        var ok: XCUIElement?
        repeat {
            ok = [ui.sheets, ui.dialogs, ui.windows].lazy
                .map { $0.buttons["OK"].firstMatch }
                .first { $0.exists && $0.isHittable }
            if ok == nil { Thread.sleep(forTimeInterval: 0.25) }
        } while ok == nil && Date() < okUntil
        if let ok { ok.click() } else {
            XCTFail("APPARATUS: XCTest finds no clickable OK in the alert's sheet or dialog (only, perhaps, the Touch Bar's)")
        }
        let notKept = aliceLine()
        XCTAssertTrue(notKept.contains("attached") && !notKept.hasSuffix("(kept)"),
                      "PRODUCT: declining the offer must leave node alice attached and not kept; `vox node list` says \(notKept.debugDescription)")
        voxMenu.click()
        present(ui, Key.menuItem("Turn Keep Running Off"), timeout: 10,
                "with Keep Running on again, the Vox menu must offer Turn Keep Running Off")
        ui.typeKey(.escape, modifierFlags: [])
        // Nothing here registered a real login item: none is loaded for this user.
        let uid = stager.run(["/usr/bin/id", "-u"], env: [:]).out.trimmingCharacters(in: .whitespacesAndNewlines)
        // Only the proof build's own: the person's own Vox (us.vox.app) may have its login item
        // loaded, and launchd names whose it is.
        let loaded = stager.run(["/bin/launchctl", "print", "gui/\(uid)/us.vox.daemon"], env: [:])
        let proofs = loaded.status == 0 && loaded.out.contains("parent bundle identifier = \(proofAppID)\n")
        XCTAssertFalse(proofs,
                       "PRODUCT: Vox Proof's login item is loaded after this case: the app registered a real one past its stand-in (app-proofs.sh refused to start with one loaded): \(loaded.out.prefix(200))")
        print("[proof] keep running: off kept \(answerOff.debugDescription) and left the login item \(itemOff.debugDescription); on kept \(answerOn.debugDescription) and left it \(itemOn.debugDescription)")
    }

    /// Settings (⌘,), v0.4.1, the UX review's proposal 1, alone. Staged by `vox`: node alice kept
    /// (`--keep`), first run answered Keep Running with alice chosen, the menu bar item off, the
    /// stand-in login item registered as approved. Keep Running is turned off and on last: on
    /// again, the app offers to keep alice, which Escape leaves.
    /// - **menu bar**: Settings' "Show Vox in the menu bar" turns the item on and off again, kept
    ///   in `<config>/app/menubar`. Mutation: the toggle's setter dropped → red at "on".
    /// - **keep running**: Settings' switch turns Keep Running off and on, the answer and the
    ///   stand-in login item following, and the Vox menu agrees (one implementation, #571).
    ///   Mutation: the switch's setter dropped → red at "no".
    /// - **text size**: Settings' Text size sets the app's size (the defaults key View > Bigger
    ///   uses) and sets it back. Mutation: setTextSize a no-op → red at 1.3.
    ///
    /// **No login item is registered**: the same stand-in as testKeepRunning…; the case refuses an
    /// executable without it.
    func testSettingsKeepRunningMenuBarAndTextSize() throws {
        let env = ProcessInfo.processInfo.environment
        guard let appPath = env["VOX_PROOF_APP"], let scratchPath = env["VOX_PROOF_SCRATCH"] else {
            throw Apparatus("VOX_PROOF_APP and VOX_PROOF_SCRATCH are set by scripts/app-proofs.sh")
        }
        let exe = appPath + "/Contents/MacOS/Vox"
        guard stager.run(["/usr/bin/grep", "-q", "vox-proof-service-stand-in", exe], env: [:]).status == 0 else {
            throw Apparatus("\(exe) carries no stand-in background items (VOX_PROOF_STUB_SERVICES): it would register a real login item, which runs on the real profile; build it with scripts/app-proofs.sh")
        }
        let vox = URL(fileURLWithPath: appPath).appendingPathComponent("Contents/Helpers/vox").path
        let root = URL(fileURLWithPath: scratchPath).appendingPathComponent("settings")
        let data = root.appendingPathComponent("data").path
        let config = root.appendingPathComponent("config").path
        let home = root.appendingPathComponent("home").path
        let voxEnv = ["VOX_DATA_DIR": data, "VOX_CONFIG_DIR": config, "VOX_PROXY": "127.0.0.1:0"]
        daemon = try start(vox, ["daemon", "--listen", "127.0.0.1:0"], env: voxEnv,
                           until: "vox daemon: control socket")
        // Alice kept as Keep Running keeps a node (`--keep`, its passphrase from a scratch file: the
        // Keychain is the person's, never a proof's), so the app opens acting as her.
        let pass = root.appendingPathComponent("alice.pass").path
        try stager.write(Data("alice identity\n".utf8), to: pass)
        try staged(vox, ["node", "create", "alice", "--passphrase-file", pass], env: voxEnv)
        try staged(vox, ["node", "attach", "alice", "--keep", "--passphrase-file", pass], env: voxEnv)
        try stager.write(Data("keep\n".utf8), to: config + "/app/login-item")
        try stager.write(Data("alice\n".utf8), to: config + "/app/node")
        try stager.write(Data("off\n".utf8), to: config + "/app/menubar")
        try stager.write(Data("registered vox-proof-service-stand-in\n".utf8),
                         to: config + "/app/proof-login-item")
        func read(_ name: String) -> String {
            stager.run(["/bin/cat", config + "/app/" + name], env: [:]).out
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }
        func settle(_ name: String, _ want: (String) -> Bool) -> String {
            var got = read(name)
            let until = Date().addingTimeInterval(10)
            while !want(got) && Date() < until {
                Thread.sleep(forTimeInterval: 0.25)
                got = read(name)
            }
            return got
        }
        /// The app's text size as View > Bigger keeps it, in its defaults (read, never written):
        /// the domain of the bundle under proof, whatever its identifier.
        let domain = stager.run(["/usr/bin/defaults", "read", appPath + "/Contents/Info", "CFBundleIdentifier"],
                                env: [:]).out.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !domain.isEmpty else { throw Apparatus("\(appPath) has no CFBundleIdentifier to read its text size under") }
        func textScale() -> String {
            stager.run(["/usr/bin/defaults", "read", domain, "textScale"], env: [:]).out
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }

        let ui = voxApp(appPath)
        ui.launchEnvironment = voxEnv.merging(["HOME": home]) { $1 }
        try launchVox(ui, appPath, env: ui.launchEnvironment, scratch: scratchPath)
        defer { ui.terminate() }
        present(ui, Key.id("attached"), timeout: 60,
                "with Keep Running chosen and alice needing no passphrase, the app must open attached as alice")

        // Settings, by ⌘, as a person opens it.
        ui.typeKey(",", modifierFlags: .command)
        present(ui, Key.id("settings-menu-bar"), timeout: 10, "⌘, must open Settings")

        // menu bar: on, then off again.
        tap(ui, Key.id("settings-menu-bar"), "Settings > Show Vox in the menu bar")
        let barOn = settle("menubar") { $0 == "on" }
        tap(ui, Key.id("settings-menu-bar"), "Settings > Show Vox in the menu bar, again")
        let barOff = settle("menubar") { $0 == "off" }
        XCTAssertTrue(barOn == "on" && barOff == "off",
                      "PRODUCT: Settings > Show Vox in the menu bar must turn the item on and off; the choice was kept as \(barOn.debugDescription), then \(barOff.debugDescription)")

        // text size: 130%, then back to Actual Size.
        let before = textScale()
        tap(ui, Key.id("settings-text-size"), "Settings > Text size")
        tap(ui, Key.menuItem("130%"), "Settings > Text size > 130%")
        var scaled = textScale()
        let until = Date().addingTimeInterval(10)
        while scaled != "1.3" && Date() < until { Thread.sleep(forTimeInterval: 0.25); scaled = textScale() }
        // The window is drawn again at the new size, so the control is looked up afresh.
        tap(ui, Key.id("settings-text-size"), "Settings > Text size, again")
        tap(ui, Key.menuItem("100% (Actual Size)"), "Settings > Text size > 100% (Actual Size)")
        var back = textScale()
        let until2 = Date().addingTimeInterval(10)
        while back != "1" && Date() < until2 { Thread.sleep(forTimeInterval: 0.25); back = textScale() }
        XCTAssertTrue(scaled == "1.3" && back == "1",
                      "PRODUCT: Settings > Text size must set the app's text size, as View > Bigger keeps it; 130% left it \(scaled.debugDescription) and Actual Size \(back.debugDescription) (it was \(before.debugDescription) before)")

        // keep running: off from Settings, the Vox menu agreeing; then on again.
        tap(ui, Key.id("settings-keep-running"), "Settings > Keep Vox running while you're logged in")
        let answerOff = settle("login-item") { $0 == "no" }
        let itemOff = settle("proof-login-item") { $0.hasPrefix("unregistered") }
        XCTAssertTrue(answerOff == "no" && itemOff.hasPrefix("unregistered"),
                      "PRODUCT: turning Keep Running off in Settings must keep the answer as Not Now and unregister the login item; the answer is \(answerOff.debugDescription), the login item was left \(itemOff.debugDescription)")
        let voxMenu = ui.menuBars.menuBarItems["Vox"]
        guard voxMenu.waitForExistence(timeout: 10) else {
            throw Apparatus("XCTest finds no Vox menu in the menu bar")
        }
        voxMenu.click()
        present(ui, Key.menuItem("Keep Running While Logged In"), timeout: 10,
                "with Keep Running turned off in Settings, the Vox menu must offer Keep Running While Logged In")
        ui.typeKey(.escape, modifierFlags: [])
        tap(ui, Key.id("settings-keep-running"), "Settings > Keep Vox running while you're logged in, again")
        let answerOn = settle("login-item") { $0 == "keep" }
        let itemOn = settle("proof-login-item") { $0.hasPrefix("registered") }
        XCTAssertTrue(answerOn == "keep" && itemOn.hasPrefix("registered"),
                      "PRODUCT: turning Keep Running on in Settings must keep the answer as Keep Running and register the login item; the answer is \(answerOn.debugDescription), the login item was left \(itemOn.debugDescription)")

        ui.typeKey(.escape, modifierFlags: [])
        let uid = stager.run(["/usr/bin/id", "-u"], env: [:]).out.trimmingCharacters(in: .whitespacesAndNewlines)
        // The person's own Vox may keep its login item loaded (us.vox.app's); only one whose parent
        // bundle is the proof build would mean the app registered a real one past its stand-in.
        let loaded = stager.run(["/bin/launchctl", "print", "gui/\(uid)/us.vox.daemon"], env: [:])
        let proofs = loaded.status == 0 && loaded.out.contains("parent bundle identifier = \(proofAppID)\n")
        XCTAssertFalse(proofs,
                       "PRODUCT: the proof build's own login item is loaded after this case: the app registered a real one past its stand-in")
        print("[proof] settings: menu bar \(barOn.debugDescription) then \(barOff.debugDescription); keep running \(answerOff.debugDescription)/\(itemOff.debugDescription) then \(answerOn.debugDescription)/\(itemOn.debugDescription); text size \(scaled.debugDescription) then \(back.debugDescription)")
    }

    /// View > Bigger (⌘+) scales the conversation only (the decider, v0.4.1; ADR-028 L-1a, L-1b),
    /// alone. Staged by `vox`: alice attached, with one room holding two messages of hers, chosen
    /// before. Two ⌘+ grow the message's text and the space between the two messages with it; a
    /// sidebar row and the inspector's MEMBERS line keep their size. ⌘0 puts the size back.
    /// Mutations: the conversation's scale applied to the whole window → red at "unchanged";
    /// voxPadding and the timeline's spacing left at Actual Size → red at "spacing".
    func testBiggerScalesTheConversationOnly() throws {
        let env = ProcessInfo.processInfo.environment
        guard let appPath = env["VOX_PROOF_APP"], let scratchPath = env["VOX_PROOF_SCRATCH"] else {
            throw Apparatus("VOX_PROOF_APP and VOX_PROOF_SCRATCH are set by scripts/app-proofs.sh")
        }
        let vox = URL(fileURLWithPath: appPath).appendingPathComponent("Contents/Helpers/vox").path
        let root = URL(fileURLWithPath: scratchPath).appendingPathComponent("bigger")
        let data = root.appendingPathComponent("data").path
        let config = root.appendingPathComponent("config").path
        let home = root.appendingPathComponent("home").path
        let voxEnv = ["VOX_DATA_DIR": data, "VOX_CONFIG_DIR": config, "VOX_PROXY": "127.0.0.1:0"]
        daemon = try start(vox, ["daemon", "--listen", "127.0.0.1:0"], env: voxEnv,
                           until: "vox daemon: control socket")
        let idPass = root.appendingPathComponent("alice.pass").path
        let roomPass = root.appendingPathComponent("room.pass").path
        try stager.write(Data("alice identity\n".utf8), to: idPass)
        try stager.write(Data("bigger room\n".utf8), to: roomPass)
        try staged(vox, ["node", "create", "alice"],
                   env: voxEnv.merging(["VOX_IDENTITY_PASSPHRASE": "alice identity"]) { $1 })
        try staged(vox, ["node", "attach", "alice", "--passphrase-file", idPass], env: voxEnv)
        try staged(vox, ["room", "create", "--node", "alice", "--passphrase-file", roomPass,
                         "--name", "talk"], env: voxEnv)
        let room = try line(staged(vox, ["room", "list", "--node", "alice"], env: voxEnv)) {
            $0.contains(" talk")
        }.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? ""
        try staged(vox, ["room", "post", "--node", "alice", room, "MEASURE-THIS-MESSAGE"], env: voxEnv)
        try staged(vox, ["room", "post", "--node", "alice", room, "AND-THE-NEXT-ONE"], env: voxEnv)
        try stager.write(Data("no\n".utf8), to: config + "/app/login-item")
        try stager.write(Data("alice\n".utf8), to: config + "/app/node")

        let ui = voxApp(appPath)
        ui.launchEnvironment = voxEnv.merging(["HOME": home]) { $1 }
        try launchVox(ui, appPath, env: ui.launchEnvironment, scratch: scratchPath)
        defer { ui.terminate() }
        present(ui, Key.id("attached"), timeout: 60, "the app must open attached as alice")
        ui.typeKey("0", modifierFlags: .command)
        tap(ui, Key.id("room-talk"), "the room talk in the sidebar")
        present(ui, Key.showing("MEASURE-THIS-MESSAGE"), timeout: 20, "alice's message must show in the timeline")

        func height(_ key: Key) -> CGFloat {
            guard let e = locate(ui, key) else { return -1 }
            return e.frame.height
        }
        let message = Key.showing("MEASURE-THIS-MESSAGE")
        let next = Key.showing("AND-THE-NEXT-ONE")
        let sidebarRow = Key.id("room-talk")
        let members = Key.showing("MEMBERS")
        // From one message's text to the next one's: the rows' padding, the timeline's spacing and
        // the next row's author line, all of which are the conversation's (L-1a).
        func gap() -> CGFloat {
            guard let a = locate(ui, message), let b = locate(ui, next) else { return -1 }
            return b.frame.minY - a.frame.maxY
        }
        present(ui, next, timeout: 20, "alice's second message must show in the timeline")
        Thread.sleep(forTimeInterval: 1)
        let m0 = height(message), s0 = height(sidebarRow), i0 = height(members), g0 = gap()
        ui.typeKey("+", modifierFlags: .command)
        ui.typeKey("+", modifierFlags: .command)
        Thread.sleep(forTimeInterval: 2)
        present(ui, message, timeout: 10, "after View > Bigger, the message must still show")
        let m1 = height(message), s1 = height(sidebarRow), i1 = height(members), g1 = gap()
        ui.typeKey("0", modifierFlags: .command)
        XCTAssertTrue(m0 > 0 && m1 > m0 * 1.15,
                      "PRODUCT: View > Bigger twice must grow the conversation's text; the message was \(m0) high and is \(m1)")
        XCTAssertTrue(s0 > 0 && i0 > 0 && abs(s1 - s0) <= 1 && abs(i1 - i0) <= 1,
                      "PRODUCT: View > Bigger must leave the sidebar and the inspector unchanged; a sidebar row went from \(s0) to \(s1), the inspector's MEMBERS line from \(i0) to \(i1)")
        // Two steps are 1.3 times Actual Size: spacing taken at the text size grows the gap by
        // about that; spacing left at Actual Size grows it by only the author line's share.
        XCTAssertTrue(g0 > 0 && g1 >= g0 * 1.24,
                      "PRODUCT: View > Bigger twice must grow the conversation's spacing with its text (L-1a); the gap between two messages was \(g0) and is \(g1)")
        print("[proof] bigger: message \(m0) → \(m1); gap between messages \(g0) → \(g1); sidebar row \(s0) → \(s1); inspector line \(i0) → \(i1)")
    }

    /// The look as a person sees it (ADR-028 L-2, L-6, L-7; A9; P5), alone. Staged by `vox`:
    /// alice and bob, alice attached and trusting bob with read, with one room holding a message
    /// of hers, chosen before. Read from the window's own pixels where a person sees them: the
    /// sidebar on bg.panel, the timeline on bg.base, the inspector and the status bar on
    /// bg.raised, and between the timeline and the inspector a line of line.hair. Room > Rename's
    /// sheet is on bg.panel, its title SF Pro semibold (one line of about 24 points, not Inter
    /// Display's 34). Return in Room > Retention sets nothing: the sheet stays. On bob's keyring
    /// row, "Also let bob drive my Sessions…" opens its confirm sheet, and Return there cancels:
    /// the sheet goes and bob still has read. Colours are compared in sRGB, within 4 of 255 per
    /// channel. Mutations: the inspector without bg.raised → red at "inspector"; the hairline the
    /// system's divider again → red at "line.hair"; a sheet title in Inter Display → red at
    /// "title"; Set the default again → red at "Retention"; Give Drive the default → red at
    /// "drive". Then Node > Detach: the chooser lists alice, detached, with her fingerprint and
    /// "Everything you post, trust and share will be as alice."; `vox node list` shows the same
    /// fingerprint; and with bob's vault copied over hers, it shows none (P8). Before that, the
    /// sidebar opens with "node alice, attached" and ends with ON THIS MACHINE listing bob as
    /// attached, below Services (G5; mutation: the footer gone → red at "foot"). Mutations: the
    /// fingerprint file not written → red at "chooser must show"; its vault hash not checked → red
    /// at "stale".
    func testTheLookIsTheTokensAndReturnNeverGivesWhatItShouldNot() throws {
        let env = ProcessInfo.processInfo.environment
        guard let appPath = env["VOX_PROOF_APP"], let scratchPath = env["VOX_PROOF_SCRATCH"] else {
            throw Apparatus("VOX_PROOF_APP and VOX_PROOF_SCRATCH are set by scripts/app-proofs.sh")
        }
        let vox = URL(fileURLWithPath: appPath).appendingPathComponent("Contents/Helpers/vox").path
        let root = URL(fileURLWithPath: scratchPath).appendingPathComponent("look")
        let data = root.appendingPathComponent("data").path
        let config = root.appendingPathComponent("config").path
        let home = root.appendingPathComponent("home").path
        let voxEnv = ["VOX_DATA_DIR": data, "VOX_CONFIG_DIR": config, "VOX_PROXY": "127.0.0.1:0"]
        let pass = { (name: String) in root.appendingPathComponent("\(name).pass").path }
        daemon = try start(vox, ["daemon", "--listen", "127.0.0.1:0"], env: voxEnv,
                           until: "vox daemon: control socket")
        try stager.write(Data("alice identity\n".utf8), to: pass("alice"))
        try stager.write(Data("bob identity\n".utf8), to: pass("bob"))
        try stager.write(Data("look room\n".utf8), to: pass("room"))
        for (name, words) in [("alice", "alice identity"), ("bob", "bob identity")] {
            try staged(vox, ["node", "create", name],
                       env: voxEnv.merging(["VOX_IDENTITY_PASSPHRASE": words]) { $1 })
        }
        try staged(vox, ["node", "attach", "alice", "--passphrase-file", pass("alice")], env: voxEnv)
        try staged(vox, ["node", "attach", "bob", "--passphrase-file", pass("bob")], env: voxEnv)
        let bobFp = try line(staged(vox, ["id", "--node", "bob"], env: voxEnv)) { $0.count == 52 }
        let aliceFp = try line(staged(vox, ["id", "--node", "alice"], env: voxEnv)) { $0.count == 52 }
        try staged(vox, ["trust", "add", "--node", "alice", bobFp, "--name", "bob",
                         "--identity-passphrase-file", pass("alice")], env: voxEnv)
        try staged(vox, ["room", "create", "--node", "alice", "--passphrase-file", pass("room"),
                         "--name", "talk"], env: voxEnv)
        let room = try line(staged(vox, ["room", "list", "--node", "alice"], env: voxEnv)) {
            $0.contains(" talk")
        }.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? ""
        try staged(vox, ["room", "post", "--node", "alice", room, "LOOK-AT-THIS"], env: voxEnv)
        try stager.write(Data("no\n".utf8), to: config + "/app/login-item")
        try stager.write(Data("alice\n".utf8), to: config + "/app/node")

        let ui = voxApp(appPath)
        ui.launchEnvironment = voxEnv.merging(["HOME": home]) { $1 }
        try launchVox(ui, appPath, env: ui.launchEnvironment, scratch: scratchPath)
        defer { ui.terminate() }
        present(ui, Key.id("attached"), timeout: 60, "the app must open attached as alice")
        ui.typeKey("0", modifierFlags: .command)
        tap(ui, Key.id("room-talk"), "the room talk in the sidebar")
        present(ui, Key.showing("LOOK-AT-THIS"), timeout: 20, "alice's message must show in the timeline")
        Thread.sleep(forTimeInterval: 1.5)

        // The window's pixels, in sRGB, at a point in screen coordinates.
        let window = ui.windows.firstMatch
        guard let status = locate(ui, Key.id("status")), let members = locate(ui, Key.showing("MEMBERS")),
              let message = locate(ui, Key.showing("LOOK-AT-THIS")) else {
            throw Apparatus("the status bar, MEMBERS or the message is not readable to XCTest, so no point can be placed")
        }
        let frame = window.frame
        let shot = window.screenshot().image
        guard let cg = shot.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
            throw Apparatus("XCTest's screenshot of the window has no bitmap")
        }
        let bitmap = NSBitmapImageRep(cgImage: cg)
        let perPoint = CGFloat(cg.width) / frame.width
        func rgb(_ p: CGPoint) -> (Int, Int, Int)? {
            let x = Int((p.x - frame.minX) * perPoint), y = Int((p.y - frame.minY) * perPoint)
            guard x >= 0, y >= 0, x < cg.width, y < cg.height,
                  let c = bitmap.colorAt(x: x, y: y)?.usingColorSpace(.sRGB) else { return nil }
            return (Int((c.redComponent * 255).rounded()), Int((c.greenComponent * 255).rounded()),
                    Int((c.blueComponent * 255).rounded()))
        }
        func hex(_ c: (Int, Int, Int)?) -> String {
            guard let c else { return "nothing (off the window)" }
            return String(format: "#%02x%02x%02x", c.0, c.1, c.2)
        }
        func near(_ c: (Int, Int, Int)?, _ want: String) -> Bool {
            guard let c, let v = Int(want.dropFirst(), radix: 16) else { return false }
            return abs(c.0 - (v >> 16 & 0xff)) <= 4 && abs(c.1 - (v >> 8 & 0xff)) <= 4
                && abs(c.2 - (v & 0xff)) <= 4
        }
        let above = status.frame.minY - 24
        let points: [(String, CGPoint, String)] = [
            // Inside the sidebar's left margin: the foot's words (ON THIS MACHINE) start 16 in.
            ("the sidebar", CGPoint(x: frame.minX + 6, y: above), "#16171a"),
            ("the timeline", CGPoint(x: message.frame.minX + 40, y: message.frame.maxY + 40), "#0c0d0f"),
            ("the inspector", CGPoint(x: frame.maxX - 16, y: above), "#131417"),
            ("the status bar", CGPoint(x: status.frame.minX + 3, y: status.frame.midY), "#131417"),
        ]
        var read: [String] = []
        for (place, point, want) in points {
            let got = rgb(point)
            read.append("\(place) \(hex(got))")
            XCTAssertTrue(near(got, want),
                          "PRODUCT: \(place) must be drawn in \(want) (L-6); at \(point) it is \(hex(got))")
        }
        // The line between the timeline and the inspector: line.hair somewhere in the 40 points
        // left of the inspector's MEMBERS, at the height of the timeline's middle.
        let y = (message.frame.maxY + status.frame.minY) / 2
        var hair: CGFloat?
        var x = members.frame.minX - 40
        while x < members.frame.minX && hair == nil {
            if near(rgb(CGPoint(x: x, y: y)), "#303137") { hair = x }
            x += 0.5
        }
        XCTAssertNotNil(hair, "PRODUCT: the timeline and the inspector must be separated by line.hair #303137 (L-2, L-6); no pixel of it in the 40 points left of the inspector, at height \(y)")
        read.append("line.hair at x \(hair.map { "\($0)" } ?? "none")")

        // Room > Rename…: a sheet on bg.panel, its title SF Pro semibold.
        ui.menuBars.menuBarItems["Room"].click()
        tap(ui, Key.menuItem("Rename…"), "Room > Rename…")
        let title = Key.showing("Rename the room")
        present(ui, title, timeout: 10, "Room > Rename… must open its sheet")
        Thread.sleep(forTimeInterval: 1)
        let titleHeight = locate(ui, title)?.frame.height ?? -1
        XCTAssertTrue(titleHeight > 0 && titleHeight <= 28,
                      "PRODUCT: a sheet's title must be SF Pro semibold, one line of about 24 points (L-7); \"Rename the room\" is \(titleHeight) high")
        if let sheet = ui.sheets.firstMatch.exists ? ui.sheets.firstMatch : nil,
           let t = locate(ui, title) {
            let shotSheet = window.screenshot().image
            if let cgs = shotSheet.cgImage(forProposedRect: nil, context: nil, hints: nil) {
                let b = NSBitmapImageRep(cgImage: cgs)
                let p = CGPoint(x: t.frame.minX - 12, y: t.frame.minY - 12)
                let px = Int((p.x - frame.minX) * perPoint), py = Int((p.y - frame.minY) * perPoint)
                let c = b.colorAt(x: px, y: py)?.usingColorSpace(.sRGB)
                let got = c.map { (Int(($0.redComponent * 255).rounded()), Int(($0.greenComponent * 255).rounded()),
                                   Int(($0.blueComponent * 255).rounded())) }
                read.append("sheet \(hex(got))")
                XCTAssertTrue(near(got, "#16171a"),
                              "PRODUCT: a sheet must be drawn in bg.panel #16171a (L-6); inside Rename's, at \(p), it is \(hex(got)) (sheet at \(sheet.frame))")
            }
        } else {
            XCTFail("APPARATUS: Rename's title shows, but XCTest finds no sheet to read")
        }
        ui.typeKey(XCUIKeyboardKey.escape.rawValue, modifierFlags: [])
        missingWithin(ui, title, 5, "Escape must close Rename's sheet")

        // Room > Retention…: Return sets nothing (A9: a retention that deletes has no default).
        ui.menuBars.menuBarItems["Room"].click()
        tap(ui, Key.menuItem("Retention…"), "Room > Retention…")
        present(ui, Key.id("retention-effect"), timeout: 10, "Room > Retention… must open its sheet")
        ui.typeKey(XCUIKeyboardKey.return.rawValue, modifierFlags: [])
        Thread.sleep(forTimeInterval: 2)
        XCTAssertNotNil(locate(ui, Key.id("retention-effect")),
                        "PRODUCT: Return in Retention must set nothing (A9); the sheet closed, as if Set was pressed")
        ui.typeKey(XCUIKeyboardKey.escape.rawValue, modifierFlags: [])
        missingWithin(ui, Key.id("retention-effect"), 5, "Escape must close Retention's sheet")

        // The keyring: drive through its own sheet, whose Return is Cancel (P5).
        ui.typeKey("k", modifierFlags: [.command, .shift])
        tap(ui, Key.id("keyring-give-drive-bob"), "\"Also let bob drive my Sessions…\" on bob's row")
        present(ui, Key.id("keyring-drive-effect"), timeout: 10, "the drive confirm sheet must open")
        ui.typeKey(XCUIKeyboardKey.return.rawValue, modifierFlags: [])
        missingWithin(ui, Key.id("keyring-drive-effect"), 5,
                      "Return in the drive sheet must be Cancel, closing it (P5)")
        let capability = words(ui, Key.id("keyring-capability-bob"), timeout: 10,
                               "bob's row must say what it grants") ?? ""
        XCTAssertEqual(capability, "read",
                       "PRODUCT: Return in the drive sheet must give nothing (P5); bob's row says \(capability.debugDescription)")

        // G5: the sidebar opens with who you are, and ends with this Mac's nodes and their state.
        words(ui, Key.id("attached"), timeout: 10, "the sidebar must open with the acting node (G5)",
              until: { $0 == "node alice, attached" })
        words(ui, Key.id("node-bob"), timeout: 10, "the sidebar's foot must list bob and his state (G5)",
              until: { $0 == "bob attached" })
        let foot = locate(ui, Key.id("on-this-machine"))?.frame ?? .null
        let lastAbove = locate(ui, Key.id("services"))?.frame ?? .null
        XCTAssertTrue(!foot.isNull && !lastAbove.isNull && foot.minY > lastAbove.maxY,
                      "PRODUCT: \"ON THIS MACHINE\" must be at the sidebar's foot, below Services (G5); it is at \(foot), Services at \(lastAbove)")

        // P8: Node > Detach, and the chooser lists alice, now detached, with her fingerprint (from
        // her fingerprint file) and what choosing her means; `vox node list` shows it too. Then a
        // vault copied over hers, as a restore would: her fingerprint is not known, never stale.
        ui.menuBars.menuBarItems["Node"].click()
        tap(ui, Key.menuItem("Detach"), "Node > Detach")
        let plain = { (s: String) in s.lowercased().filter { $0.isLetter || $0.isNumber } }
        let shown = words(ui, Key.id("node-fingerprint-alice"), timeout: 30,
                          "after Detach, the chooser must list alice with her fingerprint (P8)") ?? ""
        XCTAssertEqual(plain(shown), plain(aliceFp),
                       "PRODUCT: the chooser must show detached alice's fingerprint, \(aliceFp) (P8); it shows \(shown.debugDescription)")
        words(ui, Key.id("node-acting-as-alice"), timeout: 5, "the chooser must say what choosing alice means (P8)",
              until: { $0 == "Everything you post, trust and share will be as alice." })
        let listed = run(vox, ["node", "list"], env: voxEnv).out
        let aliceLine = nodeLine(listed, "alice") ?? ""
        XCTAssertTrue(aliceLine.contains(" detached ") && plain(aliceLine).contains(plain(aliceFp)),
                      "PRODUCT: `vox node list` must show detached alice with her fingerprint; it says \(aliceLine.debugDescription)")
        guard stager.run(["/bin/cp", data + "/nodes/bob/vault.cbor", data + "/nodes/alice/vault.cbor"],
                         env: [:]).status == 0 else {
            throw Apparatus("staging not achieved: bob's vault.cbor could not be copied over alice's")
        }
        let restored = nodeLine(run(vox, ["node", "list"], env: voxEnv).out, "alice") ?? ""
        XCTAssertFalse(plain(restored).contains(plain(aliceFp)) || plain(restored).contains(plain(bobFp)),
                       "PRODUCT: with another vault in alice's place, `vox node list` must not show a fingerprint for her, stale or otherwise; it says \(restored.debugDescription)")
        print("[proof] look: \(read.joined(separator: "; ")); title \(titleHeight) high; retention kept by Return; bob \(capability.debugDescription) after Return; chooser shows alice \(shown.debugDescription); node list \(aliceLine.debugDescription), then with bob's vault \(restored.debugDescription)")
    }

    /// `key` gone within `timeout`: PRODUCT naming what still shows it.
    private func missingWithin(_ ui: XCUIApplication, _ key: Key, _ timeout: TimeInterval, _ product: String,
                               file: StaticString = #filePath, line: UInt = #line) {
        let end = Date().addingTimeInterval(timeout)
        while locate(ui, key) != nil && Date() < end { Thread.sleep(forTimeInterval: 0.25) }
        if locate(ui, key) != nil {
            XCTFail("PRODUCT: \(product); \(key) still shows", file: file, line: line)
        }
    }

    /// The window's side columns (v0.4.1, the decider: "I should also be able to resize it, and
    /// resize the one on the right too"), alone. Staged by `vox`: alice attached, with one room,
    /// chosen before; Keep Running not chosen. Dragging the inspector's divider changes its width,
    /// and the width is the same after ⌘Q and a new launch; the sidebar's own resize is the
    /// decider's hand test (XCTest's drag does not reach it; see below); and View >
    /// Hide Inspector (⌥⌘I) hides the inspector and Show Inspector brings it back. Made short, the
    /// window cuts the inspector's family LAN section off, and scrolling the inspector brings it
    /// into view with MEMBERS still at the top (P13).
    /// Mutations: Columns.remember a no-op → red at "after a new launch"; the inspector without
    /// its scroll view → red at "must scroll".
    func testColumnsResizeAndAreRememberedAndTheInspectorHides() throws {
        let env = ProcessInfo.processInfo.environment
        guard let appPath = env["VOX_PROOF_APP"], let scratchPath = env["VOX_PROOF_SCRATCH"] else {
            throw Apparatus("VOX_PROOF_APP and VOX_PROOF_SCRATCH are set by scripts/app-proofs.sh")
        }
        let vox = URL(fileURLWithPath: appPath).appendingPathComponent("Contents/Helpers/vox").path
        let root = URL(fileURLWithPath: scratchPath).appendingPathComponent("columns")
        let data = root.appendingPathComponent("data").path
        let config = root.appendingPathComponent("config").path
        let home = root.appendingPathComponent("home").path
        let voxEnv = ["VOX_DATA_DIR": data, "VOX_CONFIG_DIR": config, "VOX_PROXY": "127.0.0.1:0"]
        daemon = try start(vox, ["daemon", "--listen", "127.0.0.1:0"], env: voxEnv,
                           until: "vox daemon: control socket")
        let idPass = root.appendingPathComponent("alice.pass").path
        let roomPass = root.appendingPathComponent("room.pass").path
        try stager.write(Data("alice identity\n".utf8), to: idPass)
        try stager.write(Data("columns room\n".utf8), to: roomPass)
        try staged(vox, ["node", "create", "alice"],
                   env: voxEnv.merging(["VOX_IDENTITY_PASSPHRASE": "alice identity"]) { $1 })
        try staged(vox, ["node", "attach", "alice", "--passphrase-file", idPass], env: voxEnv)
        try staged(vox, ["room", "create", "--node", "alice", "--passphrase-file", roomPass,
                         "--name", "columns"], env: voxEnv)
        try stager.write(Data("no\n".utf8), to: config + "/app/login-item")
        try stager.write(Data("alice\n".utf8), to: config + "/app/node")
        // The widths start from the standard ones: the column keys, in the bundle under proof's
        // own defaults (never the person's Vox), are removed first.
        let domain = stager.run(["/usr/bin/defaults", "read", appPath + "/Contents/Info", "CFBundleIdentifier"],
                                env: [:]).out.trimmingCharacters(in: .whitespacesAndNewlines)
        let proofID = "us.vox.app.proof"  // app-proofs.sh's VOX_APP_ID
        guard domain == proofID else {
            throw Apparatus("\(appPath) is \(domain.debugDescription), not \(proofID): its defaults could be the person's")
        }
        for key in ["column.sidebar.width", "column.inspector.width", "column.inspector.shown"] {
            _ = stager.run(["/usr/bin/defaults", "delete", domain, key], env: [:])
        }

        let ui = voxApp(appPath)
        ui.launchEnvironment = voxEnv.merging(["HOME": home]) { $1 }
        try launchVox(ui, appPath, env: ui.launchEnvironment, scratch: scratchPath)
        defer { ui.terminate() }
        present(ui, Key.id("attached"), timeout: 60, "the app must open attached as alice")
        tap(ui, Key.id("room-columns"), "the room columns in the sidebar")
        present(ui, Key.id("inspector"), timeout: 10, "a room on screen must show its inspector")

        /// The sidebar's divider: the window's split view's (NavigationSplitView).
        func sidebarDivider() -> XCUIElement? {
            ui.windows.firstMatch.splitters.allElementsBoundByIndex
                .filter { $0.exists && $0.frame.width > 0 }
                .min { $0.frame.minX < $1.frame.minX }
        }
        func inspectorDivider() -> XCUIElement {
            ui.descendants(matching: .any).matching(identifier: "inspector-divider").firstMatch
        }
        func sidebarWidth() -> CGFloat {
            guard let d = sidebarDivider() else { return -1 }
            return d.frame.minX - ui.windows.firstMatch.frame.minX
        }
        func inspectorWidth() -> CGFloat {
            let e = ui.descendants(matching: .any).matching(identifier: "inspector").firstMatch
            return e.exists ? e.frame.width : -1
        }
        /// A person's drag: press, move slowly, and hold before letting go.
        func drag(_ divider: XCUIElement, by dx: CGFloat) {
            let at = divider.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5))
            at.press(forDuration: 0.5, thenDragTo: at.withOffset(CGVector(dx: dx, dy: 0)),
                     withVelocity: .slow, thenHoldForDuration: 0.5)
            Thread.sleep(forTimeInterval: 1)
        }
        guard let side = sidebarDivider() else {
            throw Apparatus("XCTest finds no split view divider in the window for the sidebar")
        }
        guard inspectorDivider().waitForExistence(timeout: 10) else {
            throw Apparatus("XCTest finds no \"inspector-divider\" beside the inspector")
        }
        // Room to widen both: the timeline keeps 400 points (its minimum), so a window only as
        // wide as the three columns need leaves the sidebar nowhere to go. Widen the window first,
        // from its right edge, as a person would.
        let window = ui.windows.firstMatch
        let edge = window.coordinate(withNormalizedOffset: CGVector(dx: 1, dy: 0.5))
            .withOffset(CGVector(dx: -1, dy: 0))
        edge.press(forDuration: 0.5, thenDragTo: edge.withOffset(CGVector(dx: 400, dy: 0)),
                   withVelocity: .slow, thenHoldForDuration: 0.5)
        Thread.sleep(forTimeInterval: 1)
        let sidebar0 = sidebarWidth(), inspector0 = inspectorWidth()
        let needed = sidebar0 + 80 + 400 + 7 + inspector0 + 60
        guard window.frame.width >= needed else {
            throw Apparatus("staging not achieved: the window is \(window.frame.width) wide after widening, and both drags need \(needed) (the timeline keeps 400)")
        }
        // The sidebar's own resize is not driven here: XCTest's drag does not reach the split
        // view's resize area (the sidebar-resize spike, 2026-10-09: 13 grips around the separator,
        // with and without a hover and a long press; and this case's hover +5 point grip, 233 →
        // 233 on 2026-10-09). A person's drag there resizes it (the decider, by hand, on a proof
        // build without remembersWidth). That claim rests on the hand test and on 9f0559f6, which
        // keeps the width out of the live resize; this case says what XCTest's drag did, as
        // information, and asserts nothing about it.
        let grip = window.coordinate(withNormalizedOffset: .zero)
            .withOffset(CGVector(dx: side.frame.midX + 5 - window.frame.minX,
                                 dy: side.frame.midY - window.frame.minY))
        grip.hover()
        Thread.sleep(forTimeInterval: 0.5)
        grip.press(forDuration: 0.5, thenDragTo: grip.withOffset(CGVector(dx: 80, dy: 0)),
                   withVelocity: .slow, thenHoldForDuration: 0.5)
        Thread.sleep(forTimeInterval: 1)
        let sidebar1 = sidebarWidth()
        print("[proof] columns: XCTest's sidebar drag (not asserted): \(sidebar0) → \(sidebar1)")
        drag(inspectorDivider(), by: -60)
        let inspector1 = inspectorWidth()
        XCTAssertTrue(inspector1 > inspector0 + 30,
                      "PRODUCT: dragging the inspector's divider 60 points left must widen the inspector; it went from \(inspector0) to \(inspector1)")

        // ⌘Q, and a new launch: the same widths.
        handOff(ui, "q")
        XCTAssertTrue(ui.wait(for: .notRunning, timeout: 30), "PRODUCT: ⌘Q did not quit the app")
        try launchVox(ui, appPath, env: ui.launchEnvironment, scratch: scratchPath)
        present(ui, Key.id("attached"), timeout: 60, "after a new launch, the app must open attached as alice")
        tap(ui, Key.id("room-columns"), "after a new launch, the room columns")
        present(ui, Key.id("inspector"), timeout: 10, "after a new launch, the room's inspector")
        Thread.sleep(forTimeInterval: 1)
        let sidebar2 = sidebarWidth(), inspector2 = inspectorWidth()
        XCTAssertTrue(abs(inspector2 - inspector1) <= 4,
                      "PRODUCT: the inspector's width must be the same after a new launch; it was \(inspector1) and is \(inspector2) (the sidebar was \(sidebar1) and is \(sidebar2))")

        // Hide the inspector, then show it again, with ⌥⌘I.
        ui.typeKey("i", modifierFlags: [.command, .option])
        let hidden = ui.descendants(matching: .any).matching(identifier: "inspector").firstMatch
            .waitForNonExistence(timeout: 5)
        ui.typeKey("i", modifierFlags: [.command, .option])
        let back = present(ui, Key.id("inspector"), timeout: 5, "⌥⌘I again must show the inspector")
        XCTAssertTrue(hidden && back,
                      "PRODUCT: View > Hide Inspector (⌥⌘I) must hide the inspector and Show Inspector bring it back; hidden \(hidden), back \(back)")

        // A short window (P13): the inspector's last section, the family LAN, is below its
        // bottom, and scrolling the inspector brings it into view while MEMBERS stays pinned.
        let bottom = window.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 1))
            .withOffset(CGVector(dx: 0, dy: -1))
        bottom.press(forDuration: 0.5, thenDragTo: bottom.withOffset(CGVector(dx: 0, dy: -(window.frame.height - 300))),
                     withVelocity: .slow, thenHoldForDuration: 0.5)
        Thread.sleep(forTimeInterval: 1)
        let inspector = ui.descendants(matching: .any).matching(identifier: "inspector").firstMatch
        // The section's last control: Allow the LAN Helper, or Remove it once it is allowed.
        let lan = ui.descendants(matching: .any).matching(NSPredicate(
            format: "identifier == 'family-lan-allow' OR identifier == 'family-lan-remove'")).firstMatch
        func lanInView() -> Bool {
            lan.exists && lan.frame.maxY <= inspector.frame.maxY + 1 && lan.frame.minY >= inspector.frame.minY
        }
        guard !lanInView() else {
            throw Apparatus("staging not achieved: the window is \(window.frame.height) high and the inspector's family LAN section still fits (\(lan.frame) in \(inspector.frame)), so there is nothing to scroll")
        }
        inspector.scroll(byDeltaX: 0, deltaY: -2000)
        Thread.sleep(forTimeInterval: 1)
        let members = locate(ui, Key.showing("MEMBERS"))?.frame ?? .null
        XCTAssertTrue(lanInView(),
                      "PRODUCT: the inspector must scroll (P13): in a window \(window.frame.height) high, scrolled down, its family LAN section is still out of view (\(lan.exists ? "\(lan.frame)" : "not shown") in \(inspector.frame))")
        XCTAssertTrue(!members.isNull && members.minY >= inspector.frame.minY - 1 && members.maxY <= inspector.frame.maxY,
                      "PRODUCT: scrolled, the inspector's MEMBERS heading must stay in view (P13); it is at \(members) in \(inspector.frame)")
        print("[proof] columns: sidebar \(sidebar0) → \(sidebar1) → after relaunch \(sidebar2); inspector \(inspector0) → \(inspector1) → \(inspector2); hide \(hidden), show \(back); scrolled, LAN in view \(lanInView()), MEMBERS at \(members.minY)")
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

        let ui = voxApp(appPath)
        ui.launchEnvironment = voxEnv
        try launchVox(ui, appPath, env: ui.launchEnvironment, scratch: scratchPath)
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

    /// A new person, with no node on this Mac, starts in the app and ends in a room with a post,
    /// never sent to Terminal: the welcome makes their node (a name, the identity passphrase typed
    /// twice, the no-backup notice), as `vox node create` makes it, and attaches it; the empty
    /// window offers New Room; the room takes a post. Every screen on the way is read for Terminal
    /// or a `vox` command. Mutant: the welcome sending the person to `vox node create` in Terminal
    /// → red at "must not send a person to Terminal".
    func testANewPersonMakesTheirNodeAndARoomInTheApp() throws {
        let env = ProcessInfo.processInfo.environment
        guard let appPath = env["VOX_PROOF_APP"], let scratchPath = env["VOX_PROOF_SCRATCH"] else {
            throw Apparatus("VOX_PROOF_APP and VOX_PROOF_SCRATCH are set by scripts/app-proofs.sh")
        }
        let vox = URL(fileURLWithPath: appPath).appendingPathComponent("Contents/Helpers/vox").path
        let root = URL(fileURLWithPath: scratchPath).appendingPathComponent("new-person")
        let data = root.appendingPathComponent("data").path
        let config = root.appendingPathComponent("config").path
        let voxEnv = ["VOX_DATA_DIR": data, "VOX_CONFIG_DIR": config, "VOX_PROXY": "127.0.0.1:0"]
        // An empty data root and its daemon: no node on this Mac.
        daemon = try start(vox, ["daemon", "--listen", "127.0.0.1:0"], env: voxEnv,
                           until: "vox daemon: control socket")
        let before = run(vox, ["node", "list"], env: voxEnv)
        guard before.status == 0, nodeLine(before.out, "alice") == nil else {
            throw Apparatus("staging not achieved: the data root is to hold no node; `vox node list` said \(before.out)")
        }

        let ui = voxApp(appPath)
        ui.launchEnvironment = voxEnv
        try launchVox(ui, appPath, env: ui.launchEnvironment, scratch: scratchPath)
        defer {
            ui.terminate()
            _ = run(vox, ["node", "detach", "alice"], env: voxEnv)
        }
        present(ui, Key.id("login-item-why"), timeout: 30, "at first run the app must ask about Keep Running")
        tap(ui, Key.id("login-item-not-now"), "Not Now")

        // The welcome: the node is made here.
        let name = Key.id("new-node-name")
        present(ui, name, timeout: 30,
                "with no node on this Mac, the first run must offer to make one in the app")
        noCommandLine(ui, "the welcome")
        words(ui, Key.id("new-node-no-backup"), timeout: 5,
              "making a node must say there is no backup of it",
              until: { $0.lowercased().contains("there is no backup of a node") })
        if tap(ui, name, "the node's name field") {
            ui.typeKey("a", modifierFlags: .command)
            el(ui, name).typeText("alice")
        }
        // Typed twice, differently: refused, and nothing made.
        type(ui, Key.id("new-node-passphrase"), "alice identity", "the passphrase field")
        type(ui, Key.id("new-node-passphrase-again"), "not the same", "the passphrase again field")
        tap(ui, Key.id("new-node-make"), "Make Node")
        words(ui, Key.id("said"), timeout: 15,
              "a passphrase typed twice differently must be refused, where it was typed",
              until: { $0.lowercased().contains("the two passphrases differ") })
        let refused = run(vox, ["node", "list"], env: voxEnv).out
        XCTAssertNil(nodeLine(refused, "alice"),
                     "PRODUCT: refused for two different passphrases, the app must have made no node; `vox node list` says \(refused)")
        noCommandLine(ui, "the welcome, after a refusal")
        type(ui, Key.id("new-node-passphrase"), "alice identity", "the passphrase field")
        type(ui, Key.id("new-node-passphrase-again"), "alice identity", "the passphrase again field")
        tap(ui, Key.id("new-node-make"), "Make Node")
        present(ui, Key.id("attached"), timeout: 90,
                "made in the app, node alice must be attached in its window")
        let listed = run(vox, ["node", "list"], env: voxEnv).out
        XCTAssertTrue(nodeLine(listed, "alice")?.contains(" attached ") ?? false,
                      "PRODUCT: the app's new node must be alice, attached, as `vox node list` lists it; it says \(listed)")

        // In no room yet: the window offers the ways in.
        let newRoom = Key.id("empty-new-room")
        present(ui, newRoom, timeout: 15, "a node in no room must be offered New Room in the window")
        noCommandLine(ui, "the window of a node in no room")
        tap(ui, newRoom, "New Room…")
        let roomName = Key.id("room-form-name")
        present(ui, roomName, timeout: 10, "New Room… must open the New Room form")
        noCommandLine(ui, "the New Room form")
        type(ui, roomName, "first", "the room's name field")
        type(ui, Key.id("room-form-passphrase"), "first room", "the room's passphrase field")
        tap(ui, Key.id("room-form-submit"), "Create")
        tap(ui, Key.id("room-first"), "first in the sidebar", premise: inRoom(vox, voxEnv, "first"))
        let compose = Key.id("compose")
        present(ui, compose, timeout: 15, "the new room must offer its composer")
        type(ui, compose, "HELLO-FIRST-RUN\r", "the composer")
        present(ui, Key.showing("HELLO-FIRST-RUN"), timeout: 15, "alice's post must show in her new room")
        noCommandLine(ui, "the new room")
        let rooms = run(vox, ["room", "list", "--node", "alice"], env: voxEnv).out
        let room = rooms.split(separator: "\n").first { $0.contains(" first") }?
            .split(whereSeparator: \.isWhitespace).first.map(String.init) ?? ""
        let read = run(vox, ["room", "read", "--node", "alice", room], env: voxEnv).out
        XCTAssertTrue(!room.isEmpty && read.contains("HELLO-FIRST-RUN"),
                      "PRODUCT: the room made in the app must hold alice's post, as `vox room read` reads it; `vox room list` says \(rooms), and the room reads \(read)")
        print("[proof] new person: node alice made and attached in the app, room \(room) made from the empty window, HELLO-FIRST-RUN posted; no screen named Terminal or a vox command")

        // **Sign Out, then sign in as a new node (ADR-028 E-4, the decider 2026-10-08).** Alice is
        // kept as Keep Running keeps a node (`--keep`, from a scratch file: the Keychain is the
        // person's, never a proof's). Node › Sign Out… says what it does; confirmed, alice is
        // detached, no longer kept, and the app's choice of her forgotten, her room still on disk;
        // the sign-in lists her with her fingerprint and offers New Node…, which makes and attaches
        // bob, and the app acts as bob.
        let alicePass = root.appendingPathComponent("alice.pass").path
        try stager.write(Data("alice identity\n".utf8), to: alicePass)
        try staged(vox, ["node", "attach", "alice", "--keep", "--passphrase-file", alicePass], env: voxEnv)
        let aliceFp = try line(staged(vox, ["id", "--node", "alice"], env: voxEnv)) { $0.count == 52 }
        func aliceLine() -> String { nodeLine(run(vox, ["node", "list"], env: voxEnv).out, "alice") ?? "" }
        guard aliceLine().hasSuffix("(kept)") else {
            throw Apparatus("staging not achieved: node alice is not kept before Sign Out; `vox node list` says \(aliceLine().debugDescription)")
        }
        let nodeMenu = ui.menuBars.menuBarItems["Node"]
        guard nodeMenu.waitForExistence(timeout: 10) else { throw Apparatus("XCTest finds no Node menu") }
        nodeMenu.click()
        tap(ui, Key.menuItem("Sign Out…"), "Node › Sign Out…")
        words(ui, Key.id("sign-out-effect"), timeout: 10,
              "Sign Out… must say what it does before it does it",
              until: { $0.contains("stay on this Mac") && $0.contains("Keychain") })
        tap(ui, Key.id("sign-out-confirm"), "Sign Out")
        let signIn = Key.id("node-alice")
        let listedAlice = words(ui, signIn, timeout: 30,
                                "signed out, the app must offer the sign-in, listing node alice with her fingerprint",
                                until: { $0.contains("Act as node alice") && $0.contains(String(aliceFp.prefix(4))) }) ?? ""
        let out = aliceLine()
        let keepFile = stager.run(["/bin/sh", "-c", "cat \"$0\" 2>/dev/null", data + "/.daemon/attach"], env: [:]).out
        let choice = stager.run(["/bin/sh", "-c", "cat \"$0\" 2>/dev/null", config + "/app/node"], env: [:]).out
        XCTAssertTrue(!out.contains(" attached") && !out.hasSuffix("(kept)")
                        && !keepFile.split(separator: "\n").contains { $0.hasPrefix("alice\t") },
                      "PRODUCT: signed out, node alice must be detached and no longer kept: `vox node list` says \(out.debugDescription), the attach file \(keepFile.debugDescription)")
        XCTAssertTrue(choice.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                      "PRODUCT: signed out, the app must forget it opens node alice; its choice file says \(choice.debugDescription)")
        let aliceDir = stager.run(["/bin/ls", data + "/nodes/alice"], env: [:])
        XCTAssertEqual(aliceDir.status, 0, "PRODUCT: signed out, node alice must stay on disk: \(aliceDir.out)")
        tap(ui, Key.id("new-node"), "New Node… in the sign-in")
        if tap(ui, name, "the node's name field") {
            ui.typeKey("a", modifierFlags: .command)
            el(ui, name).typeText("bob")
        }
        type(ui, Key.id("new-node-passphrase"), "bob identity", "the passphrase field")
        type(ui, Key.id("new-node-passphrase-again"), "bob identity", "the passphrase again field")
        tap(ui, Key.id("new-node-make"), "Make Node")
        present(ui, Key.id("attached"), timeout: 90, "made at the sign-in, node bob must be attached in the window")
        let nodes = run(vox, ["node", "list"], env: voxEnv).out
        let chosen = stager.run(["/bin/sh", "-c", "cat \"$0\" 2>/dev/null", config + "/app/node"], env: [:]).out
        XCTAssertTrue((nodeLine(nodes, "bob")?.contains(" attached ") ?? false)
                        && chosen.trimmingCharacters(in: .whitespacesAndNewlines) == "bob",
                      "PRODUCT: signed in as the new node bob, the app must act as bob: `vox node list` says \(nodes), its choice \(chosen.debugDescription)")
        _ = run(vox, ["node", "detach", "bob"], env: voxEnv)
        print("[proof] sign out: \(out.debugDescription) after; sign-in listed \(listedAlice.debugDescription); signed in as new node bob")
    }

    /// Red when what the app shows sends a person to Terminal or names a `vox` command: every
    /// label and value in its windows, sheets and dialogs, read as they are.
    private func noCommandLine(_ ui: XCUIApplication, _ where: String,
                               file: StaticString = #filePath, line: UInt = #line) {
        // Read from one snapshot per container: an element looked up again by its index can be
        // gone by then (a menu closing), which XCTest fails on as no match.
        func words(_ s: XCUIElementSnapshot) -> [String] {
            let own = [s.label, (s.value as? String) ?? "", s.title].filter { !$0.isEmpty }
            return own + s.children.flatMap(words)
        }
        let shownNow = containers(ui).flatMap { $0.allElementsBoundByIndex }
            .compactMap { try? $0.snapshot() }
            .flatMap(words)
        let words = ["Terminal", "terminal", "command line", "vox node", "vox room", "vox id", "vox trust", "`vox"]
        if let said = shownNow.first(where: { text in words.contains { text.contains($0) } }) {
            keepTree(ui, "\(`where`) named Terminal or a command")
            XCTFail("PRODUCT: \(`where`) must not send a person to Terminal or name a vox command; it shows \"\(said)\"",
                    file: file, line: line)
        }
    }

    /// A data root an earlier release left (a node directory beside `nodes/`, which this version
    /// refuses) is said plainly in the app, with "Move It Aside and Start Fresh": the directory is
    /// moved, whole and unread, under `moved-aside/`, nothing deleted, and the welcome follows,
    /// saying where it went. Staged with dummy files only. Mutant: the move deleting the directory
    /// instead of renaming it → red at "must be kept, whole".
    func testAnEarlierReleasesNodeIsMovedAsideInTheApp() throws {
        let env = ProcessInfo.processInfo.environment
        guard let appPath = env["VOX_PROOF_APP"], let scratchPath = env["VOX_PROOF_SCRATCH"] else {
            throw Apparatus("VOX_PROOF_APP and VOX_PROOF_SCRATCH are set by scripts/app-proofs.sh")
        }
        let root = URL(fileURLWithPath: scratchPath).appendingPathComponent("old-node")
        let data = root.appendingPathComponent("data").path
        let config = root.appendingPathComponent("config").path
        let voxEnv = ["VOX_DATA_DIR": data, "VOX_CONFIG_DIR": config, "VOX_PROXY": "127.0.0.1:0"]
        // The layout an earlier release left: dummy files, no real data.
        let vault = "STAGED-OLD-VAULT \(UUID().uuidString)"
        try stager.write(Data(vault.utf8), to: data + "/default/vault.cbor")
        try stager.write(Data("STAGED-OLD-STORE".utf8), to: data + "/default/store.redb")
        // The daemon the app starts after the move, stopped by its pid when the case ends.
        defer {
            let pid = stager.run(["/bin/cat", data + "/.daemon/lock"], env: [:]).out
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if Int32(pid) != nil { _ = stager.run(["/bin/kill", pid], env: [:]) }
        }

        let ui = voxApp(appPath)
        ui.launchEnvironment = voxEnv
        try launchVox(ui, appPath, env: ui.launchEnvironment, scratch: scratchPath)
        defer { ui.terminate() }
        present(ui, Key.id("login-item-why"), timeout: 30, "at first run the app must ask about Keep Running")
        tap(ui, Key.id("login-item-not-now"), "Not Now")

        let moveAside = Key.id("old-move-aside")
        present(ui, moveAside, timeout: 30,
                "a data root an earlier release left must be said in the app, with a way to move it aside")
        words(ui, Key.id("old-layout-why"), timeout: 5,
              "the app must say plainly which node it cannot read",
              until: { $0.contains("cannot read default") && $0.contains("Nothing in it is deleted") })
        noCommandLine(ui, "the earlier-release screen")
        tap(ui, moveAside, "Move It Aside and Start Fresh")
        present(ui, Key.id("new-node-name"), timeout: 60,
                "moved aside, the app must go on to the welcome that makes a node")
        let note = words(ui, Key.id("moved-aside-note"), timeout: 10,
                         "the welcome must say where the old node went",
                         until: { $0.contains("/moved-aside/default-") }) ?? ""
        noCommandLine(ui, "the welcome after the move")
        let gone = stager.run(["/bin/test", "-e", data + "/default"], env: [:]).status != 0
        let kept = stager.run(["/bin/sh", "-c", "cat \"$0\"/moved-aside/default-*/vault.cbor", data], env: [:]).out
        XCTAssertTrue(gone && kept == vault,
                      "PRODUCT: Move It Aside must move the old node directory, whole: it must be kept under moved-aside/ with its vault as it was, and gone from where it was; gone from there: \(gone), the kept vault reads \(kept.debugDescription); the app said \(note.debugDescription)")
        print("[proof] earlier release: default moved aside whole (\(note)); the welcome followed; no screen named Terminal or a vox command")
    }

    /// Driving Sessions in the app goes where it is shown (D2, D12, D13, P1). Alice and the
    /// agent node claude-a share rooms work and other; claude-a's two Sessions S1 and S2 are opened
    /// by `vox agent hook` as Claude Code runs it, and S1 asks an approval. Claims, each with its
    /// mutant:
    /// - D12: work's draft survives going to other and back (mutant: the draft not restored);
    ///   S1's draft never shows in S2, and comes back in S1 (mutant: the composer not keyed by
    ///   its Session).
    /// - D2: with S1 shown, ⌘↩ sends nothing to the room, and Send Urgent is disabled (mutant:
    ///   Send Urgent enabled in a Session).
    /// - D13: a prompt the Session does not take stays in its composer (mutant: cleared before
    ///   delivery), and ⌃C asks before stopping.
    /// - P1: ⌘J opens S1 with its waiting request selected, and ⌥⌘Y approves it: the hook gets
    ///   "allow" (mutant: ⌘J opening the room only).
    func testSessionsAreDrivenWhereTheyAreShown() throws {
        let env = ProcessInfo.processInfo.environment
        guard let appPath = env["VOX_PROOF_APP"], let scratchPath = env["VOX_PROOF_SCRATCH"] else {
            throw Apparatus("VOX_PROOF_APP and VOX_PROOF_SCRATCH are set by scripts/app-proofs.sh")
        }
        let vox = URL(fileURLWithPath: appPath).appendingPathComponent("Contents/Helpers/vox").path
        let root = URL(fileURLWithPath: scratchPath).appendingPathComponent("sessions")
        let data = root.appendingPathComponent("data").path
        let config = root.appendingPathComponent("config").path
        let work = root.appendingPathComponent("work").path
        let home = root.appendingPathComponent("home").path
        let voxEnv = ["VOX_DATA_DIR": data, "VOX_CONFIG_DIR": config, "VOX_PROXY": "127.0.0.1:0"]
        let pass = { (name: String) in root.appendingPathComponent("\(name).pass").path }
        try stager.write(Data("alice identity\n".utf8), to: pass("alice"))
        try stager.write(Data("agent identity\n".utf8), to: pass("claude-a"))
        try stager.write(Data("work room\n".utf8), to: pass("room"))
        try stager.write(Data("keep\n".utf8), to: work + "/.keep")
        try stager.write(Data("keep\n".utf8), to: home + "/.keep")
        // The first run answered (Not Now) and the node chosen: the app opens as alice.
        try stager.write(Data("no\n".utf8), to: config + "/app/login-item")
        try stager.write(Data("alice\n".utf8), to: config + "/app/node")
        daemon = try start(vox, ["daemon", "--listen", "127.0.0.1:0"], env: voxEnv,
                           until: "vox daemon: control socket")
        for (name, words) in [("alice", "alice identity"), ("claude-a", "agent identity")] {
            try staged(vox, ["node", "create", name],
                       env: voxEnv.merging(["VOX_IDENTITY_PASSPHRASE": words]) { $1 })
            try staged(vox, ["node", "attach", name, "--passphrase-file", pass(name)], env: voxEnv)
        }
        let aliceFp = try line(staged(vox, ["id", "--node", "alice"], env: voxEnv)) { $0.count == 52 }
        let agentFp = try line(staged(vox, ["id", "--node", "claude-a"], env: voxEnv)) { $0.count == 52 }
        var rooms: [String: String] = [:]
        for name in ["work", "other"] {
            try staged(vox, ["room", "create", "--node", "alice", "--passphrase-file", pass("room"),
                             "--name", name], env: voxEnv)
            let id = try line(staged(vox, ["room", "list", "--node", "alice"], env: voxEnv)) {
                $0.contains(" \(name)")
            }.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? ""
            let link = try line(staged(vox, ["room", "link", "--node", "alice", id], env: voxEnv)) {
                $0.hasPrefix("vox://")
            }
            try staged(vox, ["room", "join", "--node", "claude-a", "--passphrase-file", pass("room"), link],
                       env: voxEnv)
            rooms[name] = id
        }
        let room = rooms["work"] ?? ""
        try staged(vox, ["trust", "add", "--node", "alice", agentFp, "--name", "claude-a",
                         "--identity-passphrase-file", pass("alice")], env: voxEnv)
        try staged(vox, ["trust", "add", "--node", "claude-a", aliceFp, "--name", "alice", "--drive",
                         "--identity-passphrase-file", pass("claude-a")], env: voxEnv)
        // Claude Code's two sessions, opened by its hook as it runs it.
        let hookEnv = voxEnv.merging(["HOME": home, "VOX_NODE": "claude-a",
                                      "VOX_IDENTITY_PASSPHRASE": "agent identity",
                                      "CLAUDE_CODE_ENTRYPOINT": "cli", "PATH": "/usr/bin:/bin"]) { $1 }
        let s1 = "51aaaaaa-4c0e-4f00-9a1b-0c0ffee54001", s2 = "52bbbbbb-4c0e-4f00-9a1b-0c0ffee54002"
        func event(_ session: String, _ name: String, _ extra: [String: Any] = [:]) -> String {
            var e: [String: Any] = ["session_id": session, "transcript_path": work + "/\(session).jsonl",
                                    "cwd": work, "permission_mode": "default", "hook_event_name": name]
            for (k, v) in extra { e[k] = v }
            let bytes = (try? JSONSerialization.data(withJSONObject: e)) ?? Data()
            return String(decoding: bytes, as: UTF8.self)
        }
        func hook(_ json: String) throws {
            let r = stager.run(["/bin/sh", "-c", "cd \"$1\" && exec \"$2\" agent hook --node claude-a --room \"$3\"",
                                "hook", work, vox, room], env: hookEnv, input: json)
            guard r.status == 0 else { throw Apparatus("`vox agent hook` exited \(r.status): \(r.out)") }
        }
        for (session, words) in [(s1, "S1-WORDS"), (s2, "S2-WORDS")] {
            try stager.write(Data(), to: work + "/\(session).jsonl")
            try hook(event(session, "UserPromptSubmit", ["prompt": words]))
        }
        // S1 asks an approval: its hook waits for the answer, in the background, its pid kept.
        // Only the hook itself goes to the background, with its own output in a file, so nothing
        // left running holds the stager's pipe open; `&&` would background a subshell holding it.
        let touch: [String: Any] = ["command": "touch p1", "description": "Make p1"]
        try hook(event(s1, "PreToolUse", ["tool_name": "Bash", "tool_input": touch, "tool_use_id": "toolu_P1"]))
        let asked = root.appendingPathComponent("asked")
        try stager.write(Data(event(s1, "PermissionRequest", ["tool_name": "Bash", "tool_input": touch,
                                                               "permission_suggestions": []]).utf8),
                         to: asked.path + ".json")
        let started = stager.run(["/bin/sh", "-c",
                                  "cd \"$1\" || exit 1; \"$2\" agent hook --node claude-a --room \"$3\" < \"$4.json\" > \"$4.out\" 2>&1 & echo $!",
                                  "hook", work, vox, room, asked.path], env: hookEnv)
        let hookPid = started.out.trimmingCharacters(in: .whitespacesAndNewlines)
        guard started.status == 0, Int32(hookPid) != nil else {
            throw Apparatus("the waiting PermissionRequest hook did not start: \(started.out)")
        }
        defer { _ = stager.run(["/bin/kill", hookPid], env: [:]) }
        // The request is waiting on alice once S1's read marks it so (`"waiting":true`); the
        // room's Sessions list never says "waiting", so it cannot tell.
        let s1Read = { self.run(vox, ["room", "session", "--node", "alice", "--json", room, s1], env: voxEnv).out }
        let waitingUntil = Date().addingTimeInterval(20)
        var s1Now = ""
        while Date() < waitingUntil && !s1Now.contains("\"waiting\":true") {
            s1Now = s1Read()
            if !s1Now.contains("\"waiting\":true") { Thread.sleep(forTimeInterval: 0.5) }
        }
        guard s1Now.contains("\"waiting\":true") else {
            throw Apparatus("staging not achieved: S1's request is not waiting on alice within 20 s; `vox room session --json` said \(s1Now.debugDescription)")
        }

        let ui = voxApp(appPath)
        ui.launchEnvironment = voxEnv
        try launchVox(ui, appPath, env: ui.launchEnvironment, scratch: scratchPath)
        defer { ui.terminate() }
        present(ui, Key.id("attached"), timeout: 60, "the app must open attached as alice")

        // P1: ⌘J lands on S1, its waiting request selected.
        ui.typeKey("j", modifierFlags: .command)
        let requestRow = Key.idPrefix("request-row-")
        present(ui, requestRow, timeout: 30,
                "⌘J must open S1, the Session waiting on alice, with its request",
                premise: Premise("S1 has a request waiting on alice") {
                    let now = s1Read()
                    return (now.contains("\"waiting\":true"), "`vox room session --json` said \(now.debugDescription)")
                })
        if let row = locate(ui, requestRow), !row.isSelected {
            keepTree(ui, "the request ⌘J landed on was not selected")
            XCTFail("PRODUCT: ⌘J must select the waiting request in S1; its row is not selected")
        }
        // ⌥⌘Y approves the selected request: the hook gets allow.
        ui.typeKey("y", modifierFlags: [.command, .option])
        let answerUntil = Date().addingTimeInterval(20)
        var answered = ""
        while Date() < answerUntil && !answered.contains("behavior") {
            answered = stager.run(["/bin/cat", asked.path + ".out"], env: [:]).out
            if !answered.contains("behavior") { Thread.sleep(forTimeInterval: 0.5) }
        }
        XCTAssertTrue(answered.contains("\"allow\""),
                      "PRODUCT: ⌥⌘Y must approve the selected request: S1's hook must get allow; it printed \(answered.debugDescription)")

        // D12: work's draft survives going to other and back.
        tap(ui, Key.id("session-general"), "General in work's Sessions")
        let compose = Key.id("compose")
        type(ui, compose, "KEEP-ROOM-DRAFT", "work's composer")
        tap(ui, Key.id("room-other"), "other in the sidebar", premise: inRoom(vox, voxEnv, "other"))
        tap(ui, Key.id("room-work"), "work in the sidebar", premise: inRoom(vox, voxEnv, "work"))
        tap(ui, Key.id("session-general"), "General in work's Sessions")
        words(ui, compose, timeout: 10, "work's draft must be kept when another room is opened and work again",
              until: { $0.contains("KEEP-ROOM-DRAFT") }, field: true)

        // D2: with S1 shown, ⌘↩ sends nothing to the room, and Send Urgent is disabled.
        let s1Row = Key.id("session-\(s1.prefix(8))"), s2Row = Key.id("session-\(s2.prefix(8))")
        tap(ui, s1Row, "S1 in work's Sessions")
        ui.typeKey(.return, modifierFlags: .command)
        Thread.sleep(forTimeInterval: 3)
        let roomRead = run(vox, ["room", "read", "--node", "alice", room], env: voxEnv).out
        XCTAssertFalse(roomRead.contains("KEEP-ROOM-DRAFT"),
                       "PRODUCT: ⌘↩ while S1 is shown must not send work's General draft to the room; the room reads it")
        let urgent = ui.menuBars.menuItems["Send Urgent"]
        if urgent.exists && urgent.isEnabled {
            XCTFail("PRODUCT: Send Urgent must be disabled while a Session is shown; it is enabled")
        }

        // D12: S1's draft never shows in S2, and comes back in S1.
        let sessionCompose = Key.id("session-compose")
        type(ui, sessionCompose, "S1-DRAFT", "S1's composer")
        tap(ui, s2Row, "S2 in work's Sessions")
        Thread.sleep(forTimeInterval: 1)
        if let e = locate(ui, sessionCompose), typed(e).contains("S1-DRAFT") {
            keepTree(ui, "S1's draft showed in S2")
            XCTFail("PRODUCT: S1's draft must not show in S2's composer; it shows \"\(typed(e))\"")
        }
        tap(ui, s1Row, "S1 in work's Sessions")
        words(ui, sessionCompose, timeout: 10, "S1's draft must come back in S1",
              until: { $0.contains("S1-DRAFT") }, field: true)

        // D13: a prompt S2 does not take stays. claude-a is detached first, so nothing can take
        // it: refused or unanswered, the text must stay.
        try staged(vox, ["node", "detach", "claude-a"], env: voxEnv)
        tap(ui, s2Row, "S2 in work's Sessions")
        type(ui, sessionCompose, "S2-PROMPT\r", "S2's composer")
        let said = words(ui, Key.id("session-said"), timeout: 30, "S2 must say what came of the prompt",
                         until: { !$0.isEmpty }) ?? ""
        words(ui, sessionCompose, timeout: 5,
              "a prompt S2 did not take must stay in its composer (S2 said \"\(said)\")",
              until: { $0.contains("S2-PROMPT") }, field: true)
        ui.typeKey("c", modifierFlags: .control)
        present(ui, Key.showing("It ends the session."), timeout: 10,
                "⌃C must ask before stopping the Session")
        ui.typeKey(.escape, modifierFlags: [])
        print("[proof] sessions: ⌘J landed on S1's request and ⌥⌘Y approved it; work's draft kept; ⌘↩ in S1 sent nothing; S1's draft stayed in S1; S2 said \(said.debugDescription) and kept the prompt; ⌃C asked")
    }

    /// A keyring change waiting for the passphrase is bound to what it changes (D1). Alice is
    /// attached with her keyring window closed, so a change asks for the passphrase. She adds
    /// bob; the prompt names it ("trust bob"). Carol, a newcomer to her room, is offered: carol's
    /// offer shows no prompt, only that a change is waiting; trusting carol there asks first
    /// whether to replace it, and kept, the passphrase typed makes bob's change, not carol's.
    /// Mutant: the prompt shown wherever a change waits → red at "carol's offer must not show
    /// the prompt".
    func testAKeyringChangeWaitsWhereItWasMade() throws {
        let env = ProcessInfo.processInfo.environment
        guard let appPath = env["VOX_PROOF_APP"], let scratchPath = env["VOX_PROOF_SCRATCH"] else {
            throw Apparatus("VOX_PROOF_APP and VOX_PROOF_SCRATCH are set by scripts/app-proofs.sh")
        }
        let vox = URL(fileURLWithPath: appPath).appendingPathComponent("Contents/Helpers/vox").path
        let root = URL(fileURLWithPath: scratchPath).appendingPathComponent("keyring-pending")
        let data = root.appendingPathComponent("data").path
        let config = root.appendingPathComponent("config").path
        let voxEnv = ["VOX_DATA_DIR": data, "VOX_CONFIG_DIR": config, "VOX_PROXY": "127.0.0.1:0"]
        let pass = { (name: String) in root.appendingPathComponent("\(name).pass").path }
        for name in ["alice", "bob", "carol"] {
            try stager.write(Data("\(name) identity\n".utf8), to: pass(name))
        }
        try stager.write(Data("pending room\n".utf8), to: pass("room"))
        try stager.write(Data("no\n".utf8), to: config + "/app/login-item")
        try stager.write(Data("alice\n".utf8), to: config + "/app/node")
        daemon = try start(vox, ["daemon", "--listen", "127.0.0.1:0"], env: voxEnv,
                           until: "vox daemon: control socket")
        for name in ["alice", "bob", "carol"] {
            try staged(vox, ["node", "create", name],
                       env: voxEnv.merging(["VOX_IDENTITY_PASSPHRASE": "\(name) identity"]) { $1 })
            try staged(vox, ["node", "attach", name, "--passphrase-file", pass(name)], env: voxEnv)
        }
        let bobFp = try line(staged(vox, ["id", "--node", "bob"], env: voxEnv)) { $0.count == 52 }
        let carolFp = try line(staged(vox, ["id", "--node", "carol"], env: voxEnv)) { $0.count == 52 }
        try staged(vox, ["room", "create", "--node", "alice", "--passphrase-file", pass("room"),
                         "--name", "pending"], env: voxEnv)
        let room = try line(staged(vox, ["room", "list", "--node", "alice"], env: voxEnv)) {
            $0.contains(" pending")
        }.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? ""
        let link = try line(staged(vox, ["room", "link", "--node", "alice", room], env: voxEnv)) {
            $0.hasPrefix("vox://")
        }
        // Carol joins: alice is offered carol (K-15).
        try staged(vox, ["room", "join", "--node", "carol", "--passphrase-file", pass("room"), link],
                   env: voxEnv)
        let offerUntil = Date().addingTimeInterval(30)
        var offers = ""
        while Date() < offerUntil && !offers.contains(String(carolFp.prefix(12))) {
            offers = run(vox, ["trust", "offers", "--node", "alice"], env: voxEnv).out
            if !offers.contains(String(carolFp.prefix(12))) { Thread.sleep(forTimeInterval: 0.5) }
        }
        guard offers.contains(String(carolFp.prefix(12))) else {
            throw Apparatus("staging not achieved: alice was never offered carol: `vox trust offers` said \(offers)")
        }

        let ui = voxApp(appPath)
        ui.launchEnvironment = voxEnv
        try launchVox(ui, appPath, env: ui.launchEnvironment, scratch: scratchPath)
        defer { ui.terminate() }
        present(ui, Key.id("attached"), timeout: 60, "the app must open attached as alice")

        // Bob's change, waiting for the passphrase, named.
        tap(ui, Key.id("keyring"), "Keyring in the sidebar")
        type(ui, Key.id("keyring-add-fingerprint"), bobFp, "the fingerprint field")
        type(ui, Key.id("keyring-add-alias"), "bob", "the alias field")
        tap(ui, Key.id("keyring-trust"), "Trust")
        words(ui, Key.id("keyring-passphrase-why"), timeout: 15,
              "a change waiting for the passphrase must name itself",
              until: { $0.contains("trust bob") })

        // Carol's offer: no prompt there, only that bob's change waits.
        let offer = Key.id("offer-\(carolFp.prefix(12))")
        tap(ui, offer, "carol's offer in the sidebar",
            premise: Premise("carol is offered to alice") {
                (offers.contains(String(carolFp.prefix(12))), "`vox trust offers` said \(offers.debugDescription)")
            })
        present(ui, Key.id("offer-alias"), timeout: 10, "carol's offer must open")
        if locate(ui, Key.id("keyring-passphrase")) != nil {
            keepTree(ui, "carol's offer showed the passphrase prompt")
            XCTFail("PRODUCT: carol's offer must not show the passphrase prompt for bob's change")
        }
        words(ui, Key.id("keyring-waiting"), timeout: 10,
              "carol's offer must say a keyring change is waiting, and which",
              until: { $0.contains("trust bob") })
        // Trusting carol while bob's waits: asked first; kept.
        type(ui, Key.id("offer-alias"), "carol", "carol's alias field")
        tap(ui, Key.id("offer-accept"), "Trust on carol's offer")
        present(ui, Key.id("keyring-replace-ask"), timeout: 15,
                "a second change waiting for the passphrase must ask before replacing the first")
        tap(ui, Key.id("keyring-replace-no"), "Keep Waiting Change")

        // The passphrase, typed where bob's change waits, makes bob's change only.
        tap(ui, Key.id("keyring"), "Keyring in the sidebar")
        type(ui, Key.id("keyring-passphrase"), "alice identity", "the keyring's passphrase field")
        tap(ui, Key.id("keyring-passphrase-continue"), "Trust (with the passphrase)")
        let listUntil = Date().addingTimeInterval(30)
        var list = ""
        while Date() < listUntil && !list.contains(bobFp) {
            list = run(vox, ["trust", "list", "--node", "alice"], env: voxEnv).out
            if !list.contains(bobFp) { Thread.sleep(forTimeInterval: 0.5) }
        }
        XCTAssertTrue(list.contains(bobFp) && !list.contains(carolFp),
                      "PRODUCT: the passphrase typed for bob's change must trust bob, and not carol; `vox trust list` says \(list)")
        print("[proof] keyring: bob's change named and waiting; carol's offer showed only the waiting line; a second change asked first; the passphrase trusted bob only")
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

        let ui = voxApp(appPath)
        ui.launchEnvironment = voxEnv
        try launchVox(ui, appPath, env: ui.launchEnvironment, scratch: scratchPath)

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
        // the manual check manual.login_item); then the one node is asked for, and a wrong
        // passphrase is the daemon's sentence.
        words(ui, Key.id("login-item-why"), timeout: 30,
              "at first run the app must ask whether to keep the daemon running, saying what that does",
              until: { $0.contains("keeps Vox running in the background while you're logged in, even with the app closed") })
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
        // Alice is the one node on this Mac: the app acts as her without asking which, and asks
        // only for her passphrase.
        let field = Key.id("passphrase")
        present(ui, field, timeout: 30,
                "with one node on this Mac, the app must ask for node alice's passphrase, not which node")
        type(ui, field, "not the passphrase", "the passphrase field")
        tap(ui, Key.id("attach"), "Attach")
        words(ui, Key.id("said"), timeout: 30,
              "a wrong passphrase must show the daemon's own sentence where it was typed",
              until: { $0.lowercased().contains("that passphrase does not open node alice's identity") })

        // (2) The right one attaches it, pasted with ⌘V, as from a password manager (v0.4.1).
        if let held = paste(ui, field, "alice identity", "the passphrase field") {
            if held.count != "alice identity".count {
                XCTFail("PRODUCT: ⌘V into the passphrase field must paste the passphrase on the pasteboard (\("alice identity".count) characters); the field holds \(held.count)")
            }
        } else if locate(ui, field) != nil {
            XCTFail("APPARATUS: XCTest reads no value from the passphrase field after ⌘V")
        }
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
              until: { $0.hasPrefix("bob, trusted both ways") || $0.hasPrefix("bob, waiting for the other side") })
        // Off the room, so a message to alice is unread: a room on screen is read.
        tap(ui, Key.id("keyring"), "Keyring in the sidebar")
        try staged(vox, ["room", "post", "--node", "bob", "--to", aliceFp, room, "NEEDS-YOU"],
                   env: bobSession)
        words(ui, Key.id("group-needs you"), timeout: 60,
              "a message to alice must list the room under \"needs you (1)\"",
              until: { $0.lowercased() == "needs you (1)" })
        let row = Key.id("room-mission")
        words(ui, row, timeout: 10, "the room's row must say it needs you",
              until: { $0.contains("needs you") })
        tap(ui, row, "mission in the sidebar", premise: inRoom(vox, voxEnv, "mission"))
        let bob = Key.id("member-bob")
        let bobWords = words(ui, bob, timeout: 30, "the inspector must list bob in alice's keyring",
                             until: { $0.hasPrefix("bob, trusted both ways") || $0.hasPrefix("bob, waiting for the other side") }) ?? ""
        let bar = words(ui, Key.id("status"), timeout: 10,
                        "the status bar must say the node, its peers and the keyring window",
                        until: { $0.contains("node alice") && $0.contains("peer") && $0.contains("keyring") }) ?? ""
        let regrouped = words(ui, Key.id("group-needs you"), timeout: 10,
                              "the room shown is read, so nothing needs alice: \"needs you (0)\"",
                              until: { $0.lowercased() == "needs you (0)" }) ?? ""
        print("[proof] grouped: needs you (1), then \(regrouped); inspector: \(bobWords); status: \(bar)")

        // (3b) The platform bob's node says it runs on (ADR-020 §4.9b): a claim of a resource has
        // bob's session announce itself, and Vox fills its hello's os, os_version and arch from
        // the machine. What the inspector must say is what that hello says, read through `vox`.
        // Whether the claim is won does not matter here: its hello is posted first, either way.
        _ = run(vox, ["room", "claim", "--node", "bob", room, "platform-proof"], env: bobSession)
        var claimed: (os: String, version: String, arch: String)?
        let helloUntil = Date().addingTimeInterval(30)
        while Date() < helloUntil && claimed == nil {
            for line in run(vox, ["room", "read", "--node", "bob", "--json", room], env: voxEnv).out
                .split(separator: "\n") {
                guard let row = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                      let env = row["envelope"] as? [String: Any], env["type"] as? String == "hello",
                      let data = env["data"] as? [String: Any],
                      let os = data["os"] as? String, !os.isEmpty else { continue }
                claimed = (os, data["os_version"] as? String ?? "", data["arch"] as? String ?? "")
            }
            if claimed == nil { Thread.sleep(forTimeInterval: 1) }
        }
        guard let claimed else {
            throw Apparatus("bob's claim was to post his session's hello with os, os_version and arch, and `vox room read --node bob --json` shows none in 30 s, so the inspector's claim cannot be checked")
        }
        let platform = [[claimed.os, claimed.version].filter { !$0.isEmpty }.joined(separator: " "),
                        claimed.arch.isEmpty ? "" : "(\(claimed.arch))"]
            .filter { !$0.isEmpty }.joined(separator: " ")
        let says = "bob says it runs on \(platform)"
        words(ui, Key.id("member-platform-bob"), timeout: 30,
              "alice's inspector must say, under bob, the platform his node's hello claims: \"\(says)\"",
              until: { $0 == says })
        print("[proof] inspector: \(says)")

        // (3d) Watching a Session (P7), and what comes meanwhile in General (D18). bob's agent
        // session opens a Session in mission through its hook, as Claude Code's does, and bob's
        // node lets alice read it (drive). Its 60 tool calls are more than the timeline shows,
        // with room to spare on a tall display.
        try staged(vox, ["trust", "drive", "--node", "bob", aliceFp,
                         "--identity-passphrase-file", bobPass], env: voxEnv)
        let sid = "p7proofs-session"
        let hookEnv = voxEnv.merging(["CLAUDE_CODE_ENTRYPOINT": "cli"]) { $1 }
        func hook(_ event: [String: Any]) throws {
            var input: [String: Any] = ["session_id": sid, "cwd": "/tmp",
                                        "transcript_path": "/tmp/p7.jsonl"]
            input.merge(event) { $1 }
            let json = String(decoding: try JSONSerialization.data(withJSONObject: input), as: UTF8.self)
            let r = run(vox, ["agent", "hook", "--node", "bob", "--room", room], env: hookEnv, input: json)
            guard r.status == 0 else {
                throw Apparatus("bob's session hook (\(event["hook_event_name"] ?? "")) exited \(r.status): \(r.out)")
            }
        }
        // A tool call is its PreToolUse and its PostToolUse: the Session's line is the call
        // ("Bash: echo P7-LINE-n → P7-LINE-n"); a result with no call shows nothing.
        // Three digits, so no line's name is part of another's ("P7-LINE-1" is in "P7-LINE-12").
        func p7Line(_ n: Int) -> String { String(format: "P7-LINE-%03d", n) }
        func toolCall(_ n: Int) throws {
            let call: [String: Any] = ["tool_name": "Bash", "tool_use_id": "p7-\(n)",
                                       "tool_input": ["command": "echo \(p7Line(n))"]]
            try hook(call.merging(["hook_event_name": "PreToolUse"]) { $1 })
            try hook(call.merging(["hook_event_name": "PostToolUse",
                                   "tool_response": ["stdout": p7Line(n), "stderr": "",
                                                     "interrupted": false]]) { $1 })
        }
        // What alice's node holds of the Session, as `vox room session` prints it to her.
        func sessionHolds(_ text: String, within seconds: TimeInterval) -> Bool {
            let end = Date().addingTimeInterval(seconds)
            repeat {
                let r = run(vox, ["room", "session", "--node", "alice", room, "p7proofs"], env: voxEnv)
                if r.status == 0 && r.out.contains(text) { return true }
                Thread.sleep(forTimeInterval: 1)
            } while Date() < end
            return false
        }
        try hook(["hook_event_name": "UserPromptSubmit", "prompt": "sort the photos"])
        for n in 1...60 { try toolCall(n) }
        guard sessionHolds("P7-LINE-060", within: 60) else {
            throw Apparatus("bob's Session never showed P7-LINE-060 to alice's node: `vox room session --node alice` says \(run(vox, ["room", "session", "--node", "alice", room, "p7proofs"], env: voxEnv).out.suffix(600)), so the app's Session cannot be checked")
        }
        let sessionRow = Key.id("session-p7proofs")
        present(ui, sessionRow, timeout: 60,
                "bob's Session, opened by his session's hook, must be listed in mission")
        // D18's premise: what mission's row counts as new before anything is posted.
        func newCount() -> Int? {
            let words = shown(el(ui, Key.id("room-mission")))
            guard let r = words.range(of: #"(\d+) new"#, options: .regularExpression) else { return 0 }
            return Int(words[r].split(separator: " ")[0])
        }
        // In view: at least half of it inside the timeline's frame, as Seen counts a row seen.
        // (Hit-testing is not this: the line at the bottom of the timeline, drawn and in view in
        // the first run's kept tree, was still not hittable, a false red.)
        func inTimeline(_ key: Key) -> Bool {
            let e = el(ui, key), t = el(ui, Key.id("timeline"))
            guard e.exists, t.exists else { return false }
            let shown = e.frame.intersection(t.frame)
            return !shown.isNull && shown.height * 2 >= e.frame.height
        }
        tap(ui, sessionRow, "bob's Session")
        let newestLine = Key.showing("P7-LINE-060")
        let openedUntil = Date().addingTimeInterval(20)
        while Date() < openedUntil && !inTimeline(newestLine) { Thread.sleep(forTimeInterval: 0.25) }
        if inTimeline(Key.showing("P7-LINE-001")) && inTimeline(newestLine) {
            throw Apparatus("all 60 of the Session's lines fit in the timeline, so opening at its newest cannot be told from opening at its top")
        }
        if !inTimeline(newestLine) {
            keepTree(ui, "the Session did not open at its newest line")
            XCTFail("PRODUCT: a Session opened must show its newest line, P7-LINE-060, in view; it is not on screen 20 s after bob's Session was chosen")
        }
        try toolCall(61)
        guard sessionHolds("P7-LINE-061", within: 30) else {
            throw Apparatus("bob's 61st tool call never reached alice's node (`vox room session --node alice`), so following it cannot be checked")
        }
        let followUntil = Date().addingTimeInterval(30)
        while Date() < followUntil && !inTimeline(Key.showing("P7-LINE-061")) {
            Thread.sleep(forTimeInterval: 0.25)
        }
        if !inTimeline(Key.showing("P7-LINE-061")) {
            keepTree(ui, "the Session did not follow its new line")
            XCTFail("PRODUCT: a Session watched at its newest line must follow what it prints next; P7-LINE-061 is not on screen 30 s after bob's session made it")
        }
        // D18: a message to the room while the Session is shown is not seen, so it counts.
        guard let before = newCount() else {
            throw Apparatus("mission's sidebar row could not be read")
        }
        try staged(vox, ["room", "post", "--node", "bob", room, "D18-UNSEEN"], env: voxEnv)
        var counted = before
        let countUntil = Date().addingTimeInterval(30)
        while Date() < countUntil && counted <= before {
            counted = newCount() ?? before
            if counted <= before { Thread.sleep(forTimeInterval: 0.5) }
        }
        if counted <= before {
            keepTree(ui, "a message posted while a Session was shown was not counted")
            XCTFail("PRODUCT: bob's D18-UNSEEN, posted to mission while alice watched a Session there, is not seen, so mission's row must count it new; it says \"\(shown(el(ui, Key.id("room-mission"))))\" (\(before) new before)")
        }
        tap(ui, Key.id("session-general"), "General")
        let seenUntil = Date().addingTimeInterval(20)
        var after = counted
        while Date() < seenUntil && after >= counted {
            after = newCount() ?? counted
            if after >= counted { Thread.sleep(forTimeInterval: 0.5) }
        }
        if after >= counted {
            keepTree(ui, "a message seen in General was still counted")
            XCTFail("PRODUCT: General shown with D18-UNSEEN in view must read it, so mission's row counts one fewer new; it still says \"\(shown(el(ui, Key.id("room-mission"))))\"")
        }
        print("[proof] Session opened at P7-LINE-060 and followed P7-LINE-061; D18-UNSEEN counted while a Session was shown (\(before) → \(counted) new), read once General showed it (\(after))")

        // (3c) The family LAN asks for its helper only when turned on (the app review's proposal 4): a sheet
        // that names where to allow it, waits, and, once macOS says it is allowed and the person is
        // back in Vox, closes by itself and asks the daemon to bring the LAN up. The helper is the
        // proof build's stand-in (VOX_PROOF_STUB_SERVICES): it registers nothing, and here makes
        // register wait for an approval the proof gives by writing its file, as the person's switch
        // in System Settings would.
        let helperFile = config + "/app/proof-lan-helper"
        try stager.write(Data("ask\n".utf8), to: helperFile + ".approval")
        tap(ui, Key.id("family-lan"), "the family LAN's toggle in mission's inspector")
        let steps = words(ui, Key.id("lan-helper-steps"), timeout: 15,
                          "turning the family LAN on, with no LAN helper allowed, must ask for it and say where: \"System Settings › General › Login Items & Extensions\", then \"Allow in the Background\"",
                          until: { $0.contains("System Settings › General › Login Items & Extensions")
                              && $0.contains("Allow in the Background") }) ?? ""
        present(ui, Key.id("lan-helper-waiting"), timeout: 5,
                "the LAN helper's sheet must say it is waiting for the person to allow it")
        let asked = stager.run(["/bin/cat", helperFile], env: [:]).out
        guard asked.hasPrefix("awaiting-approval") else {
            throw Apparatus("the stand-in LAN helper was to wait for approval once registered; its file says \"\(asked)\", so the wait for the person cannot be staged")
        }
        // The person goes to System Settings, turns Vox on there, and comes back. The proof hands
        // the foreground away itself, so it is not counted as lost.
        handedOff = true
        XCUIApplication(bundleIdentifier: "com.apple.finder").activate()
        try stager.write(Data("registered vox-proof-service-stand-in\n".utf8), to: helperFile)
        ui.activate()
        var sheetGone = false
        let allowedUntil = Date().addingTimeInterval(15)
        while Date() < allowedUntil && !sheetGone {
            sheetGone = locate(ui, Key.id("lan-helper-sheet")) == nil
                && locate(ui, Key.id("lan-helper-waiting")) == nil
            if !sheetGone { Thread.sleep(forTimeInterval: 0.25) }
        }
        if !sheetGone {
            keepTree(ui, "the LAN helper's sheet stayed after approval")
            XCTFail("PRODUCT: once the LAN helper is allowed and Vox is in front again, its sheet must close by itself and the LAN go on; after 15 s it still says \"\(shown(el(ui, Key.id("lan-helper-waiting"))))\"")
        } else {
            // The LAN asked of the daemon: its line, or why it could not (no real helper runs here).
            var answer = ""
            let answerUntil = Date().addingTimeInterval(15)
            while Date() < answerUntil && answer.isEmpty {
                for key in [Key.id("family-lan-said"), Key.id("family-lan-failed")] {
                    if let e = locate(ui, key) { answer = shown(e) }
                }
                if answer.isEmpty { Thread.sleep(forTimeInterval: 0.25) }
            }
            if answer.isEmpty {
                keepTree(ui, "the family LAN was not asked for after approval")
                XCTFail("PRODUCT: with the LAN helper allowed, Vox must go on to turn mission's family LAN on and say the daemon's answer; the inspector shows neither family-lan-said nor family-lan-failed")
            }
            print("[proof] family LAN: asked (\(steps)); allowed; the daemon said \(answer)")
        }
        try stager.write(Data("unregistered vox-proof-service-stand-in\n".utf8), to: helperFile)

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
        // Bob's message, selected by dragging across it and copied, as a person copies what a
        // member wrote (v0.4.1).
        if windowReadable(ui) {
            if let body = textSaying(ui, "NEEDS-YOU") {
                let copied = selectAndCopy(ui, body, "bob's message NEEDS-YOU")
                XCTAssertEqual(copied, "NEEDS-YOU",
                               "PRODUCT: bob's message, selected by dragging across it and copied with ⌘C, must put NEEDS-YOU on the pasteboard; it holds \(copied.debugDescription)")
            } else {
                keepTree(ui, "no Text says exactly NEEDS-YOU")
                XCTFail("APPARATUS: XCTest finds no element whose words are exactly NEEDS-YOU, though bob's message was read on alice's screen")
            }
        }
        // A sidebar row's name, whose words a drag cannot select (it selects the row): copied
        // from its right-click Copy Name (v0.4.1).
        let missionRow = Key.id("room-mission")
        if present(ui, missionRow, timeout: 10, "the sidebar must list mission") {
            let named = copiedBy(ui, {
                self.el(ui, missionRow).rightClick()
                self.tap(ui, Key.menuItem("Copy Name"), "Copy Name in mission's right-click menu")
            })
            XCTAssertEqual(named, "mission",
                           "PRODUCT: Copy Name in the right-click menu of mission's sidebar row must put mission on the pasteboard; it holds \(named.debugDescription)")
        }
        // Hidden (⌘H), alice's app shows nobody bob's next message: it is not read.
        handOff(ui, "h")
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
        // Pasted (⌘V), then sent with Return (v0.4.1).
        let composed = paste(ui, compose, "FROM-ALICE", "the composer")
        if composed != "FROM-ALICE" {
            XCTFail("PRODUCT: ⌘V into the composer must paste FROM-ALICE; it holds \(composed.debugDescription)")
        }
        el(ui, compose).typeText("\r")
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

        // (4b) Several messages copied at once (v0.4.1): three of bob's, by a drag from the first
        // to the last, by ⇧-click, by ⌘-click with Edit › Copy, and by ⇧↑ from the keyboard. Each
        // copies "<author>, <time>: <text>" lines, oldest first, the times as alice's node has them.
        let three = ["COPY ONE", "COPY TWO", "COPY THREE"]
        for text in three {
            try staged(vox, ["room", "post", "--node", "bob", room, text], env: voxEnv)
        }
        var postedAt: [String: UInt64] = [:]
        let postedUntil = Date().addingTimeInterval(60)
        while Date() < postedUntil && postedAt.count < three.count {
            let rows = run(vox, ["room", "read", "--node", "alice", "--json", room], env: voxEnv).out
            for line in rows.split(separator: "\n") {
                guard let row = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                      let text = row["text"] as? String, three.contains(text),
                      let at = (row["created_millis"] as? NSNumber)?.uint64Value else { continue }
                postedAt[text] = at
            }
            if postedAt.count < three.count { Thread.sleep(forTimeInterval: 0.5) }
        }
        guard postedAt.count == three.count else {
            throw Apparatus("alice's `vox room read --json` holds \(postedAt.count) of bob's three COPY posts after 60 s")
        }
        let want = three.sorted { postedAt[$0]! < postedAt[$1]! }
            .map { "bob, \(copiedTime(postedAt[$0]!)): \($0)" }.joined(separator: "\n")
        var shownRows: [XCUIElement] = []
        for text in three {
            let until = Date().addingTimeInterval(30)
            var row: XCUIElement?
            while Date() < until && row == nil {
                row = rowSaying(ui, "bob: \(text)")
                if row == nil { Thread.sleep(forTimeInterval: 0.25) }
            }
            guard let row else {
                keepTree(ui, "no row says bob: \(text)")
                XCTFail("PRODUCT: alice's timeline must show bob's \(text) as its own row within 30 s")
                return
            }
            shownRows.append(row)
        }
        // A click on a row's empty right side selects the row, never its words.
        func click(_ row: XCUIElement, _ keys: XCUIElement.KeyModifierFlags = []) {
            if !inView(ui, row) { scrollTo(ui, row) }
            let at = row.coordinate(withNormalizedOffset: CGVector(dx: 0.97, dy: 0.5))
            XCUIElement.perform(withKeyModifiers: keys) { at.click() }
        }
        func check(_ how: String, _ copied: String) {
            XCTAssertEqual(copied, want,
                           "PRODUCT: bob's three messages, \(how), must copy as \(want.debugDescription); the pasteboard holds \(copied.debugDescription)")
        }
        // A drag from the first message's words to the last's.
        if let first = textSaying(ui, three[0]), let last = textSaying(ui, three[2]) {
            check("selected by a drag from the first to the last and copied with ⌘C", copiedBy(ui, {
                let from = first.coordinate(withNormalizedOffset: CGVector(dx: 0, dy: 0.5)).withOffset(CGVector(dx: 1, dy: 0))
                let to = last.coordinate(withNormalizedOffset: CGVector(dx: 1, dy: 0.5)).withOffset(CGVector(dx: -1, dy: 0))
                from.click(forDuration: 0.3, thenDragTo: to)
                ui.typeKey("c", modifierFlags: .command)
            }))
        } else {
            keepTree(ui, "no Text says exactly a COPY post")
            XCTFail("APPARATUS: XCTest finds no element whose words are exactly COPY ONE and COPY THREE, though their rows are shown")
        }
        check("the first clicked and the last ⇧-clicked, copied with ⌘C", copiedBy(ui, {
            click(shownRows[0])
            click(shownRows[2], .shift)
            ui.typeKey("c", modifierFlags: .command)
        }))
        check("the first clicked and the others ⌘-clicked, copied with Edit › Copy", copiedBy(ui, {
            click(shownRows[0])
            click(shownRows[1], .command)
            click(shownRows[2], .command)
            ui.menuBars.menuBarItems["Edit"].click()
            self.tap(ui, Key.menuItem("Copy"), "Edit › Copy")
        }))
        check("the last clicked and ⇧↑ pressed twice, copied with ⌘C", copiedBy(ui, {
            click(shownRows[2])
            ui.typeKey(.upArrow, modifierFlags: .shift)
            ui.typeKey(.upArrow, modifierFlags: .shift)
            ui.typeKey("c", modifierFlags: .command)
        }))
        print("[proof] three messages copied four ways: \(want.debugDescription)")

        // (4c) A reply quotes what it answers, and the quote goes to it (ADR-028 R-9, D6): bob
        // replies to FROM-ALICE; alice's timeline shows "re you: FROM-ALICE" above his reply, and
        // clicking it, or ⌘↑ with the reply selected, selects FROM-ALICE.
        func entry(_ text: String) -> String? {
            let rows = run(vox, ["room", "read", "--node", "alice", "--json", room], env: voxEnv).out
            for line in rows.split(separator: "\n") {
                guard let row = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                      (row["text"] as? String)?.contains(text) == true else { continue }
                return row["entry_hash"] as? String
            }
            return nil
        }
        guard let fromAlice = entry("FROM-ALICE") else {
            throw Apparatus("alice's `vox room read --json` holds no FROM-ALICE to reply to")
        }
        try staged(vox, ["room", "post", "--node", "bob", "--re", fromAlice, room, "REPLY-TO-ALICE"],
                   env: voxEnv)
        let quote = Key.idPrefix("quote-")
        words(ui, quote, timeout: 30,
              "bob's reply must show what it replies to, quoted above it: \"re you: FROM-ALICE\"",
              until: { $0 == "re you: FROM-ALICE" })
        func selectedRow(_ start: String) -> Bool? {
            let row = ui.windows.firstMatch.descendants(matching: .any)
                .matching(rowSays(start)).firstMatch
            return row.exists ? row.isSelected : nil
        }
        func reaches(_ how: String, _ act: () -> Void) {
            // From the reply, so a selection of FROM-ALICE is the jump's.
            tap(ui, Key.showing(": REPLY-TO-ALICE"), "bob's reply")
            act()
            let until = Date().addingTimeInterval(5)
            var now = selectedRow("you: FROM-ALICE")
            while Date() < until && now != true {
                Thread.sleep(forTimeInterval: 0.2)
                now = selectedRow("you: FROM-ALICE")
            }
            switch now {
            case nil:
                keepTree(ui, "no row starts \"you: FROM-ALICE\"")
                XCTFail("APPARATUS: XCTest finds no row saying \"you: FROM-ALICE\", though its reply quotes it")
            case false?:
                XCTFail("PRODUCT: \(how) must select the message the reply quotes, FROM-ALICE; it is not selected")
            case true?:
                break
            }
        }
        reaches("clicking the reply's quote") { tap(ui, quote, "the reply's quote") }
        reaches("⌘↑ with the reply selected") { ui.typeKey(.upArrow, modifierFlags: .command) }
        print("[proof] bob's reply quotes \"re you: FROM-ALICE\", and its quote and ⌘↑ go to it")

        // (4d) To: offers bob's open Session under him, and a message to it alone is addressed to
        // that Session (MADR W-4, ADR-029 TA-1, D7): bob's Claude Code session opens a Session in
        // mission by its hook, as a person's does; alice ticks it in To: and posts; bob's node holds
        // the post addressed to <bob>/<session>, as `vox room post --to bob/<session>` sends it.
        let d7Session = "d7-proof-session"
        let opened = run(vox, ["agent", "hook", "--node", "bob", "--room", room, "--format", "text"],
                         env: voxEnv.merging(["CLAUDE_CODE_ENTRYPOINT": "cli"]) { $1 },
                         input: "{\"session_id\":\"\(d7Session)\",\"hook_event_name\":\"UserPromptSubmit\",\"cwd\":\"/tmp\",\"transcript_path\":\"/tmp/t.jsonl\",\"prompt\":\"go\"}")
        guard opened.status == 0 else {
            throw Apparatus("bob's Claude Code hook, to open a Session in mission, exited \(opened.status): \(opened.out)")
        }
        let sessionsUntil = Date().addingTimeInterval(30)
        var listed = ""
        while Date() < sessionsUntil && !listed.contains(d7Session.prefix(8)) {
            listed = run(vox, ["room", "sessions", "--node", "alice", room], env: voxEnv).out
            if !listed.contains(d7Session.prefix(8)) { Thread.sleep(forTimeInterval: 0.5) }
        }
        guard listed.contains(d7Session.prefix(8)) else {
            throw Apparatus("alice's `vox room sessions` never listed bob's Session \(d7Session) in 30 s: \(listed)")
        }
        let toBox = Key.id("compose-to")
        tap(ui, toBox, "To:")
        // By its own id: bob has another Session open in mission (bob-proof, his hook's from step 4).
        tap(ui, Key.id("to-bob-\(d7Session.prefix(8))"), "bob's open Session \(d7Session) under bob in To:",
            premise: Premise("alice's `vox room sessions` lists bob's open Session \(d7Session)") {
                let now = self.run(vox, ["room", "sessions", "--node", "alice", room], env: voxEnv).out
                return (now.contains(d7Session.prefix(8)), now)
            })
        ui.typeKey(.escape, modifierFlags: [])
        type(ui, Key.id("compose"), "TO-BOB-SESSION\r", "the composer")
        var addressedTo: [String] = []
        let addressedUntil = Date().addingTimeInterval(30)
        while Date() < addressedUntil && addressedTo.isEmpty {
            let rows = run(vox, ["room", "read", "--node", "bob", "--json", room], env: voxEnv).out
            for line in rows.split(separator: "\n") {
                guard let row = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                      (row["text"] as? String)?.contains("TO-BOB-SESSION") == true else { continue }
                addressedTo = (row["envelope"] as? [String: Any])?["to"] as? [String] ?? ["(not addressed)"]
            }
            if addressedTo.isEmpty { Thread.sleep(forTimeInterval: 0.5) }
        }
        XCTAssertTrue(addressedTo.count == 1 && addressedTo[0].hasSuffix("/\(d7Session)")
                      && addressedTo[0].lowercased().hasPrefix(bobFp.lowercased()),
                      "PRODUCT: alice's post with bob's Session ticked in To: must be addressed to that Session alone, <bob>/\(d7Session); bob's node holds it addressed to \(addressedTo)")
        print("[proof] To: bob's Session: the post is addressed to \(addressedTo)")

        // (4e) @alias (ADR-028 K-4, D8): typing "@b" in the composer offers @bob; picked, it is
        // written in full and bob is addressed, as ticking him in To: does.
        // From an empty To:: bob's d7 Session, ticked in 4d, stays ticked in the room after its post.
        tap(ui, Key.id("compose-to"), "To:")
        tap(ui, Key.id("to-bob-\(d7Session.prefix(8))"), "bob's Session \(d7Session), ticked in 4d, to untick it")
        ui.typeKey(.escape, modifierFlags: [])
        words(ui, Key.id("compose-to"), timeout: 10, "To: with bob's Session unticked must say the room",
              until: { $0 == "To: the room" })
        let composeBox = Key.id("compose")
        type(ui, composeBox, "MENTION @b", "the composer")
        tap(ui, Key.id("mention-bob"), "@bob offered for \"@b\"",
            premise: member(vox, voxEnv, room, bobFp, "bob"))
        words(ui, Key.id("compose-to"), timeout: 10, "@bob picked must address bob, as To: says",
              until: { $0 == "To: bob" })
        el(ui, composeBox).typeText("\r")
        var mentionedTo: [String] = []
        let mentionUntil = Date().addingTimeInterval(30)
        while Date() < mentionUntil && mentionedTo.isEmpty {
            let rows = run(vox, ["room", "read", "--node", "bob", "--json", room], env: voxEnv).out
            for line in rows.split(separator: "\n") {
                guard let row = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                      (row["text"] as? String)?.contains("MENTION @bob") == true else { continue }
                mentionedTo = (row["envelope"] as? [String: Any])?["to"] as? [String] ?? ["(not addressed)"]
            }
            if mentionedTo.isEmpty { Thread.sleep(forTimeInterval: 0.5) }
        }
        XCTAssertEqual(mentionedTo.map { $0.lowercased() }, [bobFp.lowercased()],
                       "PRODUCT: \"MENTION @bob\", @bob picked in the composer, must be addressed to bob; bob's node holds it addressed to \(mentionedTo)")

        // (4e2) The composer takes more than one line (P19): ⇧↩ adds a line, Return sends both.
        // ⇧↩, not ⌥↩: a Mac's global hotkey may take ⌥↩ (the decider's brings Alacritty forward).
        // To the room, so bob's node holds the text alone: 4e left bob ticked in To:, and an
        // addressed post is held as its envelope.
        tap(ui, Key.id("compose-to"), "To:")
        tap(ui, Key.id("to-bob"), "bob, ticked in 4e by @bob, to untick him")
        ui.typeKey(.escape, modifierFlags: [])
        words(ui, Key.id("compose-to"), timeout: 10, "To: with bob unticked must say the room",
              until: { $0 == "To: the room" })
        type(ui, Key.id("compose"), "LINE ONE", "the composer")
        el(ui, Key.id("compose")).typeKey(.return, modifierFlags: .shift)
        el(ui, Key.id("compose")).typeText("LINE TWO\r")
        var twoLines: String?
        let linesUntil = Date().addingTimeInterval(30)
        while Date() < linesUntil && twoLines == nil {
            let rows = run(vox, ["room", "read", "--node", "bob", "--json", room], env: voxEnv).out
            for line in rows.split(separator: "\n") {
                guard let row = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                      let text = row["text"] as? String, text.contains("LINE TWO") else { continue }
                twoLines = text
            }
            if twoLines == nil { Thread.sleep(forTimeInterval: 0.5) }
        }
        XCTAssertEqual(twoLines, "LINE ONE\nLINE TWO",
                       "PRODUCT: \"LINE ONE\", ⇧↩, \"LINE TWO\", Return in the composer must post one message of two lines; bob's node holds \(twoLines.debugDescription)")

        // (4f) ↑/↓ reach a Session's entries (P14): bob grants alice drive, so she reads inside his
        // Session; with it shown, View > Focus Timeline selects its newest entry and ↑ the one
        // before it, as among messages.
        try staged(vox, ["trust", "drive", "--node", "bob", aliceFp,
                         "--identity-passphrase-file", bobPass], env: voxEnv)
        let again = run(vox, ["agent", "hook", "--node", "bob", "--room", room, "--format", "text"],
                        env: voxEnv.merging(["CLAUDE_CODE_ENTRYPOINT": "cli"]) { $1 },
                        input: "{\"session_id\":\"\(d7Session)\",\"hook_event_name\":\"UserPromptSubmit\",\"cwd\":\"/tmp\",\"transcript_path\":\"/tmp/t.jsonl\",\"prompt\":\"again\"}")
        guard again.status == 0 else {
            throw Apparatus("bob's Claude Code hook, to write a second entry in his Session, exited \(again.status): \(again.out)")
        }
        tap(ui, Key.id("session-\(d7Session.prefix(8))"), "bob's Session in mission's Sessions")
        let entryRows = ui.windows.firstMatch.descendants(matching: .any)
            .matching(NSPredicate(format: "identifier BEGINSWITH %@", "entry-row-"))
        let entriesUntil = Date().addingTimeInterval(30)
        while Date() < entriesUntil && entryRows.count < 2 { Thread.sleep(forTimeInterval: 0.5) }
        guard entryRows.count >= 2 else {
            keepTree(ui, "bob's Session shows fewer than two entries")
            throw Product("bob's Session, shown to alice whom bob trusts with drive, must show its two entries; it shows \(entryRows.count)")
        }
        let rows = entryRows.allElementsBoundByIndex.sorted { $0.frame.minY < $1.frame.minY }
        ui.typeKey("t", modifierFlags: [.command, .control])
        func onlySelected(_ want: XCUIElement, _ how: String) {
            let until = Date().addingTimeInterval(5)
            while Date() < until && !want.isSelected { Thread.sleep(forTimeInterval: 0.2) }
            XCTAssertTrue(want.isSelected && rows.filter(\.isSelected).count == 1,
                          "PRODUCT: \(how) must select \(want.identifier) alone; selected: \(rows.filter(\.isSelected).map(\.identifier))")
        }
        onlySelected(rows[rows.count - 1], "View > Focus Timeline on bob's Session")
        ui.typeKey(.upArrow, modifierFlags: [])
        onlySelected(rows[rows.count - 2], "↑ from the newest entry")

        // (5) The keyring: carol, a node made here, added by her pasted fingerprint, then removed.
        try staged(vox, ["node", "create", "carol"],
                   env: voxEnv.merging(["VOX_IDENTITY_PASSPHRASE": "carol identity"]) { $1 })
        let carolFp = try line(staged(vox, ["id", "--node", "carol"], env: voxEnv)) { $0.count == 52 }
        tap(ui, Key.id("keyring"), "Keyring in the sidebar")
        let addFp = Key.id("keyring-add-fingerprint")
        present(ui, addFp, timeout: 10, "the keyring view must offer to add a node")
        // Pasted from Edit › Paste, as the field invites ("paste or type", v0.4.1).
        let pastedFp = paste(ui, addFp, carolFp, "the fingerprint field", fromMenu: true)
        if pastedFp != carolFp {
            XCTFail("PRODUCT: Edit › Paste into the fingerprint field must paste carol's fingerprint \(carolFp); it holds \(pastedFp.debugDescription)")
        }
        let addAlias = Key.id("keyring-add-alias")
        // An alias the same as bob's but for case is warned of before it is given (K-4, D8).
        type(ui, addAlias, "BOB", "the alias field")
        words(ui, Key.id("alias-clash"), timeout: 10,
              "an alias the same as bob's but for case must be warned of before it is given",
              until: { $0.contains("Your keyring already has bob") })
        el(ui, addAlias).typeKey("a", modifierFlags: .command)
        el(ui, addAlias).typeText(XCUIKeyboardKey.delete.rawValue)
        type(ui, addAlias, "carol", "the alias field")
        // The effect sentences are Texts: their words are their accessibility value.
        words(ui, Key.id("keyring-add-effect"), timeout: 10,
              "adding must say what trusting does before it is done",
              until: { $0.contains("it may read what you write") })
        tap(ui, Key.id("keyring-trust"), "Trust")
        let carolRow = Key.id("keyring-row-carol")
        keyringPassphraseIfAsked(ui) { self.locate(ui, carolRow) != nil }
        present(ui, carolRow, timeout: 30, "carol, once trusted, must be listed in the keyring view")
        // Her grouped fingerprint, selected and copied, as a person copies it to compare (v0.4.1).
        let copiedFp = selectAndCopy(ui, Key.id("keyring-fingerprint-carol"), "carol's grouped fingerprint")
        if copiedFp.filter({ !$0.isWhitespace }) != carolFp {
            XCTFail("PRODUCT: carol's grouped fingerprint, selected by dragging across it and copied with ⌘C, must put her fingerprint \(carolFp) on the pasteboard; it holds \(copiedFp.debugDescription)")
        }
        let trustList = run(vox, ["trust", "list", "--node", "alice"], env: voxEnv).out
        XCTAssertTrue(trustList.contains(carolFp),
                      "PRODUCT: `vox trust list` must list carol once the app trusted her; it said: \(trustList)")
        tap(ui, Key.id("keyring-remove-carol"), "Remove… on carol",
            premise: trusted(vox, voxEnv, carolFp, "carol"))
        words(ui, Key.id("keyring-remove-effect"), timeout: 10,
              "removing must say what removing does before it is done",
              until: { $0.contains("reads nothing you write from now on") })
        tap(ui, Key.id("keyring-remove-confirm"), "Remove, in its sheet")
        keyringPassphraseIfAsked(ui) { self.locate(ui, carolRow) == nil }
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
        print("[proof] keyring: added and listed carol, then removed her after saying what removing does")

        // (5b) Two aliases the same but for case are told apart (ADR-028 K-4, D8): carol trusted as
        // "Bob", bob is shown in mission's members as bob#<his fingerprint's first 6>.
        try staged(vox, ["trust", "add", "--node", "alice", carolFp, "--name", "Bob",
                         "--identity-passphrase-file", alicePass], env: voxEnv)
        tap(ui, Key.id("room-mission"), "mission in the sidebar", premise: inRoom(vox, voxEnv, "mission"))
        present(ui, Key.id("member-bob#\(bobFp.prefix(6).lowercased())"), timeout: 30,
                "with carol trusted as \"Bob\", bob must be told apart in mission's members as bob#\(bobFp.prefix(6).lowercased())",
                premise: trusted(vox, voxEnv, carolFp, "Bob"))
        try staged(vox, ["trust", "remove", "--node", "alice", carolFp,
                         "--identity-passphrase-file", alicePass], env: voxEnv)

        }

        // (5d) Finding your way (v0.4.1). Each part is what a person sees, and stages what it needs
        // itself, so it runs from step 6 too (VOX_PROOF_FROM=6).
        //
        // The room's header: its name and its retention, always (R-7); the window takes its name.
        tap(ui, Key.id("room-mission"), "mission in the sidebar", premise: inRoom(vox, voxEnv, "mission"))
        // A room opens at what it last showed (D12), here bob's Session from 4f: General first.
        tap(ui, Key.id("session-general"), "General in mission's Sessions")
        words(ui, Key.id("room-header-name"), timeout: 10, "the room's header must name it: \"mission\"",
              until: { $0 == "mission" })
        words(ui, Key.id("room-header-meta"), timeout: 10,
              "the room's header must say what is shown and the room's retention: \"… · General · ⏱ …\"",
              until: { $0.contains("General") && $0.contains("⏱") })
        let titled = Date().addingTimeInterval(10)
        while Date() < titled && !ui.windows.firstMatch.title.hasPrefix("mission") {
            Thread.sleep(forTimeInterval: 0.25)
        }
        XCTAssertTrue(ui.windows.firstMatch.title.hasPrefix("mission"),
                      "PRODUCT: the window must take the room's name as its title; it is \"\(ui.windows.firstMatch.title)\"")

        // Who you can't read yet, and why: erin joins, and neither she nor alice has trusted the
        // other; then erin trusts alice, and the line says so and offers her offer.
        let erinPass = scratch.appendingPathComponent("erin.pass").path
        try stager.write(Data("erin identity\n".utf8), to: erinPass)
        try staged(vox, ["node", "create", "erin"],
                   env: voxEnv.merging(["VOX_IDENTITY_PASSPHRASE": "erin identity"]) { $1 })
        try staged(vox, ["node", "attach", "erin", "--passphrase-file", erinPass], env: voxEnv)
        let erinFp = try line(staged(vox, ["id", "--node", "erin"], env: voxEnv)) { $0.count == 52 }
        let erinLink = try line(staged(vox, ["room", "link", "--node", "alice", room], env: voxEnv)) {
            $0.hasPrefix("vox://")
        }
        try staged(vox, ["room", "join", "--node", "erin", "--passphrase-file", roomPass, erinLink],
                   env: voxEnv)
        let erinShort = String(erinFp.prefix(12))
        let banner = Key.id("trust-banner")
        words(ui, banner, timeout: 60,
              "erin joined and nobody trusted anybody: the room must say \"You and \(erinShort) can't read each other yet\"",
              until: { $0.contains(erinShort) && $0.contains("can't read each other") })
        try staged(vox, ["trust", "add", "--node", "erin", aliceFp, "--name", "alice",
                         "--identity-passphrase-file", erinPass], env: voxEnv)
        words(ui, banner, timeout: 60,
              "erin trusts alice now: the room must say \"\(erinShort) trusts you. Trust \(erinShort) too\"",
              until: { $0.contains("\(erinShort) trusts you") })
        present(ui, Key.id("trust-banner-offer"), timeout: 10,
                "the line must offer erin's trust offer, \"Trust \(erinShort)…\"")

        // The Dock badge: the same count as the sidebar's NEEDS YOU, read from what macOS shows.
        func badge() -> String {
            let id = Bundle(path: appPath)?.bundleIdentifier ?? ""
            let out = run("/usr/bin/lsappinfo", ["info", "-only", "StatusLabel", "-app", id], env: [:]).out
            guard let r = out.range(of: "\"label\"=\"") else { return "" }
            return String(out[r.upperBound...].prefix { $0 != "\"" })
        }
        let needs = words(ui, Key.id("group-needs you"), timeout: 10,
                          "the sidebar must count what needs alice", until: { $0.lowercased().hasPrefix("needs you (") }) ?? ""
        let counted = needs.filter(\.isNumber)
        var badged = ""
        let badgeUntil = Date().addingTimeInterval(10)
        while Date() < badgeUntil {
            badged = badge()
            if badged == (counted == "0" ? "" : counted) { break }
            Thread.sleep(forTimeInterval: 0.5)
        }
        XCTAssertEqual(badged, counted == "0" ? "" : counted,
                       "PRODUCT: the Dock badge must say what the sidebar's NEEDS YOU counts, \"\(needs)\"; macOS shows \"\(badged)\"")

        // Making an admin asks first; Cancel makes nobody an admin; Make Admin does.
        ui.typeKey("k", modifierFlags: .command)
        type(ui, Key.id("palette-query"), "Admins", "the command palette")
        ui.typeKey(.return, modifierFlags: [])
        let bobAdmin = Key.id("admin-bob")
        if present(ui, bobAdmin, timeout: 10, "the Admins sheet must list bob") {
            tap(ui, bobAdmin, "bob's admin switch")
            words(ui, Key.id("admin-confirm"), timeout: 10,
                  "turning bob into an admin must ask first, saying what an admin can do",
                  until: { $0.contains("Make bob an admin?") && $0.contains("end this room for everyone") })
            tap(ui, Key.id("admin-confirm-cancel"), "Cancel")
            let listed = run(vox, ["room", "admin", "list", "--node", "alice", room], env: voxEnv).out
            XCTAssertFalse(listed.contains(bobFp) || listed.contains("bob"),
                           "PRODUCT: Cancel must make nobody an admin; `vox room admin list` says: \(listed)")
            tap(ui, bobAdmin, "bob's admin switch")
            tap(ui, Key.id("admin-confirm-make"), "Make Admin")
            var made = ""
            let madeUntil = Date().addingTimeInterval(15)
            while Date() < madeUntil && !(made.contains(bobFp) || made.contains("bob")) {
                made = run(vox, ["room", "admin", "list", "--node", "alice", room], env: voxEnv).out
                Thread.sleep(forTimeInterval: 0.5)
            }
            XCTAssertTrue(made.contains(bobFp) || made.contains("bob"),
                          "PRODUCT: Make Admin must make bob an admin; `vox room admin list` says: \(made)")
            ui.typeKey(.return, modifierFlags: [])  // Done
        }

        // A vox:// link opened by the system fills in the Join sheet; nothing is joined by it.
        try staged(vox, ["room", "create", "--node", "bob", "--passphrase-file", roomPass, "--name", "orient"],
                   env: voxEnv)
        let orient = try line(staged(vox, ["room", "list", "--node", "bob"], env: voxEnv)) {
            $0.contains(" orient")
        }.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? ""
        let orientLink = try line(staged(vox, ["room", "link", "--node", "bob", orient], env: voxEnv)) {
            $0.hasPrefix("vox://")
        }
        _ = run("/usr/bin/open", ["-a", appPath, orientLink], env: [:])
        let linkField = Key.id("room-form-link")
        if present(ui, linkField, timeout: 15, "opening a vox:// link must open the Join sheet") {
            XCTAssertEqual(el(ui, linkField).value as? String, orientLink,
                           "PRODUCT: the Join sheet must hold the link Vox was opened with")
            ui.typeKey(.escape, modifierFlags: [])
        }
        Thread.sleep(forTimeInterval: 2)
        let aliceRooms = run(vox, ["room", "list", "--node", "alice"], env: voxEnv).out
        XCTAssertFalse(aliceRooms.contains(" orient"),
                       "PRODUCT: opening a room link must never join by itself; alice's `vox room list` says: \(aliceRooms)")

        // The composer says who posts (E-4): alice, before a field that names the room.
        tap(ui, Key.id("room-mission"), "mission in the sidebar", premise: inRoom(vox, voxEnv, "mission"))
        if present(ui, Key.id("compose-as"), timeout: 10, "the composer must say who posts: \"alice ▸\"") {
            let shownAs = el(ui, Key.id("compose-as"))
            XCTAssertTrue((shownAs.value as? String) == "alice ▸" || shownAs.label == "posting as alice",
                          "PRODUCT: the composer must say who posts, \"alice ▸\"; it shows \(String(describing: shownAs.value)) (\(shownAs.label))")
        }
        if present(ui, Key.id("compose"), timeout: 10, "the room must have its composer") {
            XCTAssertEqual(el(ui, Key.id("compose")).placeholderValue, "Message mission…",
                           "PRODUCT: the composer's field must name the room it posts to")
        }

        // A stopped node shows as detached, keeps what was typed, and attaches again.
        tap(ui, Key.id("room-mission"), "mission in the sidebar", premise: inRoom(vox, voxEnv, "mission"))
        type(ui, Key.id("compose"), "DRAFT-KEPT-P12", "the composer")
        try staged(vox, ["node", "detach", "alice"], env: voxEnv)
        words(ui, Key.id("node-stopped"), timeout: 30,
              "node alice was detached from outside: the window must say so",
              until: { $0.contains("detached") })
        present(ui, Key.id("detached"), timeout: 10, "the sidebar must say node alice is detached")
        XCTAssertEqual(el(ui, Key.id("compose")).value as? String, "DRAFT-KEPT-P12",
                       "PRODUCT: what was typed must stay while the node is detached")
        type(ui, Key.id("node-stopped-passphrase"), "alice identity", "the passphrase field")
        tap(ui, Key.id("node-stopped-attach"), "Attach Again")
        present(ui, Key.id("attached"), timeout: 60, "Attach Again must attach node alice again")
        XCTAssertEqual(el(ui, Key.id("compose")).value as? String, "DRAFT-KEPT-P12",
                       "PRODUCT: what was typed must still be there once the node is attached again")
        // The draft goes, so later steps start from an empty composer.
        tap(ui, Key.id("compose"), "the composer")
        ui.typeKey("a", modifierFlags: .command)
        ui.typeKey(.delete, modifierFlags: [])
        print("[proof] finding your way: header, who can't read whom, Dock badge \(badged.isEmpty ? "none" : badged), admin asked first, a link fills Join, a stopped node attaches again with its draft")
        // (5b) When each message was posted, and where what alice had not read starts. Bob posts
        // UNREAD-579 while alice is in the keyring, so the room opens with it unread. Its row says
        // its time of day, and the whole date and time to VoiceOver; the unread line sits above it,
        // and today's divider above that. Times are the ones the node keeps, in milliseconds. It
        // stages what it unread579 itself, so it runs from step 6 too (VOX_PROOF_FROM=6).
        tap(ui, Key.id("keyring"), "Keyring in the sidebar")
        try staged(vox, ["room", "post", "--node", "bob", room, "UNREAD-579"], env: voxEnv)
        var unread579: (id: String, millis: UInt64)?
        let unread579Until = Date().addingTimeInterval(30)
        while unread579 == nil && Date() < unread579Until {
            unread579 = posted(vox, voxEnv, room, "UNREAD-579")
            if unread579 == nil { Thread.sleep(forTimeInterval: 0.5) }
        }
        guard let unread579 else {
            throw Apparatus("alice's `vox room read --json` never showed bob's UNREAD-579 in 30 s, so its time cannot be checked")
        }
        tap(ui, Key.id("room-mission"), "mission in the sidebar", premise: inRoom(vox, voxEnv, "mission"))
        let needsAt = Date(timeIntervalSince1970: TimeInterval(unread579.millis) / 1_000)
        let needsTime = Key.id("time-\(unread579.id)")
        if present(ui, needsTime, timeout: 30, "bob's UNREAD-579 must show the time it was posted") {
            let e = el(ui, needsTime)
            let short = needsAt.formatted(.dateTime.hour().minute())
            let full = needsAt.formatted(date: .complete, time: .standard)
            XCTAssertEqual(e.value as? String, short,
                           "PRODUCT: UNREAD-579, posted at \(full) (\(unread579.millis) ms), must show its time of day \"\(short)\"; it shows \(String(describing: e.value))")
            XCTAssertEqual(e.label, full,
                           "PRODUCT: UNREAD-579's time must say the whole date and time to VoiceOver, \"\(full)\"; it says \"\(e.label)\"")
        }
        let unreadLine = Key.id("unread-divider")
        words(ui, unreadLine, timeout: 10,
              "the room opened with UNREAD-579 unread: an unread line must say how many, \"N unread\"",
              until: { $0.hasSuffix(" unread") })
        XCTAssertLessThanOrEqual(el(ui, unreadLine).frame.maxY, el(ui, needsTime).frame.minY,
                                 "PRODUCT: the unread line must sit above UNREAD-579, which alice had not read; the line is at \(el(ui, unreadLine).frame), UNREAD-579's time at \(el(ui, needsTime).frame)")
        let today = Key.id("day-\(Self.dayKey(Date()))")
        words(ui, today, timeout: 10, "today's messages must sit under a \"Today\" divider",
              until: { $0 == "Today" })
        print("[proof] times: UNREAD-579 at \(needsAt.formatted(.dateTime.hour().minute())), under the unread line and \"Today\"")

        // (5c) A message from another day sits under that day's divider. Dora is a node of a
        // daemon of her own whose clock is two days behind: apparatus, a `vox` built with
        // test-knobs (VOX_TEST_CLOCK_SKEW_MS), never the app's. She joins, she and alice trust each
        // other, and she posts until alice reads one; it claims a time two days ago.
        guard let knobs = env["VOX_PROOF_KNOBS_VOX"], !knobs.isEmpty else {
            throw Apparatus("VOX_PROOF_KNOBS_VOX (a vox built with test-knobs, for dora's clock) is set by scripts/app-proofs.sh")
        }
        let doraEnv = ["VOX_DATA_DIR": scratch.appendingPathComponent("dora-data").path,
                       "VOX_CONFIG_DIR": scratch.appendingPathComponent("dora-config").path,
                       "VOX_PROXY": "127.0.0.1:0",
                       "VOX_TEST_CLOCK_SKEW_MS": String(-2 * 86_400_000)]
        let doraPass = scratch.appendingPathComponent("dora.pass").path
        try stager.write(Data("dora identity\n".utf8), to: doraPass)
        peer = try start(knobs, ["daemon", "--listen", "127.0.0.1:0"], env: doraEnv,
                         until: "vox daemon: control socket")
        try staged(knobs, ["node", "create", "dora"],
                   env: doraEnv.merging(["VOX_IDENTITY_PASSPHRASE": "dora identity"]) { $1 })
        try staged(knobs, ["node", "attach", "dora", "--passphrase-file", doraPass], env: doraEnv)
        let doraFp = try line(staged(knobs, ["id", "--node", "dora"], env: doraEnv)) { $0.count == 52 }
        let doraLink = try line(staged(vox, ["room", "link", "--node", "alice", room], env: voxEnv)) {
            $0.hasPrefix("vox://")
        }
        try staged(knobs, ["room", "join", "--node", "dora", "--passphrase-file", roomPass, doraLink],
                   env: doraEnv)
        try staged(vox, ["trust", "add", "--node", "alice", doraFp, "--name", "dora",
                         "--identity-passphrase-file", alicePass], env: voxEnv)
        try staged(knobs, ["trust", "add", "--node", "dora", aliceFp, "--name", "alice",
                           "--identity-passphrase-file", doraPass], env: doraEnv)
        var old: (id: String, millis: UInt64)?
        let oldUntil = Date().addingTimeInterval(120)
        var d = 0
        while old == nil && Date() < oldUntil {
            d += 1
            try staged(knobs, ["room", "post", "--node", "dora", room, "FROM-ANOTHER-DAY-\(d)"], env: doraEnv)
            Thread.sleep(forTimeInterval: 1)
            old = posted(vox, voxEnv, room, "FROM-ANOTHER-DAY-")
        }
        guard let old else {
            throw Apparatus("alice never read a post of dora's in 120 s, so no message from another day was staged")
        }
        let oldAt = Date(timeIntervalSince1970: TimeInterval(old.millis) / 1_000)
        guard !Calendar.current.isDateInToday(oldAt) else {
            throw Apparatus("dora's post claims \(oldAt.formatted()) (\(old.millis) ms), today: VOX_TEST_CLOCK_SKEW_MS did not move her clock")
        }
        let oldTime = Key.id("time-\(old.id)")
        let oldDay = Key.id("day-\(Self.dayKey(oldAt))")
        let oldWords = Self.dayWords(oldAt)
        if present(ui, oldTime, timeout: 60, "dora's post, from \(oldAt.formatted()), must be in alice's timeline with its time",
                   premise: trusted(vox, voxEnv, doraFp, "dora")) {
            scrollTo(ui, el(ui, oldTime))
            words(ui, oldDay, timeout: 10,
                  "dora's post claims \(oldAt.formatted()): a divider must say its day, \"\(oldWords)\"",
                  until: { $0 == oldWords })
            // The divider nearest above it is its own day's.
            let at = el(ui, oldTime).frame.minY
            let above = ui.windows.firstMatch.descendants(matching: .any)
                .matching(NSPredicate(format: "identifier BEGINSWITH %@", "day-"))
                .allElementsBoundByIndex.filter { $0.frame.maxY <= at }
                .max { $0.frame.minY < $1.frame.minY }
            XCTAssertEqual(above?.identifier, "day-\(Self.dayKey(oldAt))",
                           "PRODUCT: dora's post from \(oldAt.formatted()) must sit under its own day's divider, \"\(oldWords)\"; the divider nearest above it is \(above.map { "\"\($0.label)\" (\($0.identifier))" } ?? "none")")
        }
        print("[proof] another day: dora's post at \(oldAt.formatted()), under \"\(oldWords)\"")
        peer?.terminate()
        peer = nil

        // (16) Outcomes (#608, #611, #615): run here, with the room and bob's trust in place, so
        // that VOX_PROOF_FROM=16 runs it alone, on what steps 1 to 5 leave (staged by `vox`), and
        // stops after it.
        if from <= 5 || from == 16 {
            try outcomes(ui, vox: vox, voxEnv: voxEnv, roomPass: roomPass)
            try addressAnatomy(ui, vox: vox, voxEnv: voxEnv, room: room)
            if from == 16 {
                print("[proof] VOX_PROOF_FROM=16: step 16 run alone; steps 6 to 15 NOT RUN")
                return
            }
        }

        // (6) Attach a file to the room, To: bob, with a note.
        tap(ui, Key.id("room-mission"), "mission in the sidebar", premise: inRoom(vox, voxEnv, "mission"))
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
            // The path is typed only into the Go To sheet once it shows: typed into a panel still
            // opening, it went nowhere. ⌘⇧G again if the panel was not yet taking keys.
            let panel = el(ui, Key.id("open-panel"))
            func goTo() -> Bool { panel.sheets.firstMatch.exists || ui.sheets.firstMatch.exists }
            var asked = 0
            while asked < 3 && !goTo() {
                asked += 1
                ui.typeKey("g", modifierFlags: [.command, .shift])
                let until = Date().addingTimeInterval(5)
                while Date() < until && !goTo() { Thread.sleep(forTimeInterval: 0.25) }
            }
            guard goTo() else {
                keepTree(ui, "the file panel's Go To sheet never showed")
                XCTFail("APPARATUS: ⌘⇧G, typed \(asked) times, never showed the file panel's Go To sheet")
                return
            }
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
        present(ui, toBob, timeout: 10, "attaching a file must ask To: with bob in it",
                premise: member(vox, voxEnv, room, bobFp, "bob"))
        tap(ui, toBob, "To: bob", premise: member(vox, voxEnv, room, bobFp, "bob"))
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
            // Premise: bob's room read shows the room at all (a message staged before).
            let bobs = run(vox, ["room", "read", "--node", "bob", room], env: voxEnv).out
            guard bobs.contains("STAGE-") else {
                throw Apparatus("bob's `vox room read` shows none of the room's earlier messages either, so the share's absence says nothing: \(bobs.suffix(600))")
            }
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
            // Premise: bob's node directory, under which pulls land, is where the proof looks.
            let nodeDir = URL(fileURLWithPath: data).appendingPathComponent("nodes/bob").path
            guard stager.run(["/bin/test", "-d", nodeDir], env: [:]).status == 0 else {
                throw Apparatus("bob's node directory \(nodeDir) does not exist, so the proof is looking in the wrong data root")
            }
            let there = stager.run(["/bin/ls", "-lR", URL(fileURLWithPath: data).appendingPathComponent("nodes/bob/files").path], env: [:]).out
            let pulls = run(vox, ["room", "read", "--node", "bob", room], env: voxEnv).out
            XCTFail("PRODUCT: the file attached To: bob must be pulled by bob's node, byte for byte, into \(bobCopy.path) within 120 s; it holds \(got.isEmpty ? "nothing" : "sha256 \(got)"); bob's files: \(there.isEmpty ? "none" : there.replacingOccurrences(of: "\n", with: " ⏎ ")); bob's room read: \(pulls.suffix(1200))")
        }
        let pulledBytes: Data? = got == want ? bytes : nil
        print("[proof] attached for-bob.bin To: bob; bob pulled \(pulledBytes?.count ?? 0) bytes; rows with the note: \(bobRows.count)")

        // (7) The lanes view was removed (ADR-029 Sessions replace it; ADR-028 W-3 withdrawn).

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
        present(ui, aaa, timeout: 30, "room aaa must show in the sidebar",
                premise: inRoom(vox, voxEnv, "aaa"))
        present(ui, Key.id("room-bbb"), timeout: 30,
                "room bbb must show in the sidebar",
                premise: inRoom(vox, voxEnv, "bbb"))
        tap(ui, aaa, "aaa in the sidebar", premise: inRoom(vox, voxEnv, "aaa"))
        try staged(vox, ["room", "post", "--node", "bob", "--to", aliceFp, room, "NEEDS-YOU-9"],
                   env: bobSession)
        words(ui, Key.id("group-needs you"), timeout: 60,
              "bob's message to alice must put mission under needs you",
              until: { $0.lowercased() == "needs you (1)" })
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
        tap(ui, Key.id("to-bob"), "bob in To:", premise: member(vox, voxEnv, room, bobFp, "bob"))
        ui.typeKey(.escape, modifierFlags: [])
        words(ui, to, timeout: 10, "ticking bob in To: must say so", until: { $0 == "To: bob" })
        // Seen in mission, then at once another room: the read record names mission, the room the
        // message is in.
        tap(ui, aaa, "aaa in the sidebar", premise: inRoom(vox, voxEnv, "aaa"))
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
        tap(ui, aaa, "aaa in the sidebar", premise: inRoom(vox, voxEnv, "aaa"))
        tap(ui, Key.id("room-mission"), "mission in the sidebar", premise: inRoom(vox, voxEnv, "mission"))
        let card = Key.id("service-\(cliAddress)")
        present(ui, card, timeout: 30, "the room must show a card for bob's service \(cliAddress)")
        tap(ui, card, "the service card")
        // Clicked, the card is selected (it says so to VoiceOver), and enables Room > Copy
        // Selected Service's Address (⌘⇧C).
        // Two signals of one selection, read together: neither found is the proof's; the trait
        // unread while the menu item is enabled is the proof's too (the selection took).
        let copyItem = el(ui, Key.menuItem("Copy Selected Service's Address"))
        let selectedUntil = Date().addingTimeInterval(5)
        while Date() < selectedUntil && !(el(ui, card).isSelected && copyItem.isEnabled) {
            Thread.sleep(forTimeInterval: 0.2)
        }
        let selected = el(ui, card).isSelected
        if !copyItem.exists {
            keepTree(ui, "the copy menu item was not found")
            XCTFail("APPARATUS: XCTest finds no menu item \"Copy Selected Service's Address\" in the app's menus")
        } else if !selected && copyItem.isEnabled {
            keepTree(ui, "the card's Selected trait was unread")
            XCTFail("APPARATUS: the copy menu item is enabled (the card is selected) but XCTest reads no Selected trait on the card")
        } else if !selected || !copyItem.isEnabled {
            keepTree(ui, "the service card was not selected")
            XCTFail("PRODUCT: clicking bob's service card must select it (said to VoiceOver) and enable Room > Copy Selected Service's Address; selected \(selected), enabled \(copyItem.isEnabled)")
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
        tap(ui, Key.menuItem("mission"), "mission in the room picker", premise: inRoom(vox, voxEnv, "mission"))
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
        tap(ui, Key.id("keyring-remove-bob"), "Remove… on bob", premise: trusted(vox, voxEnv, bobFp, "bob"))
        words(ui, Key.id("keyring-remove-effect"), timeout: 10,
              "removing bob must say what removing does first",
              until: { $0.contains("reads nothing you write from now on") })
        tap(ui, Key.id("keyring-remove-confirm"), "Remove, in its sheet")
        keyringPassphraseIfAsked(ui) { self.locate(ui, Key.id("keyring-row-bob")) == nil }
        XCTAssertTrue(live.cut(within: 30),
                      "PRODUCT: alice untrusted bob in the keyring view; bob's live connection into her service must be cut within 30 s, and it was not")
        print("[proof] untrust cut bob's live forward into alice's notes service")

        // (12) Quitting detaches it.
        handOff(ui, "q")
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
        try launchVox(ui, appPath, env: ui.launchEnvironment, scratch: scratchPath)
        let reopened = words(ui, Key.id("group-needs you"), timeout: 30,
                             "bob's message to alice came while the app was closed; opened again, the app must count it from what her node recorded as read, mission under \"needs you (1)\"",
                             until: { $0.lowercased() == "needs you (1)" }) ?? ""
        print("[proof] opened again: \(reopened)")

        // (14) The keyboard. Bob posts KEYS-A and KEYS-B, then shares a file to alice, which her
        // node pulls: the newest row of mission is the file's.
        try staged(vox, ["room", "post", "--node", "bob", room, "KEYS-A"], env: bobSession)
        try staged(vox, ["room", "post", "--node", "bob", room, "KEYS-B"], env: bobSession)
        let keysFile = scratch.appendingPathComponent("for-keys.txt")
        try stager.write(Data("opened from the keyboard\n".utf8), to: keysFile.path)
        try staged(vox, ["share", "--node", "bob", room, keysFile.path, "--to", aliceFp,
                         "-m", "KEYS-FILE"], env: bobSession)
        tap(ui, Key.id("room-mission"), "mission in the sidebar", premise: inRoom(vox, voxEnv, "mission"))
        // Premise: alice's node pulled it (the row offers Quick Look only then).
        let lookButton = Key.id("quick-look-for-keys.txt")
        present(ui, lookButton, timeout: 120,
                "the file bob shared to alice must be pulled and offer Quick Look in her timeline")
        // Premise: Quick Look, opened with the mouse, shows as one more window, and Escape closes
        // it; else the proof cannot tell it from the keyboard.
        let windowsBefore = ui.windows.count
        tap(ui, lookButton, "Quick Look on for-keys.txt")
        func lookOpened() -> Bool {
            let end = Date().addingTimeInterval(10)
            while Date() < end {
                if ui.windows.count > windowsBefore { return true }
                Thread.sleep(forTimeInterval: 0.2)
            }
            return false
        }
        func lookClosed() -> Bool {
            ui.typeKey(.escape, modifierFlags: [])
            let end = Date().addingTimeInterval(10)
            while Date() < end {
                if ui.windows.count == windowsBefore { return true }
                Thread.sleep(forTimeInterval: 0.2)
            }
            return false
        }
        guard lookOpened(), lookClosed() else {
            keepTree(ui, "Quick Look by mouse was not seen to open and close")
            throw Apparatus("Quick Look, opened with the mouse on for-keys.txt, did not show as one more window that Escape closes (\(windowsBefore) windows before, \(ui.windows.count) now), so the keyboard's cannot be told")
        }
        // ⌃⌘T: the keyboard on the timeline, the newest row (the file's) selected.
        ui.typeKey("t", modifierFlags: [.command, .control])
        ui.typeKey(" ", modifierFlags: [])
        if !lookOpened() {
            keepTree(ui, "Space opened nothing")
            XCTFail("PRODUCT: View > Focus Timeline, then Space, must open the selected row's pulled file, for-keys.txt, in Quick Look; no window opened")
        } else if !lookClosed() {
            // The mouse's preview closed on Escape above, so this one is the product's.
            keepTree(ui, "Quick Look opened by Space stayed open")
            XCTFail("PRODUCT: Escape must close the Quick Look that Space opened from the timeline; it stayed open, so the keyboard is trapped")
            return
        }
        ui.typeKey(.return, modifierFlags: [])
        if !lookOpened() {
            keepTree(ui, "Return opened nothing")
            XCTFail("PRODUCT: Return on the selected row, whose file alice pulled, must open its first action, Quick Look; no window opened")
        } else if !lookClosed() {
            // The mouse's preview closed on Escape above, so this one is the product's.
            keepTree(ui, "Quick Look opened by Return stayed open")
            XCTFail("PRODUCT: Escape must close the Quick Look that Return opened from the timeline; it stayed open, so the keyboard is trapped")
            return
        }
        // ↑ to KEYS-B, ↑ to KEYS-A, ↓ back to KEYS-B: each said by Reply to Selected Message.
        for (key, want) in [(XCUIKeyboardKey.upArrow, "KEYS-B"), (.upArrow, "KEYS-A"),
                            (.downArrow, "KEYS-B")] {
            ui.typeKey(key, modifierFlags: [])
            ui.typeKey("r", modifierFlags: .command)
            present(ui, Key.showing("Replying to bob: \(want)"), timeout: 10,
                    "\(key == .upArrow ? "↑" : "↓") on the timeline must select \(want), which ⌘R then replies to")
            // Back to the timeline for the next key: ⌘R leaves the keyboard where it was.
            ui.typeKey("t", modifierFlags: [.command, .control])
        }
        // Tab from the timeline reaches the composer. Premise: XCTest reads the composer's
        // keyboard focus (clicked, it has it).
        let compose = Key.id("compose")
        tap(ui, compose, "the composer")
        guard el(ui, compose).value(forKey: "hasKeyboardFocus") as? Bool == true else {
            throw Apparatus("XCTest reads no keyboard focus on the composer after clicking it")
        }
        ui.typeKey("t", modifierFlags: [.command, .control])
        var tabs = 0
        while tabs < 25 && el(ui, compose).value(forKey: "hasKeyboardFocus") as? Bool != true {
            ui.typeKey(.tab, modifierFlags: [])
            tabs += 1
        }
        XCTAssertTrue(el(ui, compose).value(forKey: "hasKeyboardFocus") as? Bool == true,
                      "PRODUCT: Tab from the timeline must reach the composer; after \(tabs) Tabs it has no keyboard focus")
        print("[proof] keyboard: Space and Return opened Quick Look; ↑ ↑ ↓ selected KEYS-B, KEYS-A, KEYS-B; Tab reached the composer in \(tabs)")

        // (15) Who trusts whom, from a member (ADR-028 K-5, K-7, R-5, R-6, E-4; D4, D9, D10, D17).
        // Dave, a node made here, is trusted by bob before he joins, so bob's grant to him is on
        // mission's log once he is in.
        let davePass = scratch.appendingPathComponent("dave.pass").path
        try stager.write(Data("dave identity\n".utf8), to: davePass)
        try staged(vox, ["node", "create", "dave"],
                   env: voxEnv.merging(["VOX_IDENTITY_PASSPHRASE": "dave identity"]) { $1 })
        try staged(vox, ["node", "attach", "dave", "--passphrase-file", davePass], env: voxEnv)
        let daveFp = try line(staged(vox, ["id", "--node", "dave"], env: voxEnv)) { $0.count == 52 }
        try staged(vox, ["trust", "add", "--node", "bob", daveFp, "--name", "dave",
                         "--identity-passphrase-file", bobPass], env: voxEnv)
        tap(ui, Key.id("room-mission"), "mission in the sidebar", premise: inRoom(vox, voxEnv, "mission"))
        try staged(vox, ["room", "join", "--node", "dave", "--passphrase-file", roomPass, missionLink],
                   env: voxEnv)
        // (15a, D10) The join is said in mission's timeline with who alice trusts that trusts dave.
        let daveNamed = "\(daveFp.prefix(26)) (not in keyring)"
        let joinSaid = words(ui, Key.id("join-\(daveFp)"), timeout: 90,
                             "dave joined mission while it was on screen; its timeline must say so, and that bob (whom alice trusts) trusts him: \"\(daveNamed) joined. bob trusts it.\"",
                             until: { $0 == "\(daveNamed) joined. bob trusts it." }) ?? ""
        print("[proof] join: \(joinSaid)")
        // (15b, D4) Dave trusts alice; she has not trusted him. His row says so, the room says who
        // does not read her yet, and his card says each direction and trusts him from there.
        try staged(vox, ["trust", "add", "--node", "dave", aliceFp, "--name", "alice",
                         "--identity-passphrase-file", davePass], env: voxEnv)
        let daveRow = Key.id("member-\(daveFp.prefix(12))")
        let rowSaid = words(ui, daveRow, timeout: 60,
                            "dave trusts alice and she has not trusted him: her member pane must say \"not in keyring, trusts you\"",
                            until: { $0.hasSuffix("not in keyring, trusts you") }) ?? ""
        let trustBanner = words(ui, Key.id("trust-banner"), timeout: 10,
                           "mission must say whom alice does not yet read each other with: dave",
                           until: { $0.contains(String(daveFp.prefix(12))) }) ?? ""
        // (15e, #624) Compare, group by group: on dave's offer, collapsed until asked for, a
        // partial entry says how far it matches.
        tap(ui, Key.id("offer-\(daveFp.prefix(12))"), "dave's offer under needs you")
        tap(ui, Key.id("offer-compare-open"), "Compare… on dave's offer")
        type(ui, Key.id("offer-compare"), String(daveFp.prefix(16)), "the offer's compare field")
        let offerSoFar = words(ui, Key.id("offer-compare-said"), timeout: 10,
                               "four groups of dave's own fingerprint typed on his offer must say \"So far matches 4 of 13 groups.\"",
                               until: { $0 == "So far matches 4 of 13 groups." }) ?? ""
        tap(ui, Key.id("room-mission"), "mission in the sidebar", premise: inRoom(vox, voxEnv, "mission"))
        tap(ui, daveRow, "dave in the member pane")
        let directions = words(ui, Key.id("card-directions"), timeout: 10,
                               "dave's card must say both directions: he trusts alice, she has not trusted him",
                               until: { $0.contains("trusts you; you haven't trusted") }) ?? ""
        // On his card: two groups so far; a wrong third named, with no Remove (he is not in the
        // keyring); the whole of it marked as a match.
        tap(ui, Key.id("card-compare-open"), "Compare… on dave's card")
        let field = Key.id("card-compare")
        type(ui, field, String(daveFp.prefix(8)), "the card's compare field")
        let soFar = words(ui, Key.id("card-compare-said"), timeout: 10,
                          "two groups of dave's fingerprint typed must say \"So far matches 2 of 13 groups.\"",
                          until: { $0 == "So far matches 2 of 13 groups." }) ?? ""
        let third = daveFp.dropFirst(8).prefix(4)
        el(ui, field).typeText(String(third.map { $0 == "a" ? "b" : "a" }))
        let wrong = words(ui, Key.id("card-compare-said"), timeout: 10,
                          "a third group that differs must be named: \"Group 3 does not match: you have …\"",
                          until: { $0.hasPrefix("Group 3 does not match: you have ") && $0.hasSuffix("do not trust it.") }) ?? ""
        XCTAssertNil(locate(ui, Key.id("card-compare-remove")),
                     "PRODUCT: dave is not in alice's keyring, so his compare must offer no Remove")
        el(ui, field).typeKey("a", modifierFlags: .command)
        el(ui, field).typeText(daveFp)
        let whole = words(ui, Key.id("card-compare-said"), timeout: 10,
                          "dave's whole fingerprint typed must be marked as a match of all 13 groups",
                          until: { $0.hasSuffix("all 13 groups.") && $0.hasPrefix("Matches ") }) ?? ""
        print("[proof] compare: offer \(offerSoFar); card \(soFar) → \(wrong) → \(whole)")
        tap(ui, Key.id("card-trust-open"), "Trust… on dave's card")
        type(ui, Key.id("card-alias"), "dave", "the card's alias field")
        tap(ui, Key.id("card-trust-confirm"), "Trust")
        keyringPassphraseIfAsked(ui) {
            self.run(vox, ["trust", "list", "--node", "alice"], env: voxEnv).out.contains(daveFp)
        }
        let cardSaid = words(ui, Key.id("card-trust"), timeout: 60,
                             "trusted from his card, dave, who trusts alice, must read \"dave, trusted both ways\"",
                             until: { $0 == "dave, trusted both ways" }) ?? ""
        let ring = run(vox, ["trust", "list", "--node", "alice"], env: voxEnv).out
        XCTAssertTrue(ring.contains(daveFp),
                      "PRODUCT: trusted from his card, dave must be in alice's keyring; `vox trust list` said: \(ring)")
        tap(ui, Key.id("card-close"), "Close on dave's card")
        print("[proof] dave's row: \(rowSaid); banner: \(trustBanner); card: \(directions) → \(cardSaid)")
        // (15f, G2) The keyring's card for dave: each direction, the room it covers, and what
        // removing him would change, behind a disclosure.
        tap(ui, Key.id("keyring"), "Keyring in the sidebar")
        tap(ui, Key.id("keyring-row-dave"), "dave's keyring entry", premise: trusted(vox, voxEnv, daveFp, "dave"))
        let ringHead = words(ui, Key.id("keyring-card-heading"), timeout: 15,
                             "dave's keyring card must head \"dave ⇄ you\": he trusts alice too",
                             until: { $0 == "dave, trusted both ways" }) ?? ""
        let theirs = words(ui, Key.id("keyring-card-theirs"), timeout: 5,
                           "dave's direction must say he trusts alice too",
                           until: { $0.hasPrefix("dave trusts you too.") }) ?? ""
        let rooms = words(ui, Key.id("keyring-card-rooms"), timeout: 15,
                          "dave's card must name the room alice shares with him, mission",
                          until: { $0.hasPrefix("Shared rooms: ") && $0.contains("mission") }) ?? ""
        tap(ui, Key.id("keyring-card-removal-open"), "What would removing dave change?")
        let removal = words(ui, Key.id("keyring-card-removal"), timeout: 5,
                            "the disclosure must say what removing dave would change",
                            until: { $0.hasPrefix("Removing dave: it reads nothing you write from now on") }) ?? ""
        tap(ui, Key.id("room-mission"), "mission in the sidebar", premise: inRoom(vox, voxEnv, "mission"))
        print("[proof] keyring card: \(ringHead); \(theirs); \(rooms); \(removal.prefix(40))…")
        // (15c, D9) A message of alice's no member's node holds says so, then where it is.
        try staged(vox, ["node", "detach", "bob"], env: voxEnv)
        try staged(vox, ["node", "detach", "dave"], env: voxEnv)
        try staged(vox, ["room", "post", "--node", "alice", room, "WHERE-15"], env: voxEnv)
        var whereId = ""
        for row in run(vox, ["room", "read", "--node", "alice", "--json", room], env: voxEnv).out
            .split(separator: "\n") {
            guard let r = try? JSONSerialization.jsonObject(with: Data(row.utf8)) as? [String: Any],
                  r["text"] as? String == "WHERE-15", let id = r["entry_hash"] as? String else { continue }
            whereId = id
        }
        guard !whereId.isEmpty else { throw Apparatus("alice's `vox room read --json` lists no WHERE-15") }
        let alone = words(ui, Key.id("whereabouts-\(whereId)"), timeout: 60,
                          "alice's WHERE-15, posted with bob's and dave's nodes detached, must say \"only on this machine\"",
                          until: { $0 == "only on this machine" }) ?? ""
        try staged(vox, ["node", "attach", "bob", "--passphrase-file", bobPass], env: voxEnv)
        let spread = words(ui, Key.id("whereabouts-\(whereId)"), timeout: 90,
                           "once bob's node is back and holds WHERE-15, it must say \"on 1 of 2 members' nodes\"",
                           until: { $0 == "on 1 of 2 members' nodes" }) ?? ""
        print("[proof] whereabouts: \(alone) → \(spread)")
        // (15d, D17) Node > Detach leaves the window alice's: Attach again (or Quit), never another
        // node of this Mac's.
        ui.menuBars.menuBarItems["Node"].click()
        tap(ui, Key.menuItem("Detach"), "Node > Detach")
        var offered = ""
        let detachedUntil = Date().addingTimeInterval(30)
        while Date() < detachedUntil && offered.isEmpty {
            if locate(ui, Key.id("node-carol")) != nil || locate(ui, Key.id("node-bob")) != nil {
                offered = "another node"
            } else if locate(ui, Key.id("attach-again")) != nil {
                offered = "attach again"
            } else {
                Thread.sleep(forTimeInterval: 0.25)
            }
        }
        XCTAssertEqual(offered, "attach again",
                       "PRODUCT: after Node > Detach the window must offer only to attach alice again (E-4); it offered \(offered.isEmpty ? "neither within 30 s" : offered): \(onScreen(ui))")
        tap(ui, Key.id("attach-again"), "Attach alice Again")
        let again = Key.id("passphrase")
        if present(ui, again, timeout: 15, "Attach alice Again must ask for her passphrase") {
            type(ui, again, "alice identity", "the passphrase field")
            tap(ui, Key.id("attach"), "Attach")
        }
        present(ui, Key.id("attached"), timeout: 60, "attached again, the window must be alice's")
        let fp = run(vox, ["node", "list"], env: voxEnv).out
        XCTAssertTrue(nodeLine(fp, "alice")?.contains(" attached ") ?? false,
                      "PRODUCT: attached again, `vox node list` must say alice is attached: \(fp)")
        print("[proof] after Detach: \(offered); attached again")
        handOff(ui, "q")
        _ = ui.wait(for: .notRunning, timeout: 30)
        _ = run(vox, ["node", "detach", "alice"], env: voxEnv)
    }

    /// (16) What an operation comes to, as a person meets it.
    /// - #608 (D16): New Room with its passphrase field left empty says "No passphrase: anyone
    ///   with the link can join." and makes the room, as `vox room list` lists it.
    /// - #611 (D19): End for Everyone in a room alice did not create is refused by her node; the
    ///   sheet stays open and says why, under its button.
    /// - #615 (P6): that refusal is the status bar's, as a refusal, and is not shown in the
    ///   Retention sheet opened next, which is another operation's; dismissed, it is gone.
    ///
    /// Mutants: New Room taking an empty field as nothing typed (D16): no room, red. The End sheet
    /// closing whatever leaving did (D19): no reason shown, red. A sheet showing any operation's
    /// failure (`failure(of:)` ignoring the operation, P6): the Retention sheet shows End's
    /// refusal, red.
    private func outcomes(_ ui: XCUIApplication, vox: String, voxEnv: [String: String],
                          roomPass: String) throws {
        // #608: a room with no passphrase, made by the app.
        ui.typeKey("n", modifierFlags: .command)
        let roomName = Key.id("room-form-name")
        present(ui, roomName, timeout: 10, "⌘N must open the New Room form")
        type(ui, roomName, "open", "the room's name field")
        words(ui, Key.id("room-form-no-passphrase"), timeout: 10,
              "with its passphrase field empty, New Room must say what no passphrase means",
              until: { $0 == "No passphrase: anyone with the link can join." })
        tap(ui, Key.id("room-form-submit"), "Create, the passphrase field left empty")
        var rooms = ""
        let madeUntil = Date().addingTimeInterval(60)
        while Date() < madeUntil && !rooms.contains(" open") {
            rooms = run(vox, ["room", "list", "--node", "alice"], env: voxEnv).out
            if !rooms.contains(" open") { Thread.sleep(forTimeInterval: 0.5) }
        }
        guard rooms.contains(" open") else {
            throw Product("New Room with an empty passphrase field must make a room with none; "
                + "alice's `vox room list` lists no room \"open\": \(rooms)")
        }
        print("[proof] New Room with no passphrase made \"open\"")

        // #611: a room bob made, which alice joins: her End for Everyone there is refused.
        try staged(vox, ["room", "create", "--node", "bob", "--passphrase-file", roomPass,
                         "--name", "bobs"], env: voxEnv)
        let bobsRoom = try line(staged(vox, ["room", "list", "--node", "bob"], env: voxEnv)) {
            $0.contains(" bobs")
        }.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? ""
        let bobsLink = try line(staged(vox, ["room", "link", "--node", "bob", bobsRoom], env: voxEnv)) {
            $0.hasPrefix("vox://")
        }
        try staged(vox, ["room", "join", "--node", "alice", "--passphrase-file", roomPass, bobsLink],
                   env: voxEnv)
        tap(ui, Key.id("room-bobs"), "bobs in the sidebar", premise: inRoom(vox, voxEnv, "bobs"))
        ui.menuBars.menuBarItems["Room"].click()
        tap(ui, Key.menuItem("End for Everyone…"), "Room > End for Everyone…")
        tap(ui, Key.id("leave-confirm"), "End for Everyone, in its sheet")
        let refusal = words(ui, Key.id("leave-failed"), timeout: 30,
                            "End for Everyone, refused by alice's node (she did not make bobs), must keep its sheet open and say why",
                            until: { $0.contains("creator") }) ?? ""
        if locate(ui, Key.id("leave-confirm")) == nil {
            XCTFail("PRODUCT: a refused End for Everyone must keep its sheet open; it closed")
        }
        print("[proof] End for Everyone refused, said in its sheet: \(refusal)")
        ui.typeKey(.escape, modifierFlags: [])

        // #615: the refusal is the status bar's, as a refusal; not the Retention sheet's.
        let barSays = words(ui, Key.id("status-outcome-refused"), timeout: 10,
                            "the status bar must say End for Everyone was refused, as a refusal",
                            until: { $0.contains("creator") }) ?? ""
        ui.menuBars.menuBarItems["Room"].click()
        tap(ui, Key.menuItem("Retention…"), "Room > Retention…")
        present(ui, Key.id("retention-effect"), timeout: 10, "Room > Retention… must open its sheet")
        if let shownThere = locateEverywhere(ui, Key.id("retention-said")) {
            keepTree(ui, "the Retention sheet showed another operation's result")
            XCTFail("PRODUCT: the Retention sheet must show only its own result; it shows End for Everyone's: \"\(shown(shownThere))\"")
        }
        ui.typeKey(.escape, modifierFlags: [])
        tap(ui, Key.id("status-dismiss"), "the status bar's dismiss")
        let goneUntil = Date().addingTimeInterval(5)
        while Date() < goneUntil && locate(ui, Key.id("status-outcome-refused")) != nil {
            Thread.sleep(forTimeInterval: 0.25)
        }
        if locate(ui, Key.id("status-outcome-refused")) != nil {
            XCTFail("PRODUCT: dismissed, the status bar's result must go; it still says it")
        }
        print("[proof] status bar said \(barSays) as a refusal; the Retention sheet did not; dismissed, it went")
    }

    /// (16, G3) A service's address in its parts (ADR-017 S-1): bob shares `photos` in mission;
    /// alice's services view shows its readable address with each part labelled, as alice's
    /// `vox service list --json` gives the address, and Copy Address copies its canonical form.
    ///
    /// Mutant: no anatomy under the address (`AddressAnatomy` drawing nothing): red.
    private func addressAnatomy(_ ui: XCUIApplication, vox: String, voxEnv: [String: String],
                                room: String) throws {
        let echo = try EchoServer(stager)
        try staged(vox, ["service", "add", "--node", "bob", room, "photos", "127.0.0.1:\(echo.port)"],
                   env: voxEnv)
        var readable = ""
        var canonical = ""
        let until = Date().addingTimeInterval(60)
        while Date() < until && canonical.isEmpty {
            let listed = run(vox, ["service", "list", "--node", "alice", "--json", room], env: voxEnv).out
            let json = (try? JSONSerialization.jsonObject(with: Data(listed.utf8))) as? [String: Any]
            let photos = (json?["shared"] as? [[String: Any]] ?? []).first {
                ($0["readable"] as? String)?.hasPrefix("photos.") == true
            }
            readable = photos?["readable"] as? String ?? ""
            canonical = photos?["address"] as? String ?? ""
            if canonical.isEmpty { Thread.sleep(forTimeInterval: 1) }
        }
        guard !canonical.isEmpty else {
            throw Apparatus("alice's `vox service list --json` never listed bob's photos share")
        }
        // The parts, from the address `vox` gives: service and room one label each, the node
        // part between them.
        let labels = readable.dropLast(4).split(separator: ".").map(String.init)
        guard readable.hasSuffix(".vox"), labels.count >= 3 else {
            throw Apparatus("alice's `vox service list` gave the address \(readable), not <service>.<node>.<room>.vox")
        }
        let want = "\(labels[0]), service; \(labels.dropFirst().dropLast().joined(separator: ".")), your node alias; "
            + "\(labels[labels.count - 1]), your room alias; vox, Vox address"
        ui.typeKey("s", modifierFlags: [.command, .shift])
        present(ui, Key.id("service-box-\(readable)"), timeout: 30,
                "the services view must list bob's photos share \(readable)")
        let said = words(ui, Key.id("service-anatomy-\(readable)"), timeout: 10,
                         "the services view must show \(readable) in its parts, each labelled: \(want)",
                         until: { $0 == want }) ?? ""
        let pasted = copiedBy(ui) {
            tap(ui, Key.id("copy-address-\(readable)"), "Copy Address on bob's photos share")
        }
        if pasted != canonical {
            XCTFail("PRODUCT: Copy Address must copy the whole address, canonical (\(canonical)); the pasteboard holds \(pasted.debugDescription)")
        }
        print("[proof] G3: \(readable) shown as \(said); Copy Address copied \(pasted)")
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
        containers(ui).flatMap { $0.staticTexts.allElementsBoundByIndex.prefix(120) }.map { e -> String in
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

    /// The pids of the processes named `name`, by the stager (outside the runner's sandbox).
    private func pids(_ name: String) -> Set<Int32> {
        Set(stager.run(["/usr/bin/pgrep", "-x", name], env: [:]).out
            .split(whereSeparator: \.isNewline).compactMap { Int32($0) })
    }

    /// The running Vox Proof apps (bundle id us.vox.app.proof), by pid: the person's own Vox
    /// (us.vox.app), also named Vox, is never counted.
    private func proofApps() -> Set<Int32> {
        Set(NSRunningApplication.runningApplications(withBundleIdentifier: proofAppID)
            .filter { !$0.isTerminated }.map(\.processIdentifier))
    }

    /// The executable `pid` runs, by proc_pidpath (ps names a process by its argv), symlinks
    /// resolved ("" when it has ended).
    private func executable(_ pid: Int32) -> String {
        let path = stager.run(["/usr/bin/python3", "-c",
            "import ctypes, sys; b = ctypes.create_string_buffer(4096); n = ctypes.CDLL('/usr/lib/libproc.dylib').proc_pidpath(\(pid), b, 4096); print(b.value.decode() if n > 0 else '')"],
            env: [:]).out.trimmingCharacters(in: .whitespacesAndNewlines)
        return path.isEmpty ? "" : URL(fileURLWithPath: path).resolvingSymlinksInPath().path
    }

    private func resolved(_ path: String) -> String {
        URL(fileURLWithPath: path).resolvingSymlinksInPath().path
    }

    /// Each Vox.app this case started, quit at its end however it ends.
    private var launched: [XCUIApplication] = []

    /// The app the proof drives: this build's own Vox.app, by its path (app-proofs.sh refuses any
    /// other: XCTest launches another bundle without the environment).
    private func voxApp(_ appPath: String) -> XCUIApplication {
        XCUIApplication(url: URL(fileURLWithPath: appPath))
    }

    /// Start Vox.app on this run's scratch profile and show, before any step, that it is on it;
    /// else stop (fail closed). XCTest once launched a bundle other than this build's without its
    /// environment, and the app opened the account's real data root (read-only); app-proofs.sh now
    /// refuses such a bundle, and this guard stops any launch that still lands there.
    ///
    /// Before: no Vox.app runs, so the proof cannot drive another. After: exactly one Vox runs,
    /// this app's executable; and within 30 s the app shows this run's scratch path or a node
    /// staged only here, or asks the first-run question the account's own config has answered.
    /// The account's data root shown, or none of these, stops the case.
    private func launchVox(_ ui: XCUIApplication, _ appPath: String, env: [String: String],
                           scratch: String) throws {
        try scratchOnly(env, under: scratch)
        let appExe = resolved(appPath + "/Contents/MacOS/Vox")
        if let running = proofApps().first {
            throw Apparatus("refusing to start Vox Proof: one already runs (pid \(running), \(executable(running))), and the proof could drive it")
        }
        ui.launch()
        launched.append(ui)
        let running = proofApps()
        guard running.count == 1, let pid = running.first, executable(pid) == appExe else {
            throw Apparatus("after starting Vox Proof, the \(proofAppID) processes are \(running.map { "\($0) \(executable($0))" }), not one of \(appExe)")
        }
        // The profile, positively, before any step. The account's own config has answered the
        // first-run question (checked here, by the stager), so an app asking it is not reading
        // the account's config: the launch environment, which comes whole or not at all, reached it.
        let accountAnswered = stager.run(["/usr/bin/python3", "-c",
            "import os, pwd, sys; sys.exit(0 if os.path.isfile(os.path.join(pwd.getpwuid(os.getuid()).pw_dir, 'Library/Application Support/vox/app/login-item')) else 1)"],
            env: [:]).status == 0
        let realRoot = Key.showing("Library/Application Support/vox")
        let scratchSigns: [Key] = [Key.showing(resolved(scratch)), Key.showing(scratch),
                                   Key.id("node-alice"), Key.showing("node alice"), Key.showing("alice")]
        let until = Date().addingTimeInterval(30)
        while Date() < until {
            if let real = locate(ui, realRoot) {
                let said = shown(real)
                keepTree(ui, "Vox.app showed the account's data root")
                ui.terminate()
                throw Apparatus("Vox.app is on the account's real profile, not this run's scratch one: it shows \(said); stopped before any step")
            }
            if let sign = scratchSigns.first(where: { locate(ui, $0) != nil }) {
                print("[guard] Vox.app (pid \(pid)) is on this run's scratch profile: it shows \(sign)")
                return
            }
            if accountAnswered, locate(ui, Key.id("login-item-why")) != nil {
                print("[guard] Vox.app (pid \(pid)) asks the first-run question, which the account's own config has answered: it reads this run's config")
                return
            }
            Thread.sleep(forTimeInterval: 0.5)
        }
        keepTree(ui, "Vox.app could not be shown on the scratch profile")
        ui.terminate()
        throw Apparatus("Vox.app could not be shown to be on this run's scratch profile within 30 s (no scratch path, no node staged here, nor a first-run question the account has answered); stopped before any step")
    }

    /// The proof hides (⌘H) or quits (⌘Q) Vox itself: what takes the foreground next is handed
    /// it, so it is not counted as lost, until Vox is active again.
    private func handOff(_ ui: XCUIApplication, _ key: String) {
        handedOff = true
        ui.typeKey(key, modifierFlags: .command)
    }

    /// Whether a menu other than the menu bar's is open: the menu bar's own menus have no size
    /// until opened.
    private func menuOpen(_ ui: XCUIApplication) -> Bool {
        ui.menus.allElementsBoundByIndex.contains { $0.frame.width > 0 && $0.frame.height > 0 }
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
                         premise: Premise? = nil,
                         file: StaticString = #filePath, line: UInt = #line) -> Bool {
        guard windowReadable(ui, file: file, line: line) else { return false }
        let end = Date().addingTimeInterval(timeout)
        repeat {
            if locate(ui, key) != nil { return true }
            Thread.sleep(forTimeInterval: 0.25)
        } while Date() < end
        if locateEverywhere(ui, key) != nil { return true }
        missing(ui, key, product, premise: premise, file: file, line: line)
        return false
    }

    /// The red for `key` not shown: APPARATUS when the app has it only outside what it shows a
    /// person, or when `premise` (what the daemon holds that it is drawn from) does not hold;
    /// PRODUCT otherwise, quoting everything shown and what the daemon said.
    private func missing(_ ui: XCUIApplication, _ key: Key, _ product: String, premise: Premise? = nil,
                         file: StaticString, line: UInt) {
        keepTree(ui, "\(key) was not shown")
        // Premise: the same search finds a known sibling of the same kind; if not, the search is
        // what failed, not the app.
        if locateEverywhere(ui, key.sibling) == nil {
            XCTFail("APPARATUS: \(key) not found, and the same search finds not even \(key.sibling), which is always shown: the search, not the app, is at fault",
                    file: file, line: line)
            return
        }
        let anywhere = key.query(in: ui.descendants(matching: .any)).firstMatch
        if anywhere.exists {
            XCTFail("APPARATUS: \(key) is in the app only outside its windows, dialogs, sheets, popovers and menus (\(anywhere.elementType.rawValue)); the proof's search missed it",
                    file: file, line: line)
            return
        }
        // A menu item is shown only in an open menu: none open, the click that was to open it
        // reached nothing (the menu never opened), which the app's words cannot settle.
        if case .menuItem = key, !menuOpen(ui) {
            XCTFail("APPARATUS: \(key) is not shown because no menu is open: the click that was to open its menu opened nothing",
                    file: file, line: line)
            return
        }
        var held = ""
        if let premise {
            let (holds, said) = premise.read()
            guard holds else {
                XCTFail("APPARATUS (staging not achieved): \(key) is not shown, and the daemon says \(premise.what) does not hold: \(said)",
                        file: file, line: line)
                return
            }
            held = "; \(premise.what), as the daemon says: \(said)"
        }
        XCTFail("PRODUCT: \(product)\(held); \(key) is in none of the app's windows, dialogs, sheets, popovers or menus, which show: \(onScreen(ui))",
                file: file, line: line)
    }

    /// `key`'s words once `holds` is true of them, within `timeout`, the premise holding: PRODUCT
    /// quoting them when it never is; `missing` when it never shows; APPARATUS when it shows and
    /// XCTest reads neither its label nor its value. A `field` is read by what is typed in it
    /// (`typed`), and an empty one is read as empty.
    @discardableResult
    private func words(_ ui: XCUIApplication, _ key: Key, timeout: TimeInterval, _ product: String,
                       until holds: (String) -> Bool = { _ in true }, field: Bool = false,
                       file: StaticString = #filePath, line: UInt = #line) -> String? {
        let read = field ? typed : shown
        guard windowReadable(ui, file: file, line: line) else { return nil }
        let end = Date().addingTimeInterval(timeout)
        var last = ""
        var seen = false
        repeat {
            if let e = locate(ui, key) {
                seen = true
                last = read(e)
                if (field || !last.isEmpty) && holds(last) { return last }
            }
            Thread.sleep(forTimeInterval: 0.25)
        } while Date() < end
        if !seen, let e = locateEverywhere(ui, key) {
            seen = true
            last = read(e)
            if (field || !last.isEmpty) && holds(last) { return last }
        }
        if !seen {
            missing(ui, key, product, file: file, line: line)
        } else if last.isEmpty && !field {
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

    /// Click `key`, once it is shown and hittable, never an exception that names no side. Shown
    /// but never hittable: APPARATUS (XCTest cannot click it). Not shown: `missing`'s red, PRODUCT
    /// when the search works and `premise` holds. A target drawn from what the daemon holds names
    /// that as its premise; any other target is a control of the screen the proof has just
    /// reached, which the app must show.
    @discardableResult
    private func tap(_ ui: XCUIApplication, _ key: Key, _ what: String, premise: Premise? = nil,
                     file: StaticString = #filePath, line: UInt = #line) -> Bool {
        let end = Date().addingTimeInterval(10)
        repeat {
            if let e = locate(ui, key) {
                // Shown but out of view (off screen, or clipped by its scroll view): scrolled to,
                // as a person does, so the click lands on it.
                // A menu item is in its open menu, not in a scroll view: hittable is enough.
                let reached: () -> Bool
                if case .menuItem = key { reached = { e.isHittable } } else { reached = { self.inView(ui, e) } }
                if !reached() { scrollTo(ui, e) }
                if reached() {
                    // A notification banner, or the screenshot overlay (the person may be taking
                    // a screenshot), over the click's point would take the click: waited out, as
                    // a person waits, and never stopped: it may be theirs.
                    let at = CGPoint(x: e.frame.midX, y: e.frame.midY)
                    let clearBy = Date().addingTimeInterval(20)
                    while systemOverlayOver(at) != nil, Date() < clearBy {
                        Thread.sleep(forTimeInterval: 0.5)
                    }
                    if let held = systemOverlayOver(at) {
                        keepTree(ui, "a system window covered \(what)")
                        XCTFail("APPARATUS: \(held) covered \(what) (\(key)) for 20 s; not Vox's, and left alone",
                                file: file, line: line)
                        return false
                    }
                    e.click()
                    return true
                }
            }
            Thread.sleep(forTimeInterval: 0.25)
        } while Date() < end
        guard locateEverywhere(ui, key) != nil else {
            missing(ui, key, "the app must show \(what)", premise: premise, file: file, line: line)
            return false
        }
        keepTree(ui, "\(what) could not be clicked")
        XCTFail("APPARATUS: XCTest cannot click \(what) (\(key)): shown, never in view to click",
                file: file, line: line)
        return false
    }

    /// Scroll the window's scroll view that holds `e` until `e` is on screen (or it moves no more).
    /// Whether a click on `e` reaches it: hittable, and wholly inside the scroll view that holds it
    /// (XCTest calls a row clipped below its scroll view hittable, and a click there lands on
    /// whatever is drawn over it).
    private func inView(_ ui: XCUIApplication, _ e: XCUIElement) -> Bool {
        guard e.isHittable else { return false }
        let f = e.frame
        // The scroll view that holds it: one it is a descendant of, found by its identifier,
        // under it on screen (XCTest also found it among the sidebar's descendants); a target
        // with no identifier, or in no scroll view, is clicked where it is.
        let id = e.identifier
        guard !id.isEmpty, let view = ui.windows.firstMatch.scrollViews.allElementsBoundByIndex.first(where: {
            $0.frame.minX <= f.midX && f.midX <= $0.frame.maxX
                && $0.descendants(matching: .any).matching(identifier: id).firstMatch.exists
        })?.frame else { return true }
        return view.minY <= f.minY && f.maxY <= view.maxY
    }

    private func scrollTo(_ ui: XCUIApplication, _ e: XCUIElement) {
        let target = e.frame
        let id = e.identifier
        guard let view = ui.windows.firstMatch.scrollViews.allElementsBoundByIndex.first(where: {
            $0.frame.minX <= target.midX && target.midX <= $0.frame.maxX
                && (id.isEmpty || $0.descendants(matching: .any).matching(identifier: id).firstMatch.exists)
        }) else { return }
        for _ in 0..<20 where !inView(ui, e) {
            let now = e.frame
            let down = now.maxY > view.frame.maxY
            let up = now.minY < view.frame.minY
            guard down || up else { return }
            view.scroll(byDeltaX: 0, deltaY: down ? -200 : 200)
            if e.frame == now { return }
        }
    }

    /// Paste `text` into `key` as a person does (the decider, v0.4.1: "All input fields, I
    /// should be able to paste into"): put on the pasteboard, the field clicked, then ⌘V, or Edit ›
    /// Paste from the menu bar. What the field then holds (a secure field's value is one bullet per
    /// character), or nil when the field was not reached. The person's clipboard is put back by
    /// tearDown.
    /// Premise: the runner reads back what it puts on the pasteboard, else APPARATUS.
    @discardableResult
    private func paste(_ ui: XCUIApplication, _ key: Key, _ text: String, _ what: String,
                       fromMenu: Bool = false,
                       file: StaticString = #filePath, line: UInt = #line) -> String? {
        let board = NSPasteboard.general
        board.clearContents()
        board.setString(text, forType: .string)
        guard board.string(forType: .string) == text else {
            XCTFail("APPARATUS: the proof cannot put what it pastes into \(what) on the pasteboard",
                    file: file, line: line)
            return nil
        }
        guard tap(ui, key, what, file: file, line: line) else { return nil }
        if fromMenu {
            let edit = ui.menuBars.menuBarItems["Edit"]
            guard edit.waitForExistence(timeout: 10) else {
                keepTree(ui, "no Edit menu")
                XCTFail("PRODUCT: the app must have an Edit menu to paste into \(what) from; the menu bar has none",
                        file: file, line: line)
                return nil
            }
            edit.click()
            guard tap(ui, Key.menuItem("Paste"), "Edit › Paste, into \(what)", file: file, line: line) else {
                return nil
            }
        } else {
            el(ui, key).typeKey("v", modifierFlags: .command)
        }
        Thread.sleep(forTimeInterval: 0.5)
        return el(ui, key).value as? String
    }

    /// Select what `key` shows by dragging across it, as a person does, and copy it with ⌘C: what
    /// the pasteboard then holds (the decider, v0.4.1: "All text in the app, I should be able to
    /// select it for copy purposes").
    private func selectAndCopy(_ ui: XCUIApplication, _ key: Key, _ what: String,
                               file: StaticString = #filePath, line: UInt = #line) -> String {
        guard let e = locate(ui, key) else {
            missing(ui, key, "the app must show \(what)", file: file, line: line)
            return ""
        }
        return selectAndCopy(ui, e, what, file: file, line: line)
    }

    /// A timeline row by what it says as one sentence ("bob: COPY ONE"), not by its words alone.
    private func rowSaying(_ ui: XCUIApplication, _ sentence: String) -> XCUIElement? {
        let e = ui.windows.firstMatch.descendants(matching: .any)
            .matching(rowSays(sentence)).firstMatch
        return e.exists ? e : nil
    }

    /// A message's time as ⌘C copies it: this Mac's time zone, to the minute.
    private func copiedTime(_ millis: UInt64) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = .current
        f.dateFormat = "yyyy-MM-dd HH:mm"
        return f.string(from: Date(timeIntervalSince1970: Double(millis) / 1000))
    }

    /// The element whose own words are exactly `words` (a Text's value, or its label), in the
    /// window: one Text, not a row that says it among other things.
    private func textSaying(_ ui: XCUIApplication, _ words: String) -> XCUIElement? {
        let e = ui.windows.firstMatch.descendants(matching: .any)
            .matching(NSPredicate(format: "value == %@ OR label == %@", words, words)).firstMatch
        return e.exists ? e : nil
    }

    private func selectAndCopy(_ ui: XCUIApplication, _ e: XCUIElement, _ what: String,
                               file: StaticString = #filePath, line: UInt = #line) -> String {
        if !inView(ui, e) { scrollTo(ui, e) }
        return copiedBy(ui, {
            // From just inside its first character to just inside its last, on its first line and
            // its last if it wraps: the whole of it.
            let from = e.coordinate(withNormalizedOffset: CGVector(dx: 0, dy: 0.25)).withOffset(CGVector(dx: 1, dy: 0))
            let to = e.coordinate(withNormalizedOffset: CGVector(dx: 1, dy: 0.75)).withOffset(CGVector(dx: -1, dy: 0))
            from.click(forDuration: 0.3, thenDragTo: to)
            ui.typeKey("c", modifierFlags: .command)
        }, file: file, line: line)
    }

    /// Type `text` into `key`, only once it was clicked.
    /// A keyring change made in the app after the keyring window closed, or before it ever
    /// opened (attaching does not open it, ADR-028 K-12, #523): the app asks for the identity
    /// passphrase, and alice types it, as a person would. Answered only if asked: the change may
    /// land first, with the window open.
    private func keyringPassphraseIfAsked(_ ui: XCUIApplication, landed: () -> Bool) {
        let field = Key.id("keyring-passphrase")
        let end = Date().addingTimeInterval(30)
        while Date() < end && !landed() {
            if locate(ui, field) != nil {
                type(ui, field, "alice identity", "the keyring's passphrase field")
                tap(ui, Key.id("keyring-passphrase-continue"), "Continue")
                print("[proof] the keyring window was closed: the app asked for the passphrase, typed")
                return
            }
            Thread.sleep(forTimeInterval: 0.25)
        }
    }

    private func type(_ ui: XCUIApplication, _ key: Key, _ text: String, _ what: String,
                      file: StaticString = #filePath, line: UInt = #line) {
        if tap(ui, key, what, file: file, line: line) { el(ui, key).typeText(text) }
    }

    /// A staging step: `vox` must succeed, else the staging was not achieved. Its output, trimmed.
    @discardableResult
    private func staged(_ vox: String, _ args: [String], env: [String: String]) throws -> String {
        var argv = [vox] + args
        var input: String?
        // A keyring change's passphrase is typed at a terminal, never read from a file (ADR-028
        // K-13): the file's passphrase is typed at vox's prompt by the pty driver
        // (scripts/type-passphrase.py, copied into the scratch directory by app-proofs.sh).
        if let t = args.firstIndex(of: "trust"), t + 1 < args.count,
           ["add", "remove", "rename", "drive", "read"].contains(args[t + 1]),
           let f = args.firstIndex(of: "--identity-passphrase-file"), f + 1 < args.count {
            guard let scratch = ProcessInfo.processInfo.environment["VOX_PROOF_SCRATCH"] else {
                throw Apparatus("VOX_PROOF_SCRATCH is set by scripts/app-proofs.sh")
            }
            input = stager.run(["/bin/cat", args[f + 1]], env: [:]).out
            var rest = args
            rest.removeSubrange(f...(f + 1))
            argv = ["/usr/bin/python3", scratch + "/type-passphrase.py", "120", vox] + rest
        }
        let (status, out) = stager.run(argv, env: env, input: input)
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

    /// Premise: `fp` (alias `name`) is in alice's roster of `room`, as `vox room roster` says.
    private func member(_ vox: String, _ env: [String: String], _ room: String, _ fp: String,
                        _ name: String) -> Premise {
        Premise("\(name) is a member of the room") {
            let r = self.run(vox, ["room", "roster", "--node", "alice", room], env: env)
            return (r.status == 0 && r.out.contains(fp),
                    "`vox room roster` exited \(r.status) listing \(r.out.trimmingCharacters(in: .whitespacesAndNewlines).debugDescription), \(name) being \(fp)")
        }
    }

    /// Premise: `fp` (alias `name`) is in alice's keyring, as `vox trust list` says.
    private func trusted(_ vox: String, _ env: [String: String], _ fp: String,
                         _ name: String) -> Premise {
        Premise("\(name) is in alice's keyring") {
            let r = self.run(vox, ["trust", "list", "--node", "alice"], env: env)
            return (r.status == 0 && r.out.contains(fp),
                    "`vox trust list` exited \(r.status): \(r.out.trimmingCharacters(in: .whitespacesAndNewlines).debugDescription), \(name) being \(fp)")
        }
    }

    /// Premise: alice is in the room named `name`, as `vox room list` says.
    private func inRoom(_ vox: String, _ env: [String: String], _ name: String) -> Premise {
        Premise("alice is in room \(name)") {
            let r = self.run(vox, ["room", "list", "--node", "alice"], env: env)
            return (r.status == 0 && r.out.split(separator: "\n").contains { $0.contains(" \(name)") },
                    "`vox room list` exited \(r.status): \(r.out.trimmingCharacters(in: .whitespacesAndNewlines).debugDescription)")
        }
    }

    /// A message of `room` as alice's node reads it, by the start of its text: its id and the
    /// time it claims, in milliseconds.
    private func posted(_ vox: String, _ env: [String: String], _ room: String,
                        _ text: String) -> (id: String, millis: UInt64)? {
        let rows = run(vox, ["room", "read", "--node", "alice", "--json", room], env: env).out
        for line in rows.split(separator: "\n") {
            guard let row = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                  (row["text"] as? String)?.contains(text) == true,
                  let id = row["entry_hash"] as? String,
                  let millis = (row["created_millis"] as? NSNumber)?.uint64Value else { continue }
            return (id, millis)
        }
        return nil
    }

    /// The local day of `date`, as the timeline's day dividers name it: "2026-10-04".
    private static func dayKey(_ date: Date) -> String {
        let c = Calendar.current.dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", c.year ?? 0, c.month ?? 0, c.day ?? 0)
    }

    /// What a day divider says for a day other than today and yesterday: "Sunday, October 4", the
    /// year when it is not this one.
    private static func dayWords(_ date: Date) -> String {
        let cal = Calendar.current
        if cal.isDateInYesterday(date) { return "Yesterday" }
        if cal.component(.year, from: date) == cal.component(.year, from: Date()) {
            return date.formatted(.dateTime.weekday(.wide).month(.wide).day())
        }
        return date.formatted(.dateTime.weekday(.wide).month(.wide).day().year())
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
