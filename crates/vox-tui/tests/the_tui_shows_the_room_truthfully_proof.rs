//! The TUI shows a room as it is (V210-82, #273),
//! through the shipped `vox tui` in a pty.
//!
//! The work is in `tests/pty/tui_room_truth.py`: real daemons build a room of Alice, Bob, Carol and
//! Dave (Alice and Bob trust each other, nobody trusts Carol, Bob trusts Dave and Dave nobody),
//! Alice posts 70 lines, and Bob's real `vox tui` is read through the `pyte` terminal emulator at
//! 160x50. It checks thirty-one claims, each
//! printed as a `CLAIM <name> ok|RED` line:
//!
//! - `newest`: the timeline shows m-070, the newest, and not m-001 (it drew from the top and never
//!   scrolled, so once a room filled the pane a new message was never seen);
//! - `hidden`: characters a reader cannot see read as `⟨U+XXXX⟩` escapes in the timeline (#331):
//!   Alice's tag characters (U+E0068, U+E0069), her word split by U+200B and U+200C, and her stray
//!   U+200D, and her bidi override U+202E, in the one style (#331); her family emoji 👨‍👩‍👧 is drawn whole: no escape on its row, and the TUI wrote the
//!   cluster to the terminal unbroken, joiners and all. pyte splits a cluster into cells and keeps
//!   only its first person, so the rest is read from the bytes the TUI wrote, and how a real
//!   terminal draws the glyph is not seen;
//! - `readby`: under a message Bob posts, nothing is said of readers until Alice's agent drains
//!   it, and then exactly "read by alice", from the read record her node posted; Carol, who cannot
//!   read Bob, is named neither way (ADR-028 R-6, RR-3, #505);
//! - `nostorm`: read records never answer read records (the decider; ADR-028 RR-2): with Alice's
//!   real `vox tui` on the room beside Bob's and both agents draining, once each TUI says the other
//!   has read its post, the entries `vox status --json` says each node holds stay the same for 15 s;
//! - `serve`: Bob's `:serve <port>`, for a service the driver listens on on every interface, says
//!   before sharing it its address, that alice can reach it and that it listens on every
//!   interface; Enter shares it, and Alice's `vox service list` lists it (ADR-028 S-4, #491);
//! - `retention`: with both TUIs open, Alice sets the room's retention to 1 week: each header, which
//!   said "⏱ forever", says "⏱ 1 week", and each timeline shows one line saying who set it and
//!   that messages older than that are removed from now on (ADR-028 R-7, #483); and a focused
//!   pane's border names it once;
//! - `words`: `:link` says "room link: vox://…" and `:join` asks for a "room link (vox://…)",
//!   never an "invite link" (the decider's words, #406);
//! - `follows`: m-071, posted while the TUI is open, is shown when it arrives;
//! - `shown`: what Bob's TUI drew is read, and only that: Alice's `vox room read --json` says
//!   m-071, on his screen, is read by bob, and m-001, not yet drawn, by nobody (ADR-028 RR-1,
//!   #504);
//! - `scrolls`: PageUp brings m-001 into view, and End returns to m-071;
//! - `clamp`: PageUp well past the oldest line, then one PageDown, shows m-010 first, the oldest
//!   line being the one saying alice named the room (the scroll
//!   ran on past the top, so PageDown needed as many presses again before the view moved);
//! - `renamed`: Alice renames the room while Bob's TUI is open, and his timeline says so in one
//!   line, by his name for her: "alice renamed the room to family" (ADR-028 R-1, E-5);
//! - `quote`: Alice posts q-root, q-mid replying to it, and 50 lines; Bob selects q-mid, presses
//!   Ctrl-R and sends q-answer. His post's `re` names q-mid, and the TUI shows it under "┆ alice:
//!   q-mid…", one level, never q-root, while q-mid itself is off screen (ADR-028 R-9, #485);
//! - `jump`: Bob selects q-answer and presses Enter, and q-mid is scrolled to and selected;
//! - `consent`: who reads whom, in words (ADR-028 R-5, #481): Carol, whom Bob never trusted, reads
//!   "not in keyring: trust to read each other", Dave, whom he trusts and who trusts nobody,
//!   "waiting for the other side", and Alice "trusted both ways" (the pane said "consented" for
//!   everyone, then "? unverified" on every row and "← in-only" for Carol, though Bob's node
//!   refuses her key; V210-155); and no row of the pane names a verified, TOFU or key-changed
//!   state, a consent or a block: one trust state, in the keyring or not (ADR-028 K-2, K-6, #473);
//! - `look`: in truecolour, Alice's row reads "⇄ alice" (each trusts the other) and Dave's
//!   "→ dave" (only Bob trusts him), both in text.primary bold, and Carol's "· <fingerprint>" in
//!   text.secondary, not bold; the accent is on the focused members pane's border and nowhere
//!   else (ADR-028 L-3, L-4; colours read from the token file);
//! - `unknown`: `:show`, `:hide`, `:block`, `:unblock`, `:verify`, `:consent`, `:grant` and
//!   `:revoke` each answer "unknown command",
//!   and the help line names none of them (they only said "not available yet"; V210-155);
//! - `sync`: the status bar says how many peers the node is connected to, the anchor and at least
//!   one member, so 2 or more (it said "idle" always);
//! - `reach`: back on the channel list, the room reads "● online" while Bob's node is connected
//!   to its other members (it said offline always);
//! - `notify`: with no room on screen, three messages Alice posts raise one notification, titled
//!   with the room, naming Alice and holding none of their text (ADR-028 R-10, #486), and no
//!   second one for the same room while it stays off screen;
//! - `regions`: the sidebar names Bob's node attached; once Alice writes to him there, the room is
//!   listed under "needs you (1)" reading "to you 1"; and the nodes on his machine are listed, his
//!   attached and a second one detached (ADR-028 W-1, W-2, #511);
//! - `newcomer`: Frank joins while Bob's TUI is open, and it says "<frank> joined. No one you trust
//!   trusts it yet.", then, once Alice (whom Bob trusts) trusts Frank, "<frank> joined. alice trusts
//!   it.", naming neither Erin (in Bob's keyring, never in the room, never granting Frank) nor
//!   anyone outside Bob's keyring (ADR-028 K-7, #476); Frank is added to no keyring of Bob's;
//! - `onenode`: `:node spare` is refused, naming the one node the window acts as, and the window
//!   still acts as default, by its status bar and sidebar (ADR-028 E-4, #470);
//! - `trust`: the join's line offers ":trust <frank's first 8>" (ADR-028 K-5, #475); `t` on Frank
//!   in the members pane opens the trust prompt showing his fingerprint; Dave's fingerprint pasted
//!   there adds nothing, says not to trust him and shows both; Frank's own, pasted through the
//!   `:trust` the hint offers, in groups and upper case, adds him and says so once the identity
//!   passphrase is typed into the prompt (`VOX_TEST_KEYRING_WINDOW_SECS` makes Bob's window a
//!   minute, so it has closed): a wrong passphrase adds nothing and is never shown;
//! - `unreach`: once every other member's daemon is stopped, it reads "○ offline";
//! - `fewer`: the status bar then says "connected to 1 peer", the anchor alone (a count that was
//!   not the node's stayed where it was);
//! - `where`: with Alice's, Carol's and Dave's daemons stopped, under a message Bob then posts his TUI
//!   says "only on this machine"; once Alice's daemon is back and has synced, "on 1 of 3 members'
//!   nodes" (ADR-028 R-6, #482);
//! - `accent`: there, the accent marks only the focused list's border and the live "● online";
//! - `idle`: once the anchor is stopped too, it says "idle", with no count;
//! - `depths`: Bob's TUI opened again three ways (ADR-028 L-5, #509): under `NO_COLOR` with
//!   `LC_ALL=C` it draws no colour at all, and Alice reads "<> alice" and Dave "-> dave", bold, and
//!   Carol ". <her fingerprint>", every state still read by glyph, weight and word; in 16 colours (`TERM=xterm`)
//!   every colour drawn is one of the 16; in 256 colours Alice's name is index 255 and Carol's 247.
//!   In each the words are as in truecolour and the accent is on the focused border alone.
//! - `copies`: Alice shares an ssh stand-in; Bob's Shared pane lists it, and `y` on it puts
//!   `ssh $USER@<its canonical address>` on the clipboard by OSC 52, prints it in full under the
//!   service and says "copied" on the status line, the address Alice's `vox service list --json`
//!   gives (ADR-028 S-3, #490).
//!
//! The `target`, `delivers` and `revoke` claims are gone with `:consent grant|revoke` (V210-148): a
//! key goes only to a member the owner trusts, so the TUI has no per-room grant to aim.
//!
//! Each claim turns red against a product that restores its defect: the timeline drawn from the
//! top, a scroll not clamped to the oldest line, the room's own lines (who named it) not drawn,
//! every member shown `Trust::Trusted`, a stub command restored, the message pane's `reveal` removed, a member whose read records Bob cannot open named
//! as not having read, every message marked read whether drawn or not, a message called held by a
//! node that has not said it holds it, a read record named by a read record, `SyncStatus`
//! hard-coded (idle, or any one count), `Reachability` hard-coded either way, a notification that
//! carries the message text or is raised per message, a room with a message to Bob grouped other
//! than "needs you", trust coloured with the accent (`look`, `depths`), or the snapshot's
//! `consenting` list sent empty, so no member reads `⇄` (`look`, `depths`), a join line naming a
//! trusted member that has not granted the newcomer (`newcomer`), a retention change with no line in
//! the timeline or a focused pane titled twice (`retention`), the share flow's every-interface
//! warning left out (`serve`), a quote of the thread's root rather than `re`, Enter on a reply not
//! moving the selection, a trusted member shown as "verified" (`consent`), `:node <name>` acting as
//! another node again, a copied command that is not the service's canonical address (`copies`), or
//! a pasted fingerprint that is not the node's let through to the keyring (`trust`). It passes only
//! on the script's PASS with all 31 claims ok.
//!
//! A `vox` step on the way to the claims that fails (an identity, a daemon, create, invite, join,
//! trust, a post, the roster, the TUI drawing the room or answering a command it supports) is
//! PRODUCT: the driver says `PRODUCT:` with what `vox` said. Only the driver's own machinery is
//! APPARATUS (exit 2: `pyte` missing, the driver crashing), CANNOT MEASURE, never a pass.
//! A driver that runs past its budget was still waiting on `vox` at its last stage, so it
//! reads PRODUCT, unless the runner itself stalled past `STALL_BUDGET` meanwhile, which reads
//! CANNOT MEASURE; a driver that ends with no verdict at all is APPARATUS.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/pty_driver.rs"]
mod pty_driver;

#[path = "support/test_knobs.rs"]
mod test_knobs;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The runner's own stalls across the driver's run: a thread that asks to sleep [`Self::TICK`]
/// and records how much longer than that it was away. A driver past its budget while the
/// runner itself stood still for a good part of it measured the runner, not `vox`.
struct StallClock {
    stop: Arc<AtomicBool>,
    worst_ms: Arc<AtomicU64>,
    thread: std::thread::JoinHandle<()>,
}

impl StallClock {
    const TICK: Duration = Duration::from_millis(100);

    fn start() -> Self {
        let (stop, worst_ms) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
        );
        let (s, w) = (stop.clone(), worst_ms.clone());
        let thread = std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                let t = Instant::now();
                std::thread::sleep(Self::TICK);
                let late = t.elapsed().saturating_sub(Self::TICK);
                w.fetch_max(late.as_millis() as u64, Ordering::Relaxed);
            }
        });
        Self {
            stop,
            worst_ms,
            thread,
        }
    }

    /// The longest the runner was away past one tick.
    fn stop(self) -> Duration {
        self.stop.store(true, Ordering::Relaxed);
        self.thread
            .join()
            .expect("APPARATUS: the stall clock's thread panicked");
        Duration::from_millis(self.worst_ms.load(Ordering::Relaxed))
    }
}

/// A runner stall past this, during a driver that ran out its budget, is the runner's.
const STALL_BUDGET: Duration = Duration::from_secs(30);

#[test]
#[ignore = "real daemons and `vox tui` in a pty, with production Argon2id; CI runs it in release"]
fn the_tui_shows_the_room_truthfully_and_consents_to_the_member_chosen() {
    // A hung proof is a failing proof (ADR-018 §6), and the driver is bounded on its own (#240).
    // Its bounds are the product's: a member waits 480 s for a joiner's proof of work (V210-87),
    // which a debug build can take minutes to grind, and the driver joins three members at once, then
    // a fourth while the TUI is open, then opens the TUI three times more (`depths`, about 90 s).
    // So the driver's budget is 1750 s, it is stopped from outside at 1780 s, and the watchdog is
    // past both. A release run takes about two minutes.
    watchdog::arm_for(Duration::from_secs(1880));
    // Bob's keyring window is a minute, so the trust prompt's passphrase field is typed into
    // (`trust`): the window is closed by then.
    test_knobs::require(&["VOX_TEST_KEYRING_WINDOW_SECS"]);
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_room_truth.py");
    let clock = StallClock::start();
    let out = pty_driver::run_within(
        script,
        &[env!("CARGO_BIN_EXE_vox"), "truth"],
        Duration::from_secs(1780),
    );
    let stall = clock.stop();
    let said = out.stdout.clone();
    let claims: Vec<&str> = said.lines().filter(|l| l.contains(" CLAIM ")).collect();
    let green = claims.iter().filter(|l| l.contains(" ok: ")).count();
    eprintln!(
        "{said}\n[proof] claims ok: {green} of {} (31 expected); the driver took {:?}; its last \
         stage: {:?}; the runner's longest stall: {stall:?}",
        claims.len(),
        out.took,
        out.stage
    );
    match out.code {
        Some(0) => {
            assert!(
                said.contains("truth PASS"),
                "APPARATUS: the driver exited 0 without a PASS line: {said}"
            );
            assert_eq!(
                (claims.len(), green),
                (31, 31),
                "APPARATUS: the driver said PASS without all 31 claims ok: {said}"
            );
        }
        Some(2) => panic!("APPARATUS, CANNOT MEASURE: the TUI proof's driver failed: {said}"),
        _ if !out.has_verdict("truth") => panic!(
            "APPARATUS: the TUI proof's driver ended with no verdict — an uncaught exception, \
             its faulthandler backstop, or a stop from outside — at stage {:?} (exit {:?}; its \
             stack is above, on stderr): {said}",
            out.stage.as_deref().unwrap_or("(before its first stage)"),
            out.code
        ),
        _ if said.contains("outlived SIGKILL") => panic!(
            "APPARATUS: the TUI proof's driver could not reap the `vox tui` it started, even \
             after SIGKILL: {said}"
        ),
        _ if said.contains("HUNG at") || out.code.is_none() => {
            let stage = out.stage.as_deref().unwrap_or("(before its first stage)");
            // Past its budget the driver was still waiting on `vox` at `stage`, unless the
            // runner itself stood still: the stall clock says which.
            assert!(
                stall <= STALL_BUDGET,
                "APPARATUS, CANNOT MEASURE: the runner stalled {stall:?} during the driver's {:?}, \
                 which ran past its budget at stage {stage:?} (exit {:?}): {said}",
                out.took,
                out.code
            );
            panic!(
                "PRODUCT: the driver ran past its budget at stage {stage:?} after {:?}, waiting \
                 on `vox` there while the runner kept time (its longest stall {stall:?}); the \
                 stage and the driver's stack are above, on stderr: exit {:?}: {said}",
                out.took,
                out.code
            )
        }
        // A `vox` step before the claims failed: the driver quotes what `vox` said.
        _ if said.contains("truth PRODUCT:") => panic!(
            "PRODUCT: a `vox` step on the way to the TUI's claims failed: {said}"
        ),
        _ => panic!(
            "PRODUCT: the TUI must show the room's newest message, follow and scroll, show trust, \
             offer only working commands, reachability and sync as the node has them: red claims: {:?}",
            claims
                .iter()
                .filter(|l| l.contains(" RED: "))
                .collect::<Vec<_>>()
        ),
    }
}
