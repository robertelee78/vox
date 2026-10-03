//! The TUI shows a room as it is (V210-82, #273),
//! through the shipped `vox tui` in a pty.
//!
//! The work is in `tests/pty/tui_room_truth.py`: real daemons build a room of Alice, Bob and Carol
//! (Alice and Bob trust each other, nobody trusts Carol), Alice posts 70 lines, and Bob's real
//! `vox tui` is read through the `pyte` terminal emulator at 160x50. It checks eleven claims, each
//! printed as a `CLAIM <name> ok|RED` line:
//!
//! - `newest`: the timeline shows m-070, the newest, and not m-001 (it drew from the top and never
//!   scrolled, so once a room filled the pane a new message was never seen);
//! - `follows`: m-071, posted while the TUI is open, is shown when it arrives;
//! - `scrolls`: PageUp brings m-001 into view, and End returns to m-071;
//! - `clamp`: PageUp well past the oldest line, then one PageDown, shows m-011 first (the scroll
//!   ran on past the top, so PageDown needed as many presses again before the view moved);
//! - `consent`: Carol, whom Bob never trusted, reads "not trusted · you don't read each other", and
//!   Alice "trusted · reads you" (the pane said "consented" for everyone, then "? unverified" on
//!   every row and "← in-only" for Carol, though Bob's node refuses her key; V210-155);
//! - `unknown`: `:show`, `:hide`, `:block`, `:unblock` and `:verify` each answer "unknown command",
//!   and the help line names none of them (they only said "not available yet"; V210-155);
//! - `sync`: the status bar says how many peers the node is connected to, the anchor and at least
//!   one member, so 2 or more (it said "idle" always);
//! - `reach`: back on the channel list, the room reads "● online" while Bob's node is connected
//!   to its other members (it said offline always);
//! - `unreach`: once every other member's daemon is stopped, it reads "○ offline";
//! - `fewer`: the status bar then says "connected to 1 peer", the anchor alone (a count that was
//!   not the node's stayed where it was);
//! - `idle`: once the anchor is stopped too, it says "idle", with no count.
//!
//! The `target`, `delivers` and `revoke` claims are gone with `:consent grant|revoke` (V210-148): a
//! key goes only to a member the owner trusts, so the TUI has no per-room grant to aim.
//!
//! Each claim turns red against a product that restores its defect: the timeline drawn from the
//! top, a scroll not clamped to the oldest line, every member shown `Trust::Trusted`, a stub command
//! restored, `SyncStatus` hard-coded (idle, or any one count), or `Reachability`
//! hard-coded either way. It passes only on the script's PASS with all 11 claims ok; its
//! apparatus failures (exit 2: `pyte` missing, a join or a precondition that did not happen, such
//! as Alice never shown trusted) fail as CANNOT MEASURE, never as a pass.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/pty_driver.rs"]
mod pty_driver;

use std::time::Duration;

#[test]
#[ignore = "real daemons and `vox tui` in a pty, with production Argon2id; CI runs it in release"]
fn the_tui_shows_the_room_truthfully_and_consents_to_the_member_chosen() {
    // A hung proof is a failing proof (ADR-018 §6), and the driver is bounded on its own (#240).
    // Its bounds are the product's: a member waits 480 s for a joiner's proof of work (V210-87),
    // which a debug build can take minutes to grind, and the driver joins three members. So the
    // driver's budget is 1170 s, it is stopped from outside at 1200 s, and the watchdog is past
    // both. A release run takes about a minute.
    watchdog::arm_for(Duration::from_secs(1300));
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_room_truth.py");
    let out = pty_driver::run_within(
        script,
        &[env!("CARGO_BIN_EXE_vox"), "truth"],
        Duration::from_secs(1200),
    );
    let said = out.stdout.clone();
    let claims: Vec<&str> = said.lines().filter(|l| l.contains(" CLAIM ")).collect();
    let green = claims.iter().filter(|l| l.contains(" ok: ")).count();
    eprintln!(
        "{said}\n[proof] claims ok: {green} of {} (11 expected); the driver took {:?}; its last \
         stage: {:?}",
        claims.len(),
        out.took,
        out.stage
    );
    match out.code {
        Some(0) => {
            assert!(
                said.contains("truth PASS"),
                "exit 0 without a PASS line: {said}"
            );
            assert_eq!(
                (claims.len(), green),
                (11, 11),
                "a PASS must rest on all 11 claims, each ok: {said}"
            );
        }
        Some(2) => panic!("CANNOT MEASURE: the TUI proof's apparatus failed: {said}"),
        _ if !out.has_verdict("truth") => panic!(
            "the TUI proof's driver was stopped before it gave a verdict — by its faulthandler \
             backstop, or from outside — at stage {:?} (exit {:?}; its stack is above, on \
             stderr): {said}",
            out.stage.as_deref().unwrap_or("(before its first stage)"),
            out.code
        ),
        _ if said.contains("outlived SIGKILL") => {
            panic!("the TUI proof could not stop the `vox tui` it started: {said}")
        }
        _ if said.contains("HUNG at") || out.code.is_none() => panic!(
            "the TUI proof hung (its stage and stack are above, on stderr): exit {:?}: {said}",
            out.code
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
