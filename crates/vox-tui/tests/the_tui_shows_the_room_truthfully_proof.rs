//! The TUI shows a room as it is, and consent acts on the member you chose (V210-82, #273),
//! through the shipped `vox tui` in a pty.
//!
//! The work is in `tests/pty/tui_room_truth.py`: real daemons build a room of Alice, Bob and Carol
//! (Alice and Bob trust each other, nobody trusts Carol), Alice posts 70 lines, and Bob's real
//! `vox tui` is read through the `pyte` terminal emulator at 160x50. It checks fifteen claims, each
//! printed as a `CLAIM <name> ok|RED` line:
//!
//! - `newest`: the timeline shows m-070, the newest, and not m-001 (it drew from the top and never
//!   scrolled, so once a room filled the pane a new message was never seen);
//! - `follows`: m-071, posted while the TUI is open, is shown when it arrives;
//! - `scrolls`: PageUp brings m-001 into view, and End returns to m-071;
//! - `clamp`: PageUp well past the oldest line, then one PageDown, shows m-011 first (the scroll
//!   ran on past the top, so PageDown needed as many presses again before the view moved);
//! - `consent`: Carol, whom Bob never consented to, is not shown "consented", while Alice is (the
//!   pane said "consented" for everyone);
//! - `verify`: `:verify` does not mark Carol "verified" (it did, with nothing compared);
//! - `sync`: the status bar says how many peers the node is connected to, the anchor and at least
//!   one member, so 2 or more (it said "idle" always);
//! - `target`: with Carol selected, Dave joins and sorts in above her; `:consent grant` then
//!   consents to Carol and not to Dave (the selection was a position, so the join moved it onto
//!   someone else);
//! - `delivers`: the grant is the node's, not only the pane's: a line Bob then posts from the
//!   composer reaches Carol's `vox room read`;
//! - `revoke`: `:consent revoke`, with Carol still selected and not first in the pane, takes her
//!   back to "← in-only" and leaves Alice "↔ consented"; a line Bob then posts reaches Alice's
//!   `vox room read` and not Carol's (a revoke that acted on a position would take someone else);
//! - `trusted`: `:consent revoke` on Alice, whom Bob trusts, is refused and the status line says
//!   she is in his trust keyring and that `vox trust remove` withdraws her (it said "internal
//!   error"); 10 s later she is still "consented" and reads a line Bob then posts (a per-room
//!   revoke of a trusted member heals itself on the next tick, so the node refuses it);
//! - `reach`: back on the channel list, the room reads "● online" while Bob's node is connected
//!   to its other members (it said offline always);
//! - `unreach`: once every other member's daemon is stopped, it reads "○ offline";
//! - `fewer`: the status bar then says "connected to 1 peer", the anchor alone (a count that was
//!   not the node's stayed where it was);
//! - `idle`: once the anchor is stopped too, it says "idle", with no count.
//!
//! A selected member who leaves the pane is replaced by its first member, so the marker and the
//! member a command acts on stay one; no `vox` verb removes a member from a room's pane today, so
//! that point rests on code review (`UiState::settle`), not on this proof.
//!
//! Each claim turns red against a product that restores its defect: the timeline drawn from the
//! top, a scroll not clamped to the oldest line, `OutboundConsent::Granted` for everyone, the local
//! verification mark, `SyncStatus` hard-coded (idle, or any one count), the member selected by
//! index, `Reachability` hard-coded either way, or a per-room revoke of a trusted member let
//! through (the `is_trusted` refusal in `NodeCommand::Revoke` removed). It passes only on the
//! script's PASS with all 15 claims ok; its
//! apparatus failures (exit 2: `pyte` missing, a join or a precondition that did not happen, such
//! as Dave's join not moving Carol) fail as CANNOT MEASURE, never as a pass.

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
        "{said}\n[proof] claims ok: {green} of {} (15 expected); the driver took {:?}; its last \
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
                (15, 15),
                "a PASS must rest on all 15 claims, each ok: {said}"
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
            "PRODUCT: the TUI must show the room's newest message, follow and scroll, show consent, \
             verification, reachability and sync as the node has them, and consent to the \
             member selected, and refuse a per-room revoke of a trusted member: \
             red claims: {:?}",
            claims
                .iter()
                .filter(|l| l.contains(" RED: "))
                .collect::<Vec<_>>()
        ),
    }
}
