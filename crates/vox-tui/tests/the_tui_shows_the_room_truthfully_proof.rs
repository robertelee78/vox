//! The TUI shows a room as it is, and consent acts on the member you chose (V210-82, #273),
//! through the shipped `vox tui` in a pty.
//!
//! The work is in `tests/pty/tui_room_truth.py`: real daemons build a room of Alice, Bob and Carol
//! (Alice and Bob trust each other, nobody trusts Carol), Alice posts 70 lines, and Bob's real
//! `vox tui` is read through the `pyte` terminal emulator at 160x50. It checks seven claims, each
//! printed as a `CLAIM <name> ok|RED` line:
//!
//! - `newest`: the timeline shows m-070, the newest, and not m-001 (it drew from the top and never
//!   scrolled, so once a room filled the pane a new message was never seen);
//! - `follows`: m-071, posted while the TUI is open, is shown when it arrives;
//! - `scrolls`: PageUp brings m-001 into view, and End returns to m-071;
//! - `consent`: Carol, whom Bob never consented to, is not shown "consented", while Alice is (the
//!   pane said "consented" for everyone);
//! - `verify`: `:verify` does not mark Carol "verified" (it did, with nothing compared);
//! - `sync`: the status bar says how many peers the node is connected to (it said "idle" always);
//! - `target`: with Carol selected, Dave joins and sorts in above her; `:consent grant` then
//!   consents to Carol and not to Dave (the selection was a position, so the join moved it onto
//!   someone else).
//!
//! Each claim turns red against a product that restores its defect: the timeline drawn from the
//! top, `OutboundConsent::Granted` for everyone, the local verification mark, `SyncStatus::Idle`,
//! or the member selected by index. It passes only on the script's PASS with all 7 claims ok; its
//! apparatus failures (exit 2: `pyte` missing, a join or a precondition that did not happen, such
//! as Dave's join not moving Carol) fail as CANNOT MEASURE, never as a pass.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/pty_driver.rs"]
mod pty_driver;

#[test]
#[ignore = "real daemons and `vox tui` in a pty, with production Argon2id; CI runs it in release"]
fn the_tui_shows_the_room_truthfully_and_consents_to_the_member_chosen() {
    // A hung proof is a failing proof (ADR-018 §6), and the driver is bounded on its own (#240).
    watchdog::arm();
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_room_truth.py");
    let out = pty_driver::run(script, &[env!("CARGO_BIN_EXE_vox"), "truth"]);
    let said = out.stdout.clone();
    let claims: Vec<&str> = said.lines().filter(|l| l.contains(" CLAIM ")).collect();
    let green = claims.iter().filter(|l| l.contains(" ok: ")).count();
    eprintln!(
        "{said}\n[proof] claims ok: {green} of {} (7 expected); the driver took {:?}; its last \
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
                (7, 7),
                "a PASS must rest on all 7 claims, each ok: {said}"
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
            "the TUI must show the room's newest message, follow and scroll, show consent, \
             verification and sync as the node has them, and consent to the member selected: \
             red claims: {:?}",
            claims
                .iter()
                .filter(|l| l.contains(" RED: "))
                .collect::<Vec<_>>()
        ),
    }
}
