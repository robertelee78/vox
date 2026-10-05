//! The TUI names a member by the name you gave it, or by 26 characters of its fingerprint, whole,
//! with "not in keyring" on its state line (#198, V210-24; ADR-028 L-4), through the shipped
//! `vox tui` in a pty; and (ADR-028 K-1, L-9, W-1, #472) draws the selected member's card, its fingerprint grouped beside its art, and a
//! keyring view (`k`) of every node you trust with the same card, each node's art its own.
//! Mutation: the art drawn from the alias instead of the fingerprint turns it red (Alice's art and
//! Erin's are then one).
//!
//! The work is in `tests/pty/tui_member_names.py` (real daemons; the TUI's screen read through the
//! `pyte` terminal emulator). This wrapper is what makes CI run it: a script nobody runs guards
//! nothing. It passes only on the script's PASS; its apparatus failures (exit 2, e.g. `pyte`
//! missing, or the driver past its budget) fail as CANNOT MEASURE, never as a pass, and its product
//! reds say PRODUCT.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/pty_driver.rs"]
mod pty_driver;

use std::time::Duration;

#[test]
#[ignore = "real daemons and `vox tui` in a pty, with production Argon2id; CI runs it in release"]
fn the_tui_names_a_trusted_member_by_name_and_anyone_else_by_fingerprint_marked() {
    // A hung proof is a failing proof (ADR-018 §6), and the driver is bounded on its own (V210-54,
    // #240). Its bounds are the product's: a member waits 480 s for a joiner's proof of work
    // (V210-87), which a debug build grinds for a minute or more, and the driver joins two members.
    // At a 240 s budget a debug run was cut off mid-join and read as a hang (V210-111, #307). So the
    // driver's budget is 1260 s, it is stopped from outside at 1290 s, and the watchdog is past
    // both. A release run takes about 40 s.
    watchdog::arm_for(Duration::from_secs(1400));
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_member_names.py");
    let out = pty_driver::run_within(
        script,
        &[env!("CARGO_BIN_EXE_vox"), "cargo"],
        Duration::from_secs(1290),
    );
    let said = out.stdout.clone();
    eprintln!(
        "{said}\n[proof] the driver took {:?}; its last stage: {:?}",
        out.took, out.stage
    );
    // Every red names whose it is. The driver exits 1 only on a product verdict: the members pane
    // drawn wrong, or a `vox` verb past the product's own bound for it. Everything else is the
    // apparatus: exit 2 (`pyte` missing, the driver past its budget, a `vox tui` it could not
    // reap), or a driver stopped from outside before it gave a verdict.
    match out.code {
        Some(0) => assert!(
            said.contains("cargo PASS"),
            "APPARATUS: the driver exited 0 without a PASS line: {said}"
        ),
        Some(2) => panic!("APPARATUS, CANNOT MEASURE: the TUI proof's driver failed: {said}"),
        _ if !out.has_verdict("cargo") => panic!(
            "CANNOT MEASURE: APPARATUS: the TUI driver gave no verdict after {:?} at stage {:?} \
             (exit {:?}): stopped from outside at the wrapper's 1290 s bound, by its faulthandler \
             backstop, or crashed; its stack or traceback is above, on stderr: {said}",
            out.took,
            out.stage.as_deref().unwrap_or("(before its first stage)"),
            out.code
        ),
        Some(1) if said.contains("did not return within") => {
            panic!("PRODUCT: a `vox` verb ran past the product's own bound for it: {said}")
        }
        // A `vox` step before the members pane failed: the driver quotes what `vox` said.
        Some(1) if said.contains("cargo PRODUCT:") => {
            panic!("PRODUCT: a `vox` step before the TUI's members pane failed: {said}")
        }
        Some(1) if said.contains("cargo RED") => panic!(
            "PRODUCT: the TUI must name alice \"alice\" and carol by 26 characters + \"(not in \
             keyring)\", and draw each node's own card in the members pane and the keyring view: \
             {said}"
        ),
        _ => panic!(
            "CANNOT MEASURE: APPARATUS: the TUI driver ended after {:?} at stage {:?} with exit \
             {:?} and no verdict this wrapper knows: {said}",
            out.took,
            out.stage.as_deref().unwrap_or("(before its first stage)"),
            out.code
        ),
    }
}
