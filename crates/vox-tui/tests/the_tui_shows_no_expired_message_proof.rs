//! PRD-001 R10 in the TUI: an open `vox tui` stops showing a message once it expires, and keeps
//! following the room (`tests/pty/tui_expired.py`, real daemons and the shipped `vox tui` read
//! through the `pyte` terminal emulator). The CLI surfaces are in
//! `an_expired_message_shows_on_no_surface_proof`.
//!
//! This wrapper is what makes CI run the driver. It passes only on the driver's PASS. The driver
//! exits 1 on a product verdict, quoting what `vox` said or drew; exit 2, or no verdict at all, is
//! the apparatus (CANNOT MEASURE).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/pty_driver.rs"]
mod pty_driver;

use std::time::Duration;

#[test]
#[ignore = "real daemons and `vox tui` in a pty, with production Argon2id; CI runs it in release"]
fn an_open_tui_stops_showing_a_message_once_it_expires() {
    // The driver's budget is 900 s (one debug-build join plus the retention waits), it is stopped
    // from outside at 930 s, and the watchdog is past both.
    watchdog::arm_for(Duration::from_secs(1000));
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_expired.py");
    let out = pty_driver::run_within(
        script,
        &[env!("CARGO_BIN_EXE_vox"), "cargo"],
        Duration::from_secs(930),
    );
    let said = out.stdout.clone();
    eprintln!(
        "{said}\n[proof] the driver took {:?}; its last stage: {:?}",
        out.took, out.stage
    );
    match out.code {
        Some(0) => assert!(
            said.contains("cargo PASS"),
            "APPARATUS: the driver exited 0 without a PASS line: {said}"
        ),
        Some(2) => panic!("CANNOT MEASURE: the TUI proof's apparatus failed: {said}"),
        _ if !out.has_verdict("cargo") => panic!(
            "CANNOT MEASURE: APPARATUS: the TUI driver gave no verdict after {:?} at stage {:?} \
             (exit {:?}): stopped from outside at the wrapper's 930 s bound, by its faulthandler \
             backstop, or crashed; its stack or traceback is above, on stderr: {said}",
            out.took,
            out.stage.as_deref().unwrap_or("(before its first stage)"),
            out.code
        ),
        Some(1) if said.contains("did not return within") => {
            panic!("PRODUCT: a `vox` verb ran past the product's own bound for it: {said}")
        }
        Some(1) if said.contains("cargo PRODUCT:") => {
            panic!("PRODUCT: a `vox` step failed: {said}")
        }
        Some(1) if said.contains("cargo RED") => {
            panic!("PRODUCT: the open TUI still shows messages past the room's retention: {said}")
        }
        _ => panic!(
            "CANNOT MEASURE: APPARATUS: the TUI driver ended after {:?} at stage {:?} with exit \
             {:?} and no verdict this wrapper knows: {said}",
            out.took,
            out.stage.as_deref().unwrap_or("(before its first stage)"),
            out.code
        ),
    }
}
