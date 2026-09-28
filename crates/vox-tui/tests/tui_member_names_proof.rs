//! The TUI names a member by the name you gave it, or by 26 characters of its fingerprint marked
//! "(not in keyring)" (#198, V210-24), through the shipped `vox tui` in a pty.
//!
//! The work is in `tests/pty/tui_member_names.py` (real daemons; the TUI's screen read through the
//! `pyte` terminal emulator). This wrapper is what makes CI run it: a script nobody runs guards
//! nothing. It passes only on the script's PASS; its apparatus failures (exit 2, e.g. `pyte`
//! missing) fail as CANNOT MEASURE, never as a pass.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/pty_driver.rs"]
mod pty_driver;

#[test]
#[ignore = "real daemons and `vox tui` in a pty, with production Argon2id; CI runs it in release"]
fn the_tui_names_a_trusted_member_by_name_and_anyone_else_by_fingerprint_marked() {
    // A hung proof is a failing proof (ADR-018 §6). Unarmed, this one ran 40 min on the macOS CI
    // runner until the job's 120-minute limit cancelled everything (run 36397085576, 2f49ffb). Armed,
    // the watchdog dumps stacks and kills the pty driver, `vox tui` and the daemons (#201).
    watchdog::arm();
    // And the driver is bounded on its own (V210-54, #240): past its budget it says where it was
    // and stops everything, and past `pty_driver::BOUND` it is stopped from outside.
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_member_names.py");
    let out = pty_driver::run(script, &[env!("CARGO_BIN_EXE_vox"), "cargo"]);
    let said = out.stdout.clone();
    eprintln!(
        "{said}\n[proof] the driver took {:?}; its last stage: {:?}",
        out.took, out.stage
    );
    match out.code {
        Some(0) => assert!(said.contains("cargo PASS"), "exit 0 without a PASS line: {said}"),
        Some(2) => panic!("CANNOT MEASURE: the TUI proof's apparatus failed: {said}"),
        _ if !out.has_verdict("cargo") => panic!(
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
        _ => panic!("the TUI must name alice \"alice\" and carol by 26 characters + \"(not in keyring)\": {said}"),
    }
}
