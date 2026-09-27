//! The TUI names a member by the name you gave it, or by 26 characters of its fingerprint marked
//! "(not in keyring)" (#198, V210-24), through the shipped `vox tui` in a pty.
//!
//! The work is in `tests/pty/tui_member_names.py` (real daemons; the TUI's screen read through the
//! `pyte` terminal emulator). This wrapper is what makes CI run it: a script nobody runs guards
//! nothing. It passes only on the script's PASS; its apparatus failures (exit 2, e.g. `pyte`
//! missing) fail as CANNOT MEASURE, never as a pass.

#![cfg(unix)]

#[test]
#[ignore = "real daemons and `vox tui` in a pty, with production Argon2id; CI runs it in release"]
fn the_tui_names_a_trusted_member_by_name_and_anyone_else_by_fingerprint_marked() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_member_names.py");
    let out = std::process::Command::new("python3")
        .args([script, env!("CARGO_BIN_EXE_vox"), "cargo"])
        .output()
        .expect("python3 must be on PATH to run the TUI proof");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!("{said}");
    match out.status.code() {
        Some(0) => assert!(said.contains("cargo PASS"), "exit 0 without a PASS line: {said}"),
        Some(2) => panic!("CANNOT MEASURE: the TUI proof's apparatus failed: {said}"),
        _ => panic!("the TUI must name alice \"alice\" and carol by 26 characters + \"(not in keyring)\": {said}"),
    }
}
