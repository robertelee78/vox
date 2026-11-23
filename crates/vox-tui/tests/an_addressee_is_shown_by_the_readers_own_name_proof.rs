//! PRD-001 R15 (#18) — **every surface a person reads shows an addressee by the reader's own
//! keyring name**, through the shipped `vox` binary. The wire carries fingerprints (V210-161,
//! shipped); the drain already shows `to …` by the reader's names (V210-162). This proof drives
//! the TUI's timeline, which showed only the raw text, whose `to` is fingerprints.
//!
//! `the_tui_shows_each_node_its_own_name_for_the_addressee` (`tests/pty/tui_addressee_names.py`):
//! bob, who has no name for carol, sees alice's message to `mom` in his own `vox tui` as `alice to
//! <carol's fingerprint>:`, never `to mom`; alice sees `you to mom:`.
//!
//! Then (ADR-028 K-4, #474) bob trusts carol as `Alice`, which his `alice` differs from only by
//! case: his TUI must show `alice#<6 of alice's fingerprint>` and `Alice#<6 of carol's>` in the
//! members pane and on alice's message, never either bare; and `@alice …` typed in his composer
//! must carry alice's whole fingerprint in `to`.
//!
//! Mutation: a TUI that does not name addressees goes red on its screen; a TUI that drops the
//! suffix for a case-only clash goes red on its screen.

#![cfg(unix)]

#[path = "support/pty_driver.rs"]
mod pty_driver;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::Duration;

#[test]
#[ignore = "real daemons and `vox tui` in a pty, with production Argon2id; run it in release"]
fn the_tui_shows_each_node_its_own_name_for_the_addressee() {
    // The pty driver owns the causal join bounds.
    watchdog::arm();
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/pty/tui_addressee_names.py"
    );
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
    match out.code {
        Some(0) => assert!(
            said.contains("cargo PASS"),
            "APPARATUS: exit 0 without a PASS line: {said}"
        ),
        Some(2) => panic!("CANNOT MEASURE: the TUI proof's apparatus failed: {said}"),
        _ if !out.has_verdict("cargo") => panic!(
            "CANNOT MEASURE: APPARATUS: the TUI driver gave no verdict after {:?} at stage {:?} \
             (exit {:?}): {said}",
            out.took,
            out.stage.as_deref().unwrap_or("(before its first stage)"),
            out.code
        ),
        Some(1) => panic!(
            "PRODUCT: each node's TUI must show the addressee by its own name for her, or her \
             fingerprint, never another node's name; tell two aliases that differ only by case \
             apart by a fingerprint suffix; and send `@alias` to the member's whole fingerprint \
             (the driver's PRODUCT line says which): {said}"
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
