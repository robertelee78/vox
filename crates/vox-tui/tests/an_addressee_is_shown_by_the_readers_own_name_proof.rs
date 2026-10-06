//! PRD-001 R15 (#18) — **every surface a person reads shows an addressee by the reader's own
//! keyring name**, through the shipped `vox` binary. The wire carries fingerprints (V210-161,
//! shipped); the drain already shows `to …` by the reader's names (V210-162). What remained were
//! the person's surfaces: `vox room read` (and `vox room tail`, which prints the same rows) and the
//! TUI's timeline, which showed only the raw text, whose `to` is fingerprints.
//!
//! `the_room_read_shows_each_reader_its_own_name_for_the_addressee`: an anchor and alice's, bob's
//! and carol's `vox daemon` in one room (`support/room.rs`). Alice renames carol `mom`, bob renames
//! her `cee`. Bob posts an `ask` `--to cee`. Then:
//!
//! 1. alice's `vox room read` shows the row followed by the line `  (to mom)`, bob's `  (to cee)`,
//!    carol's `  (to you)`, and no reader is shown another node's name for her;
//! 2. `vox room read --json` gives the same as `to_names`: `["mom"]`, `["cee"]`, `["you"]`, while
//!    `envelope.to` is carol's whole fingerprint on every node.
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
//! Mutation: `vox room read` that does not name addressees goes red at (1); a TUI that does not goes
//! red on its screen; a TUI that drops the suffix for a case-only clash goes red on its screen.

#![cfg(unix)]

#[path = "support/pty_driver.rs"]
mod pty_driver;
#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::Duration;

use support::{until, Worker};

/// `w`'s operator renames the member `who` in `w`'s own keyring.
fn rename(w: &Worker, who: &Worker, name: &str) {
    let o = w.vox(
        None,
        &[
            "trust",
            "rename",
            &who.b32(),
            name,
            "--identity-passphrase-file",
            w.pass.to_str().expect("APPARATUS: a UTF-8 temp path"),
        ],
    );
    assert!(
        o.ok,
        "PRODUCT (staging): {}'s `vox trust rename` of {} failed: {o:?}",
        w.name, who.name
    );
}

#[test]
#[ignore = "on demand: real daemons with production Argon2id; run it in release"]
fn the_room_read_shows_each_reader_its_own_name_for_the_addressee() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("APPARATUS: a tokio runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: a tempdir");
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob", "carol"]));
    let (alice, bob, carol) = (&room.workers[0], &room.workers[1], &room.workers[2]);
    let r = room.id.as_str();
    rename(alice, carol, "mom");
    rename(bob, carol, "cee");

    let posted = bob.vox_in(
        Some("bob-s"),
        &["room", "post", r, "--type", "ask", "--to", "cee", "-"],
        Some("R15-ASK which port?"),
    );
    assert!(
        posted.ok,
        "PRODUCT (staging): bob's `vox room post --to cee` failed: {posted:?}"
    );

    let mut failures: Vec<String> = Vec::new();
    for (w, own, others) in [
        (alice, "mom", ["cee"]),
        (bob, "cee", ["mom"]),
        (carol, "you", ["mom"]),
    ] {
        let read = until(w, None, "bob's ask to arrive", &["room", "read", r], |o| {
            o.ok && o.stdout.contains("R15-ASK")
        });
        let lines: Vec<&str> = read.stdout.lines().collect();
        let at = lines
            .iter()
            .position(|l| l.contains("R15-ASK"))
            .unwrap_or_default();
        let next = lines.get(at + 1).copied().unwrap_or_default();
        let want = format!("  (to {own})");
        println!(
            "[proof] {}'s `vox room read`:\n  {}\n  {next}",
            w.name, lines[at]
        );
        if next != want {
            failures.push(format!(
                "PRODUCT (1): {}'s `vox room read` must show the addressee as {want:?} on the line \
                 after the row; it showed {next:?}",
                w.name
            ));
        }
        if others
            .iter()
            .any(|o| read.stdout.contains(&format!("(to {o})")))
        {
            failures.push(format!(
                "PRODUCT (1): {} was shown another node's name for the addressee:\n{}",
                w.name, read.stdout
            ));
        }
        let json = w.vox(None, &["room", "read", r, "--json"]);
        let row = json
            .ndjson()
            .into_iter()
            .find(|x| x["text"].as_str().is_some_and(|t| t.contains("R15-ASK")));
        let to = row.as_ref().map(|x| x["envelope"]["to"].clone());
        let names = row.as_ref().map(|x| x["to_names"].clone());
        println!("[proof] {}'s --json: to {to:?}, to_names {names:?}", w.name);
        if to != Some(serde_json::json!([carol.b32()])) {
            failures.push(format!(
                "PRODUCT (2): {}'s copy must carry carol's whole fingerprint in `to`: {to:?}",
                w.name
            ));
        }
        if names != Some(serde_json::json!([own])) {
            failures.push(format!(
                "PRODUCT (2): {}'s `vox room read --json` must give `to_names` [{own:?}]: {names:?}",
                w.name
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    println!("[proof] R15: each reader is shown its own name for the addressee: mom, cee, you");
}

#[test]
#[ignore = "real daemons and `vox tui` in a pty, with production Argon2id; run it in release"]
fn the_tui_shows_each_node_its_own_name_for_the_addressee() {
    // Bounded as `tui_member_names_proof` is, for the same two joins in a debug build.
    watchdog::arm_for(Duration::from_secs(1400));
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
