//! A join that reaches a board **which does not hold the room** says so, names the board, and
//! says what to do — driven through the shipped binary.
//!
//! Found on 2026-09-25 in the relayed-restart gate: a guest's join reached its anchor after 20s,
//! the anchor had nothing for the room (the host's publish had not landed there), and `vox`
//! printed
//!
//! ```text
//! cannot join: that address will not parse, or names a room this node cannot use
//!        this one IS the address — check you copied all of it
//! ```
//!
//! The address was fine. The join code returned `Fault::BadLink` for "the board I reached has no
//! genesis for this room", so the one thing a person was told to check was the one thing that
//! was not wrong, and the thing that was — the host had not published to that board — was never
//! mentioned.
//!
//! The board cannot tell a room whose host has not published it there from a room that does not
//! exist — an invite link carries no checksum, so a room id with one mistyped character still
//! parses — so the advice must name both and claim neither. Two cases, nothing faked:
//!
//! 1. **A mistyped room id.** A host `vox serve`s a room through anchor A. One character of the
//!    room id is changed to another base32 digit, and a guest joins with that address: it parses,
//!    reaches A (up, holding the real room), and A has nothing for it.
//! 2. **An unpublished room.** Anchor A and the host are stopped — both hold the room, and the
//!    address names both as boards — and the guest joins with the real address and its own anchor
//!    B, which never had the room.
//!
//! Asserted in both: the join fails; the reason names the board reached and the room; the advice
//! names both causes (not published yet, host must be online; or a wrong room id) and never says
//! the address is fine; and the old "will not parse" advice is gone. Mutation: returning
//! `Fault::BadLink` for a board without the room turns it red.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use world::{after_label, args, echo_service, vox_once, VoxProc};

/// A `vox node` anchor on loopback, and the `--anchor` spec it prints.
fn anchor(dir: &std::path::Path, name: &str) -> (VoxProc, String) {
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    let mut node = VoxProc::spawn(name, dir, &args(&["node", "--listen", "127.0.0.1:0"]));
    let spec = node
        .expect_line("an --anchor spec", |l| {
            !l.starts_with("! ")
                && l.trim_start().contains('@')
                && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
        })
        .trim()
        .to_owned();
    (node, spec)
}

#[test]
#[ignore = "production Argon2id and a real PoW, driving the real binary; CI runs it in release"]
fn a_join_to_a_board_without_the_room_names_the_board_and_the_remedy() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (host_dir, guest_dir) = (tmp.path().join("host"), tmp.path().join("guest"));
    for d in [&host_dir, &guest_dir] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let (anchor_a, spec_a) = anchor(&tmp.path().join("anchor-a"), "anchor-a");
    let (_anchor_b, spec_b) = anchor(&tmp.path().join("anchor-b"), "anchor-b");
    let board_a: String = spec_a.chars().take(12).collect();
    let board_b: String = spec_b.chars().take(12).collect();

    for dir in [&host_dir, &guest_dir] {
        let (ok, _, err) = vox_once(dir, &args(&["id"]));
        assert!(ok, "vox id: {err}");
    }

    // The room exists, and anchor A holds it: `vox serve` publishes before it prints the address.
    let mut host = VoxProc::spawn(
        "host",
        &host_dir,
        &args(&[
            "serve",
            &echo_service().to_string(),
            "--anchor",
            &spec_a,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    let room = after_label(
        &host.expect_line("room", |l| l.starts_with("room ")),
        "room",
    );
    let address = after_label(
        &host.expect_line("address", |l| l.starts_with("address ")),
        "address",
    );
    let passphrase = after_label(
        &host.expect_line("passphrase", |l| l.starts_with("passphrase ")),
        "passphrase",
    );
    assert!(
        address.contains(&spec_a[..52]),
        "the address must name anchor A, or B is not the only board the join can reach: {address}"
    );

    // ---- Case 1: a mistyped room id, against boards that are up ----
    //
    // One character of the room id changed to another base32 digit: still 32 valid bytes, so the
    // address parses, reaches anchor A — which is up and holds the *real* room — and finds nothing
    // for this one. The board cannot tell this from "not published yet", so the advice must not
    // claim the address is fine.
    let wrong = mistype_room(&address);
    let wrong_room: String = wrong["vox://".len()..].chars().take(12).collect();
    assert_ne!(wrong, address, "the mistyped address must differ");
    let said = join(&guest_dir, &wrong, &passphrase, &spec_a);
    assert_names_both_causes(&said, &board_a, &wrong_room, "a mistyped room id");

    // ---- Case 2: the room is real, and nowhere the guest can reach holds it ----
    //
    // Every board that holds the room goes away — anchor A, and the host itself, which the
    // address also names as a board — and the one the guest can reach never had it. The host
    // being offline is also the field case: it is what leaves a room unpublished where a joiner
    // looks.
    drop(anchor_a);
    drop(host);
    let room12: String = room.chars().take(12).collect();
    let said = join(&guest_dir, &address, &passphrase, &spec_b);
    assert_names_both_causes(&said, &board_b, &room12, "an unpublished room");
}

/// `vox connect` the profile at `dir` with `address`, and everything it said.
fn join(dir: &std::path::Path, address: &str, passphrase: &str, anchor: &str) -> String {
    let (ok, out, err) = vox_once(
        dir,
        &args(&[
            "connect",
            address,
            "--passphrase",
            passphrase,
            "--anchor",
            anchor,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    let said = format!("{out}{err}");
    eprintln!("[test] the guest's join said:\n{said}");
    assert!(
        !ok,
        "the join must fail: no board it can reach holds that room\n{said}"
    );
    said
}

/// Change one character of the room id (the part after `vox://`) to a different base32 digit.
/// The first character carries a full five bits, so any digit there is still a valid encoding.
fn mistype_room(address: &str) -> String {
    let at = "vox://".len();
    let old = address.as_bytes()[at];
    let new = if old == b'a' { 'b' } else { 'a' };
    format!("{}{new}{}", &address[..at], &address[at + 1..])
}

/// The reason names the board and the room; the advice names **both** possible causes and never
/// claims the address is fine; and the old malformed-address advice is gone.
fn assert_names_both_causes(said: &str, board: &str, room: &str, case: &str) {
    assert!(
        said.contains(&format!("board {board} has nothing for room {room}")),
        "{case}: the reason must name the board that was reached ({board}) and the room ({room}): \
         {said}"
    );
    assert!(
        said.contains("has not published the room there yet")
            && said.contains("host must be online")
            && said.contains("the room part of the address is wrong"),
        "{case}: the advice must name both causes — not published yet, or a wrong room id: {said}"
    );
    assert!(
        !said.contains("address is fine"),
        "{case}: the advice claimed the address is fine, which the board cannot know: {said}"
    );
    assert!(
        !said.contains("will not parse"),
        "{case}: reported as a malformed address, which it is not: {said}"
    );
}
