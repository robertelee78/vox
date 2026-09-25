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
//! Staging, with nothing faked: a host `vox serve`s a room through anchor A, so the address names
//! A (and the host itself) as boards, and both hold the room. Both are then stopped, and a guest
//! joins with that address and its own anchor B, which has never heard of the room. The join
//! tries A and the host (down), reaches B, and B answers the room fetch with nothing. The same state as the field: the room exists and the
//! address is right, but the board the joiner could reach does not hold it.
//!
//! Asserted: the join fails; the reason names board B and the room; the advice says the room is
//! not on that board yet and that its host must be online; and the old "will not parse" advice
//! is gone. Mutation: returning `Fault::BadLink` for a board without the room again turns it red.

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

    // Every board that holds the room goes away — anchor A, and the host itself, which the
    // address also names as a board — and the one the guest can reach never had it. The host
    // being offline is also the field case: it is what leaves a room unpublished where a joiner
    // looks.
    drop(anchor_a);
    drop(host);

    let (ok, out, err) = vox_once(
        &guest_dir,
        &args(&[
            "connect",
            &address,
            "--passphrase",
            &passphrase,
            "--anchor",
            &spec_b,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    let said = format!("{out}{err}");
    eprintln!("[test] the guest's join said:\n{said}");
    assert!(
        !ok,
        "the join must fail: no board it can reach holds the room"
    );
    assert!(
        said.contains(&format!("board {board_b} does not hold room")),
        "the reason must name the board that was reached ({board_b}): {said}"
    );
    assert!(
        said.contains(&room.chars().take(12).collect::<String>()),
        "the reason must name the room: {said}"
    );
    assert!(
        said.contains("the room is not on that board yet") && said.contains("host must be online"),
        "the advice must say the room has not been published there and that its host must be \
         online: {said}"
    );
    assert!(
        !said.contains("will not parse"),
        "a board without the room was reported as a bad address — the one thing that was right: \
         {said}"
    );
}
