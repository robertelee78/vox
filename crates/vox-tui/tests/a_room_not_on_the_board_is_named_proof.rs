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
//! exist — an room link carries no checksum, so a room id with one mistyped character still
//! parses — so the advice must name both and claim neither. Two cases, nothing faked:
//!
//! 1. **A mistyped room id.** A host `vox serve`s a room through anchor A. One character of the
//!    room id is changed to another base32 digit, and a guest joins with that address: it parses,
//!    reaches A (up, holding the real room), and A has nothing for it.
//! 2. **A host that goes offline as it is read.** Anchor A is stopped, and the guest joins with the
//!    real address and its own anchor B, which never had the room; while its read of the host is
//!    held (a test knob on the host), the host's `vox serve` ends and its daemon stops the node.
//!    Found on 8faf006a (#406): that moment, reached by chance, was reported as "the room's host
//!    answered, then its connection closed … run the join again", though the host had gone
//!    offline and B had nothing for the room.
//! 3. **An unpublished room.** Anchor A and the host are both gone — both held the room, and the
//!    address names both as boards — and the guest joins again the same way.
//!
//! Asserted in each: the join fails; the reason names the board reached and the room; the advice
//! names both causes (not published yet, host must be online; or a wrong room id) and never says
//! the address is fine; and the old "will not parse" advice is gone. Mutations: returning
//! `Fault::BadLink` for a board without the room turns it red; so does taking a host that went
//! offline as it was read for one that answered and closed (`went_offline` ignored in
//! `Joiner::a_board_with_the_room`), in case 2.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::time::{Duration, Instant};

use world::{after_label, args, echo_service, vox_once, VoxProc};

/// A `vox node` anchor on loopback, and the `--anchor` spec it prints.
fn anchor(dir: &std::path::Path, name: &str) -> (VoxProc, String) {
    std::fs::create_dir_all(dir.join("cfg"))
        .expect("APPARATUS: cannot make the anchor's profile directory");
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
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let (host_dir, guest_dir) = (tmp.path().join("host"), tmp.path().join("guest"));
    for d in [&host_dir, &guest_dir] {
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: cannot make a profile directory");
    }
    let (anchor_a, spec_a) = anchor(&tmp.path().join("anchor-a"), "anchor-a");
    let (_anchor_b, spec_b) = anchor(&tmp.path().join("anchor-b"), "anchor-b");
    let board_a: String = spec_a.chars().take(12).collect();
    let board_b: String = spec_b.chars().take(12).collect();

    for dir in [&host_dir, &guest_dir] {
        let (ok, _, err) = vox_once(dir, &args(&["id"]));
        assert!(ok, "PRODUCT (staging): vox id failed: {err}");
    }

    // The room exists, and anchor A holds it: `vox serve` publishes before it prints the address.
    // The host's daemon holds each board read it serves for a while (a test knob), so case 2 can
    // stop the host while a join's read of it is in flight.
    let mut host = VoxProc::spawn_env(
        "host",
        &host_dir,
        &args(&[
            "serve",
            &format!("{0}={0}", echo_service()),
            "--anchor",
            &spec_a,
            "--listen",
            "127.0.0.1:0",
        ]),
        &[(
            HOLD_BOARD_READ_ENV,
            &HOLD_BOARD_READ.as_millis().to_string(),
        )],
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
        "PRODUCT (staging): the address must name anchor A, or B is not the only board the join can \
         reach: {address}"
    );

    // ---- Case 1: a mistyped room id, against boards that are up ----
    //
    // One character of the room id changed to another base32 digit: still 32 valid bytes, so the
    // address parses, reaches anchor A — which is up and holds the *real* room — and finds nothing
    // for this one. The board cannot tell this from "not published yet", so the advice must not
    // claim the address is fine.
    let wrong = mistype_room(&address);
    let wrong_room: String = wrong["vox://".len()..].chars().take(12).collect();
    assert_ne!(
        wrong, address,
        "APPARATUS: the proof's mistyped address must differ"
    );
    let said = join(&guest_dir, &wrong, &passphrase, &spec_a);
    assert_names_both_causes(&said, &board_a, &wrong_room, "a mistyped room id");

    // ---- Case 2: the host goes offline while the join reads it ----
    //
    // Anchor A goes away, so the boards up are the host and the guest's anchor B, which never had
    // the room; the join reaches the host first (the address names it before B). While its read
    // of the host is held, the host's `vox serve` ends: its daemon stops the node, which closes
    // the connection the read is on. Found on 8faf006a (#406): a daemon finishing a node's stop
    // after its last client went was reached by a join in that moment, and the join said "the
    // room's host answered, then its connection closed … run the join again", with B saying it
    // had nothing for the room. The host had gone offline, which is what leaves a room
    // unpublished where a joiner looks: a board not reached.
    drop(anchor_a);
    let room12: String = room.chars().take(12).collect();
    let before = world::log_tail(&host_dir, usize::MAX).lines().count();
    let read_held = |since: usize| {
        world::log_tail(&host_dir, usize::MAX)
            .lines()
            .skip(since)
            .any(|l| l.contains("vox: test: holding a board read from"))
    };
    let (said, stopped_in_time) = std::thread::scope(|s| {
        let joining = s.spawn(|| join(&guest_dir, &address, &passphrase, &spec_b));
        let held = wait_for(Duration::from_secs(40), || read_held(before));
        let t = Instant::now();
        drop(host);
        let detached = wait_for(Duration::from_secs(20), || {
            world::log_tail(&host_dir, 40).contains("node default detached")
        });
        let stopped_in_time = held && detached && t.elapsed() < HOLD_BOARD_READ;
        (
            joining
                .join()
                .expect("APPARATUS: the join's thread panicked"),
            stopped_in_time,
        )
    });
    assert!(
        stopped_in_time,
        "CANNOT MEASURE: the host did not stop while the join's read of it was held ({} ms): the \
         read was not seen held, or the host's node was not detached in time; the host's daemon \
         log:\n{}\nthe join said:\n{said}",
        HOLD_BOARD_READ.as_millis(),
        world::log_tail(&host_dir, 40)
    );
    assert_names_both_causes(
        &said,
        &board_b,
        &room12,
        "a host gone offline as it was read",
    );

    // ---- Case 3: the room is real, and nowhere the guest can reach holds it ----
    //
    // Every board that holds the room has gone away — anchor A, and the host itself, which the
    // address also names as a board — and the one the guest can reach never had it. The host
    // being offline is also the field case: it is what leaves a room unpublished where a joiner
    // looks.
    let said = join(&guest_dir, &address, &passphrase, &spec_b);
    assert_names_both_causes(&said, &board_b, &room12, "an unpublished room");
}

/// The host's test knob that holds each board read it serves, and for how long: long enough for
/// the proof to see the hold and stop the host inside it.
const HOLD_BOARD_READ_ENV: &str = "VOX_TEST_HOLD_BOARD_READ_MS";
const HOLD_BOARD_READ: Duration = Duration::from_secs(8);

/// Whether `ok` holds within `limit`, asking every 50 ms.
fn wait_for(limit: Duration, mut ok: impl FnMut() -> bool) -> bool {
    let t = Instant::now();
    while t.elapsed() < limit {
        if ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    ok()
}

/// `vox connect` the profile at `dir` with `address`, and everything it said.
fn join(dir: &std::path::Path, address: &str, passphrase: &str, anchor: &str) -> String {
    let (ok, out, err) = vox_once(
        dir,
        &args(&[
            "connect",
            address,
            "--passphrase-file",
            &world::room_pass_file(dir, passphrase),
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
        "PRODUCT: the join succeeded, but no board it can reach holds that room\n{said}"
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
        "PRODUCT: {case}: the reason must name the board that was reached ({board}) and the room ({room}): \
         {said}"
    );
    assert!(
        said.contains("has not published the room there yet")
            && said.contains("host must be online")
            && said.contains("the room part of the address is wrong"),
        "PRODUCT: {case}: the advice must name both causes — not published yet, or a wrong room id: {said}"
    );
    assert!(
        !said.contains("address is fine"),
        "PRODUCT: {case}: the advice claimed the address is fine, which the board cannot know: {said}"
    );
    assert!(
        !said.contains("will not parse"),
        "PRODUCT: {case}: reported as a malformed address, which it is not: {said}"
    );
}
