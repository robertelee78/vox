//! A member on an **IPv6-only** socket reaches a board for its join in under two seconds (PRD-001
//! R42: a first connection in under 2s) — driven through the shipped binary.
//!
//! Found on 2026-09-26 while chasing #182: in the relayed-restart staging, a guest listening only
//! on `[::1]` printed `join got in — board 20.76s` even when the join succeeded. Its address named
//! the room's anchor and host on IPv4 (`b=/ip4/127.0.0.1/…`), and the join tried its board routes
//! **one after another**: each IPv4 route was dialled from a socket that cannot reach it and ran
//! its full timeout before the guest's own IPv6 anchor was tried at all. An IPv6-only member waited
//! twenty seconds for a board that was reachable the whole time.
//!
//! Staging, nothing faked: one anchor listening dual-stack (`[::]:0`); a host `vox serve`s a room
//! on IPv4 with the anchor's IPv4 spec, so the address it prints advertises only IPv4 routes; a
//! guest joins from `[::1]:0` with the anchor's IPv6 spec as its own `--anchor`. The anchor is the
//! same node either way, and it holds the room.
//!
//! Asserted: the join's own `board` step — which the node prints whether the join gets in or not —
//! took under [`BOARD_WITHIN`]. What happens after the board is not under test here: reaching an
//! IPv4 host from an IPv6-only guest needs a relay circuit (#173), so the join as a whole is
//! reported but not asserted.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::time::Duration;

use world::{after_label, args, echo_service, vox_once, VoxProc};

/// PRD-001 R42's bound for a first connection.
const BOARD_WITHIN: Duration = Duration::from_secs(2);

#[test]
#[ignore = "production Argon2id and a real PoW, driving the real binary; CI runs it in release"]
fn an_ipv6_only_joiner_reaches_its_board_within_two_seconds() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (anchor_dir, host_dir, guest_dir) = (
        tmp.path().join("anchor"),
        tmp.path().join("host"),
        tmp.path().join("guest"),
    );
    for d in [&anchor_dir, &host_dir, &guest_dir] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }

    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "[::]:0"]),
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            !l.starts_with("! ")
                && l.trim_start().contains('@')
                && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
        })
        .trim()
        .to_owned();
    let (fp, addr) = spec.split_once('@').expect("fp@addr");
    let port = addr.rsplit('/').next().expect("port");
    let v4_spec = format!("{fp}@/ip4/127.0.0.1/udp/{port}");
    let v6_spec = format!("{fp}@/ip6/::1/udp/{port}");

    for dir in [&host_dir, &guest_dir] {
        let (ok, _, err) = vox_once(dir, &args(&["id"]));
        assert!(ok, "vox id: {err}");
    }
    let mut host = VoxProc::spawn(
        "host",
        &host_dir,
        &args(&[
            "serve",
            &echo_service().to_string(),
            "--anchor",
            &v4_spec,
            "--listen",
            "127.0.0.1:0",
        ]),
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
        address.contains("/ip4/") && !address.contains("/ip6/"),
        "the address must advertise only IPv4 routes, or this is not the case under test: {address}"
    );

    let (joined, out, err) = vox_once(
        &guest_dir,
        &args(&[
            "connect",
            &address,
            "--passphrase",
            &passphrase,
            "--anchor",
            &v6_spec,
            "--listen",
            "[::1]:0",
        ]),
    );
    let said = format!("{out}{err}");
    eprintln!("[test] the IPv6-only guest's join (joined={joined}) said:\n{said}");
    // The join's step line: `join got in — board 0.41s, …` or `join did not get in — board …`.
    let board = said
        .split(" in — board ")
        .nth(1)
        .and_then(|rest| rest.split('s').next())
        .and_then(|secs| secs.trim().parse::<f64>().ok())
        .unwrap_or_else(|| panic!("the join must report its board step: {said}"));
    eprintln!(
        "[test] board reached in {board:.2}s (bound {}s)",
        BOARD_WITHIN.as_secs()
    );
    assert!(
        Duration::from_secs_f64(board) < BOARD_WITHIN,
        "an IPv6-only joiner took {board:.2}s to reach a board it could reach at once — the \
         address's IPv4 routes were dialled one by one, each to its timeout, before its own IPv6 \
         anchor: {said}"
    );
    drop(host);
    drop(anchor);
}
