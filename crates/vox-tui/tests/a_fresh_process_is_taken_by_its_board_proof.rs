//! V210-51 (#230) — **a fresh process's address is taken by its board**, through the shipped binary.
//!
//! A board replaces a member's record only with a later `timestamp`, in whole seconds — ADR-012's
//! bound of one changed claim a second per author (`nat::store::check_replacement`). A process that
//! starts within the second its predecessor last published in signs its first record in that same
//! second, and the board refused it as stale. Every cold `vox forward` on integrate 1de7548 logged
//! `a board would not take our address … the board holds a newer record from that author`, and
//! the board went on naming the previous, dead process's address until the next publish round.
//!
//! The node now publishes its own record again just past the next second when a board refuses it
//! as stale (`NetEvent::RepublishTo`), and a refusal no republish cures is said once its short grace
//! is over (`NetEvent::StaleGraceOver`) — held, never dropped.
//!
//! **Read through the product.** `vox node` prints, per member, the address its board holds for it
//! (`board — <room> holding <addr> for <member>`): what the board hands anyone asking where that
//! member is. The decider chose this readout for the proof (#230).
//!
//! **The scene.** A host serves an echo behind a real `vox node` anchor; a guest joins; then
//! [`SAMPLES`] cold `vox forward`s run one after another from the guest's profile, each a new process
//! on its own UDP port, started as soon as the last one is killed.
//!
//! **What must hold:** within [`TAKEN_WITHIN`] of each forward binding, the anchor prints that it
//! holds **that** process's address for the guest; and no forward says a board would not take its
//! address.
//!
//! Mutation: `NetEvent::RepublishTo` does nothing — red: the anchor keeps the previous process's
//! address, and the forward says a board would not take its address.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::time::{Duration, Instant};

use relay::{RelayWorld, Split};
use world::{args, vox_once, VoxProc};

/// Cold forwards, one after another.
const SAMPLES: usize = 5;
/// How long after a forward binds the anchor may take to hold its address.
const TAKEN_WITHIN: Duration = Duration::from_secs(2);
/// How long each forward is watched for a refusal it did not cure: past the node's grace for a
/// stale refusal (5 s).
const WATCH: Duration = Duration::from_secs(8);
/// What a node prints when a board would not take its own address.
const REFUSED: &str = "would not take our address";

/// A UDP port nobody holds right now.
fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn a_fresh_process_is_taken_by_its_board() {
    watchdog::arm();
    let mut w = RelayWorld::new(Split::None);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "CANNOT PROVE: the guest could not join ({took:?}).\n{out}\n{err}"
    );
    let (ok, guest_fp, err) = vox_once(&w.guest_dir, &args(&["id"]));
    assert!(ok, "vox id (guest): {err}");
    let guest: String = guest_fp.trim().chars().take(26).collect();

    let mut refused: Vec<String> = Vec::new();
    for n in 0..SAMPLES {
        // A fresh `vox forward` on a port of its own, started as soon as the previous one is
        // killed by its PID.
        drop(w.fwd.take());
        let port = free_udp_port();
        let listen = format!("127.0.0.1:{port}");
        let mut fwd = VoxProc::spawn(
            "forward",
            &w.guest_dir,
            &args(&[
                "forward",
                &w.room,
                &w.host_fp,
                &w.service,
                "127.0.0.1:0",
                "--passphrase",
                &w.passphrase,
                "--anchor",
                &w.anchor.v4_spec,
                "--listen",
                &listen,
            ]),
        );
        fwd.expect_line("the forward's bound address", |l| {
            l.starts_with("vox: 127.0.0.1:") && l.contains('→')
        });
        let bound = Instant::now();
        let held = format!("/udp/{port} for {guest}");
        let line = w.anchor.proc.expect_within(
            TAKEN_WITHIN,
            &format!("the anchor holding sample {n}'s address (port {port}) for the guest"),
            |l| l.contains(" holding ") && l.contains(&held),
        );
        eprintln!(
            "[proof] sample {n}: the anchor holds its address {:?} after binding: {}",
            bound.elapsed(),
            line.trim()
        );
        std::thread::sleep(WATCH.saturating_sub(bound.elapsed()));
        let said = fwd.transcript();
        refused.extend(
            said.lines()
                .filter(|l| l.contains(REFUSED))
                .map(|l| format!("sample {n}: {l}")),
        );
        w.fwd = Some(fwd);
    }
    assert!(
        refused.is_empty(),
        "a fresh process was told its board would not take its address:\n{}",
        refused.join("\n")
    );
}
