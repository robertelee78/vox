//! RP-27 — **`vox forward` binds loopback only** (ADR-013), through the shipped binary.
//!
//! A forward is a local TCP listener that carries every connection it accepts into a
//! room-bound service, authorized by *this* node's membership of the room. On loopback that is
//! a private door. Bound where the network can reach it, it is an open one: whoever connects
//! gets the service, with no room, no passphrase, no key and no consent of their own. And a
//! forward's target is already chosen, so reaching the port is the whole attack.
//!
//! **Staging.** Real `vox` processes only (`support/world.rs`): an anchor (`vox node`), a host
//! running `vox serve` in front of a real TCP echo service, and a guest who joined with
//! `vox connect` and whom the host trusts (`vox trust add`) — so a forward from the guest to
//! that service is one the host would carry.
//!
//! **Asserted.**
//! 1. `vox forward <port>.<host>.<room>.vox 0.0.0.0:<P>` — the guest asking for a forward on every
//!    interface — **exits non-zero within 60 s, says the port must be on loopback, and never
//!    reports a bound forward**. It is refused before any dial: it never says it is waiting for
//!    a path to the host.
//! 2. Nothing is left listening on `<P>`: this test can bind `0.0.0.0:<P>` itself afterwards.
//! 3. The refusal is about the address, not about forwarding: the same guest's
//!    `vox forward … 127.0.0.1:0` binds, and a connection through it round-trips the echo.
//!
//! **Mutation that must turn it red.** Delete the loopback checks — `Fault::NotLoopback` in
//! `node::actor`'s forward handler and the `is_loopback` refusal in `node::tunnel`'s
//! `Forward::bind`. The forward then binds `0.0.0.0:<P>`, prints its bound line, and carries a
//! connection, and assertion 1 fails naming that.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use world::{args, echo_service, round_trip, VoxProc, World};

/// How long the refusal may take: a node starts, unlocks with production Argon2id and opens
/// the room first. Far below the 300 s a forward waits for an unreachable host.
const REFUSAL: Duration = Duration::from_secs(60);

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .unwrap_or_else(|e| panic!("APPARATUS: pick a free TCP port: {e}"))
        .port()
}

#[test]
#[ignore = "real vox processes, production Argon2id and a real join; run in release"]
fn a_forward_refuses_to_bind_where_the_network_can_reach_it() {
    watchdog::arm();
    let w = World::new(echo_service(), true);
    let port = free_tcp_port();
    let exposed = format!("0.0.0.0:{port}");

    // ---- 1. the guest asks for a forward on every interface --------------------------------
    let t0 = Instant::now();
    let mut fwd = VoxProc::spawn(
        "exposed-forward",
        &w.guest_dir,
        &args(&[
            "forward",
            &w.service_host(),
            &exposed,
            "--anchor",
            &w.guest_anchor,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    let mut bound_line = None;
    loop {
        let left = REFUSAL.saturating_sub(t0.elapsed());
        assert!(
            !left.is_zero(),
            "PRODUCT: `vox forward … {exposed}` neither exited nor bound within {REFUSAL:?}. It said:\n{}",
            fwd.transcript()
        );
        match fwd.lines.recv_timeout(left.min(Duration::from_secs(1))) {
            Ok(line) => {
                eprintln!("[exposed-forward] {line}");
                let bound = line.starts_with("vox: ") && line.contains('→');
                fwd.seen.push(line.clone());
                if bound {
                    bound_line = Some(line);
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    if let Some(line) = bound_line {
        // The defect: show what it means before failing on it.
        let carried = round_trip(
            format!("127.0.0.1:{port}")
                .parse()
                .expect("APPARATUS: a loopback address"),
            b"reached through an exposed forward",
            Duration::from_secs(60),
        );
        panic!(
            "PRODUCT: `vox forward` bound {exposed} — every interface — and reported {line:?}; a \
             connection through it {}. Whoever reaches that port gets this room's service on \
             the guest's membership, with no key and no consent of their own",
            match carried {
                Ok(_) => "was carried to the host's service".to_owned(),
                Err(e) => format!("failed ({e})"),
            }
        );
    }
    let status = fwd
        .child
        .wait()
        .unwrap_or_else(|e| panic!("APPARATUS: wait for the forward's exit status: {e}"));
    let took = t0.elapsed();
    let said = fwd.transcript();
    println!("[proof] `vox forward … {exposed}` exited {status} after {took:?}");
    assert!(
        !status.success(),
        "PRODUCT: `vox forward … {exposed}` exited successfully. It said:\n{said}"
    );
    assert!(
        said.contains("loopback"),
        "PRODUCT: the refusal must say the port has to be on loopback. It said:\n{said}"
    );
    assert!(
        !said.contains("not reachable yet"),
        "PRODUCT: the refusal came only after waiting for a path to the host — it must be refused before \
         anything is dialled. It said:\n{said}"
    );

    // ---- 2. nothing was left listening ------------------------------------------------------
    let taken = std::net::TcpListener::bind(exposed.as_str());
    println!("[proof] {exposed} free afterwards: {}", taken.is_ok());
    assert!(
        taken.is_ok(),
        "PRODUCT: the refused forward left something on {exposed}: {:?}",
        taken.err()
    );
    drop(taken);

    // ---- 3. the same guest forwarding on loopback works -------------------------------------
    let (_fwd, at) = w.forward("loopback-forward", &w.guest_dir);
    assert!(
        at.ip().is_loopback(),
        "PRODUCT: the control forward on loopback bound {at}"
    );
    let payload = b"through a loopback forward";
    let back = round_trip(at, payload, Duration::from_secs(120)).expect(
        "PRODUCT (staging): a loopback forward from the same guest must carry a connection",
    );
    assert_eq!(
        back, payload,
        "PRODUCT (staging): the loopback forward's echo came back wrong"
    );
    println!(
        "[proof] control: a forward on {at} round-tripped {} bytes",
        back.len()
    );
}
