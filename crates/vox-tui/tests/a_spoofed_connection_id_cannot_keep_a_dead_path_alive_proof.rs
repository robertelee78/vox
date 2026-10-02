//! PRD-001 R22 / ADR-012 — **a connection's liveness is counted only from authenticated
//! packets** (V210-140), driven through the shipped `vox` binary with an on-path attacker.
//!
//! **The claim.** A node decides a held connection is dead from silence, and fails over to a
//! working path. ADR-012 recorded a residual: the silence was measured from datagrams quinn
//! *observed* on the connection, a count it raises before the packet is decrypted. So a peer on
//! the path that knows the connection's ID could keep a dead connection looking alive to the 60 s
//! idle timeout, delaying the failover. The fix counts only authenticated frames, which quinn
//! tallies after a packet decrypts.
//!
//! **The staging — real processes, an on-path attacker in userspace.** A `vox node` anchor, a
//! `vox serve` host on `127.0.0.1` behind a **port forward the proof owns** (`support/port_forward.rs`,
//! via the proof-only `VOX_TEST_ADVERTISE`), and a guest on `[::1]` whose only direct path to the
//! host is that forward (ADR address-family split; see `relay.rs`). The forward is the on-path
//! position ADR-012 describes: it sees every datagram, so it learns the connection ID the guest's
//! QUIC routes its host connection by, from the host's packets to the guest. No root, no packet
//! filter.
//!
//! **What happens.**
//! 1. The guest's `vox up` opens a SOCKS connection to the host's echo service over the direct
//!    path and it echoes: the guest now holds a live connection to the host process, and the
//!    forward has learned that connection's ID.
//! 2. The host process is killed. Its connection to the guest is now dead. The attacker turns on:
//!    the forward keeps carrying real traffic **and** sends the guest packets that its QUIC routes
//!    to the dead connection (they carry the learned connection ID) but that carry no valid
//!    crypto. These raise `udp_rx` (counted before decryption) and never `frame_rx`.
//! 3. The **same identity and room** come back as a `vox daemon` on the same address, reached
//!    through the same forward.
//! 4. A fresh SOCKS connection through the still-running `vox up` must reach the restarted host
//!    and echo within [`BOUND`] — the silence window plus the time to dial the new process — not
//!    the 60 s idle timeout.
//!
//! **What is asserted:**
//! - the attacker is really on path: the forward learned the connection ID, and sent spoofed
//!   packets throughout (else `CANNOT MEASURE`);
//! - the first connection and echo before the kill worked (staging);
//! - after the restart, under the attacker, a connection echoes within [`BOUND`].
//!
//! **Control:** the same world with no attacker reaches the restarted host within the same
//! [`BOUND`] — so the bound is death-detection, not the attacker's doing.
//!
//! **The mutation that must turn it red:** count `udp_rx` (datagrams observed) for liveness, the
//! behaviour before V210-140. The spoofed packets then keep the dead connection "heard", so the
//! new connection never takes over and the fresh connection waits out the idle timeout — red as
//! PRODUCT.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

#[path = "support/port_forward.rs"]
mod port_forward;

use std::time::{Duration, Instant};

use port_forward::{echo_over, interrupt, ForwardedWorld};
use world::socks5_connect;

/// A fresh connection must reach the restarted host within this of the restart: the silence
/// window ([`vox_core::node::net::SILENCE_IS_DEATH`], 30 s) plus the time to notice it, dial the
/// new process through the forward and echo. Well under QUIC's 60 s idle timeout, which is what a
/// dead connection kept "heard" waits out. A bound for a machine under ordinary load.
const BOUND: Duration = Duration::from_secs(45);

/// How often the attacker sends a spoofed packet: faster than the 1 s liveness sample, so the
/// buggy count would be raised on every sample.
const SPOOF_EVERY: Duration = Duration::from_millis(200);

/// The echo payload.
const PAYLOAD: usize = 4 * 1024;

/// Open a fresh SOCKS connection through `proxy` to the host and return whether it echoed within
/// `within`, and how long it took.
fn reach_and_echo(
    proxy: std::net::SocketAddr,
    hostname: &str,
    port: u16,
    within: Duration,
) -> (bool, Duration) {
    let t0 = Instant::now();
    let (code, mut s) = socks5_connect(proxy, hostname, port);
    if code != 0x00 {
        return (false, t0.elapsed());
    }
    let payload: Vec<u8> = (0..PAYLOAD).map(|i| (i % 251) as u8).collect();
    let ok = echo_over(&mut s, &payload, within.saturating_sub(t0.elapsed()));
    (ok, t0.elapsed())
}

/// Bring up a world, confirm the live direct path, kill the host, (optionally) turn on the
/// attacker, restart the host as a daemon, and return how long a fresh connection took to reach
/// it and whether it echoed.
fn failover_under(attacker: bool) -> (bool, Duration) {
    let mut w = ForwardedWorld::new(true);
    let hostname = w.hostname();
    let (_up, proxy, _ready) = w.up("up");

    // Step 1: the live direct path, which also makes the forward learn the connection's ID.
    let (ok, took) = reach_and_echo(proxy, &hostname, w.service_port, Duration::from_secs(30));
    assert!(
        ok,
        "PRODUCT (staging): the first connection to the host did not echo (after {took:?}), so \
         there is no live connection whose death to measure"
    );
    assert!(
        w.forward.learned_guest_cid(),
        "CANNOT MEASURE: the forward never learned the guest's connection ID from the host's \
         packets, so the on-path attacker cannot target the connection"
    );

    // Step 2: the host dies; the attacker turns on (snapshotting the dead connection's ID).
    interrupt(&mut w.host, Duration::from_secs(15));
    if attacker {
        assert!(
            w.forward.start_spoofing(SPOOF_EVERY),
            "CANNOT MEASURE: the attacker could not start — no connection ID or guest source learned"
        );
    }

    // Step 3: the same identity and room come back on the same address.
    let restarted_at = Instant::now();
    w.restart_host_as_daemon();

    // Step 4: a fresh connection must reach the new process within the bound.
    let (ok, _) = reach_and_echo(proxy, &hostname, w.service_port, BOUND);
    let elapsed = restarted_at.elapsed();
    if attacker {
        eprintln!(
            "[test] under the attacker ({} spoofed packets): a fresh connection {} after {elapsed:?}",
            w.forward.spoofed(),
            if ok { "echoed" } else { "did NOT echo" }
        );
        assert!(
            w.forward.spoofed() > 0,
            "CANNOT MEASURE: the attacker sent nothing, so the connection was never kept 'heard'"
        );
        w.forward.stop_spoofing();
    } else {
        eprintln!(
            "[test] control (no attacker): a fresh connection {} after {elapsed:?}",
            if ok { "echoed" } else { "did NOT echo" }
        );
    }
    (ok, elapsed)
}

#[test]
#[ignore = "real vox processes, production Argon2id + a real PoW, a 30 s silence window; CI runs it in release"]
fn a_spoofed_connection_id_cannot_keep_a_dead_path_alive() {
    watchdog::arm_for(Duration::from_secs(300));
    test_knobs::require(&["VOX_TEST_ADVERTISE"]);

    // Under the attacker: the connection ID is spoofed throughout, and the node must still fail
    // over within the bound.
    let (ok, took) = failover_under(true);
    assert!(
        ok && took <= BOUND,
        "PRODUCT: with an on-path attacker spoofing the dead connection's ID, a fresh connection \
         reached the restarted host only after {took:?} (echoed: {ok}); liveness must be counted \
         from authenticated packets so the dead connection is given up within {BOUND:?}, not kept \
         alive to the idle timeout (PRD-001 R22, ADR-012, V210-140)"
    );

    // The control: with no attacker, death is detected within the same bound, so the bound is the
    // product's own failover, not anything the attacker does.
    let (ok, took) = failover_under(false);
    assert!(
        ok && took <= BOUND,
        "PRODUCT (staging): with no attacker, a fresh connection reached the restarted host only \
         after {took:?} (echoed: {ok}); the bound {BOUND:?} must hold without any attacker, or it \
         measures the attacker and not the product"
    );
}
