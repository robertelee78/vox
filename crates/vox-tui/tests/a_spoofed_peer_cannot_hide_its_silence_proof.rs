//! V210-140 (#359) — **a connection's liveness is counted only from packets that authenticate**, so
//! garbage carrying a known connection ID cannot keep a dead connection looking alive.
//!
//! **The claim, as a person meets it.** A guest uses a host's service through `vox up`, over a
//! direct path. The path dies: from then on nothing the host sends reaches the guest. An attacker
//! on the path, who has seen the host's packets, keeps sending the guest garbage that carries the
//! host's connection ID, from the host's address. The guest must still notice the connection is
//! dead within the normal bound and carry its next request over the anchor's circuit. The room's
//! host is a member, never an anchor (V030-51); a direct connection that something is waiting on
//! is probed as an anchor's is: probed after 3 s of silence, taken for gone after 8 s of unanswered
//! probes (V210-93). Before the fix the liveness count was of datagrams routed to the connection,
//! taken before authentication, so the garbage kept the dead connection "heard" and the guest
//! waited for QUIC's 60 s idle timeout.
//!
//! Measured: 9.5 s from the cut with the fix, when the host was still probed as an anchor. With the
//! host a member only (V030-51) and nothing probing a member's connection in use, 30.4–30.7 s: the
//! dead connection was caught only by `SILENCE_IS_DEATH`.
//!
//! **The staging — real processes only** (`support/port_forward.rs`'s `ForwardedWorld`). A `vox
//! node` anchor, a `vox serve` host on `127.0.0.1` behind a port forward the proof owns, and the
//! guest's `vox up` on `[::1]`. The forward is the pair's only direct path, so closing it kills the
//! direct path while both processes keep running, and the forward is also where the attacker sits:
//! while closed it spoofs the host to the guest (garbage after the head of the host's last
//! short-header packet, every 20 ms).
//!
//! **What is asserted.** A request rode the direct path before the cut (its echo crossed the
//! forward); the spoofer sent the guest garbage throughout; and from the cut, a request is answered
//! again within [`FAILOVER_WITHIN`].
//!
//! **The mutations that must turn it red:** count datagrams before authentication again
//! (`heard_count` in `node/net.rs` returning `quic.stats().udp_rx.datagrams`). The garbage then
//! keeps the dead connection heard, and the first request answered after the cut comes after the
//! idle timeout: red, as PRODUCT. And no probe of a connection in use
//! (`ConnectionManager::tend_liveness`): the first answer comes at `SILENCE_IS_DEATH`, 30 s.

// Optional (decider, 2026-10-01): it blocks nothing and CI only compiles it. Without
// `--features optional-proofs` a stand-in takes its place and says it was not run
// (`support/optional_proof.rs`). How to run it: docs/release/optional-proofs.md.
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(a_spoofed_peer_cannot_hide_a_dead_connection);

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

use std::sync::mpsc;
use std::time::{Duration, Instant};

use port_forward::{echo_over, interrupt, ForwardedWorld};
use world::socks5_connect;

/// From the cut to the first request answered again: an anchor's 8 s loss and its 1 s tick, a
/// request's spacing, a ladder, and room for a loaded machine; far under QUIC's 60 s idle timeout,
/// which is where a dead connection kept "heard" by garbage ends.
const FAILOVER_WITHIN: Duration = Duration::from_secs(20);
/// How long the proof waits for any answer after the cut before it stops looking.
const GIVE_UP: Duration = Duration::from_secs(120);
/// A new request after the cut, every this long, each on a thread of its own.
const REQUEST_EVERY: Duration = Duration::from_secs(2);
/// How long one request's echo may take once its CONNECT succeeded.
const ECHO_WITHIN: Duration = Duration::from_secs(5);
/// The echo payload: big enough that one which crossed the forward is unmistakable.
const PAYLOAD: usize = 16 * 1024;

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "real binaries, production Argon2id and a PoW, a dead path; run in release"]
fn a_spoofed_peer_cannot_hide_a_dead_connection() {
    watchdog::arm();
    let w = ForwardedWorld::new(true);
    eprintln!(
        "[proof] guest joined in {:?}; the forward at {} carries {} for the host",
        w.joined_in, w.forward.public, w.forward.host
    );
    let hostname = w.hostname();
    let payload: Vec<u8> = (0..PAYLOAD).map(|i| (i % 251) as u8).collect();
    let (mut up, proxy, _) = w.up("up");

    // Before the cut: a request whose echo crossed the forward, so the connection that dies is the
    // direct one.
    let staged = Instant::now();
    let direct = loop {
        let (code, mut s) = socks5_connect(proxy, &hostname, w.service_port);
        if code == 0 {
            let sent = w.forward.to_host();
            if echo_over(&mut s, &payload, ECHO_WITHIN)
                && w.forward.to_host() - sent >= PAYLOAD as u64
            {
                break true;
            }
        }
        if staged.elapsed() > Duration::from_secs(30) {
            break false;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    assert!(
        direct,
        "PRODUCT (staging): in 30 s the guest's `vox up` never carried a request over the direct \
         path the forward gives it, so there was no direct connection to kill.\nup:\n{}",
        up.transcript()
    );
    // The source that just carried the echo is the guest's `vox up`: the connection the spoofer
    // must hit.
    let guest = w
        .forward
        .last_from()
        .unwrap_or_else(|| panic!("APPARATUS: the forward carried an echo but kept no source"));
    assert!(
        w.forward.can_spoof(),
        "APPARATUS: the forward carried the pair's traffic but kept no short-header packet of the \
         host's, so the spoofer has no connection ID to replay"
    );

    // The cut: nothing more from the host reaches the guest, and the spoofer starts.
    let mark = up
        .timed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .len();
    w.forward.set_spoof(true);
    w.forward.close();
    let cut = Instant::now();
    let dropped_at_cut = w.forward.dropped();

    let (tx, rx) = mpsc::channel::<Instant>();
    let answered = loop {
        let (tx, host, port) = (tx.clone(), hostname.clone(), w.service_port);
        let payload = payload.clone();
        std::thread::spawn(move || {
            let (code, mut s) = socks5_connect(proxy, &host, port);
            if code == 0 && echo_over(&mut s, &payload, ECHO_WITHIN) {
                let _ = tx.send(Instant::now());
            }
        });
        match rx.recv_timeout(REQUEST_EVERY) {
            Ok(at) => break Some(at),
            Err(_) if cut.elapsed() > GIVE_UP => break None,
            Err(_) => {}
        }
    };
    w.forward.set_spoof(false);
    let spoofed = w.forward.spoofed();
    let failover = answered.map(|at| at.duration_since(cut));

    let said: Vec<String> = up
        .timed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .skip(mark)
        .map(|(at, line)| format!("  +{:>6} ms  {line}", at.duration_since(cut).as_millis()))
        .collect();
    eprintln!(
        "[proof] after the cut the spoofer sent the guest at {guest} {spoofed} garbage datagram(s); the forward \
         dropped {} of the pair's own; the first request answered again {}",
        w.forward.dropped() - dropped_at_cut,
        failover.map_or_else(|| format!("NEVER within {GIVE_UP:?}"), |d| format!("{d:?} after the cut"))
    );
    eprintln!(
        "[proof] the guest's `vox up` said, from the cut:\n{}",
        said.join("\n")
    );

    assert!(
        spoofed > 0,
        "APPARATUS: the spoofer sent the guest nothing, so this run tested no spoofing"
    );
    let targets = w.forward.spoofed_to();
    assert!(
        targets.len() == 1 && targets.contains(&guest),
        "APPARATUS: the spoofer sent its garbage to {targets:?}, not only to the guest's `vox up` at \
         {guest}, so this run did not show the garbage reaching the dead connection"
    );
    let failover = failover.unwrap_or_else(|| {
        panic!(
            "PRODUCT: after the direct path died, no request was answered within {GIVE_UP:?}.\nup:\n{}",
            up.transcript()
        )
    });
    assert!(
        failover <= FAILOVER_WITHIN,
        "PRODUCT: the direct path died and a spoofer sent the guest garbage under the host's \
         connection ID; the guest's first request was answered again only {failover:?} after the \
         cut, over {FAILOVER_WITHIN:?}: {}.\nup said from the cut:\n{}",
        if failover >= Duration::from_secs(55) {
            "the garbage kept the dead connection looking alive until QUIC's idle timeout"
        } else {
            "the dead connection in use was not probed and closed within its 8 s, and waited out \
             the 30 s silence bound"
        },
        said.join("\n")
    );
    if !interrupt(&mut up, Duration::from_secs(15)) {
        eprintln!("[proof] `vox up` did not exit on Ctrl-C within 15 s; killed");
    }
}
