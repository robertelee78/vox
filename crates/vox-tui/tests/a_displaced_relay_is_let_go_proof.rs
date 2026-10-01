//! ADR-012 M15.1b, V29-15 (#50) — **a relayed path that a direct one displaced is let go once its
//! grace is up**, driven through the shipped `vox` binary: the anchor stops carrying the circuit.
//!
//! When a direct path appears behind a relayed one, the direct one replaces it and the relayed one
//! is *retired*, not closed, for a grace (`RETIRE_GRACE_SECS`, 60 s) so nothing in flight on it is
//! cut; then, if nothing is carried on it, it is closed. The defect this holds against: each
//! connection's stream loop held the connection's `Arc` for its whole life, so the "still carried"
//! count never fell and **no retired connection was ever closed** — a pair that went direct kept
//! its circuit on the anchor for good: the anchor's slot, its two connections' keep-alives, and a
//! third party still able to see that the pair talks, for a path nobody used.
//!
//! **The staging — real processes only.** `support/port_forward.rs`: a `vox node` anchor on `[::]`,
//! a `vox serve` host on `127.0.0.1` advertising a port forward the proof owns, and a guest on
//! `[::1]` that joined with `vox connect` and asks for the host's service through `vox up`. Split by
//! address family, the forward is the pair's only direct path. It starts **closed**, so the guest's
//! first request rides the anchor's circuit (observed: the anchor reports a circuit carried, and no
//! payload crossed the forward); then it is **opened**, and the pair's own retry finds the direct
//! path (observed: a request's echo payload counted crossing the forward).
//!
//! **What is asserted:** from the moment a request rides the direct path, the anchor's own report
//! of circuits carried falls to **0** within [`LET_GO_WITHIN`] = 75 s — the 60 s grace and 15 s for
//! a status line and a loaded box, written as a number so a longer grace goes red. Nothing is
//! carried on the circuit meanwhile: every request after the upgrade rides the forward.
//!
//! **The mutation that must turn it red:** `ConnectionManager::retire_expired` treating every
//! retired connection as still carried (the old defect's effect). The circuit stays at the anchor
//! and the count never reaches 0.
//!
//! Replaces `crates/vox-core/tests/displaced_relay_is_let_go.rs` (property 1), which ran every node
//! in process on a NAT simulator with an injected clock. Its property 2 — a displaced path carrying
//! a live tunnel stays up past the grace — is RP-26's, held below by
//! `a_tunnel_on_a_displaced_path_is_not_cut_by_its_grace` on the same staging.

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

/// From the direct path taking over to the anchor carrying no circuit: the 60 s grace and 15 s of
/// margin. A number, not the product constant.
const LET_GO_WITHIN: Duration = Duration::from_secs(75);
/// How long the pair may take to find the opened forward: one 60 s retry interval, the ladder,
/// and margin. Past it the proof cannot measure what it is for.
const UPGRADE_WITHIN: Duration = Duration::from_secs(100);
const PAYLOAD: usize = 16 * 1024;

#[test]
#[ignore = "production Argon2id + a real PoW, a relayed pair upgraded and a 60 s grace watched; run in release"]
fn a_relayed_path_a_direct_one_displaced_is_let_go_after_its_grace() {
    watchdog::arm();
    let mut w = ForwardedWorld::new(false);
    eprintln!(
        "[proof] guest joined through the relay in {:?}; forward {} (closed) for the host at {}",
        w.joined_in, w.forward.public, w.forward.host
    );
    let hostname = w.hostname();
    let payload: Vec<u8> = (0..PAYLOAD).map(|i| (i % 251) as u8).collect();
    let (mut up, proxy, _) = w.up("up");

    let request = |w: &ForwardedWorld| -> Option<bool> {
        let (code, mut s) = socks5_connect(proxy, &hostname, w.service_port);
        if code != 0 {
            return None;
        }
        let sent = w.forward.to_host();
        echo_over(&mut s, &payload, Duration::from_secs(10))
            .then(|| w.forward.to_host() - sent >= PAYLOAD as u64)
    };

    // Relayed first, observed.
    let first = request(&w);
    assert_eq!(
        first,
        Some(false),
        "CANNOT MEASURE: the first request, with the forward closed, should have been answered over \
         the anchor's circuit (Some(false)); it was {first:?}.\nup:\n{}",
        up.transcript()
    );
    w.anchor.assert_relayed("after the first request");

    // A direct path becomes possible; the pair's retry finds it.
    w.forward.open();
    let opened = Instant::now();
    let mut direct_at = None;
    while opened.elapsed() < UPGRADE_WITHIN {
        std::thread::sleep(Duration::from_millis(500));
        if request(&w) == Some(true) {
            direct_at = Some(Instant::now());
            break;
        }
    }
    let Some(direct_at) = direct_at else {
        panic!(
            "CANNOT MEASURE: {UPGRADE_WITHIN:?} after the forward opened, no request rode it — there \
             is no displaced relayed path to watch.\nup:\n{}",
            up.transcript()
        );
    };
    eprintln!(
        "[proof] a request rode the direct path {:?} after the forward opened",
        direct_at - opened
    );

    // The displaced circuit must be let go: the anchor's count falls to 0. Requests keep going
    // meanwhile, each checked to ride the forward, so nothing is carried on the circuit.
    let mut n = w.anchor.circuits(Duration::from_secs(1));
    let mut requests = 0usize;
    let mut over_circuit = 0usize;
    while n > 0 && direct_at.elapsed() < LET_GO_WITHIN {
        match request(&w) {
            Some(true) => requests += 1,
            Some(false) => over_circuit += 1,
            None => {}
        }
        n = w.anchor.circuits(Duration::from_secs(1));
    }
    let took = direct_at.elapsed();
    eprintln!(
        "[proof] anchor circuits {n} at {took:?} after the direct path took over; {requests} requests \
         rode the forward meanwhile, {over_circuit} the circuit"
    );
    assert_eq!(
        over_circuit, 0,
        "a request rode the circuit after the direct path took over — the displaced path was still \
         in use, so letting it go is not what is being measured"
    );
    assert_eq!(
        n,
        0,
        "NOT LET GO: the anchor still carries {n} circuit(s) {took:?} after the direct path took over, \
         past the 60 s grace — a pair that went direct keeps its relay for good.\nanchor:\n{}",
        w.anchor.proc.transcript()
    );
    interrupt(&mut up, Duration::from_secs(15));
    drop(up);
}

/// RP-26 (#133) — **a better path displacing a worse one cuts nothing it carries**, through the
/// shipped `vox`, on the staging above.
///
/// A person has a session open through `vox up` — an `ssh`, a file transfer — while the pair is on
/// the anchor's circuit. A direct path appears and displaces the circuit, which is retired for its
/// 60 s grace. The session must not notice: a retired connection still carrying something is kept
/// for as long as it does. The defect this holds against closed on the timer alone, which reached
/// the person as `Connection reset by peer` mid-session whenever a better path came along.
///
/// **Observed, never assumed** (CANNOT MEASURE otherwise): the session's first echo rode the
/// circuit (the forward was closed and carried none of it); after the forward opened a *new*
/// request rode it (the pair went direct); the host or the guest reported its relayed connection
/// displaced; and every later echo on the session still crossed the anchor, not the forward — it
/// stayed on the displaced path.
///
/// **Asserted:** the session opened before the upgrade answers an echo, whole, every few seconds
/// until the grace and 15 s for the tick have passed since the direct path took over.
///
/// **The mutation that must turn it red:** `ConnectionManager::retire_expired` treating no
/// retired connection as still carried (`let still_carried = false;`): the displaced path closes
/// when its grace ends and the session's next echo fails.
#[test]
#[ignore = "production Argon2id + a real PoW, a relayed pair upgraded and a 60 s grace held; run in release"]
fn a_tunnel_on_a_displaced_path_is_not_cut_by_its_grace() {
    watchdog::arm();
    // From the direct path taking over, past the grace and a tick: the product's constant, so a
    // longer grace lengthens the hold rather than letting a cut at its end go unseen.
    let hold = Duration::from_secs(vox_core::node::net::RETIRE_GRACE_SECS + 15);
    let mut w = ForwardedWorld::new(false);
    eprintln!(
        "[proof] guest joined through the relay in {:?}; forward {} (closed) for the host at {}",
        w.joined_in, w.forward.public, w.forward.host
    );
    let hostname = w.hostname();
    let payload: Vec<u8> = (0..PAYLOAD).map(|i| (i % 251) as u8).collect();
    let (mut up, proxy, _) = w.up("up");

    // The person's session, opened while the circuit is the only path.
    let (code, mut session) = socks5_connect(proxy, &hostname, w.service_port);
    assert_eq!(
        code,
        0,
        "PRODUCT (staging): vox up refused the session over the anchor's circuit (SOCKS reply \
         {code}).\nup:\n{}",
        up.transcript()
    );
    // One echo on the session; whether it came back, and whether it crossed the forward.
    let echo = |s: &mut std::net::TcpStream, w: &ForwardedWorld| -> (bool, bool) {
        let sent = w.forward.to_host();
        let ok = echo_over(s, &payload, Duration::from_secs(10));
        (ok, w.forward.to_host() - sent >= PAYLOAD as u64)
    };
    let (ok, direct) = echo(&mut session, &w);
    assert!(
        ok,
        "PRODUCT (staging): the session's first echo over the anchor's circuit did not come back \
         whole.\nup:\n{}",
        up.transcript()
    );
    assert!(
        !direct,
        "CANNOT MEASURE: the session's first echo crossed the forward while it was closed"
    );
    let n = w.anchor.circuits(Duration::from_secs(2));
    assert!(
        n >= 1,
        "CANNOT MEASURE: the anchor reports {n} circuits with the session open — it is not on a \
         relayed path.\nanchor:\n{}",
        w.anchor.proc.transcript()
    );

    // A direct path becomes possible; the pair's retry finds it, seen by a new request riding it.
    // The session is exercised meanwhile, as a person's would be.
    w.forward.open();
    let opened = Instant::now();
    let mut direct_at = None;
    while opened.elapsed() < UPGRADE_WITHIN {
        std::thread::sleep(Duration::from_millis(500));
        let (ok, _) = echo(&mut session, &w);
        assert!(
            ok,
            "PRODUCT: the session stopped answering {:?} after the forward opened, before any \
             request rode it.\nup:\n{}\nhost:\n{}",
            opened.elapsed(),
            up.transcript(),
            w.host.transcript()
        );
        let (code, mut s) = socks5_connect(proxy, &hostname, w.service_port);
        if code == 0 && echo(&mut s, &w) == (true, true) {
            direct_at = Some(Instant::now());
            break;
        }
    }
    let Some(direct_at) = direct_at else {
        panic!(
            "CANNOT MEASURE: {UPGRADE_WITHIN:?} after the forward opened, no request rode it — there \
             is no displaced path under the session.\nup:\n{}",
            up.transcript()
        );
    };
    // Either side's own report that its relayed connection was displaced.
    let displaced = |p: &world::VoxProc| {
        p.timed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|(_, l)| l.contains("displaced the one held") && l.contains("Relayed)"))
            .map(|(at, _)| at.saturating_duration_since(opened))
    };
    let (host_displaced, up_displaced) = (displaced(&w.host), displaced(&up));
    assert!(
        host_displaced.is_some() || up_displaced.is_some(),
        "CANNOT MEASURE: a request rode the forward, but neither side reported its relayed \
         connection displaced.\nup:\n{}\nhost:\n{}",
        up.transcript(),
        w.host.transcript()
    );
    eprintln!(
        "[proof] a request rode the direct path {:?} after the forward opened; relayed connection \
         displaced at the host {host_displaced:?}, at the guest {up_displaced:?}",
        direct_at - opened
    );

    // The hold: the session answers, on the displaced path, until well past its grace.
    let mut echoes = 0usize;
    while direct_at.elapsed() < hold {
        std::thread::sleep(Duration::from_secs(3));
        let (ok, direct) = echo(&mut session, &w);
        assert!(
            ok,
            "PRODUCT: CUT — the session opened over the relayed path stopped answering {:?} after \
             the direct path displaced it ({echoes} echoes answered before): a better path cut a \
             live session it carried.\nup:\n{}\nhost:\n{}",
            direct_at.elapsed(),
            up.transcript(),
            w.host.transcript()
        );
        assert!(
            !direct,
            "CANNOT MEASURE: an echo on the session crossed the forward {:?} after the upgrade — it \
             was not on the displaced path",
            direct_at.elapsed()
        );
        echoes += 1;
    }
    let n = w.anchor.circuits(Duration::from_secs(2));
    assert!(
        n >= 1,
        "CANNOT MEASURE: the session answered, but the anchor reports {n} circuits — it was not \
         on the displaced path.\nanchor:\n{}",
        w.anchor.proc.transcript()
    );
    eprintln!(
        "[proof] the session answered {echoes}/{echoes} echoes on the displaced path, the last {:?} \
         after the direct path took over (grace {}s)",
        direct_at.elapsed(),
        vox_core::node::net::RETIRE_GRACE_SECS
    );
    drop(session);
    interrupt(&mut up, Duration::from_secs(15));
    drop(up);
}
