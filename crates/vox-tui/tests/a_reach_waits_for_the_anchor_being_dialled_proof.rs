//! V210-57 — **a reach that finds nobody to carry its circuit yet waits for the anchor being
//! dialled**, rather than failing and costing a one-shot verb its 500 ms retry.
//!
//! **The defect.** `vox forward` reaches its host the moment its room is open. A restarted forward
//! sometimes did so before its anchor connection existed: the host's address unknown, no helper,
//! "no peer is connected to carry a circuit" — and its next attempt came 500 ms later. Two of nine
//! runs of the relayed R42 proof had a restart at 556 and 617 ms, against V210-57's 150 ms
//! (`reached … (2 attempts)`).
//!
//! **The staging — real processes only.** `support/relay.rs`'s split world: the host on
//! `127.0.0.1`, the guest on `[::1]`, so the only path between them is the anchor's circuit. The
//! guest's `vox forward` names the anchor through a port forward the proof owns
//! (`support/port_forward.rs`) that holds every datagram towards the anchor for
//! [`ANCHOR_DELAY`]: its anchor connection takes longer to come than its first reach does to begin.
//! Under one daemon per data root (ADR-026) the join's daemon would still hold the guest's node,
//! its anchor connection and its circuit to the host, so it is stopped by its pid first: the
//! forward starts the daemon afresh and attaches a node that has nothing connected yet. And the
//! guest's log holds the host's share before that (`vox service list`), or the forward would
//! wait for a sync with a member, whose own reach brings the anchor connection up first.
//!
//! **Asserted.** The premise first: the forward's first reach found nobody to carry its circuit —
//! it says it waited for a dial under way, or it says it could not reach the host because no peer
//! was connected. Neither: its anchor answered first, nothing was staged, `CANNOT MEASURE`. Then the
//! claim: it reached the host on its **first attempt**, carried an echo, and never said "no peer is
//! connected to carry a circuit". The path is asserted relayed (the forward's `still relayed`).
//! And the time: once the anchor answered, the circuit was asked at once — under [`ASK_WITHIN`] into
//! the reach, by the forward's own "asking … for a circuit N ms into the reach" — not after the
//! direct head start, since there was no direct rung to give it to.
//!
//! **Why no 150 ms bound here.** Every datagram to the anchor is held [`ANCHOR_DELAY`], so the
//! anchor handshake and the circuit alone take several hundred ms. V210-57's 150 ms restart bound
//! is proved by its own proof, `a_first_relayed_connection_is_under_two_seconds_proof`, as a caller;
//! this proof shows the two costs the product controls are gone: the forward's 500 ms retry, and
//! the head start sat out with nothing direct to wait for.
//!
//! **The mutations that must turn it red, as PRODUCT:** delete the wait for a dial under way in
//! `NodeNet::reach_ladder` — the first attempt fails with nobody to carry it, and the forward reaches
//! the host on its second; or make a circuit with no direct rung sit out the head start
//! (`direct_failed` starting `false`) — the circuit is asked about 500 ms into the reach.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[path = "support/port_forward.rs"]
mod port_forward;

use std::net::SocketAddr;
use std::time::Duration;

use port_forward::PortForward;
use relay::{RelayWorld, Split};
use world::round_trip;

/// How long the port forward holds each datagram from the guest to the anchor: long enough that
/// the forward's anchor handshake is still under way when its first reach begins.
const ANCHOR_DELAY: Duration = Duration::from_millis(100);
/// How soon, once the anchor answered, a reach with no direct rung must ask it for a circuit. The
/// head start it must not sit out is 500 ms; a prompt ask is a few ms.
const ASK_WITHIN: u128 = 50;
/// How long the guest's node, joined and running, may take to sync the host's share.
const SHARE_SYNCED_WITHIN: Duration = Duration::from_secs(60);
/// What a reach says when it fails for want of a helper.
const NOBODY: &str = "no peer is connected to carry a circuit";

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; run in release"]
fn a_forward_whose_anchor_is_still_being_dialled_reaches_on_its_first_attempt() {
    watchdog::arm();
    let mut w = RelayWorld::new(Split::Families);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "CANNOT MEASURE: the guest could not join over the relay ({took:?}).\n{out}\n{err}"
    );
    // `vox forward` resolves its name from the room's log first (V030-25): until the guest's log
    // holds the host's share, it waits for a sync with a member, and that sync's own reach takes
    // the anchor connection up before the forward's reach begins. So the share is synced while
    // the join's daemon runs, as a person's node does once it has been in the room a moment.
    // Attached for the whole wait, so one node syncs (a one-shot `vox service list` on its own
    // would attach a fresh node for each look and detach it again).
    world::attach::Root::at(&w.guest_dir, world::IDENTITY).attach(world::DEFAULT_NODE);
    let listed = format!("  {}.", w.service);
    let t0 = std::time::Instant::now();
    let mut said = String::new();
    while !said.contains(&listed) && t0.elapsed() < SHARE_SYNCED_WITHIN {
        let (_, out, err) =
            world::vox_once(&w.guest_dir, &world::args(&["service", "list", &w.room]));
        said = format!("{out}{err}");
        if !said.contains(&listed) {
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    // The guest's own node, joined and running, syncing its room: vox's step, so not reaching it
    // is the product's (a reach that fails for want of a helper instead of waiting for the dial
    // under way fails this sync too, and backs it off past the bound).
    assert!(
        said.contains(&listed),
        "PRODUCT (staging): the guest's node, joined and running, never synced the host's share \
         `{}` within {SHARE_SYNCED_WITHIN:?} (`vox service list`): {said}",
        w.service
    );
    eprintln!(
        "[proof] the guest's log held the host's share {:.1}s after its join",
        t0.elapsed().as_secs_f64()
    );
    // The join's daemon still holds the guest's node, its anchor connection and the circuit to
    // the host (ADR-026): a forward started now is a client of it and reaches in 0 ms, with
    // nothing being dialled. Stopped by its pid, the forward below starts the guest's daemon
    // afresh: the node it attaches holds the share already, so the forward reaches at once,
    // while that node's dial to its anchor, through the slow path only, is still under way.
    world::reap_daemon(&w.guest_dir);
    let slow = PortForward::start(SocketAddr::from(([127, 0, 0, 1], w.anchor.port())), true);
    slow.set_delay(ANCHOR_DELAY);
    let anchor_fp = w
        .anchor
        .v6_spec
        .split_once('@')
        .map(|(fp, _)| fp.to_owned())
        .unwrap_or_else(|| {
            panic!(
                "APPARATUS: the harness's anchor spec {:?} is not fp@address",
                w.anchor.v6_spec
            )
        });
    let spec = format!("{anchor_fp}@/ip6/::1/udp/{}", slow.public.port());

    let at = w.forward_through(&spec);
    let back = round_trip(at, b"through the slow anchor", Duration::from_secs(60));
    let said = w
        .fwd
        .as_mut()
        .map(world::VoxProc::transcript)
        .unwrap_or_default();
    let back = back.unwrap_or_else(|e| {
        panic!("PRODUCT: no echo came back through the forward ({e}).\nforward:\n{said}")
    });
    assert!(
        back == b"through the slow anchor",
        "PRODUCT: the echo came back changed: {back:?}"
    );
    w.expect_still_relayed();

    let reached = said
        .lines()
        .find(|l| l.contains("vox: reached "))
        .unwrap_or_else(|| {
            panic!("PRODUCT: the forward never said it reached the host.\nforward:\n{said}")
        })
        .to_owned();
    let attempts: u32 = reached
        .split(" ms (")
        .nth(1)
        .and_then(|r| r.split(' ').next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("PRODUCT: no attempt count in the forward's line {reached:?}"));
    let waited = said
        .lines()
        .find(|l| l.contains("for a dial under way"))
        .map(str::to_owned);
    let failed = said.lines().any(|l| l.contains(NOBODY));
    eprintln!(
        "[proof] through a {ANCHOR_DELAY:?} anchor path: {reached}; waited: {}; failed for want of a \
         helper: {failed}",
        waited.as_deref().unwrap_or("no")
    );
    assert!(
        waited.is_some() || failed,
        "CANNOT MEASURE (staging not achieved): the forward's anchor connection was up before its \
         first reach began, so nothing here needed waiting for: {reached}\nforward:\n{said}"
    );
    assert!(
        attempts == 1 && !failed,
        "PRODUCT: the forward's first reach found nobody to carry its circuit while its anchor was \
         still being dialled, and failed (\"{NOBODY}\") instead of waiting for it: {reached}\n\
         forward:\n{said}"
    );
    let asked = said
        .lines()
        .find_map(|l| {
            let rest = l.split(" for a circuit ").nth(1)?;
            let ms = rest.split(" ms into the reach").next()?;
            ms.trim().parse::<u128>().ok().map(|ms| (ms, l.to_owned()))
        })
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT: the forward reached the host relayed but never said when it asked for its \
                 circuit.\nforward:\n{said}"
            )
        });
    eprintln!(
        "[proof] the circuit was asked {} ms into the reach",
        asked.0
    );
    assert!(
        asked.0 <= ASK_WITHIN,
        "PRODUCT: with no direct rung, the reach sat out the direct head start before asking the \
         anchor for its circuit ({} ms, over {ASK_WITHIN} ms): {}\nforward:\n{said}",
        asked.0,
        asked.1
    );
}
