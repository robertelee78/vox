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
//!
//! **Asserted.** The premise first: the forward's first reach found nobody to carry its circuit —
//! it says it waited for a dial under way, or it says it could not reach the host because no peer
//! was connected. Neither: its anchor answered first, nothing was staged, `CANNOT MEASURE`. Then the
//! claim: it reached the host on its **first attempt**, carried an echo, and never said "no peer is
//! connected to carry a circuit". The path is asserted relayed (the forward's `still relayed`).
//!
//! **The mutation that must turn it red:** delete the wait for a dial under way in
//! `NodeNet::reach_ladder` — the first attempt fails with nobody to carry it, and the forward reaches
//! the host on its second: red, as PRODUCT.

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
}
