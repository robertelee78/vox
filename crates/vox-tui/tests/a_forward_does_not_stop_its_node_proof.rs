//! V210-41 (#215) — **opening a forward does not stop the node answering**, through the shipped
//! binary, on a path that is only a relay.
//!
//! **The defect.** `vox forward` dials the host once before it binds, to say why if the host
//! cannot be reached at all. That dial runs the whole reachability ladder, and it ran **on the
//! actor**, the one task that answers everyone: through a relay, one rung waits out its 10 s
//! direct-attempt timeout, so the node answered nobody for ten seconds —
//! `vox: busy 10000ms — opening a forward — nobody could be answered`, in every relayed UDP proof —
//! and `vox forward` retries the dial every 500 ms until the host is reachable.
//!
//! What this drives: an anchor, a host serving an echo on IPv4, and a guest on IPv6 that joins and
//! runs `vox forward` (so the anchor's circuit is the only path, asserted). The echo must cross,
//! and the forward's own node must report **no stall of a second or more** while opening or
//! binding the forward: the node's stall report is printed by the product itself, so this reads
//! what the product says about its own actor.
//!
//! Mutation: put the dial back on the actor (`begin_forward` awaiting `net.reach` itself) and the
//! 10 s stall is back.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::time::Duration;

use relay::{RelayWorld, Split};
use world::round_trip;

/// The longest the forward's node may be unable to answer anyone while it opens the forward.
/// The stall report itself starts at a second; anything it reports about a forward is a failure.
const STALL_ALLOWED: Duration = Duration::from_millis(999);

/// `busy 10000ms — opening a forward` → 10000, for the forward-related stalls only.
fn forward_stalls(transcript: &str) -> Vec<(u64, String)> {
    transcript
        .lines()
        .filter(|l| l.contains("busy ") && l.contains("forward"))
        .filter_map(|l| {
            let ms = l
                .split("busy ")
                .nth(1)?
                .split("ms")
                .next()?
                .trim()
                .parse()
                .ok()?;
            Some((ms, l.to_owned()))
        })
        .collect()
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn opening_a_relayed_forward_does_not_stop_the_node() {
    watchdog::arm();
    let mut w = RelayWorld::new(Split::Families);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "CANNOT PROVE: the guest could not join over the relay ({took:?}).\n{out}\n{err}"
    );
    let at = w.forward();
    let back = round_trip(at, b"through the relay", Duration::from_secs(120)).unwrap_or_else(|e| {
        panic!(
            "CANNOT PROVE: no echo through the forward ({e}).\n{}",
            w.fwd.as_mut().unwrap().transcript()
        )
    });
    assert_eq!(back, b"through the relay");
    // A relay is what makes the dial slow: prove it is one, not assume it.
    w.expect_still_relayed();
    w.assert_relayed("after the echo");

    let said = w.fwd.as_mut().unwrap().transcript();
    let stalls = forward_stalls(&said);
    eprintln!(
        "[proof] the forward's node reported {} forward stall(s): {stalls:?}",
        stalls.len()
    );
    let long: Vec<&(u64, String)> = stalls
        .iter()
        .filter(|(ms, _)| Duration::from_millis(*ms) > STALL_ALLOWED)
        .collect();
    assert!(
        long.is_empty(),
        "opening a forward stopped its node from answering anyone (#215): {long:#?}\nthe forward \
         said:\n{said}"
    );
}
