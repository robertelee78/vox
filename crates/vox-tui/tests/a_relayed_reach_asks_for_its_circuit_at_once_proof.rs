//! V210-122 (#321) — **a reach with no direct dial under way asks for its circuit at once**: the
//! direct head start is paid only while something direct might still answer.
//!
//! **The defect.** Every circuit waited the whole head start, even when the reach had no direct
//! candidate and no direct dial was running anywhere in the node. A pair that can only be relayed
//! paid it on every reach: relayed `vox forward` restarts took 253–271 ms, against 7–9 ms before
//! and V210-57's 150 ms bound (4 of 4 runs of the relayed R42 proof on c9c9e5ae).
//!
//! **The staging — real processes only.** `support/relay.rs`'s split world: the host on
//! `127.0.0.1`, the guest on `[::1]`, so the only path between them is the anchor's circuit. The
//! guest starts [`FORWARDS`] `vox forward`s, one after another, each a new process.
//!
//! **Asserted from the guest's own ladder**, not from a clock on the forward: each circuit it asks
//! for says `asking <relay> for a circuit N ms into the reach; its direct dial there was none`, and
//! adds `a direct dial elsewhere in this node held it back` when one did. The premise: at least one
//! circuit asked with no direct dial anywhere (none: `CANNOT MEASURE`). The claim: every such
//! circuit was asked under [`NO_WAIT_MS`] into its reach — far under the 500 ms head start. Each
//! forward carries an echo and stays relayed.
//!
//! **The mutation that must turn it red:** the circuit's wait made unconditional again (attempt 2's
//! `watch::channel(false)` and no check for a dial under way) — each circuit is asked ~500 ms into
//! its reach: red, as PRODUCT.

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

/// New `vox forward`s started; the first follows the guest's `vox connect`, the rest are restarts.
const FORWARDS: usize = 3;
/// Half the 500 ms head start, written as a number: a circuit asked this far into a reach with no
/// direct dial anywhere waited for something that could not come.
const NO_WAIT_MS: u128 = 250;

/// `asking <relay> for a circuit <N> ms into the reach; its direct dial there was none` with no dial
/// elsewhere holding it back → N.
fn asked_with_nothing_direct(note: &str) -> Option<u128> {
    if !note.contains("its direct dial there was none") || note.contains("held it back") {
        return None;
    }
    note.split("for a circuit ")
        .nth(1)?
        .split(" ms into")
        .next()?
        .trim()
        .parse()
        .ok()
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; run in release"]
fn a_relayed_reach_with_no_direct_dial_asks_for_its_circuit_at_once() {
    watchdog::arm();
    let mut w = RelayWorld::new(Split::Families);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "CANNOT MEASURE: the guest could not join over the relay ({took:?}).\n{out}\n{err}"
    );
    let mut asked: Vec<u128> = Vec::new();
    let mut said_all = String::new();
    for n in 0..FORWARDS {
        // A fresh `vox forward` each time: the previous one's process is killed by its PID first.
        drop(w.fwd.take());
        let at = w.forward();
        let payload = format!("forward {n}");
        let back = round_trip(at, payload.as_bytes(), Duration::from_secs(60));
        w.expect_still_relayed();
        let said = w
            .fwd
            .as_mut()
            .map(world::VoxProc::transcript)
            .unwrap_or_default();
        let back = back.unwrap_or_else(|e| {
            panic!("PRODUCT: forward {n}: no echo came back through the relay ({e}).\n{said}")
        });
        assert!(
            back == payload.as_bytes(),
            "PRODUCT: forward {n}: the echo came back changed"
        );
        let these: Vec<u128> = said.lines().filter_map(asked_with_nothing_direct).collect();
        eprintln!(
            "[proof] forward {n}: circuits asked with nothing direct under way, at {these:?} ms"
        );
        asked.extend(these);
        said_all.push_str(&format!("---- forward {n} ----\n{said}\n"));
    }
    w.assert_relayed("after the forwards");
    assert!(
        !asked.is_empty(),
        "CANNOT MEASURE (staging not achieved): in {FORWARDS} relayed forwards no circuit was asked \
         with no direct dial anywhere in the node, so nothing here could have waited for nothing.\n\
         {said_all}"
    );
    assert!(
        asked.iter().all(|ms| *ms < NO_WAIT_MS),
        "PRODUCT: a relayed reach with no direct candidate and no direct dial anywhere in the node \
         still waited before asking for its circuit (asked at {asked:?} ms into its reach, against \
         {NO_WAIT_MS} ms): a pair that can only be relayed pays the head start on every reach.\n\
         {said_all}"
    );
}
